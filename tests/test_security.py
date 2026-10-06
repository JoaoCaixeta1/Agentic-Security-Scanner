import json
import time
from pathlib import Path

import httpx
import pytest

import main
from scanner.agent import Planner
from scanner.config import Scope, ScopeError, Settings, local_url
from scanner.detectors import Detectors, valid_cpf
from scanner.network import Budget, Network, Observation, ScanLimit
from scanner.report import Finding, Redactor, Report, Results, write_report
from scanner.surface import inspect
from fixtures import fake_ollama, json_response


def context(url="http://127.0.0.1:3000/"):
    settings = Settings(url)
    report = Report()
    results = Results(report, Redactor())
    budget = Budget(30, time.monotonic() + 30)
    return settings, report, results, budget


@pytest.mark.parametrize("url", ["", "banana", "file:///etc/passwd", "http://localhost:0", "http://localhost:65536", "http://localhost:abc", "http://192.168.1.10", "http://169.254.169.254", "http://example.com", "http://localhost.evil.invalid", "http://127.0.0.1@evil.invalid", "http://user:secret@localhost", "http://@localhost", "http://[::ffff:127.0.0.1]", "http://localhost\\@evil.invalid", "http://localhost/\nfoo"])
def test_invalid_targets(url):
    with pytest.raises(ScopeError):
        local_url(url)


@pytest.mark.parametrize("url", ["http://127.0.0.1", "http://127.1.2.3:9090", "http://[::1]:3000", "https://localhost"])
def test_valid_loopback_targets(url):
    assert local_url(url).scheme in ("http", "https")


@pytest.mark.parametrize("reference", ["//example.invalid/x", "http://127.0.0.1:11434/api/chat", "https://127.0.0.1:3000/x", "http://localhost:3000/x", "http://127.0.0.2:3000/x", "ftp://127.0.0.1:3000/x"])
def test_same_origin_includes_host_port_and_scheme(reference):
    with pytest.raises(ScopeError):
        Scope("http://127.0.0.1:3000").require(reference)


def test_external_redirect_blocked_before_following():
    settings, report, results, budget = context()
    calls = []
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://127.0.0.1:11434/api/chat"}, stream=httpx.ByteStream(b""))
    net = Network(settings, budget, results, transport=httpx.MockTransport(handler))
    try:
        assert net.request("GET", settings.base_url, follow=True).status == 302
        assert calls == [settings.base_url]
        assert report.warnings
        with pytest.raises(ScopeError):
            net.request("DELETE", settings.base_url)
        assert len(calls) == 1
    finally:
        net.close()


def test_post_credentials_never_replayed_on_307():
    settings, report, results, budget = context()
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(307, headers={"Location": "/other"}, stream=httpx.ByteStream(b""))
    net = Network(settings, budget, results, transport=httpx.MockTransport(handler))
    try:
        net.request("POST", settings.base_url, data={"password": "secret"}, follow=True)
        assert len(calls) == 1
        assert report.warnings
    finally:
        net.close()


def test_budget_stops_before_extra_request():
    settings, _, results, budget = context()
    budget.max_requests = 1
    net = Network(settings, budget, results, transport=httpx.MockTransport(lambda r: json_response({})))
    try:
        net.request("GET", settings.base_url)
        with pytest.raises(ScanLimit):
            net.request("GET", settings.base_url)
        assert budget.count == 1
    finally:
        net.close()


def test_expired_budget():
    budget = Budget(10, time.monotonic() - 1)
    with pytest.raises(ScanLimit):
        budget.take()
    assert budget.count == 0


def test_cookie_secret_masked_and_short_secret_cannot_break_schema(tmp_path):
    report = Report(status="completed")
    redactor = Redactor(("a", "high", "cookie-value-18172"))
    results = Results(report, redactor)
    results.add("test", "http://localhost/x?token=cookie-value-18172", "GET", {"message": "cookie-value-18172", "cpf": "52998224725"}, title="Proof", severity="high", cwe="CWE-200", owasp="A01:2025", impact="Impact", remediation="Fix")
    path = tmp_path / "findings.json"
    write_report(report, path, redactor)
    saved = path.read_text()
    assert "cookie-value-18172" not in saved and "52998224725" not in saved
    assert Report.model_validate_json(saved).findings[0].severity == "high"
    assert path.stat().st_mode & 0o777 == 0o600


def observation(body, content_type="application/json", status=200):
    if isinstance(body, dict):
        body = json.dumps(body)
    return Observation("http-1", "http://127.0.0.1:3000/data", "GET", status, httpx.Headers({"Content-Type": content_type}), body.encode(), False, False)


@pytest.mark.parametrize("value,valid", [("529.982.247-25", True), ("52998224725", True), ("52998224724", False), ("11111111111", False), ("00000000000", False), ("123", False)])
def test_cpf_checksum(value, valid):
    assert valid_cpf(value) is valid


@pytest.mark.parametrize("body,ctype,expected", [
    ({"cpf": "52998224725"}, "application/json", 1),
    ({"cpf": "***", "order_id": "52998224725"}, "application/json", 0),
    ({"cpf": "11111111111"}, "application/json", 0),
    ({"cpf": "52998224724"}, "application/json", 0),
    ({"cpf": "example 52998224725"}, "application/json", 0),
    ("<p>CPF: 529.982.247-25</p>", "text/html", 1),
    ("<p>CPF de exemplo: 529.982.247-25</p>", "text/html", 0),
    ("<p>Pedido: 529.982.247-25</p>", "text/html", 0),
    ("{broken json cpf 52998224725", "application/json", 0),
])
def test_cpf_context_and_decoys(body, ctype, expected):
    settings, report, results, budget = context()
    net = Network(settings, budget, results, transport=httpx.MockTransport(lambda r: json_response({})))
    try:
        Detectors(net, results).cpf(observation(body, ctype, status=500))
        assert len(report.findings) == expected
    finally:
        net.close()


def test_external_form_and_script_cannot_expand_scope():
    obs = observation('<base href="https://evil.invalid/"><form action="/steal" method="post"><input type="password" name="pw"></form><script src="/x.js"></script><a href="http://127.0.0.1:11434/api/tags">model</a>', "text/html")
    surface = inspect(obs, Scope("http://127.0.0.1:3000"))
    assert surface.forms == [] and surface.links == []


@pytest.mark.parametrize("plan", [
    {"priority_ids": ["http://evil.invalid"]},
    {"priority_ids": [], "command": "rm -rf /"},
    {"login_form_id": "invented", "username_field": "user", "password_field": "secret"},
])
def test_untrusted_model_cannot_invent_actions(plan):
    settings, report, results, budget = context()
    def handler(request):
        if request.url.path == "/api/chat":
            return json_response({"message": {"content": json.dumps(plan)}})
        return fake_ollama(request)
    planner = Planner(settings, budget, results, httpx.MockTransport(handler))
    try:
        assert planner.preflight()
        assert planner.choose([{"id": "url-known", "url": settings.base_url, "source": "link"}], []) is None
        assert planner.successes == 0
        assert report.errors[0]["code"] == "ai_plan_rejected"
    finally:
        planner.close()


def test_cloud_model_metadata_rejected():
    settings, report, results, budget = context()
    def handler(request):
        if request.url.path == "/api/show":
            return json_response({"remote_host": "https://cloud.invalid"})
        return fake_ollama(request)
    planner = Planner(settings, budget, results, httpx.MockTransport(handler))
    try:
        assert not planner.preflight()
        assert planner.calls == 0
    finally:
        planner.close()


@pytest.mark.parametrize("url", [None, "http://192.168.1.10", "banana"])
def test_cli_invalid_configuration_still_writes_valid_report(monkeypatch, tmp_path, url):
    monkeypatch.chdir(tmp_path)
    if url is None:
        monkeypatch.delenv("BASE_URL", raising=False)
    else:
        monkeypatch.setenv("BASE_URL", url)
    assert main.main() == 2
    report = Report.model_validate_json((tmp_path / "findings.json").read_text())
    assert report.status == "error"
    assert report.findings == []
    assert report.finished_at


def test_json_login_is_derived_from_literal_script_only():
    html = '''<form><input name="email" type="email"><input name="password" type="password"></form>
    <script>fetch('/observed/session', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email:email.value,password:password.value})});</script>'''
    surface = inspect(observation(html, "text/html"), Scope("http://127.0.0.1:3000"))
    forms = [f for f in surface.forms if f.enctype == "application/json"]
    assert len(forms) == 1
    assert forms[0].action == "http://127.0.0.1:3000/observed/session"
    assert {f["name"] for f in forms[0].fields} == {"email", "password"}


def test_get_password_form_does_not_send_credentials(monkeypatch):
    from scanner.engine import Engine
    settings, report, results, _ = context()
    settings.username, settings.password = "private-user", "private-password"
    sent = []
    def handler(request):
        sent.append(request)
        return httpx.Response(200, headers={"Content-Type": "text/html"}, stream=httpx.ByteStream(b'<form><input name="u"><input name="p" type="password"></form>'))
    engine = Engine(settings, results, httpx.MockTransport(handler), httpx.MockTransport(fake_ollama))
    try:
        engine.run()
        assert all(r.method == "GET" and b"private" not in r.content and "private" not in str(r.url) for r in sent)
        assert report.authentication != "verified"
        assert report.warnings
    finally:
        engine.close()


def test_json_bearer_login_and_protected_reference():
    from scanner.engine import Engine
    settings, report, results, _ = context()
    settings.username, settings.password = "person-174", "secret-338"
    sent = []
    login_html = b'''<a href="/private-records">Conta</a><form><input name="email" type="email"><input name="password" type="password"></form>
    <script>fetch('/observed-session', {method:'POST', body:JSON.stringify({email:email.value,password:password.value})});</script>'''
    def handler(request):
        sent.append(request)
        if request.url.path == "/":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, stream=httpx.ByteStream(login_html))
        if request.url.path == "/observed-session" and request.method == "POST":
            assert json.loads(request.content) == {"email": settings.username, "password": settings.password}
            return json_response({"access_token": "private-token-12781"})
        if request.url.path == "/private-records":
            return json_response({"protected": "only for authenticated session"}, 200) if request.headers.get("Authorization") == "Bearer private-token-12781" else json_response({}, 401)
        return json_response({}, 404)
    engine = Engine(settings, results, httpx.MockTransport(handler), httpx.MockTransport(fake_ollama))
    try:
        engine.run()
        assert report.authentication == "verified"
        assert report.findings == []
        assert "private-token-12781" not in report.model_dump_json()
        assert sum(r.method == "POST" and r.url.path == "/observed-session" for r in sent) == 1
    finally:
        engine.close()


def test_public_redirector_remains_inconclusive():
    from urllib.parse import parse_qs
    settings, report, results, budget = context()
    def handler(request):
        destination = parse_qs(request.url.query.decode()).get("next", ["/"])[0]
        return httpx.Response(302, headers={"Location": destination}, stream=httpx.ByteStream(b"")) if request.url.path == "/go" else json_response({"public": True})
    net = Network(settings, budget, results, transport=httpx.MockTransport(handler))
    try:
        Detectors(net, results).redirects([settings.base_url + "go?next=/"])
        assert report.findings == []
        assert report.checks["open_redirect"]["inconclusive"] == 1
    finally:
        net.close()


def test_cli_request_limit_preserves_partial_json(monkeypatch, tmp_path):
    from scanner.engine import Engine
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BASE_URL", "http://127.0.0.1:3000")
    monkeypatch.setenv("MAX_REQUESTS", "1")
    monkeypatch.delenv("CHALLENGE_USERNAME", raising=False)
    monkeypatch.delenv("CHALLENGE_PASSWORD", raising=False)
    def handler(request):
        return httpx.Response(200, headers={"Content-Type": "text/html"}, stream=httpx.ByteStream(b'<a href="/next">Next</a>'))
    monkeypatch.setattr(main, "Engine", lambda settings, results: Engine(settings, results, httpx.MockTransport(handler), httpx.MockTransport(fake_ollama)))
    assert main.main() == 3
    report = Report.model_validate_json((tmp_path / "findings.json").read_text())
    assert report.status == "partial"
    assert report.coverage["target_requests"] == 1
    assert any(e["code"] == "scan_limit" for e in report.errors)


def test_cli_interrupt_preserves_valid_json(monkeypatch, tmp_path):
    from scanner.engine import Engine
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BASE_URL", "http://127.0.0.1:3000")
    def handler(request):
        raise KeyboardInterrupt()
    monkeypatch.setattr(main, "Engine", lambda settings, results: Engine(settings, results, httpx.MockTransport(handler), httpx.MockTransport(fake_ollama)))
    assert main.main() == 130
    report = Report.model_validate_json((tmp_path / "findings.json").read_text())
    assert report.status == "partial"
    assert report.errors[0]["code"] == "interrupted"


def test_inference_failure_stops_further_model_calls():
    settings, report, results, budget = context()
    calls = []
    def handler(request):
        calls.append(request.url.path)
        return json_response({"error": "private runtime detail"}, 500) if request.url.path == "/api/chat" else fake_ollama(request)
    planner = Planner(settings, budget, results, httpx.MockTransport(handler))
    try:
        assert planner.preflight()
        assert planner.choose([], []) is None
        assert planner.choose([], []) is None
        assert calls.count("/api/chat") == 1
        assert report.errors[0]["code"] == "ollama_inference_failed"
        assert "private runtime detail" not in report.model_dump_json()
    finally:
        planner.close()


def test_required_csrf_cookie_is_not_mistaken_for_authentication_cookie():
    settings, report, results, budget = context()
    body = b'{"protected":"account accessible with authenticated session"}'
    def handler(request):
        if request.url.path == "/establish":
            return httpx.Response(200, headers=[("Set-Cookie", "sid=secret-session; Path=/; HttpOnly"), ("Set-Cookie", "csrf=javascript-readable; Path=/")], stream=httpx.ByteStream(b""))
        cookie = request.headers.get("Cookie", "")
        if "sid=secret-session" in cookie and "csrf=javascript-readable" in cookie:
            return httpx.Response(200, headers={"Content-Type": "application/json"}, stream=httpx.ByteStream(body))
        return json_response({}, 403)
    net = Network(settings, budget, results, transport=httpx.MockTransport(handler))
    try:
        net.request("GET", settings.base_url + "establish")
        reference = net.request("GET", settings.base_url)
        Detectors(net, results).cookie_flags(reference)
        assert report.findings == []
        assert report.checks["session_cookie_flags"]["inconclusive"] == 1
    finally:
        net.close()


def test_url_encoded_secret_in_path_is_redacted():
    redactor = Redactor(["private/session+token with space"])
    value = redactor.url("http://localhost/private%2Fsession%2Btoken%20with%20space")
    assert "private" not in value
    assert "REDACTED" in value


def test_login_button_wins_over_registration_link_in_same_form():
    from scanner.surface import inspect
    source = '''<form action="/session" method="post">Please sign-in
      <input name="username"><input name="password" type="password">
      <input name="login-submit" type="submit" value="Login">
      Don't have an account? <a href="/register">Please register here</a></form>'''
    registration = '''<form action="/register" method="post">Create account
      <input name="username"><input name="password" type="password">
      <input name="register-submit" type="submit" value="Register"></form>'''
    def forms(html):
        return inspect(observation(html, "text/html"), Scope("http://127.0.0.1:3000")).forms
    assert forms(source)[0].login
    assert not forms(registration)[0].login


def test_short_cookie_secret_does_not_damage_target_or_evidence_urls(tmp_path):
    report = Report(target="http://127.0.0.1:4282/")
    report.checks["example"] = {"details":[{"url":"http://127.0.0.1:4282/path/0?token=secret"}]}
    redactor = Redactor(("0", "secret"))
    path = tmp_path / "findings.json"
    write_report(report, path, redactor)
    saved = Report.model_validate_json(path.read_text())
    assert saved.target == "http://127.0.0.1:4282/"
    assert saved.checks["example"]["details"][0]["url"].startswith("http://127.0.0.1:4282/")
    assert "secret" not in path.read_text()
    assert "/path/0" not in saved.checks["example"]["details"][0]["url"]
