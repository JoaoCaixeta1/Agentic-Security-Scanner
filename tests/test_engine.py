import json
from urllib.parse import urlsplit

import httpx
import pytest

from scanner.config import Settings
from scanner.engine import Engine
from scanner.report import Redactor, Report, Results, write_report
from fixtures import fake_ollama, target


def execute(state, ai_transport=None):
    user, password = state["credentials"]
    settings = Settings(state["url"], username=user, password=password, max_seconds=60)
    report = Report(target=state["url"])
    redactor = Redactor((user, password))
    engine = Engine(settings, Results(report, redactor), ai_transport=ai_transport or httpx.MockTransport(fake_ollama))
    try:
        engine.run()
    finally:
        engine.summarize()
        engine.close()
    return report, redactor


def test_five_checks_on_real_http_randomized_routes(tmp_path):
    with target(True) as state:
        report, redactor = execute(state)
        assert report.authentication == "verified"
        assert report.ai["valid_decisions"] > 0
        kinds = {f.type for f in report.findings}
        assert kinds == {"cpf_exposure", "http_method_tampering", "session_cookie_flags", "session_after_logout", "open_redirect"}
        assert not report.errors
        write_report(report, tmp_path / "findings.json", redactor)
        saved = (tmp_path / "findings.json").read_text()
        assert "529.982.247-25" not in saved
        assert state["credentials"][1] not in saved
        for session in state["sessions"]:
            assert session not in saved
        Report.model_validate_json(saved)
        assert all(path.startswith(urlsplit(state["url"]).path) for _, path in state["requests"])
        assert report.coverage["target_requests"] <= 300


def test_protected_counterpart_produces_zero_findings():
    with target(False) as state:
        report, _ = execute(state)
        assert report.authentication == "verified"
        assert report.findings == []
        assert not report.errors
        assert report.checks["session_after_logout"]["tested"] == 1
        assert report.checks["http_method_tampering"]["tested"] > 0
        assert report.checks["http_method_tampering"]["negative"] > 0
        assert report.checks["session_after_logout"]["negative"] == 1
        assert report.checks["session_cookie_flags"]["negative"] == 1
        assert report.checks["session_after_logout"]["reasons"] == {"old_session_rejected_after_logout": 1}


def test_unavailable_ai_is_explicit_and_deterministic_work_continues():
    def offline(request):
        raise httpx.ConnectError("private-secret", request=request)
    with target(False) as state:
        report, _ = execute(state, httpx.MockTransport(offline))
        assert report.ai["valid_decisions"] == 0
        assert any(e["code"] == "ollama_unavailable" for e in report.errors)
        assert report.authentication == "verified"
        assert "private-secret" not in report.model_dump_json()


@pytest.mark.parametrize('public_prefix,protected_count', [(0,4),(12,1)])
def test_method_check_reaches_late_discovered_protected_resource(public_prefix,protected_count):
    from scanner.network import Observation
    total=public_prefix+protected_count
    body=b'{"record":"stable protected account information"}'
    def handler(request):
        index=int(request.url.path.rsplit('/',1)[-1])
        authenticated='sid=accepted-session' in request.headers.get('cookie','')
        bypass=request.method=='POST' and index==total-1
        permitted=index<public_prefix or authenticated or bypass
        return httpx.Response(200 if permitted else 403,
            headers={'Content-Type':'application/json'},
            stream=httpx.ByteStream(body if permitted else b'denied'))
    report=Report()
    engine=Engine(Settings('http://127.0.0.1:3000/'),Results(report,Redactor()),
                  httpx.MockTransport(handler),httpx.MockTransport(fake_ollama))
    try:
        engine.net.client.cookies.set('sid','accepted-session',domain='127.0.0.1',path='/')
        engine.net.authenticated=True
        engine.observations=[Observation(f'initial-{i}',f'http://127.0.0.1:3000/item/{i}',
            'GET',200,httpx.Headers({'Content-Type':'application/json'}),body,False,True)
            for i in range(total)]
        engine.protected_checks()
        findings=[f for f in report.findings if f.type=='http_method_tampering']
        assert len(findings)==1
        assert findings[0].url.endswith('/'+str(total-1))
        assert len(engine.references)==protected_count
    finally:
        engine.close()
