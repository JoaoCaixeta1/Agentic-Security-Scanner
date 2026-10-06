import httpx

from fixtures import fake_ollama, json_response
from scanner.agent import Planner
from scripts import validate


def test_cpu_service_environment_overrides_gpu_and_remote_binding():
    env = validate.cpu_environment({"OLLAMA_HOST": "0.0.0.0:11434", "OLLAMA_NO_CLOUD": "0", "OLLAMA_MODELS": "/existing/models"}, 23456, True)
    assert env["OLLAMA_HOST"] == "127.0.0.1:23456"
    assert env["OLLAMA_NO_CLOUD"] == "1"
    assert env["LLAMA_ARG_DEVICE"] == "none"
    assert env["OLLAMA_MODELS"] == "/existing/models"


def test_inference_probe_actually_calls_chat(monkeypatch):
    paths = []
    def handler(request):
        paths.append(request.url.path)
        return fake_ollama(request)
    monkeypatch.setattr(validate, "Planner", lambda settings, budget, results: Planner(settings, budget, results, httpx.MockTransport(handler)))
    assert validate.check_inference({})
    assert paths == ["/api/tags", "/api/show", "/api/chat"]


def test_metal_error_is_actionable_without_exposing_server_paths(monkeypatch, capsys):
    def handler(request):
        if request.url.path == "/api/chat":
            return json_response({"error": "Metal allocation failed /private/server/secret"}, 500)
        return fake_ollama(request)
    monkeypatch.setattr(validate, "Planner", lambda settings, budget, results: Planner(settings, budget, results, httpx.MockTransport(handler)))
    assert not validate.check_inference({})
    output = capsys.readouterr().out
    assert "./test.sh --live --cpu" in output
    assert "/private/server/secret" not in output


def test_live_stops_before_scans_when_inference_fails(monkeypatch):
    monkeypatch.setattr(validate, "check_inference", lambda env: False)
    monkeypatch.setattr(validate.subprocess, "run", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("Scan must not run")))
    assert validate.live({}) == 2


def test_startup_can_finish_after_twenty_seconds(monkeypatch):
    from types import SimpleNamespace
    clock = [0.0]
    monkeypatch.setattr(validate.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(validate.time, "sleep", lambda delay: clock.__setitem__(0, clock[0] + delay))
    real_client = httpx.Client
    def response(request):
        clock[0] += 1
        if clock[0] < 30:
            raise httpx.ReadTimeout("not ready", request=request)
        return httpx.Response(200)
    monkeypatch.setattr(validate.httpx, "Client", lambda **kwargs: real_client(transport=httpx.MockTransport(response), **kwargs))
    validate.wait_ready(SimpleNamespace(poll=lambda: None), "http://127.0.0.1:12345", "test.log")
    assert 30 <= clock[0] < 120


def test_startup_timeout_is_bounded(monkeypatch):
    import pytest
    from types import SimpleNamespace
    clock = [0.0]
    monkeypatch.setattr(validate.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(validate.time, "sleep", lambda delay: clock.__setitem__(0, clock[0] + delay))
    real_client = httpx.Client
    def response(request):
        clock[0] += 1
        raise httpx.ReadTimeout("not ready", request=request)
    monkeypatch.setattr(validate.httpx, "Client", lambda **kwargs: real_client(transport=httpx.MockTransport(response), **kwargs))
    with pytest.raises(RuntimeError, match="não ficou pronto em 120s"):
        validate.wait_ready(SimpleNamespace(poll=lambda: None), "http://127.0.0.1:12345", "test.log")
    assert 120 <= clock[0] <= 121
