"""CLI finalization with the real engine and controlled failure dependencies."""
import httpx
import pytest
import main
from scanner.engine import Engine
from scanner.report import Report
from fixtures import fake_ollama, json_response, target


@pytest.mark.parametrize('failure', ['target_offline', 'ollama_offline', 'server_503'])
def test_cli_failure_is_partial_and_preserves_schema(monkeypatch, tmp_path, capsys, failure):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('BASE_URL', 'http://127.0.0.1:3000/')
    monkeypatch.delenv('CHALLENGE_USERNAME', raising=False)
    monkeypatch.delenv('CHALLENGE_PASSWORD', raising=False)
    def target_request(request):
        if failure == 'target_offline':
            raise httpx.ConnectError('private-target-detail', request=request)
        return json_response({'status':'unavailable' if failure == 'server_503' else 'public'},
                             503 if failure == 'server_503' else 200)
    def model_request(request):
        if failure == 'ollama_offline':
            raise httpx.ConnectError('private-model-detail', request=request)
        return fake_ollama(request)
    monkeypatch.setattr(main, 'Engine', lambda settings, results: Engine(
        settings, results, httpx.MockTransport(target_request), httpx.MockTransport(model_request)))
    assert main.main() == 3
    saved = (tmp_path/'findings.json').read_text()
    report = Report.model_validate_json(saved)
    assert report.status == 'partial'
    assert report.finished_at and report.findings == []
    assert report.errors or report.warnings
    output = capsys.readouterr()
    assert 'private-target-detail' not in saved + output.out + output.err
    assert 'private-model-detail' not in saved + output.out + output.err


def test_incorrect_credentials_do_not_report_success_or_leak_password(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    with target(False) as state:
        monkeypatch.setenv('BASE_URL', state['url'])
        monkeypatch.setenv('CHALLENGE_USERNAME', state['credentials'][0])
        monkeypatch.setenv('CHALLENGE_PASSWORD', 'incorrect-private-password-731')
        monkeypatch.setattr(main, 'Engine', lambda settings, results: Engine(
            settings, results, ai_transport=httpx.MockTransport(fake_ollama)))
        assert main.main() == 3
    saved = (tmp_path/'findings.json').read_text()
    report = Report.model_validate_json(saved)
    assert report.status == 'partial' and report.authentication != 'verified'
    assert report.findings == [] and report.warnings
    assert report.checks['http_method_tampering']['skipped'] >= 1
    output = capsys.readouterr()
    assert 'incorrect-private-password-731' not in saved + output.out + output.err
