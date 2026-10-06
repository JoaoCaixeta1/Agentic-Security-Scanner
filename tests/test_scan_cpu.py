from contextlib import contextmanager
import os

from scanner.report import Report
from scripts import scan_cpu


def test_cpu_scan_forwards_endpoint_and_cleans_up(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BASE_URL", "http://127.0.0.1:4280")
    monkeypatch.setenv("OLLAMA_URL", "http://127.0.0.1:11434")
    monkeypatch.delenv("OLLAMA_NUM_GPU", raising=False)
    closed = []
    @contextmanager
    def service():
        try:
            yield "http://127.0.0.1:29999"
        finally:
            closed.append(True)
    def scan():
        assert os.environ["OLLAMA_URL"] == "http://127.0.0.1:29999"
        assert os.environ["OLLAMA_NUM_GPU"] == "0"
        return 3
    monkeypatch.setattr(scan_cpu, "cpu_service", service)
    monkeypatch.setattr(scan_cpu.scanner_cli, "main", scan)
    assert scan_cpu.main() == 3
    assert closed == [True]
    assert os.environ["OLLAMA_URL"] == "http://127.0.0.1:11434"
    assert "OLLAMA_NUM_GPU" not in os.environ


def test_cpu_start_failure_preserves_valid_report(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BASE_URL", "http://127.0.0.1:4280")
    @contextmanager
    def unavailable():
        raise RuntimeError("private runtime detail")
        yield
    monkeypatch.setattr(scan_cpu, "cpu_service", unavailable)
    assert scan_cpu.main() == 2
    saved = (tmp_path / "findings.json").read_text()
    assert Report.model_validate_json(saved).status == "error"
    assert "private runtime detail" not in saved
