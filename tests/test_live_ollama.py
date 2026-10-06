"""Opt-in: actual Ollama model + real HTTP fixture + the required shell entry point."""

import json
import os
from pathlib import Path
import subprocess

import pytest

from scanner.report import Report
from fixtures import target

pytestmark = pytest.mark.skipif(os.environ.get("RUN_LIVE_OLLAMA") != "1", reason="Requer Ollama real; habilite RUN_LIVE_OLLAMA=1")


@pytest.mark.parametrize("vulnerable", [True, False])
def test_real_model_through_run_sh(vulnerable):
    root = Path(__file__).resolve().parent.parent
    with target(vulnerable) as state:
        env = dict(os.environ, BASE_URL=state["url"], CHALLENGE_USERNAME=state["credentials"][0], CHALLENGE_PASSWORD=state["credentials"][1], MAX_SCAN_SECONDS="300", AI_TIMEOUT_SECONDS="120")
        process = subprocess.run(["./run.sh"], cwd=root, env=env, capture_output=True, text=True, timeout=330)
        report = Report.model_validate_json((root / "findings.json").read_text())
        assert process.returncode == 0, process.stdout + process.stderr + json.dumps(report.errors)
        assert report.status == "completed"
        assert report.authentication == "verified"
        assert report.ai["valid_decisions"] > 0
        expected = {"cpf_exposure", "http_method_tampering", "session_cookie_flags", "session_after_logout", "open_redirect"} if vulnerable else set()
        assert {finding.type for finding in report.findings} == expected
        assert state["credentials"][1] not in (root / "findings.json").read_text()
        if os.environ.get("LIVE_REPORT_DIR"):
            destination = Path(os.environ["LIVE_REPORT_DIR"])
            destination.mkdir(parents=True, exist_ok=True)
            (destination / ("vulnerable.json" if vulnerable else "protected.json")).write_text(report.model_dump_json(indent=2) + "\n")
