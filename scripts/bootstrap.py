"""Standard-library bootstrap. Scanning never installs from the Internet."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)


def fail(message):
    stamp = datetime.now(timezone.utc).isoformat()
    report = {"schema_version": "1.0", "scanner": {"name": "Agentic Security Scanner", "version": "1.0.0"}, "target": None, "status": "error", "started_at": stamp, "finished_at": stamp, "authentication": "not_attempted", "coverage": {}, "ai": {}, "checks": {}, "findings": [], "errors": [{"code": "bootstrap_error", "message": message}], "warnings": [], "decisions": []}
    fd, temp = tempfile.mkstemp(prefix=".findings-", dir=ROOT)
    with os.fdopen(fd, "w") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
    os.replace(temp, ROOT / "findings.json")
    print(message, file=sys.stderr)
    return 2


def main():
    run = "--run" in sys.argv
    online = "--online" in sys.argv and not run
    dev = "--dev" in sys.argv
    if not (3, 9) <= sys.version_info[:2] <= (3, 13):
        return fail("Use Python 3.9 a 3.13; configure PYTHON_BIN antes da instalação.")
    python = ROOT / ".venv" / "bin" / "python"
    try:
        if not python.exists():
            subprocess.run([sys.executable, "-m", "venv", str(ROOT / ".venv")], check=True)
        available = subprocess.run([str(python), "-c", "from importlib.metadata import version; assert version('httpx') == '0.28.1'; assert version('beautifulsoup4') == '4.14.3'; assert version('pydantic') == '2.11.9'"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        if not available or not run:
            args = [str(python), "-m", "pip", "--isolated", "install", "--disable-pip-version-check", "--no-cache-dir"]
            if not online:
                manifest = ROOT / "vendor" / "SHA256SUMS"
                if not manifest.exists():
                    return fail("Dependências ausentes. Execute ./setup.sh --online antes do scan.")
                for line in manifest.read_text().splitlines():
                    digest, name = line.split("  ", 1)
                    wheel = ROOT / "vendor" / name
                    if wheel.name != name or hashlib.sha256(wheel.read_bytes()).hexdigest() != digest:
                        return fail("Falha na integridade das dependências empacotadas.")
                args += ["--no-index", "--find-links", str(ROOT / "vendor")]
            args += ["-r", "requirements-lock.txt"]
            if dev:
                args += ["-r", "requirements-dev.txt"]
            subprocess.run(args, check=True, stdout=sys.stderr)
        if run:
            entry = ROOT / "scripts/scan_cpu.py" if "--cpu" in sys.argv else ROOT / "main.py"
            os.execv(str(python), [str(python), str(entry)])
        print("Ambiente pronto. Execute BASE_URL=http://localhost:3000 ./run.sh")
        return 0
    except (OSError, subprocess.CalledProcessError):
        return fail("Não foi possível preparar o ambiente. Consulte o README; instalação online opcional: ./setup.sh --online")


if __name__ == "__main__":
    raise SystemExit(main())
