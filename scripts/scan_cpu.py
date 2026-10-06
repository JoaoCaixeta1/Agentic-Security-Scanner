"""Run the normal scanner with a private, temporary CPU Ollama service."""
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import main as scanner_cli
from scanner.config import Settings
from scanner.report import Redactor, Report, Results, now, write_report
from scripts.validate import cpu_service


def main():
    saved = {key: os.environ.get(key) for key in ("OLLAMA_URL", "OLLAMA_NUM_GPU")}
    redactor = Redactor((os.environ.get("CHALLENGE_USERNAME", ""), os.environ.get("CHALLENGE_PASSWORD", "")))
    report = Report()
    output = Path("findings.json")
    try:
        write_report(report, output, redactor)
        Settings.from_env()  # Reject invalid target/configuration before starting a service.
        print("Iniciando Ollama CPU temporário para o scan...", flush=True)
        with cpu_service() as endpoint:
            os.environ.update(OLLAMA_URL=endpoint, OLLAMA_NUM_GPU="0")
            return scanner_cli.main()
    except KeyboardInterrupt:
        report.status = "partial"
        Results(report, redactor).error("interrupted", "Inicialização CPU interrompida pelo operador.")
        code = 130
    except (RuntimeError, ValueError, OSError):
        report.status = "error"
        Results(report, redactor).error("cpu_startup_failed", "Não foi possível preparar o scan CPU. Confira BASE_URL, Ollama e os logs em work/validation.")
        code = 2
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    report.finished_at = now()
    try:
        write_report(report, output, redactor)
    except OSError:
        print("Não foi possível gravar findings.json.", file=sys.stderr)
        return 2
    print(report.errors[0]["message"], file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
