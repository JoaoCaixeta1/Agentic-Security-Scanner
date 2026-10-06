"""CLI entry point: always finalize findings.json, including failed scans."""

import os
import signal
import sys
import threading
from pathlib import Path

from scanner.config import Settings
from scanner.engine import Engine
from scanner.network import ScanLimit
from scanner.report import Redactor, Report, Results, now, write_report


def main():
    report = Report()
    redactor = Redactor((os.environ.get("CHALLENGE_USERNAME", ""), os.environ.get("CHALLENGE_PASSWORD", "")))
    results = Results(report, redactor)
    output = Path("findings.json")
    engine = None
    previous = None
    exit_code = 0
    try:
        write_report(report, output, redactor)
        settings = Settings.from_env()
        report.target = redactor.url(settings.base_url)
        if hasattr(signal, "SIGALRM") and threading.current_thread() is threading.main_thread():
            def deadline(signum, frame):
                raise ScanLimit("Limite de tempo total atingido.")
            previous = signal.signal(signal.SIGALRM, deadline)
            signal.alarm(settings.max_seconds)
        engine = Engine(settings, results)
        engine.progress = lambda message: print(message, flush=True)
        print("Scan local iniciado. Evidências e limites serão registrados em findings.json.", flush=True)
        engine.run()
        if engine.planner.successes == 0:
            results.error("no_valid_ai_decision", "Nenhuma decisão válida do modelo local foi obtida.")
        report.status = "partial" if report.errors or report.warnings else "completed"
        exit_code = 3 if report.status == "partial" else 0
    except (ValueError, TypeError) as error:
        report.status = "error" if engine is None else "partial"
        results.error("configuration_error" if engine is None else "invalid_data", str(error) if engine is None else "Dados inesperados impediram a conclusão do scan.")
        exit_code = 2 if engine is None else 3
    except ScanLimit as error:
        report.status = "partial"
        results.error("scan_limit", str(error))
        exit_code = 3
    except KeyboardInterrupt:
        report.status = "partial"
        results.error("interrupted", "Scan interrompido pelo operador.")
        exit_code = 130
    except Exception:
        report.status = "error"
        results.error("internal_error", "Erro interno; resultados disponíveis foram preservados. Execute a suíte de testes.")
        exit_code = 2
    finally:
        if previous is not None:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)
        if engine:
            engine.summarize()
            engine.close()
        report.finished_at = now()
        try:
            write_report(report, output, redactor)
        except OSError:
            print("Erro: não foi possível gravar findings.json. Verifique permissões e espaço.", file=sys.stderr)
            return 2
    for error in report.errors:
        print(redactor.text(f"Aviso [{error['code']}]: {error['message']}"))
    print(f"Resultado: {report.status}; achados: {len(report.findings)}; relatório: findings.json")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
