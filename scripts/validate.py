"""Reproducible evaluation: unit tests, actual inference, then live scan tests."""
import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import httpx
from scanner.agent import Planner
from scanner.config import Settings, local_url
from scanner.network import Budget, ScanLimit
from scanner.report import Redactor, Report, Results


def cpu_environment(environment, port, bundled=False):
    env = dict(environment)
    env.update(OLLAMA_HOST=f"127.0.0.1:{port}", OLLAMA_NO_CLOUD="1",
               OLLAMA_NUM_PARALLEL="1", OLLAMA_MAX_LOADED_MODELS="1",
               OLLAMA_LLM_LIBRARY="cpu", LLAMA_ARG_DEVICE="none", LLAMA_ARG_FIT="off")
    if bundled and not env.get("OLLAMA_MODELS"):
        env["OLLAMA_MODELS"] = str(ROOT / "work/ollama/models")
    return env


def wait_ready(process, endpoint, log_path, timeout=120):
    """Allow hardware discovery to finish, but bound the startup wait."""
    started = time.monotonic()
    deadline = started + timeout
    next_update = started + 15
    with httpx.Client(trust_env=False, timeout=1, follow_redirects=False) as client:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"Ollama CPU não iniciou. Log: {log_path}")
            try:
                if client.get(endpoint + "/api/tags").status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            current = time.monotonic()
            if current >= next_update:
                print(f"Aguardando inicialização do Ollama ({int(current - started)}s; limite {timeout}s)...", flush=True)
                next_update = current + 15
            time.sleep(min(0.2, max(0, deadline - current)))
    raise RuntimeError(f"Ollama CPU não ficou pronto em {timeout}s. Log: {log_path}")


@contextmanager
def cpu_service():
    binary = shutil.which("ollama")
    bundled = not binary
    if bundled:
        candidate = ROOT / "work/ollama/runtime/ollama"
        if not candidate.is_file():
            raise RuntimeError("Instale Ollama e baixe qwen2.5:3b antes dos testes vivos.")
        binary = str(candidate)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    env = cpu_environment(os.environ, port, bundled)
    directory = ROOT / "work/validation"
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix="ollama-cpu-", suffix=".log", dir=directory, delete=False) as log:
        process = subprocess.Popen([binary, "serve"], env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            endpoint = f"http://127.0.0.1:{port}"
            wait_ready(process, endpoint, log.name)
            yield endpoint
        finally:
            # Only terminate the private process group this command created.
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()


def check_inference(environment):
    settings = Settings("http://127.0.0.1:1", ollama_url=str(local_url(environment.get("OLLAMA_URL", "http://127.0.0.1:11434"))),
                        model=environment.get("OLLAMA_MODEL", "qwen2.5:3b"),
                        num_gpu=int(environment.get("OLLAMA_NUM_GPU", "-1")), ai_timeout=120)
    if "cloud" in settings.model.lower():
        raise ValueError("O modelo precisa ser local.")
    report = Report()
    planner = Planner(settings, Budget(0, time.monotonic() + 130), Results(report, Redactor()))
    try:
        if planner.preflight() and planner.choose([], []) is not None:
            print(f"Inferência estruturada OK: {settings.model}.", flush=True)
            return True
        for error in report.errors:
            print(error["message"], flush=True)
        return False
    finally:
        planner.close()


def live(environment):
    print("2/3 — Testando inferência real antes de iniciar os scans...", flush=True)
    if not check_inference(environment):
        print("Teste interrompido: o modelo não está operacional. Para testar com CPU isolada: ./test.sh --live --cpu", flush=True)
        return 2
    print("3/3 — Scans completos: cenário vulnerável e cenário protegido.", flush=True)
    env = dict(environment, RUN_LIVE_OLLAMA="1")
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "tests/test_live_ollama.py"], cwd=ROOT, env=env).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="inclui inferência Ollama real e os dois scans")
    parser.add_argument("--cpu", action="store_true", help="inicia e encerra Ollama CPU privado, sem alterar serviços existentes")
    args = parser.parse_args()
    if args.cpu and not args.live:
        parser.error("--cpu exige --live")
    env = dict(os.environ, RUN_LIVE_OLLAMA="0")
    print("1/3 — Testes automatizados sem modelo real.", flush=True)
    code = subprocess.run([sys.executable, "-m", "pytest", "-q"], cwd=ROOT, env=env).returncode
    if code or not args.live:
        return code
    try:
        if args.cpu:
            print("Iniciando Ollama CPU temporário em uma porta local livre...", flush=True)
            with cpu_service() as endpoint:
                return live(dict(env, OLLAMA_URL=endpoint, OLLAMA_NUM_GPU="0"))
        return live(env)
    except (RuntimeError, ValueError, OSError, ScanLimit) as error:
        print(str(error), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Validação interrompida.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
