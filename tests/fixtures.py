"""Ephemeral HTTP fixtures; randomized routes prevent target-specific hardcoding."""

import json
import secrets
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import httpx


def json_response(payload, status=200):
    return httpx.Response(status, headers={"Content-Type": "application/json"}, stream=httpx.ByteStream(json.dumps(payload).encode()))


def fake_ollama(request):
    if request.url.path == "/api/tags":
        return json_response({"models": [{"name": "qwen2.5:3b"}, {"name": "qwen2.5:7b"}]})
    if request.url.path == "/api/show":
        return json_response({"details": {"family": "qwen2"}})
    payload = json.loads(request.content)
    data = json.loads(payload["messages"][-1]["content"])
    plan = {"priority_ids": [c["id"] for c in data["candidates"]], "login_form_id": None, "username_field": None, "password_field": None}
    if data["forms"]:
        form = data["forms"][0]
        plan.update(login_form_id=form["id"], username_field=next(f["name"] for f in form["fields"] if f["type"] in ("email", "text")), password_field=next(f["name"] for f in form["fields"] if f["type"] == "password"))
    return json_response({"message": {"content": json.dumps(plan)}, "prompt_eval_count": 100, "eval_count": 30})


@contextmanager
def target(vulnerable=True):
    prefix = "/" + secrets.token_hex(5)
    paths = {name: prefix + "/" + secrets.token_hex(4) for name in ("login", "home", "vault", "redirect", "logout", "script")}
    state = {"requests": [], "sessions": set(), "paths": paths, "credentials": ("candidate-user", "unique-password-9381")}
    protected = json.dumps({"customer": "Synthetic Person", "cpf": "529.982.247-25" if vulnerable else "***.***.***-**", "record": "protected-account-data"}).encode()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, status, body=b"", headers=None):
            self.send_response(status)
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self.dispatch()

        def do_POST(self):
            self.dispatch()

        def dispatch(self):
            state["requests"].append((self.command, self.path))
            parsed = urlsplit(self.path)
            path = parsed.path
            token = next((s.split("=", 1)[1] for s in self.headers.get("Cookie", "").split("; ") if s.startswith("sid=")), "")
            authenticated = token in state["sessions"]
            html = {"Content-Type": "text/html; charset=utf-8"}
            if path == prefix:
                self.send(200, (f'<a href="{paths["login"]}">Entrar</a><a href="{paths["vault"]}">Conta</a>' + f'<a href="{paths["redirect"]}?next={paths["home"]}">Continuar</a>' + f'<script src="{paths["script"]}"></script>').encode(), html)
            elif path == paths["script"]:
                self.send(200, f'fetch("{paths["vault"]}");'.encode(), {"Content-Type": "application/javascript"})
            elif path == paths["login"]:
                if self.command == "GET":
                    self.send(200, f'<form action="{path}" method="post"><input name="nonce" type="hidden" value="csrf-local-173"><input name="identity" type="email"><input name="secret" type="password"><button>Entrar</button></form>'.encode(), html)
                else:
                    fields = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode())
                    if fields.get("identity") == [state["credentials"][0]] and fields.get("secret") == [state["credentials"][1]] and fields.get("nonce") == ["csrf-local-173"]:
                        token = secrets.token_hex(16)
                        state["sessions"].add(token)
                        self.send(303, headers={"Location": paths["home"], "Set-Cookie": "sid=" + token + "; Path=/; SameSite=Lax" + ("" if vulnerable else "; HttpOnly")})
                    else:
                        self.send(401)
            elif path == paths["home"]:
                if not authenticated:
                    self.send(401)
                else:
                    self.send(200, f'<h1>Conta autenticada</h1><a href="{paths["vault"]}">Dados pessoais</a><a href="{paths["logout"]}">Sair</a>'.encode(), html)
            elif path == paths["vault"]:
                if authenticated or (self.command == "POST" and vulnerable):
                    self.send(200, protected, {"Content-Type": "application/json", "Cache-Control": "no-store"})
                else:
                    self.send(403)
            elif path == paths["redirect"]:
                if not authenticated:
                    self.send(401)
                    return
                destination = parse_qs(parsed.query).get("next", [paths["home"]])[0]
                if not vulnerable and not destination.startswith(prefix + "/"):
                    self.send(400)
                else:
                    self.send(302, headers={"Location": destination})
            elif path == paths["logout"]:
                if not vulnerable:
                    state["sessions"].discard(token)
                self.send(303, headers={"Location": paths["login"], "Set-Cookie": "sid=; Max-Age=0; Path=/"})
            else:
                self.send(404)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    state["url"] = f"http://127.0.0.1:{server.server_port}{prefix}"
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
