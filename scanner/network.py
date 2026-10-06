"""The only target HTTP gateway. Enforces scope, budgets and bounded reads."""

import copy
import hashlib
import time
from dataclasses import dataclass
from typing import Optional

import httpx

from .config import Scope, ScopeError


class ScanLimit(RuntimeError):
    pass


class UnsupportedContentEncoding(Exception):
    pass


def read_limited_body(response, limit=1048576, budget=None):
    if limit <= 0:
        raise ValueError("O limite de leitura deve ser maior que zero.")
    encoding = response.headers.get("Content-Encoding", "").strip().lower()
    if encoding not in ("", "identity"):
        raise UnsupportedContentEncoding("Resposta comprimida não suportada.")
    body = bytearray()
    for chunk in response.iter_raw():
        if budget:
            budget.check()
        remaining = limit - len(body)
        body.extend(chunk[:remaining])
        if len(chunk) > remaining:
            return bytes(body), True
    return bytes(body), False


class PinnedTransport(httpx.HTTPTransport):
    """Resolve localhost without DNS, preserving HTTP Host and TLS server name."""

    def handle_request(self, request):
        if request.url.host == "localhost":
            request = httpx.Request(
                request.method, request.url.copy_with(host="127.0.0.1"),
                headers=request.headers, stream=request.stream,
                extensions={**request.extensions, "sni_hostname": "localhost"},
            )
        return super().handle_request(request)


@dataclass
class Budget:
    max_requests: int
    deadline: float
    count: int = 0
    bytes_read: int = 0
    max_bytes: int = 32 * 1048576

    def check(self):
        if time.monotonic() >= self.deadline:
            raise ScanLimit("Limite de tempo do scan atingido.")
        if self.bytes_read >= self.max_bytes:
            raise ScanLimit("Limite total de bytes do scan atingido.")

    def take(self):
        self.check()
        if self.count >= self.max_requests:
            raise ScanLimit("Limite de requisições atingido.")
        self.count += 1


@dataclass
class Observation:
    id: str
    url: str
    method: str
    status: int
    headers: httpx.Headers
    body: bytes
    truncated: bool
    authenticated: bool
    encoding: str = "utf-8"

    @property
    def content_type(self):
        return self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()

    @property
    def text(self):
        try:
            return self.body.decode(self.encoding, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    @property
    def digest(self):
        return hashlib.sha256(self.body).hexdigest()


class Network:
    def __init__(self, settings, budget, results, *, transport=None, authenticated=False):
        self.settings, self.budget, self.results = settings, budget, results
        self.scope = Scope(settings.base_url)
        self.authenticated = authenticated
        self.test_transport = transport
        self.client = httpx.Client(
            transport=transport if transport is not None else PinnedTransport(retries=0, trust_env=False),
            timeout=httpx.Timeout(settings.read_timeout, connect=settings.connect_timeout),
            follow_redirects=False, trust_env=False,
            headers={"Accept-Encoding": "identity", "User-Agent": "AgenticSecurityScanner/1.0", "Cache-Control": "no-cache"},
            limits=httpx.Limits(max_connections=2, max_keepalive_connections=2),
        )

    def close(self):
        self.client.close()

    def snapshot(self):
        return [copy.copy(cookie) for cookie in self.client.cookies.jar]

    def restore(self, cookies):
        self.client.cookies.clear()
        for cookie in cookies:
            self.client.cookies.jar.set_cookie(copy.copy(cookie))

    def fork(self, cookies=()):
        other = Network(self.settings, self.budget, self.results, transport=self.test_transport)
        other.restore(cookies)
        return other

    def request(self, method, url, *, data=None, json=None, follow=False, auth=None) -> Optional[Observation]:
        url = self.scope.require(url)
        method = method.upper()
        if method not in ("GET", "HEAD", "OPTIONS", "POST"):
            raise ScopeError("Método não permitido pela política do scanner.")
        visited = set()
        for hop in range(self.settings.max_redirects + 1):
            self.budget.take()
            try:
                remaining = max(0.1, self.budget.deadline - time.monotonic())
                timeout = httpx.Timeout(min(self.settings.read_timeout, remaining), connect=min(self.settings.connect_timeout, remaining))
                options = {"data": data, "json": json, "timeout": timeout}
                if auth is not None:
                    options["auth"] = auth
                with self.client.stream(method, url, **options) as response:
                    for cookie in self.client.cookies.jar:
                        self.results.redactor.add(cookie.value)
                    body, truncated = read_limited_body(response, min(self.settings.max_body, self.budget.max_bytes - self.budget.bytes_read), self.budget)
                    self.budget.bytes_read += len(body)
                    obs = Observation(
                        f"http-{self.budget.count}", str(response.url), method, response.status_code,
                        response.headers, body, truncated, self.authenticated, response.encoding or "utf-8",
                    )
                if truncated:
                    self.results.warning("Há respostas truncadas; a cobertura do conteúdo é parcial.")
                if not follow or obs.status not in (301, 302, 303, 307, 308) or "location" not in obs.headers:
                    return obs
                try:
                    destination = self.scope.require(obs.headers["location"], relative_to=url)
                except ScopeError:
                    self.results.warning("Redirecionamento fora do escopo foi bloqueado.")
                    return obs
                if destination in visited or hop == self.settings.max_redirects:
                    self.results.warning("Cadeia de redirecionamento interrompida por loop ou limite.")
                    return obs
                visited.add(destination)
                if method == "POST":
                    if obs.status in (301, 302, 303):
                        method, data, json = "GET", None, None
                    else:
                        self.results.warning("POST não foi reenviado automaticamente após redirect 307/308.")
                        return obs
                url = destination
            except UnsupportedContentEncoding:
                self.results.error("unsupported_encoding", "Uma resposta exigiu descompressão não suportada.")
                return None
            except httpx.TimeoutException:
                self.results.error("http_timeout", "Uma requisição ao alvo excedeu o tempo limite.")
                return None
            except httpx.RequestError:
                self.results.error("http_error", "Uma requisição ao alvo falhou; detalhes sensíveis foram omitidos.")
                return None
        return None
