"""Configuration and a single URL policy shared by every network operation."""

import os
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Optional
from urllib.parse import urlsplit

import httpx


class ScopeError(ValueError):
    pass


def local_url(value: str) -> httpx.URL:
    if not value or any(ord(c) < 33 or ord(c) == 127 for c in value) or "\\" in value:
        raise ScopeError("URL ausente ou com caracteres não permitidos.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
        if parsed.username is not None or parsed.password is not None:
            raise ScopeError("Credenciais não podem estar na URL.")
        if port is not None and not 1 <= port <= 65535:
            raise ScopeError("Porta inválida.")
        url = httpx.URL(value).copy_with(fragment=None)
        if url.scheme not in ("http", "https") or not url.host:
            raise ScopeError("O alvo deve ser uma URL HTTP(S) com host.")
        if url.host != "localhost" and not ip_address(url.host).is_loopback:
            raise ScopeError("Somente localhost e IPs de loopback são permitidos.")
        if url.username or url.password:
            raise ScopeError("Credenciais não podem estar na URL.")
        return url.copy_with(path=url.path or "/")
    except (ValueError, httpx.InvalidURL) as error:
        if isinstance(error, ScopeError):
            raise
        raise ScopeError("URL local inválida.") from None


def origin(url: httpx.URL):
    return url.scheme, url.host, url.port


class Scope:
    def __init__(self, base_url: str):
        self.base = local_url(base_url)

    def require(self, value: str, relative_to: Optional[str] = None) -> str:
        try:
            parent = httpx.URL(relative_to) if relative_to else self.base
            # Check the reference before HTTPX can normalize ambiguous characters.
            if any(ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value:
                raise ScopeError("Referência inválida.")
            candidate = local_url(str(parent.join(value)))
            if origin(candidate) != origin(self.base):
                raise ScopeError("Destino fora da origem autorizada.")
            return str(candidate)
        except (ValueError, httpx.InvalidURL):
            raise ScopeError("Destino inválido ou fora da origem autorizada.") from None


def integer(name, default, minimum, maximum):
    try:
        value = int(os.environ.get(name, str(default)))
        if not minimum <= value <= maximum:
            raise ValueError()
        return value
    except ValueError:
        raise ValueError(f"{name} deve estar entre {minimum} e {maximum}.") from None


@dataclass
class Settings:
    base_url: str
    username: str = field(default="", repr=False)
    password: str = field(default="", repr=False)
    ollama_url: str = "http://127.0.0.1:11434"
    model: str = "qwen2.5:3b"
    max_pages: int = 100
    max_requests: int = 600
    max_depth: int = 5
    max_redirects: int = 5
    max_body: int = 1048576
    max_seconds: int = 300
    max_ai_calls: int = 4
    ai_timeout: int = 90
    connect_timeout: int = 3
    read_timeout: int = 5
    num_gpu: int = -1

    @classmethod
    def from_env(cls):
        base = str(local_url(os.environ.get("BASE_URL", "")))
        ollama = str(local_url(os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")))
        if origin(httpx.URL(base)) == origin(httpx.URL(ollama)):
            raise ValueError("O alvo não pode ser o próprio serviço Ollama.")
        user, password = os.environ.get("CHALLENGE_USERNAME", ""), os.environ.get("CHALLENGE_PASSWORD", "")
        if bool(user) != bool(password):
            raise ValueError("Forneça ambas as credenciais ou nenhuma.")
        model = os.environ.get("OLLAMA_MODEL", "qwen2.5:3b")
        if not model or "cloud" in model.lower() or len(model) > 100:
            raise ValueError("Escolha um modelo Ollama local.")
        return cls(
            base, user, password, ollama, model,
            max_pages=integer("MAX_PAGES", 100, 1, 1000),
            max_requests=integer("MAX_REQUESTS", 600, 1, 3000),
            max_depth=integer("MAX_DEPTH", 5, 0, 20),
            max_redirects=integer("MAX_REDIRECTS", 5, 0, 10),
            max_body=integer("MAX_BODY_BYTES", 1048576, 1024, 4194304),
            max_seconds=integer("MAX_SCAN_SECONDS", 300, 10, 3600),
            max_ai_calls=integer("MAX_AI_CALLS", 4, 1, 50),
            ai_timeout=integer("AI_TIMEOUT_SECONDS", 90, 5, 300),
            connect_timeout=integer("CONNECT_TIMEOUT_SECONDS", 3, 1, 30),
            read_timeout=integer("READ_TIMEOUT_SECONDS", 5, 1, 60),
            num_gpu=integer("OLLAMA_NUM_GPU", -1, -1, 256),
        )
