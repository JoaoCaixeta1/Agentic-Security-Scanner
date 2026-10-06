"""Descoberta de links no HTML já recebido; este módulo não acessa a rede."""

from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlsplit

import httpx
from bs4 import BeautifulSoup


@dataclass
class LinkDiscovery:
    """Agrupa os links encontrados e as limitações desta análise."""

    links: List[str]
    limit_reached: bool = False
    skipped_reason: Optional[str] = None


def extract_links(
    body: bytes,
    page_url: str,
    content_type: str,
    max_links: int = 100,
) -> LinkDiscovery:
    """Encontra links únicos que mantêm o esquema, o host e a porta da página."""
    if max_links <= 0:
        raise ValueError("O limite de links deve ser maior que zero.")

    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type not in ("text/html", "application/xhtml+xml"):
        return LinkDiscovery([], skipped_reason="resposta sem tipo HTML reconhecido")

    page = httpx.URL(page_url)
    origin = (page.scheme, page.host, page.port)
    soup = BeautifulSoup(body, "html.parser")

    # <base href> altera o endereço usado para completar referências relativas.
    # Mesmo que ele aponte para fora, a origem autorizada permanece a da página.
    base = page
    base_tag = soup.find("base", href=True)
    if base_tag is not None:
        try:
            base_reference = base_tag["href"].strip()
            # O parser HTTP pode tolerar endereços malformados; validar a
            # estrutura evita resolver caminhos contra uma base ambígua.
            parsed_base = urlsplit(base_reference)
            _ = parsed_base.port
            base = page.join(base_reference)
            if base.scheme not in ("http", "https") or not base.host:
                raise ValueError("Endereço base não é HTTP(S).")
        except (httpx.InvalidURL, ValueError):
            return LinkDiscovery([], skipped_reason="HTML com endereço base inválido")

    links = []
    seen = set()
    for tag in soup.find_all(["a", "area"], href=True):
        reference = tag["href"].strip()
        if not reference or reference.startswith("#"):
            continue

        try:
            candidate = base.join(reference).copy_with(fragment=None)
        except httpx.InvalidURL:
            continue

        if candidate.scheme not in ("http", "https"):
            continue
        if candidate.username or candidate.password:
            continue
        if (candidate.scheme, candidate.host, candidate.port) != origin:
            continue

        url = str(candidate)
        if url in seen:
            continue
        if len(links) == max_links:
            return LinkDiscovery(links, limit_reached=True)

        seen.add(url)
        links.append(url)

    return LinkDiscovery(links)
