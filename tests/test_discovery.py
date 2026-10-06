import pytest

from discovery import extract_links

PAGE = "http://127.0.0.1:3000/catalogo/index.html"


def test_resolves_relative_links_and_preserves_query():
    result = extract_links(
        b'<a href="/produtos">Produtos</a>'
        b'<a href="detalhes?id=2&amp;pagina=1">Detalhes</a>'
        b'<area href="../ajuda">',
        PAGE,
        "text/html; charset=utf-8",
    )
    assert result.links == [
        "http://127.0.0.1:3000/produtos",
        "http://127.0.0.1:3000/catalogo/detalhes?id=2&pagina=1",
        "http://127.0.0.1:3000/ajuda",
    ]
    assert not result.limit_reached
    assert result.skipped_reason is None


@pytest.mark.parametrize(
    "reference",
    [
        "http://external.invalid/path",
        "//external.invalid/path",
        "http://127.0.0.1:4000/path",
        "https://127.0.0.1:3000/path",
        "http://localhost:3000/path",
        "http://user:password@127.0.0.1:3000/path",
        "http://127.0.0.1:invalid/path",
        "http://[broken/path",
        "mailto:user@example.invalid",
        "javascript:void(0)",
        "data:text/html,content",
        "file:///tmp/example",
        "#section",
        "",
    ],
)
def test_rejects_out_of_scope_or_non_http_links(reference):
    html = f'<a href="{reference}">Link</a>'.encode("utf-8")
    assert extract_links(html, PAGE, "text/html").links == []


def test_deduplicates_fragments_without_merging_different_queries():
    result = extract_links(
        b'<a href="/p?id=1#top">A</a>'
        b'<a href="/p?id=1#bottom">B</a>'
        b'<a href="/p?id=2">C</a>',
        PAGE,
        "text/html",
    )
    assert result.links == [
        "http://127.0.0.1:3000/p?id=1",
        "http://127.0.0.1:3000/p?id=2",
    ]


def test_respects_html_base_without_changing_authorized_origin():
    result = extract_links(
        b'<base href="/outra-pasta/"><a href="pagina">Pagina</a>',
        PAGE,
        "text/html",
    )
    assert result.links == ["http://127.0.0.1:3000/outra-pasta/pagina"]


def test_external_html_base_cannot_expand_scope():
    result = extract_links(
        b'<base href="https://external.invalid/">'
        b'<a href="/externo">Externo</a>'
        b'<a href="http://127.0.0.1:3000/interno">Interno</a>',
        PAGE,
        "text/html",
    )
    assert result.links == ["http://127.0.0.1:3000/interno"]


def test_invalid_html_base_is_explicitly_reported():
    result = extract_links(
        b'<base href="http://[broken"><a href="/x">X</a>', PAGE, "text/html"
    )
    assert result.links == []
    assert result.skipped_reason is not None


@pytest.mark.parametrize("content_type", ["application/json", "image/png", "", "text/plain"])
def test_other_content_types_are_not_treated_as_html(content_type):
    result = extract_links(b'<a href="/x">X</a>', PAGE, content_type)
    assert result.links == []
    assert result.skipped_reason is not None


def test_link_limit_is_reported_only_if_another_unique_link_exists():
    html = b'<a href="/a">A</a><a href="/b">B</a><a href="/b#x">B</a>'
    exact = extract_links(html, PAGE, "text/html", max_links=2)
    assert len(exact.links) == 2
    assert not exact.limit_reached

    over = extract_links(html + b'<a href="/c">C</a>', PAGE, "text/html", max_links=2)
    assert over.links == exact.links
    assert over.limit_reached


def test_handles_unclosed_html_without_inventing_paths():
    result = extract_links(b'<html><a href="/found">Found', PAGE, "text/html")
    assert result.links == ["http://127.0.0.1:3000/found"]


def test_default_port_is_equivalent_to_explicit_default_port():
    result = extract_links(
        b'<a href="http://127.0.0.1:80/x">X</a>',
        "http://127.0.0.1/",
        "text/html",
    )
    assert result.links == ["http://127.0.0.1/x"]


def test_zero_port_is_not_equivalent_to_default_port():
    result = extract_links(
        b'<a href="http://127.0.0.1:0/x">X</a>',
        "http://127.0.0.1/",
        "text/html",
    )
    assert result.links == []


def test_invalid_limit_fails_explicitly():
    with pytest.raises(ValueError):
        extract_links(b"", PAGE, "text/html", max_links=0)



def test_dynamic_shell_without_html_routes_reports_coverage_limit():
    from scanner.config import Scope
    from scanner.network import Observation
    from scanner.surface import inspect
    import httpx
    scope = Scope("http://127.0.0.1:3000")
    def page(body):
        return Observation("http-1", str(scope.base), "GET", 200,
            httpx.Headers({"Content-Type":"text/html"}), body.encode(), False, False)
    dynamic = inspect(page('<app-root></app-root><script src="main.js"></script>'), scope)
    ordinary = inspect(page('<p>Static page</p><script src="main.js"></script>'), scope)
    assert any("sem JavaScript" in w for w in dynamic.warnings)
    assert not any("sem JavaScript" in w for w in ordinary.warnings)
