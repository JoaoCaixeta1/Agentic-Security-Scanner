import httpx
import pytest
from scanner.surface import safe_to_visit
from scanner.config import Settings
from scanner.engine import Engine
from scanner.report import Report, Results, Redactor
from fixtures import fake_ollama


@pytest.mark.parametrize('path', [
    '/delete.php?id=1', '/account/remove.json', '/%64elete.php',
    '/%2564elete.php', '/action?op=%64elete', '/reset;session=1',
    '/logout.php', '/account/transfer', '/excluir?id=1',
])
def test_mutating_names_suffixes_and_encoding_are_blocked(path):
    assert not safe_to_visit('http://127.0.0.1:3000'+path)


@pytest.mark.parametrize('path', ['/account/profile.php', '/records.json', '/search?q=undeleted'])
def test_normal_read_candidates_are_preserved(path):
    assert safe_to_visit('http://127.0.0.1:3000'+path)


def test_crawler_never_requests_encoded_destructive_link():
    calls=[]
    def handler(request):
        calls.append(request.url.path)
        assert request.url.path == '/'
        return httpx.Response(200,headers={'Content-Type':'text/html'},
                              stream=httpx.ByteStream(b'<a href="/%64elete.php?id=1">Run</a><a href="/remove.json">Run</a>'))
    report=Report()
    engine=Engine(Settings('http://127.0.0.1:3000/'), Results(report,Redactor()),
                  httpx.MockTransport(handler),httpx.MockTransport(fake_ollama))
    try:
        engine.run()
        assert calls == ['/']
        assert report.findings == []
    finally:
        engine.close()
