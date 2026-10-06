import httpx
import pytest

from scanner import network as scanner


class TrackedStream(httpx.SyncByteStream):
    """Resposta controlada para testar leitura sem abrir conexões de rede."""

    def __init__(self, chunks):
        self.chunks = chunks
        self.read_count = 0
        self.closed = False

    def __iter__(self):
        for chunk in self.chunks:
            self.read_count += 1
            yield chunk

    def close(self):
        self.closed = True


@pytest.mark.parametrize(
    "payload,limit,expected,truncated",
    [
        (b"", 3, b"", False),
        (b"ab", 3, b"ab", False),
        (b"abc", 3, b"abc", False),
        (b"abcd", 3, b"abc", True),
        (b"x" * 8192, 8192, b"x" * 8192, False),
        (b"x" * 8193, 8192, b"x" * 8192, True),
    ],
)
def test_body_limit_boundaries(payload, limit, expected, truncated):
    response = httpx.Response(200, stream=TrackedStream([payload]))
    try:
        assert scanner.read_limited_body(response, limit) == (expected, truncated)
    finally:
        response.close()


def test_oversized_body_stops_reading_and_can_be_closed():
    stream = TrackedStream([b"x" * 8192] * 10)
    response = httpx.Response(200, stream=stream)
    try:
        assert scanner.read_limited_body(response, 4) == (b"xxxx", True)
        assert stream.read_count == 1
    finally:
        response.close()
    assert stream.closed


def test_length_header_does_not_replace_counting_actual_bytes():
    response = httpx.Response(
        200, headers={"Content-Length": "1"}, stream=TrackedStream([b"abcdef"])
    )
    try:
        assert scanner.read_limited_body(response, 3) == (b"abc", True)
    finally:
        response.close()


@pytest.mark.parametrize("encoding", ["gzip", "br", "deflate", "gzip, br"])
def test_unsupported_compression_is_rejected_before_reading(encoding):
    stream = TrackedStream([b"compressed-content"])
    response = httpx.Response(
        200, headers={"Content-Encoding": encoding}, stream=stream
    )
    try:
        with pytest.raises(scanner.UnsupportedContentEncoding):
            scanner.read_limited_body(response)
        assert stream.read_count == 0
    finally:
        response.close()


@pytest.mark.parametrize("limit", [0, -1])
def test_invalid_read_limit_is_rejected(limit):
    response = httpx.Response(200, stream=TrackedStream([b"abc"]))
    try:
        with pytest.raises(ValueError):
            scanner.read_limited_body(response, limit)
    finally:
        response.close()

