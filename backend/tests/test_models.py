"""Тесты валидации входных данных — те входы, что раньше давали HTTP 500."""
import pytest
from pydantic import ValidationError

from models import ScanRequest


@pytest.mark.parametrize("bad", [
    123, None, [], {}, 3.14,
])
def test_non_string_rejected(bad):
    """Раньше: v.strip() → AttributeError → HTTP 500. Теперь: 422."""
    with pytest.raises(ValidationError):
        ScanRequest(url=bad)


@pytest.mark.parametrize("bad", [
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "file:///etc/passwd",
    "vbscript:msgbox(1)",
])
def test_dangerous_schemes_rejected(bad):
    with pytest.raises(ValidationError):
        ScanRequest(url=bad)


def test_malformed_port_rejected():
    """Раньше urlsplit(...).port бросал ValueError внутри пайплайна → 500."""
    with pytest.raises(ValidationError):
        ScanRequest(url="http://example.com:notaport/")


def test_control_characters_rejected():
    """CRLF в URL — это инъекция в исходящий HTTP-запрос."""
    with pytest.raises(ValidationError):
        ScanRequest(url="evil.com\r\nHost: internal")


def test_oversized_url_rejected():
    with pytest.raises(ValidationError):
        ScanRequest(url="https://a.com/" + "x" * 5000)


def test_empty_rejected():
    with pytest.raises(ValidationError):
        ScanRequest(url="   ")


def test_scheme_added_to_bare_domain():
    assert ScanRequest(url="google.com").url == "https://google.com"


def test_existing_scheme_preserved():
    assert ScanRequest(url="http://google.com/x").url == "http://google.com/x"


def test_whitespace_trimmed():
    assert ScanRequest(url="  google.com  ").url == "https://google.com"
