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


# ── Разбирать адрес так же, как его читает браузер ───────────────
# Каждая строчка ниже сверена с настоящим Chromium: как он определит
# хост, так должны определить и мы. Иначе жертва уходит на один сайт,
# а мы проверяем другой.

@pytest.mark.parametrize("url,host", [
    # Полноширинный слеш: браузер НЕ считает его разделителем, он
    # остаётся в логине, и хост — то, что справа от «собаки».
    ("https://sberbank.ru／@evil-phish-zzz.top/", "evil-phish-zzz.top"),
    # Точки CJK браузер приводит к обычной (правила IDNA).
    ("https://google.com。evil.ru/", "google.com.evil.ru"),
    # Обратный слеш — разделитель.
    ("https://evil.top\\@sberbank.ru/", "evil.top"),
    # %2F в логине границу не двигает.
    ("https://sberbank.ru%2Flogin@evil.top/x", "evil.top"),
    ("https://example.com/", "example.com"),
])
def test_host_matches_what_the_browser_would_open(url, host):
    from urllib.parse import urlsplit
    assert urlsplit(ScanRequest(url=url).url).hostname == host


def test_at_symbol_survives_userinfo_encoding():
    """Логин с полноширинным слешем кодируем, а не выбрасываем: иначе
    теряется признак «собака в адресе», а это приём мошенника."""
    from pipeline.lexical_analyzer import lexical_analyzer
    normalised = ScanRequest(url="https://sberbank.ru／@evil.top/").url
    assert lexical_analyzer.analyze(normalised).has_at_symbol is True


@pytest.mark.parametrize("url,word", [
    ("https://example.com:abc/", "разбирается"),
    ("не ссылка", "зон"),
    ("javascript:alert(1)", "http"),
    ("", "не ввели"),
])
def test_rejection_messages_are_readable(url, word):
    """Человек должен понять, что не так. Раньше отдавали питоновские
    потроха: «Port could not be cast to integer value as 'abc'»."""
    with pytest.raises(Exception) as caught:
        ScanRequest(url=url)
    text = str(caught.value)
    assert word in text, text[:200]
    assert "Value error" not in text.replace("Value error, ", "")
