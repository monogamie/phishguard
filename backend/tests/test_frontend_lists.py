"""
H-08. Списки, по которым считает движок страницы, обязаны совпадать
с питоном. Веса и пороги сторожит test_frontend_sync.py; здесь — сами
справочники: доверенные домены, домены брендов, зоны, сокращатели,
тревожные слова, составные суффиксы.
"""
import re
from pathlib import Path

import pytest

from data import brands
from pipeline import lexical_analyzer as la

FRONTEND = Path(__file__).resolve().parents[2] / "index.html"


@pytest.fixture(scope="module")
def html() -> str:
    return FRONTEND.read_text(encoding="utf-8")


def _js_strings(html: str, start: str, end: str) -> set[str]:
    begin = html.index(start)
    return set(re.findall(r"'([^']+)'", html[begin:html.index(end, begin)]))


@pytest.mark.parametrize("start,end,expected", [
    ("const SHORTENERS = new Set([", "]);", la._SHORTENER_DOMAINS),
    ("const SUSPICIOUS_TLDS = new Set([", "]);", la._SUSPICIOUS_TLDS),
    ("const ABUSED_TLDS = new Set([", "]);", la._ABUSED_TLDS),
    ("const KEYWORDS = [", "];", la._TRIGGER_KEYWORDS),
    ("const KEYWORDS_RU = [", "];", la._TRIGGER_KEYWORDS_RU),
    ("const AMBIGUOUS_ALIASES = new Set(", ");", brands.AMBIGUOUS_ALIASES),
    ("const LURE_WORDS = new Set(", ");", brands.LURE_WORDS),
    ("const LOOKALIKE_WORDS = new Set(", ");", brands.LOOKALIKE_WORDS),
    ("const BRAND_SIDE_DOMAINS = new Set(", ");", brands.BRAND_SIDE_DOMAINS),
    ("const REDIRECT_NAMES_SURE = new Set(", ");", la._REDIRECT_NAMES_SURE),
    ("const REDIRECT_NAMES_MAYBE = new Set(", ");", la._REDIRECT_NAMES_MAYBE),
    ("const MULTI_TENANT_HOSTS = new Set(", ");", brands.MULTI_TENANT_HOSTS),
    ("const MULTI_TENANT_DOMAINS = new Set(", ");", brands.MULTI_TENANT_DOMAINS),
], ids=lambda v: v.split("=")[0].replace("const ", "").strip() if isinstance(v, str) and v.startswith("const") else "")
def test_list_matches_python(html, start, end, expected):
    got = _js_strings(html, start, end)
    assert got == set(expected), (
        f"{start} разошёлся с питоном: лишнее на странице "
        f"{sorted(got - set(expected))}, не хватает {sorted(set(expected) - got)}")


def test_brand_domains_match(html):
    block = html[html.index("const BRANDS = {"):html.index("};", html.index("const BRANDS = {"))]
    for brand, domains in brands.BRAND_DOMAINS.items():
        line = re.search(rf"\b{brand}:\[([^\]]*)\]", block)
        assert line, f"нет бренда {brand} в BRANDS"
        got = set(re.findall(r"'([^']+)'", line.group(1)))
        assert got == set(domains), f"{brand}: страница {sorted(got)}, питон {sorted(domains)}"


def test_trusted_domains_match(html):
    extra = _js_strings(html, "const TRUSTED_EXTRA = [", "];")
    expected = brands.TRUSTED_DOMAINS - brands.BRAND_OWNED_DOMAINS
    assert extra == set(expected), (
        f"лишнее {sorted(extra - expected)}, не хватает {sorted(expected - extra)}")


@pytest.mark.parametrize("suffix", [
    "co.uk", "co.il", "org.il", "com.co", "com.ua", "gov.ua", "org.ua",
    "com.tr", "ne.jp", "com.by", "com.ge", "co.kr", "com.kz", "com.au",
])
def test_common_compound_suffixes_are_known(html, suffix):
    """`google.co.il` страница читала как домен `co.il` с поддоменом
    google — и обвиняла Google в подделке самого себя."""
    assert suffix in _js_strings(html, "const MULTI_SUFFIXES = new Set([", "]);")
