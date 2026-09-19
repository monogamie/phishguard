"""
Фронтенд и бэкенд обязаны считать одинаково.

В `index.html` живёт второй, урезанный движок проверки: он работает,
когда сервер недоступен, и считает те же признаки адреса — своими
копиями весов и порогов. Копии молчаливо разъезжаются при первой же
правке весов только в питоне, и тогда страница и сервер выносят разные
вердикты по одной ссылке. Такое уже случалось дважды.

Тест сверяет три вещи: веса, пороги и то, что каждый код сигнала
фронтенду известен по-человечески, а не показывается как `CERT_MISMATCH`.
"""
import re
from pathlib import Path

import pytest

from config import settings

FRONTEND = Path(__file__).resolve().parents[2] / "index.html"


@pytest.fixture(scope="module")
def html() -> str:
    if not FRONTEND.exists():                       # pragma: no cover
        pytest.skip(f"не найден {FRONTEND}")
    return FRONTEND.read_text(encoding="utf-8")


def _js_block(html: str, start: str, end: str = "};") -> str:
    begin = html.index(start)
    return html[begin:html.index(end, begin)]


def _js_numbers(block: str) -> dict[str, int]:
    return {k: int(v) for k, v in re.findall(r"([a-z_0-9]+)\s*:\s*(-?\d+)", block)}


def test_weights_match(html):
    """Каждый вес, который знает фронтенд, должен совпадать с питоном.

    Фронтенд знает не все: сетевые уровни он не умеет и их веса ему не
    нужны. А вот те, что знает, обязаны совпадать до числа.
    """
    js = _js_numbers(_js_block(html, "const W = {"))
    assert js, "не нашёл таблицу весов W в index.html"

    mismatched = {
        key: (settings.weight(key), value)
        for key, value in js.items()
        if settings.weight(key) != value
    }
    assert not mismatched, (
        "веса разъехались (питон, js): " + repr(mismatched) +
        " — поправь backend/config.py и таблицу W в index.html вместе"
    )


def test_thresholds_match(html):
    pairs = [
        ("THRESHOLD_PHISHING", settings.PHISHING_THRESHOLD),
        ("THRESHOLD_SUSPICIOUS", settings.SUSPICIOUS_MIN),
    ]
    for name, expected in pairs:
        found = re.search(rf"{name}\s*=\s*(\d+)", html)
        assert found, f"не нашёл {name} в index.html"
        assert int(found.group(1)) == expected, (
            f"{name}: во фронтенде {found.group(1)}, в питоне {expected}"
        )


def test_trusted_cap_matches(html):
    from pipeline.scorer import TRUSTED_DOMAIN_SCORE_CAP

    found = re.search(r"TRUSTED_SCORE_CAP\s*=\s*(\d+)", html)
    assert found, "не нашёл TRUSTED_SCORE_CAP в index.html"
    assert int(found.group(1)) == TRUSTED_DOMAIN_SCORE_CAP


def test_every_signal_code_is_translated(html):
    """
    Новый сигнал в скорере — это новая строчка в словаре `SIG` во
    фронтенде. Забыл её, и пользователь видит `PAGE_NOT_SEEN` вместо
    объяснения. А объяснимость здесь главная функция.
    """
    scorer = (Path(__file__).resolve().parents[1]
              / "pipeline" / "scorer.py").read_text(encoding="utf-8")
    codes = set(re.findall(r"c\.(?:add|ok)\(\s*\"([A-Z_0-9]+)\"", scorer))
    assert codes, "не нашёл коды сигналов в scorer.py"

    compact = html.replace(" ", "")
    untranslated = sorted(c for c in codes if f"{c}:{{" not in compact)
    assert not untranslated, (
        "нет описания во фронтенде: " + ", ".join(untranslated) +
        " — добавь в словарь SIG, в оба языка"
    )


# ── Поведение, а не только таблицы ───────────────────────────────
# Сверка весов и словаря не ловит главного: правку логики, доехавшую
# до питона и не доехавшую до страницы. Так было трижды за два дня —
# гомоглиф считался дважды, цифры горели на IP, слова в пути весили
# как слова в имени. Здесь проверяем, что оговорки в копии движка есть.

@pytest.mark.parametrize("marker,why", [
    ("brand.kind === 'homograph'",
     "гомоглиф бренда не должен дублироваться смешением алфавитов"),
    ("digitsMeanSomething",
     "цифры не должны гореть на IP и на опечаточном домене"),
    ("TRIGGER_KEYWORDS_PATH",
     "слова входа в ПУТИ не должны весить столько же, сколько в имени домена"),
    ("BRAND_NAMES.has",
     "бренд на собственном домене в приличной зоне — не подделка"),
    ("labels.some(mixedScripts)",
     "нелатиница — улика только при смешении алфавитов внутри слова"),
])
def test_frontend_carries_the_same_exceptions(html, marker, why):
    assert marker in html, f"в index.html нет оговорки: {why}"


def test_brand_aliases_match_between_engines(html):
    """Псевдонимы брендов — вторая таблица, которая обязана совпадать.
    Копия движка на странице ищет по ней же."""
    from data.brands import BRAND_ALIASES

    block = _js_block(html, "const BRAND_ALIASES = {")
    for brand, aliases in BRAND_ALIASES.items():
        assert f"{brand}:" in block, f"нет бренда {brand} в index.html"
        for alias in aliases:
            assert f"'{alias}'" in block, f"нет написания «{alias}» ({brand})"


def test_scam_pattern_codes_match_between_engines(html):
    """Новая схема в питоне — новая схема на странице, иначе один
    и тот же адрес получает разные вердикты."""
    from pipeline.lexical_analyzer import _SCAM_PATTERNS

    for code, _a, _b in _SCAM_PATTERNS:
        assert f"code:'{code}'" in html, f"нет схемы {code} в index.html"
        assert f"{code}:" in html, f"нет подписи схемы {code}"
