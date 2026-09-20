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


@pytest.mark.parametrize("py_name,js_name", [
    ("TRUSTED_DOMAIN_SCORE_CAP", "TRUSTED_SCORE_CAP"),
    ("UNRESOLVED_SHORTENER_FLOOR", "UNRESOLVED_SHORTENER_FLOOR"),
    ("UNRESOLVED_SHORTENER_CAP", "UNRESOLVED_SHORTENER_CAP"),
])
def test_scoring_constants_match(py_name, js_name, html):
    """
    Поверх сложения стоят правила с числами, и они решают вердикт не
    меньше весов. Сверялся только потолок доверия — а пол сокращателя
    во фронтенд не доехал вовсе, и `bit.ly` получал на странице 10
    и зелёное «БЕЗОПАСНО» там, где сервер давал 35.
    """
    from pipeline import scorer

    expected = getattr(scorer, py_name)
    found = re.search(rf"{js_name}\s*=\s*(\d+)", html)
    assert found, f"не нашёл {js_name} в index.html"
    assert int(found.group(1)) == expected, (
        f"{js_name} на странице {found.group(1)}, "
        f"а {py_name} в питоне {expected}"
    )


def _lang_sections(html: str, start: str) -> dict[str, str]:
    """Режет словарь вида `{ ru: {...}, en: {...} }` на два куска."""
    block = _js_block(html, start)
    ru = block.index("ru:")
    en = block.index("en:", ru)
    return {"ru": block[ru:en], "en": block[en:]}


def test_every_signal_code_is_translated(html):
    """
    Новый сигнал в скорере — это новая строчка в словаре `SIG` во
    фронтенде, В ОБОИХ ЯЗЫКАХ. Забыл её, и пользователь видит
    `PAGE_NOT_SEEN` вместо объяснения. А объяснимость здесь главная
    функция.

    Раньше тест искал код по всему файлу и был доволен переводом на
    один язык: английская половина словаря отставала молча.
    """
    scorer = (Path(__file__).resolve().parents[1]
              / "pipeline" / "scorer.py").read_text(encoding="utf-8")
    codes = set(re.findall(r'c\.(?:add|ok)\(\s*"([A-Z_0-9]+)"', scorer))
    assert codes, "не нашёл коды сигналов в scorer.py"

    for lang, section in _lang_sections(html, "const SIG = {").items():
        compact = section.replace(" ", "")
        missing = sorted(c for c in codes if f"{c}:{{" not in compact)
        assert not missing, (
            f"нет описания на языке «{lang}»: " + ", ".join(missing) +
            " — добавь в словарь SIG, в оба языка"
        )


def test_local_engine_codes_are_translated(html):
    """
    Обратная сторона: локальный движок выдаёт и свои коды, которых в
    скорере нет вовсе (`TLD_OK`, `ASCII_OK`). Их тоже надо перевести —
    иначе без сервера страница покажет сам код.
    """
    codes = set(re.findall(r"\b(?:add|ok)\(\s*'([A-Z_0-9]+)'", html))
    assert codes, "не нашёл вызовов add/ok в локальном движке"

    for lang, section in _lang_sections(html, "const SIG = {").items():
        compact = section.replace(" ", "")
        missing = sorted(c for c in codes if f"{c}:{{" not in compact)
        assert not missing, (
            f"локальный движок выдаёт без перевода на «{lang}»: "
            + ", ".join(missing)
        )


def test_scam_labels_exist_in_both_languages(html):
    """Подпись схемы обмана тоже двуязычная: код схемы приходит из
    питона, а расшифровывается на странице."""
    from pipeline.lexical_analyzer import _SCAM_PATTERNS

    codes = [code for code, _a, _b in _SCAM_PATTERNS]
    for lang, section in _lang_sections(html, "const SCAM_LABELS = {").items():
        missing = [c for c in codes if f"{c}:" not in section.replace(" ", "")]
        assert not missing, (
            f"нет подписи схемы на языке «{lang}»: " + ", ".join(missing)
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


def test_main_reason_order_names_real_signals(html):
    """
    Экран результата выбирает главную причину по этому списку. Коды в
    нём были написаны от руки, и два самых сильных — попадание в базу
    Google и в URLhaus — назывались неправильно, поэтому главной
    причиной стать не могли никогда.
    """
    import re
    block = _js_block(html, "const M_REASON_ORDER = [", "];")
    listed = re.findall(r"'([A-Z_0-9]+)'", block)
    assert listed, "не нашёл список главных причин"

    scorer = (Path(__file__).resolve().parents[1]
              / "pipeline" / "scorer.py").read_text(encoding="utf-8")
    real = set(re.findall(r"c\.(?:add|ok)\(\s*\"([A-Z_0-9]+)\"", scorer))
    unknown = [code for code in listed if code not in real]
    assert not unknown, f"таких признаков скорер не выдаёт: {unknown}"
