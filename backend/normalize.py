"""Нормализация доменных имён для детекта имперсонации:
декодирование punycode, свёртка гомоглифов и leet-символов,
расстояние Левенштейна."""

from __future__ import annotations

import re
import unicodedata

import idna

from urllib.parse import quote, urlsplit

# ── 1. Таблица гомоглифов ────────────────────────────────────────
# Отображаем «обманчиво похожие» символы в латиницу.
# Источник идей: Unicode TR39 (Confusable Detection) — здесь взята
# практическая подвыборка для кириллицы и греческого, которыми
# пользуются в 95 % реальных IDN-атак на рунет-бренды.
_HOMOGLYPHS: dict[str, str] = {
    # Кириллица → латиница
    "а": "a", "б": "b", "в": "b", "г": "r", "д": "d", "е": "e", "ё": "e",
    "з": "3", "и": "u", "к": "k", "м": "m", "н": "h", "о": "o", "п": "n",
    "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ч": "4", "ѕ": "s",
    "і": "i", "ј": "j", "џ": "u", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l",
    # Греческий → латиница
    "α": "a", "β": "b", "γ": "y", "ε": "e", "ζ": "z", "η": "n", "ι": "i",
    "κ": "k", "μ": "u", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u",
    "χ": "x", "ϲ": "c", "ϳ": "j", "ѵ": "v",
    # Прочие «похожие» из латиницы-расширенной
    "ı": "i", "ȷ": "j", "ł": "l", "ɑ": "a", "ɡ": "g", "ɩ": "i", "ɪ": "i",
    "ᴀ": "a", "ᴄ": "c", "ᴇ": "e", "ᴏ": "o", "ᴘ": "p", "ѐ": "e",
    # Математические / полноширинные варианты складываются NFKC ниже,
    # здесь оставлены только те, что NFKC не трогает.
}

# ── 2. Leet-таблица ──────────────────────────────────────────────
_LEET: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "9": "g", "|": "l", "!": "i", "$": "s",
}


def decode_punycode(host: str) -> str:
    """
    Раскодирует все `xn--` метки хоста обратно в Unicode.

    `xn--80ak6aa92e.com` → `аррӏе.com`

    Если метка битая (а такое бывает — атакующие подсовывают
    некорректный ACE, чтобы сломать парсер), она остаётся как есть:
    лучше проанализировать сырую строку, чем упасть.
    """
    if "xn--" not in host:
        return host

    out: list[str] = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                out.append(idna.decode(label))
            except (idna.IDNAError, UnicodeError, ValueError):
                out.append(label)
        else:
            out.append(label)
    return ".".join(out)


_SPECIAL_SCHEMES = ("http://", "https://")
# Символы, на которых кончается адресная часть (то, что до пути).
_AUTHORITY_END = "/?#" + chr(92)


# Двойники ТОЧКИ, которые браузер приводит к обычной при разборе имени
# (это часть правил IDNA). Проверено настоящим браузером:
# `google.com。evil.ru` он читает как `google.com.evil.ru`.
#
# Полноширинные слеш, собака и двоеточие сюда НЕ входят — проверено там
# же: слеш браузер разделителем не считает, а на собаке спотыкается.
# Соблазн дописать их велик, но тогда мы разойдёмся с браузером в
# другую сторону, а это ровно то, что мы весь день чиним.
_LOOKALIKE_DELIMITERS = {
    "\u3002": ".", "\uff0e": ".", "\uff61": ".",
}
_LOOKALIKE_RE = re.compile("[" + "".join(_LOOKALIKE_DELIMITERS) + "]")


def normalize_authority(url: str) -> str:
    """
    Приводит адрес к тому виду, как его понимает браузер.

    Браузер считает обратный слеш таким же разделителем, как прямой, а
    питоновский `urlsplit` — нет. Из-за этого `https://evil.top\@bank.ru/`
    для браузера ведёт на `evil.top`, а для нас — на `bank.ru`: жертва
    уходит на одну страницу, мы проверяем другую и говорим «безопасно».

    Трогаем только адресную часть: в пути обратный слеш безобиден.
    """
    url = _LOOKALIKE_RE.sub(lambda m: _LOOKALIKE_DELIMITERS[m.group()], url)

    lowered = url[:8].lower()
    scheme_len = next((len(s) for s in _SPECIAL_SCHEMES if lowered.startswith(s)), 0)
    if not scheme_len:
        return url

    rest = url[scheme_len:]
    cut = next((i for i, ch in enumerate(rest) if ch in _AUTHORITY_END), len(rest))
    if cut == len(rest) or rest[cut] != chr(92):
        return url
    # Разделитель оказался обратным слешем — заменяем его на прямой,
    # и адресная часть кончается там же, где кончилась бы у браузера.
    return url[:scheme_len] + rest[:cut] + "/" + rest[cut + 1:]


def encode_unparseable_userinfo(url: str) -> str:
    """
    Кодирует логин в адресе, если из-за него `urlsplit` отказывается
    разбирать адрес целиком.

    Python бракует адресную часть, если NFKC-нормализация вносит в неё
    новые служебные символы (его защита от подмены хоста). Браузер так
    не делает: `https://sberbank.ru／@evil.top/` он спокойно открывает
    на `evil.top`, считая всё до «собаки» логином.

    Пока мы просто отказывались проверять такой адрес, мошенник получал
    способ вообще не попасть под проверку. Логин ПРОЦЕНТ-кодируем, а не
    выбрасываем: разборщик тогда доволен, хост определяется правильно,
    и «собака в адресе» остаётся видна как признак.
    """
    lowered = url[:8].lower()
    scheme_len = next((len(s) for s in _SPECIAL_SCHEMES if lowered.startswith(s)), 0)
    if not scheme_len:
        return url
    rest = url[scheme_len:]
    cut = next((i for i, ch in enumerate(rest) if ch in "/?#"), len(rest))
    authority, tail = rest[:cut], rest[cut:]
    if "@" not in authority:
        return url
    try:
        urlsplit(url).hostname
        return url
    except ValueError:
        pass
    userinfo, _, host_part = authority.rpartition("@")
    safe_userinfo = quote(userinfo, safe="")
    return url[:scheme_len] + safe_userinfo + "@" + host_part + tail


def to_ascii_host(host: str) -> str:
    """
    Приводит хост к `xn--`-форме: `мвд.рф` → `xn--b1aew.xn--p1ai`.

    Адрес можно набрать и русскими буквами, и через punycode — это
    один и тот же сайт, и признаки должны выйти одинаковые. Плюс
    RDAP и журналы сертификатов принимают только ASCII-форму.

    Кодируем только нелатинские метки: ASCII-метку трогать нельзя,
    кодек idna строже DNS и отбивает, например, подчёркивания.
    Битая метка остаётся как есть — лучше разобрать сырую строку,
    чем упасть.
    """
    if not has_non_ascii(host):
        return host

    out: list[str] = []
    for label in host.split("."):
        if any(ord(ch) > 127 for ch in label):
            try:
                out.append(idna.encode(label, uts46=True).decode("ascii"))
            except (idna.IDNAError, UnicodeError, ValueError):
                out.append(label)
        else:
            out.append(label)
    return ".".join(out)


def fold_homoglyphs(text: str) -> str:
    """
    Складывает визуально похожие символы к латинице.

    Сначала NFKC — он сам разбирает полноширинные («ｇｏｏｇｌｅ»)
    и математические («𝗀𝗈𝗈𝗀𝗅𝖾») варианты в обычную латиницу.
    Затем добиваем кириллицу/греческий своей таблицей.
    """
    text = unicodedata.normalize("NFKC", text).casefold()
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def fold_leet(text: str) -> str:
    """`paypa1` → `paypal`, `g00gle` → `google`."""
    return "".join(_LEET.get(ch, ch) for ch in text.lower())


# ── 3. Последовательные конфузаблы ───────────────────────────────
# Пары символов, которые в большинстве шрифтов сливаются в один:
#   rn → m  (arnazon.com  ≈ amazon.com — классика с 2015 года)
#   vv → w  (vvhatsapp.com ≈ whatsapp.com)
#   cl → d  (clropbox.com  ≈ dropbox.com)
# Одиночным расстоянием Левенштейна такие домены не ловятся:
# «arnazon» отстоит от «amazon» на 2 правки, а порог 2 для
# шестибуквенного бренда даёт слишком много ложных срабатываний.
_SEQUENCE_CONFUSABLES: tuple[tuple[str, str], ...] = (
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
    ("ii", "u"),
)


def fold_sequences(text: str) -> str:
    """Схлопывает пары символов, визуально сливающиеся в один."""
    for src, dst in _SEQUENCE_CONFUSABLES:
        text = text.replace(src, dst)
    return text


def canonical(text: str) -> str:
    """
    Полная нормализация: пуникод → гомоглифы → leet →
    последовательные конфузаблы → убрать разделители.

    Дефисы и точки выкидываем, потому что `pay-pal.com` и
    `pay.pal.com` — это та же атака, что и `paypal`-в-чужом-домене.
    """
    folded = fold_sequences(fold_leet(fold_homoglyphs(decode_punycode(text))))
    return "".join(ch for ch in folded if ch.isalnum())


def levenshtein(a: str, b: str, max_distance: int = 3) -> int:
    """
    Расстояние Левенштейна с ранним выходом.

    Классический DP по двум строкам, но храним только одну строку
    матрицы — O(min(|a|,|b|)) памяти вместо O(|a|·|b|).
    Если минимальное значение в строке уже больше max_distance,
    дальше считать бессмысленно: возвращаем max_distance + 1.

    Нужен для детекта опечаточных доменов (typosquatting):
    `gogle.com` → расстояние 1 до `google`, `arnazon` → 2 до `amazon`.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    # Длины отличаются сильнее порога — считать нечего.
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1

    # Работаем по более короткой строке, чтобы строка DP была меньше.
    if len(a) > len(b):
        a, b = b, a

    previous = list(range(len(a) + 1))
    for i, cb in enumerate(b, start=1):
        current = [i]
        for j, ca in enumerate(a, start=1):
            current.append(min(
                previous[j] + 1,          # удаление
                current[j - 1] + 1,       # вставка
                previous[j - 1] + (ca != cb),  # замена
            ))
        if min(current) > max_distance:
            return max_distance + 1
        previous = current

    return previous[-1]


def has_non_ascii(text: str) -> bool:
    """True, если строка содержит символы вне ASCII."""
    return any(ord(ch) > 127 for ch in text)


def scripts_of(text: str) -> set[str]:
    """Набор письменностей, встречающихся в строке ("CYRILLIC", "LATIN")."""
    scripts: set[str] = set()
    for ch in text:
        if not ch.isalpha():
            continue
        try:
            # Первое слово в имени символа Unicode — его письменность:
            # "CYRILLIC SMALL LETTER A", "LATIN SMALL LETTER A".
            scripts.add(unicodedata.name(ch).split()[0])
        except ValueError:
            continue
    return scripts


def mixed_scripts(text: str) -> bool:
    """
    True, если в одной метке смешаны разные письменности
    (например, латиница + кириллица).

    Это сильнейший индикатор гомоглифной атаки: легитимные домены
    не смешивают алфавиты внутри одного слова.  `аpple` — кириллическая
    «а» плюс латинские «pple» — попадает сюда даже без словаря брендов.
    """
    scripts: set[str] = set()
    for ch in text:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        # Первое слово в имени символа Unicode — это его письменность:
        # "CYRILLIC SMALL LETTER A", "LATIN SMALL LETTER A".
        scripts.add(name.split()[0])
        if len(scripts) > 1:
            return True
    return False


__all__ = [
    "decode_punycode",
    "to_ascii_host",
    "normalize_authority",
    "encode_unparseable_userinfo",
    "fold_homoglyphs",
    "fold_leet",
    "fold_sequences",
    "canonical",
    "levenshtein",
    "has_non_ascii",
    "mixed_scripts",
    "scripts_of",
]
