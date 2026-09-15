"""
normalize.py — нормализация доменных имён для детекта имперсонации.

Здесь живут три независимых приёма, которые вместе ловят подавляющее
большинство «похожих» доменов:

1. ПУНИКОД (punycode / IDN)
   Домен с не-ASCII символами передаётся по DNS в ASCII-форме
   (RFC 3492, «ACE»), начинающейся с префикса `xn--`.
   Браузер показывает пользователю `аpple.com`, а в DNS уходит
   `xn--pple-43d.com`.  Чтобы понять, ЧТО видит жертва, надо
   раскодировать метку обратно в Unicode.

2. ГОМОГЛИФЫ (homoglyphs)
   Кириллическая «а» (U+0430) и латинская «a» (U+0061) выглядят
   одинаково, но это разные символы.  Складываем визуально
   идентичные символы к одному латинскому — и `аpple` превращается
   в `apple`, после чего обычное сравнение строк ловит атаку.

3. LEET / ОПЕЧАТКИ
   `paypa1.com`, `g00gle.com`, `micros0ft.com` — цифры вместо букв.
   Складываем 0→o, 1→l, 3→e и т.д., а затем считаем расстояние
   Левенштейна до имени бренда: это ловит и то, что leet-таблица
   не покрыла (`gogle`, `paypall`, `amazn`).

Модуль намеренно без внешних зависимостей, кроме `idna` — чтобы
его можно было unit-тестировать в изоляции.
"""

from __future__ import annotations

import unicodedata

import idna

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
    "fold_homoglyphs",
    "fold_leet",
    "fold_sequences",
    "canonical",
    "levenshtein",
    "has_non_ascii",
    "mixed_scripts",
]
