"""Уровень 3: структурный и лексический анализ URL без сетевых запросов.

~20 признаков плюс детект имперсонации брендов тремя техниками:
гомоглифы, опечатки (расстояние Левенштейна), подстановка в чужой домен."""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Optional
from urllib.parse import unquote, urlsplit

import tldextract

from data.brands import (
    BRAND_DOMAINS,
    MIN_SUBSTRING_BRAND_LEN,
    TRUSTED_DOMAINS,
)
from models import BrandMatch, LexicalFeatures
from normalize import (
    canonical,
    decode_punycode,
    normalize_authority,
    to_ascii_host,
    fold_homoglyphs,
    has_non_ascii,
    levenshtein,
    mixed_scripts,
    scripts_of,
)

logger = logging.getLogger(__name__)

# suffix_list_urls=() — снимок PSL из пакета вместо HTTP-запроса:
# иначе первый скан блокирует event loop сетевым вызовом.
_extract = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)

# Второй экстрактор с приватной частью PSL. Нужен ОТДЕЛЬНО от первого:
# у `sber-vhod.github.io` регистрируемый домен для RDAP и журналов —
# `github.io`, а вот доверять надо не ему, а полному имени, иначе любой
# заведённый за минуту поддомен получает потолок доверия хозяина
# площадки. Первый экстрактор отвечает на «что зарегистрировано»,
# второй — на «кто за это отвечает».
_extract_trust = tldextract.TLDExtract(suffix_list_urls=(),
                                       fallback_to_snapshot=True,
                                       include_psl_private_domains=True)

# ── Константы ────────────────────────────────────────────────────

# Имена брендов отсюда убраны: их ловит отдельный детектор.
_TRIGGER_KEYWORDS: frozenset[str] = frozenset({
    "login", "signin", "logon", "secure", "security", "verify",
    "verification", "validate", "account", "update", "confirm",
    "banking", "bank", "recover", "recovery", "password", "passwd",
    "credential", "wallet", "prize", "winner", "bonus", "gift",
    "suspended", "limited", "unusual", "activity", "authenticate",
    "authorize", "authorization", "reactivate", "unlock", "billing",
    "invoice", "payment", "refund", "webscr", "cmd", "session",
    "token", "otp", "2fa", "id", "customer", "client", "support",
})

# Русские слова: сайт для русскоязычной жертвы пишет `golosovanie`
# и `deti`, а не `voting` и `children`.
_TRIGGER_KEYWORDS_RU: frozenset[str] = frozenset({
    # голосование и конкурсы — самая частая схема угона Telegram
    "golos", "golosovanie", "golosovat", "golosuy", "vote", "voting",
    "konkurs", "concurs", "reyting", "rating", "opros",
    # «детский» антураж, вызывающий доверие
    "deti", "detskiy", "detsad", "rebenok", "malysh", "shkola",
    # деньги
    "priz", "prize", "vyigrysh", "podarok", "podarki", "bonus",
    "vyplata", "vyplaty", "vozvrat", "kompensaciya", "posobie",
    "subsidiya", "grant", "lotereya", "rozygrysh", "akciya",
    "perevod", "oplata", "karta", "koshelek", "schet", "dengi",
    # давление и «подтверди себя»
    "podtverdit", "podtverzhdenie", "proverka", "vhod", "voyti",
    "avtorizaciya", "blokirovka", "zablokirovan", "srochno",
    # кириллица напрямую — некоторые сайты не транслитерируют
    "голос", "голосование", "конкурс", "дети", "ребенок", "приз",
    "подарок", "выплата", "возврат", "бонус", "вход", "подтвердить",
})

_TRIGGER_KEYWORDS_ALL = _TRIGGER_KEYWORDS | _TRIGGER_KEYWORDS_RU

# Бесплатные и массово злоупотребляемые доменные зоны.
_SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "xyz", "tk", "ml", "ga", "cf", "gq", "top", "click", "loan",
    "work", "date", "win", "stream", "racing", "review", "party",
    "download", "bid", "faith", "icu", "buzz", "cyou", "monster",
    "cfd", "sbs", "bar", "hair", "skin", "boats", "wang", "men",
    "rest", "quest", "beauty", "mom", "lol", "autos", "makeup",
    "zip", "mov", "kim", "country", "science", "gdn", "accountant",
})

# Дешёвые, но не бесплатные зоны: вес вдвое меньше первого яруса —
# нормальных сайтов здесь тоже много.
_ABUSED_TLDS: frozenset[str] = frozenset({
    "shop", "store", "online", "site", "website", "space", "fun",
    "live", "club", "life", "world", "today", "link", "digital",
    "agency", "city", "host", "press", "one", "uno", "run",
    "shopping", "cloud", "pics", "photo", "email", "services",
})

# Сокращатели ссылок: сам домен всегда «чистый», анализировать надо цель.
_SHORTENER_DOMAINS: frozenset[str] = frozenset({
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "cutt.ly",
    "shorturl.at", "rebrand.ly", "buff.ly", "ow.ly", "s.id", "rb.gy",
    "short.io", "lnkd.in", "tiny.cc", "clck.ru", "vk.cc", "qps.ru",
    "u.to", "v.gd", "t.ly", "dub.sh", "shrtco.de", "trib.al",
    "youtu.be", "amzn.to", "surl.li", "clc.to", "gg.gg",
})

# Параметры открытого редиректа.
_REDIRECT_PARAMS_RE = re.compile(
    r"(?i)[?&](url|redirect|redirect_uri|redirect_url|goto|go|link|"
    r"forward|return|returnurl|return_to|next|redir|dest|destination|"
    r"continue|target|out|r|u)=",
)

# Процентное кодирование.
_PERCENT_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")

# Порты, которые считаем нормальными для веба.
_STANDARD_PORTS: frozenset[int] = frozenset({80, 443})


def _keyword_pattern(keywords: frozenset[str]) -> re.Pattern[str]:
    """
    Собирает одну регулярку на все ключевые слова.

    Границы «мягкие»: буквы вокруг запрещены, цифры и разделители нет.
    Поэтому `/secure-login/` находится, а `accountant` — нет.
    """
    alternation = "|".join(sorted(map(re.escape, keywords), key=len, reverse=True))
    return re.compile(rf"(?<![a-z])({alternation})(?![a-z])", re.IGNORECASE)


_KEYWORD_RE = _keyword_pattern(_TRIGGER_KEYWORDS_ALL)

# Схемы: опасны не отдельные слова, а их связка. «Дети» и
# «голосование» по отдельности безобидны, вместе — схема угона.
# Формат: (код, группа_А, группа_Б) — нужно слово из обеих.
_SCAM_PATTERNS: tuple[tuple[str, frozenset[str], frozenset[str]], ...] = (
    # Классика угона Telegram/WhatsApp: «проголосуй за ребёнка в конкурсе»
    ("fake_vote",
     frozenset({"golos", "golosovanie", "golosovat", "golosuy", "vote",
                "voting", "konkurs", "concurs", "reyting", "rating",
                "голос", "голосование", "конкурс"}),
     frozenset({"deti", "detskiy", "rebenok", "malysh", "detsad",
                "shkola", "grant", "risunok", "talant", "дети",
                "ребенок", "конкурс", "голосование"})),
    # «Вам положена выплата / возврат налога / компенсация»
    ("fake_payout",
     frozenset({"vyplata", "vyplaty", "vozvrat", "kompensaciya",
                "posobie", "subsidiya", "refund", "payout",
                "выплата", "возврат"}),
     frozenset({"oformit", "poluchit", "karta", "schet", "nalog",
                "gosuslugi", "bank", "perevod", "dengi", "card",
                "получить", "оформить"})),
    # «Вы выиграли приз, заберите подарок»
    ("fake_prize",
     frozenset({"priz", "prize", "vyigrysh", "podarok", "podarki",
                "lotereya", "rozygrysh", "bonus", "приз", "подарок"}),
     frozenset({"poluchit", "zabrat", "aktivirovat", "claim", "win",
                "winner", "akciya", "promo", "получить", "забрать"})),
)

SCAM_PATTERN_LABELS = {
    "fake_vote": "поддельное голосование или конкурс",
    "fake_payout": "обещание выплаты или возврата денег",
    "fake_prize": "обещание приза или подарка",
}


def _group_pattern(words: frozenset[str]) -> re.Pattern[str]:
    alternation = "|".join(sorted(map(re.escape, words), key=len, reverse=True))
    return re.compile(rf"(?<![a-z])({alternation})", re.IGNORECASE)


# Компилируем группы один раз при импорте.
_SCAM_PATTERNS_RE = tuple(
    (code, _group_pattern(a), _group_pattern(b)) for code, a, b in _SCAM_PATTERNS
)


def _match_scam_pattern(text: str) -> Optional[str]:
    """
    Возвращает код схемы, если в адресе сошлись слова из обеих групп.

    Ищем по сырому тексту адреса, а не по списку найденных тревожных
    слов: слова второй группы («оформить», «получить», «налог») сами
    по себе безобидны и в списке тревожных им не место, но в связке
    с первой группой они и образуют узнаваемую схему.
    """
    lowered = text.lower()
    for code, group_a, group_b in _SCAM_PATTERNS_RE:
        if group_a.search(lowered) and group_b.search(lowered):
            return code
    return None


class LexicalAnalyzer:
    """
    Извлекатель признаков URL без состояния.

    Использование:
        features = lexical_analyzer.analyze("https://paypal.com.evil.xyz/login")
    """

    def analyze(self, url: str) -> LexicalFeatures:
        """
        Точка входа.  Ни один извлекатель не выбрасывает исключений:
        при ошибке признак возвращает False/0, и пайплайн продолжает
        работу на остальных признаках.
        """
        raw = url or ""

        # Обратный слеш браузер считает разделителем, а urlsplit — нет.
        # Без этого мы разбирали бы не тот домен, куда уйдёт жертва.
        raw = normalize_authority(raw)

        # ПОРЯДОК ВАЖЕН: %XX ищем ДО unquote, иначе искать уже нечего.
        raw_netloc = self._safe_netloc(raw)
        raw_userinfo, _, raw_host_part = raw_netloc.rpartition("@")
        has_encoded_host = bool(_PERCENT_ENCODED_RE.search(raw_host_part))
        # Кодирование в ЛОГИНЕ — отдельный приём: `%2F` раскодируется в
        # `/`, граница между логином и хостом уезжает, и адрес
        # `bank.ru%2Flogin@злой.сайт` выглядит как безобидный bank.ru.
        has_encoded_userinfo = bool(_PERCENT_ENCODED_RE.search(raw_userinfo))

        # Разбираем СЫРОЙ адрес, а не раскодированный: unquote до
        # urlsplit ломает структуру и подменяет анализируемый домен.
        # Раскодируем только путь и параметры — там оно безопасно и
        # нужно, чтобы найти спрятанные слова.
        try:
            parsed = urlsplit(raw)
        except ValueError:
            logger.warning("urlsplit failed for %r", raw[:120])
            return LexicalFeatures(url_length=len(raw))

        try:
            decoded_url = unquote(raw)
        except Exception:
            decoded_url = raw

        scheme = (parsed.scheme or "https").lower()

        # .hostname и .port ленивы: бросают ValueError при обращении.
        try:
            # К `xn--`-форме приводим сразу: дальше всё, от выделения
            # домена до запросов в RDAP, должно видеть один и тот же
            # хост независимо от того, набрали адрес русскими буквами
            # или punycode. Человеческий вид живёт в decoded_host.
            host = to_ascii_host((parsed.hostname or "").lower())
        except ValueError:
            host = ""
        try:
            port: Optional[int] = parsed.port
            port_malformed = False
        except ValueError:
            port, port_malformed = None, True

        try:
            netloc = parsed.netloc
        except ValueError:
            netloc = raw_netloc

        raw_path_and_query = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        try:
            path_and_query = unquote(raw_path_and_query)
        except Exception:                              # noqa: BLE001
            path_and_query = raw_path_and_query

        ext = _extract(host if host else decoded_url)
        sld = ext.domain.lower()
        suffix = ext.suffix.lower()
        registered_domain = f"{sld}.{suffix}" if sld and suffix else (sld or host)
        subdomains = [s for s in ext.subdomain.lower().split(".") if s]

        # Хост в «человеческом» виде: то, что видит жертва в браузере.
        # Все дальнейшие проверки идут по нему, а не по `xn--`-форме:
        # иначе «вход-сбербанк.рф» выглядит как xn----8sbcacmj6b0ad0aj2c
        # — без ключевых слов, зато с четырьмя дефисами и цифрами,
        # которых в имени нет. Из-за этого любой домен .рф получал 60
        # баллов и вердикт «ОПАСНО».
        decoded_host = decode_punycode(host) if "xn--" in host else host
        idn_native = self._idn_is_native(decoded_host)
        ext_human = _extract(decoded_host) if decoded_host != host else ext
        sld_human = ext_human.domain.lower() or sld

        # Доверие — по приватному PSL: см. комментарий к _extract_trust.
        trust_ext = _extract_trust(host)
        # domain пуст, когда хост И ЕСТЬ приватный суффикс (сам
        # `github.io`): тогда единица доверия — обычный eTLD+1.
        trust_domain = (f"{trust_ext.domain}.{trust_ext.suffix}".lower()
                        if trust_ext.suffix and trust_ext.domain
                        else registered_domain)
        is_trusted = trust_domain in TRUSTED_DOMAINS

        keywords = self._find_keywords(path_and_query, decoded_host, is_trusted)
        is_ip = self._is_ip_host(host)
        brand = self._match_brand(host, decoded_host, sld,
                                  registered_domain, subdomains, suffix)

        # Цифры в имени — слабый намёк на подмену букв (0 вместо o,
        # 1 вместо l). Но у IP-адреса цифры и есть адрес, а у опечатки
        # вроде `paypa1` именно цифра и делает её опечаткой — там этот
        # же символ уже посчитан признаком бренда. В обоих случаях
        # признак не добавляет знания, только балл.
        digits_mean_something = (
            bool(re.search(r"\d", sld_human))
            and not is_trusted
            and not is_ip
            and not (brand and brand.kind in ("typosquat", "homograph"))
        )

        features = LexicalFeatures(
            scheme                = scheme,
            host                  = host,
            registered_domain     = registered_domain,
            tld                   = suffix,
            decoded_host          = decoded_host if decoded_host != host else None,
            has_ip_address        = is_ip,
            has_at_symbol         = "@" in netloc,
            has_punycode          = any(l.startswith("xn--") for l in host.split(".")),
            idn_is_native         = idn_native,
            has_non_ascii_host    = has_non_ascii(decoded_host) and not idn_native,
            has_mixed_scripts     = self._has_mixed_scripts(decoded_host),
            has_non_standard_port = self._is_non_standard_port(port, scheme, port_malformed),
            has_encoded_host      = has_encoded_host or has_encoded_userinfo,
            has_redirect_params   = bool(_REDIRECT_PARAMS_RE.search(raw)),
            has_digits_in_domain  = digits_mean_something,
            is_insecure_scheme    = scheme == "http",
            is_shortener          = registered_domain in _SHORTENER_DOMAINS,
            subdomain_count       = len([s for s in subdomains if s != "www"]),
            url_length            = len(raw),
            domain_length         = len(sld_human),
            hyphen_count          = decoded_host.count("-"),
            trigger_keywords      = keywords,
            scam_pattern          = (None if is_trusted else
                                     _match_scam_pattern(
                                         f"{path_and_query} {decoded_host}")),
            suspicious_tld        = self._is_suspicious_tld(suffix),
            abused_tld            = self._is_abused_tld(suffix),
            is_trusted_domain     = is_trusted,
            trust_domain          = trust_domain,
            brand_match           = brand,
        )

        logger.debug("Lexical features for %s: %s", host, features.model_dump())
        return features

    # ── Отдельные извлекатели признаков ──────────────────────────

    @staticmethod
    def _idn_is_native(human_host: str) -> bool:
        """
        True, если нелатиница в домене ожидаема, а не прячется.

        Прячется она одним способом: КОГДА В ОДНОМ СЛОВЕ смешаны
        алфавиты. `аpple.com` — кириллическая «а» плюс латинские
        «pple» — на глаз неотличим от настоящего.

        А вот `мвд.рф`, `www.мвд.рф`, `société.fr`, `bücher.de` ничего
        не прячут: каждое слово там написано целиком на одном алфавите.
        Раньше проверка требовала, чтобы ВЕСЬ адрес был одной
        нелатинской письменностью, и ломалась от приставки `www`
        (`www.мвд.рф` — 90 баллов и «ОПАСНО») и от любой латинской зоны
        (`société.fr` — 75). Для сервиса, который читают люди со всего
        мира, это было хуже пропуска.

        Полностью нелатинскую подделку под бренд (`аррӏе.com`) ловит
        отдельный детектор брендов, и его вес выше.
        """
        labels = [l for l in human_host.split(".") if l]
        if len(labels) < 2:
            return False
        if not has_non_ascii(human_host):
            return False
        return not any(mixed_scripts(label) for label in labels)

    @staticmethod
    def _safe_netloc(raw: str) -> str:
        """Достаёт netloc из сырой строки, не бросая исключений."""
        try:
            return urlsplit(raw).netloc
        except ValueError:
            # Ручной разбор на случай совсем битого URL.
            without_scheme = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", raw)
            return without_scheme.split("/")[0]

    @staticmethod
    def _is_ip_host(host: str) -> bool:
        """
        True, если хост — это IP-литерал (v4 или v6).

        """
        if not host:
            return False
        try:
            ipaddress.ip_address(host.strip("[]"))
            return True
        except ValueError:
            return False

    @staticmethod
    def _has_mixed_scripts(host: str) -> bool:
        """Смешение алфавитов внутри одной метки хоста."""
        return any(mixed_scripts(label) for label in host.split("."))

    @staticmethod
    def _is_non_standard_port(port: Optional[int], scheme: str,
                              malformed: bool) -> bool:
        """
        True, если указан нестандартный порт.

        Стандартные — только 80 и 443. 8080 на «банковском» сайте аномалия.
        """
        if malformed:
            return True
        if port is None:
            return False
        expected = 443 if scheme == "https" else 80
        return port != expected and port not in _STANDARD_PORTS

    @staticmethod
    def _is_suspicious_tld(suffix: str) -> bool:
        """Проверяем последнюю метку суффикса (для co.uk это 'uk')."""
        if not suffix:
            return False
        return suffix.split(".")[-1] in _SUSPICIOUS_TLDS

    @staticmethod
    def _is_abused_tld(suffix: str) -> bool:
        """Дешёвая коммерческая зона — слабый сигнал, не приговор."""
        if not suffix:
            return False
        return suffix.split(".")[-1] in _ABUSED_TLDS

    @staticmethod
    def _find_keywords(path_and_query: str, host: str,
                       is_trusted: bool) -> list[str]:
        """
        Ищет слова-маркеры в пути и в хосте.

        Результат сортируется: порядок обхода frozenset зависит от
        хеш-сида процесса, и без sorted() ответ API недетерминирован.
        """
        if is_trusted:
            return []
        haystack = f"{path_and_query} {host}"
        found = {m.group(1).lower() for m in _KEYWORD_RE.finditer(haystack)}
        return sorted(found)

    @staticmethod
    def _match_brand(host: str, decoded_host: str, sld: str,
                     registered_domain: str, subdomains: list[str],
                     suffix: str = "") -> Optional[BrandMatch]:
        """
        Детект имперсонации бренда — три независимых техники.

        Принцип, которого не было в первой версии: прежде чем
        обвинять домен в имперсонации, проверяем, не принадлежит ли
        он самому бренду.  Без этого googleapis.com, microsoftonline.com
        и amazonaws.com получали +40 баллов как «фишинг».

        1. HOMOGRAPH — визуально совпадает с брендом, но написан
           другим алфавитом либо через punycode.  `аpple.com` (первая
           буква кириллическая) после сворачивания гомоглифов даёт
           ровно `apple`.  Самая опасная категория: отличить на глаз
           невозможно в принципе.

        2. TYPOSQUAT — «почти бренд»: расстояние Левенштейна 1–2 от
           имени бренда после сворачивания leet-символов.
           `paypa1` → `paypal`, `gogle` → 1, `arnazon` → 2.

        3. IMPERSONATION — имя бренда встречается как отдельная метка
           или подстрока в ЧУЖОМ регистрируемом домене:
           `paypal.com.evil.ru`, `secure-paypal.xyz`.
        """
        if not sld:
            return None

        # Домен принадлежит бренду — это не имперсонация.
        for domains in BRAND_DOMAINS.values():
            if registered_domain in domains:
                return None

        folded_host = fold_homoglyphs(decoded_host or host)
        canon_sld = canonical(sld)
        # Для гомоглифов сравниваем БЕЗ leet-свёртки, иначе
        # «bank1» и «bankl» смешаются с настоящими совпадениями.
        homoglyph_sld = "".join(
            ch for ch in fold_homoglyphs(decode_punycode(sld)) if ch.isalnum()
        )

        was_obfuscated = has_non_ascii(host) or "xn--" in host

        zone_is_cheap = (LexicalAnalyzer._is_suspicious_tld(suffix)
                         or LexicalAnalyzer._is_abused_tld(suffix))

        for brand, owned in BRAND_DOMAINS.items():
            # Имя домена — РОВНО бренд, и зона приличная: это почти
            # наверняка сам бренд в другой зоне (`github.blog`,
            # `yandex.by`, `alfabank.by`, `ozon.travel`). Полного списка
            # доменов Google не существует, дописывать их в словарь
            # бесполезно — а обвинять компанию в подделке самой себя
            # мы не вправе: 45 баллов и «ПОДОЗРИТЕЛЬНО» честным сайтам.
            #
            # `paypal.tk` выглядит так же, но зона бесплатная, и это уже
            # приём захватчика — там оговорка не действует.
            # Сравниваем ИСХОДНОЕ имя, а не свёрнутое: `paypa1` после
            # свёртки leet-символов тоже даёт «paypal», и по свёрнутому
            # оговорка накрыла бы настоящие опечаточные домены.
            if sld == brand and not zone_is_cheap:
                continue

            # Гомоглиф: после свёртки вышел бренд, а хост был не-ASCII.
            if was_obfuscated and homoglyph_sld == brand:
                return BrandMatch(
                    brand=brand,
                    kind="homograph",
                    evidence=f"{decoded_host or host} → {brand}",
                )

            # 2. Опечаточный домен.
            #    Для коротких брендов только точное совпадение: иначе
            #    «ozone.com» ловится как опечатка «ozon».
            if len(brand) >= 4:
                max_distance = 0 if len(brand) <= 4 else (1 if len(brand) <= 6 else 2)
                distance = levenshtein(canon_sld, brand, max_distance=max_distance)
                if distance <= max_distance:
                    kind = "typosquat" if distance > 0 or canon_sld != sld else "impersonation"
                    return BrandMatch(
                        brand=brand,
                        kind=kind,
                        evidence=f"{sld} ≈ {brand} (расстояние {distance})",
                    )

            # 3. Бренд как отдельная метка поддомена.
            if brand in subdomains:
                return BrandMatch(
                    brand=brand,
                    kind="impersonation",
                    evidence=f"поддомен «{brand}» на домене {registered_domain}",
                )

            # 4. Подстрока — только для длинных имён: «vtb» даёт шум.
            if len(brand) >= MIN_SUBSTRING_BRAND_LEN:
                if brand in canon_sld or brand in folded_host:
                    return BrandMatch(
                        brand=brand,
                        kind="impersonation",
                        evidence=f"«{brand}» внутри чужого домена {registered_domain}",
                    )

        return None


# Синглтон — объект без состояния, безопасно шарить между корутинами.
lexical_analyzer = LexicalAnalyzer()
