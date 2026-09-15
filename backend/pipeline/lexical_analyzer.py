"""
pipeline/lexical_analyzer.py — Уровень 3: лексический и структурный анализ.

Извлекает ~20 признаков из самой строки URL, без единого сетевого
запроса.  Это самый быстрый и самый надёжный этап пайплайна: он
работает всегда, даже когда Google, RDAP и abuse.ch недоступны.

ЧТО БЫЛО ИСПРАВЛЕНО
───────────────────
1. ПАДЕНИЕ НА `parsed.port`.
   urlsplit ленив: он не разбирает порт при парсинге, а бросает
   ValueError в момент обращения к `.port`.  Старый код оборачивал
   в try только сам urlparse, поэтому `https://a.com:99999/` или
   `https://a.com:abc/` роняли весь запрос в HTTP 500.

2. МЁРТВАЯ ПРОВЕРКА `has_encoded_host`.
   Старый код сначала делал `unquote(url)`, а потом искал `%XX`
   в хосте распарсенного (уже раскодированного!) URL.  Найти там
   что-то было невозможно по построению — признак всегда был False.
   Теперь процентное кодирование ищется в СЫРОЙ строке до декода.

3. НЕДЕТЕРМИНИРОВАННЫЙ ОТВЕТ API.
   Ключевые слова искались обходом frozenset, а порядок обхода
   множества строк зависит от PYTHONHASHSEED.  После перезапуска
   сервера один и тот же URL возвращал слова в другом порядке, а
   в reasons попадали первые 5 из них — то есть РАЗНЫЕ. Теперь sorted().

4. ЛОЖНЫЕ СРАБАТЫВАНИЯ НА КЛЮЧЕВЫХ СЛОВАХ.
   Докстринга обещала «word-boundary-aware», а код делал
   `kw in text`.  «account» находился в «accountant», «free» —
   в «freelancer».  Теперь границы слов проверяются регуляркой.

5. ЛОЖНЫЕ СРАБАТЫВАНИЯ НА БРЕНДАХ.
   `brand in sld` помечал googleapis.com, googleusercontent.com и
   microsoftonline.com как имперсонацию (+40 баллов каждому).
   Теперь бренд сверяется со списком ЕГО ЖЕ легитимных доменов.

6. БЛОКИРУЮЩИЙ СЕТЕВОЙ ВЫЗОВ В ASYNC-ОБРАБОТЧИКЕ.
   tldextract по умолчанию скачивает свежий Public Suffix List
   по HTTP при первом вызове — синхронно, прямо внутри async-хендлера,
   блокируя весь event loop.  Инициализируем его снимком из пакета.

ЧТО ДОБАВЛЕНО
─────────────
  • декодирование punycode и поиск гомоглифов (аpple.com → apple.com);
  • детект опечаточных доменов через расстояние Левенштейна
    (gogle.com, paypa1.com, arnazon.com);
  • детект смешения алфавитов в одной метке;
  • корректная валидация IPv4 (раньше 999.999.999.999 считался IP)
    и поддержка IPv6-литералов;
  • признак http:// вместо https://;
  • признак «домен — известный сокращатель ссылок».
"""

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
    fold_homoglyphs,
    has_non_ascii,
    levenshtein,
    mixed_scripts,
)

logger = logging.getLogger(__name__)

# ── Public Suffix List без сетевых обращений ─────────────────────
# suffix_list_urls=() заставляет tldextract использовать снимок PSL,
# вшитый в пакет, вместо HTTP-запроса к publicsuffix.org.
# Без этого первый же скан делает блокирующий сетевой вызов внутри
# event loop (и падает, если у контейнера нет исходящего доступа).
_extract = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)

# ── Константы ────────────────────────────────────────────────────

# Слова-маркеры фишинга.  Имена брендов отсюда убраны: бренды
# обрабатывает отдельный, гораздо более точный детектор.
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

# Бесплатные и массово злоупотребляемые доменные зоны.
_SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "xyz", "tk", "ml", "ga", "cf", "gq", "top", "click", "loan",
    "work", "date", "win", "stream", "racing", "review", "party",
    "download", "bid", "faith", "icu", "buzz", "cyou", "monster",
    "cfd", "sbs", "bar", "hair", "skin", "boats", "wang", "men",
    "rest", "quest", "beauty", "mom", "lol", "autos", "makeup",
    "zip", "mov", "kim", "country", "science", "gdn", "accountant",
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

    `(?<![a-z])` и `(?![a-z])` — это границы слова, но «мягкие»:
    буквы вокруг запрещены, а цифры и разделители (-, _, /, .) —
    разрешены.  Поэтому `/secure-login/`, `login2.php` и `/signin`
    находятся, а `accountant` и `freelancer` — нет.

    Одна скомпилированная регулярка вместо 50 проверок `in` —
    это ещё и примерно в 10 раз быстрее на длинных URL.
    """
    alternation = "|".join(sorted(map(re.escape, keywords), key=len, reverse=True))
    return re.compile(rf"(?<![a-z])({alternation})(?![a-z])", re.IGNORECASE)


_KEYWORD_RE = _keyword_pattern(_TRIGGER_KEYWORDS)


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

        # ВАЖЕН ПОРЯДОК: процентное кодирование в хосте ищем ДО unquote,
        # иначе искать уже нечего (это и был баг «мёртвой проверки»).
        raw_netloc = self._safe_netloc(raw)
        has_encoded_host = bool(_PERCENT_ENCODED_RE.search(raw_netloc.split("@")[-1]))

        # Теперь можно декодировать, чтобы увидеть спрятанные пути.
        try:
            decoded_url = unquote(raw)
        except Exception:
            decoded_url = raw

        try:
            parsed = urlsplit(decoded_url)
        except ValueError:
            logger.warning("urlsplit failed for %r", raw[:120])
            return LexicalFeatures(url_length=len(raw))

        scheme = (parsed.scheme or "https").lower()

        # .hostname и .port ленивы и бросают ValueError — ловим ОТДЕЛЬНО.
        try:
            host = (parsed.hostname or "").lower()
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

        path_and_query = parsed.path + (f"?{parsed.query}" if parsed.query else "")

        ext = _extract(host if host else decoded_url)
        sld = ext.domain.lower()
        suffix = ext.suffix.lower()
        registered_domain = f"{sld}.{suffix}" if sld and suffix else (sld or host)
        subdomains = [s for s in ext.subdomain.lower().split(".") if s]

        # Хост в «человеческом» виде: то, что видит жертва в браузере.
        decoded_host = decode_punycode(host) if "xn--" in host else host

        is_trusted = registered_domain in TRUSTED_DOMAINS

        features = LexicalFeatures(
            scheme                = scheme,
            host                  = host,
            registered_domain     = registered_domain,
            tld                   = suffix,
            decoded_host          = decoded_host if decoded_host != host else None,
            has_ip_address        = self._is_ip_host(host),
            has_at_symbol         = "@" in netloc,
            has_punycode          = any(l.startswith("xn--") for l in host.split(".")),
            has_non_ascii_host    = has_non_ascii(host),
            has_mixed_scripts     = self._has_mixed_scripts(decoded_host),
            has_non_standard_port = self._is_non_standard_port(port, scheme, port_malformed),
            has_encoded_host      = has_encoded_host,
            has_redirect_params   = bool(_REDIRECT_PARAMS_RE.search(raw)),
            has_digits_in_domain  = bool(re.search(r"\d", sld)) and not is_trusted,
            is_insecure_scheme    = scheme == "http",
            is_shortener          = registered_domain in _SHORTENER_DOMAINS,
            subdomain_count       = len([s for s in subdomains if s != "www"]),
            url_length            = len(raw),
            domain_length         = len(sld),
            hyphen_count          = host.count("-"),
            trigger_keywords      = self._find_keywords(path_and_query, host, is_trusted),
            suspicious_tld        = self._is_suspicious_tld(suffix),
            is_trusted_domain     = is_trusted,
            brand_match           = self._match_brand(
                                        host, decoded_host, sld,
                                        registered_domain, subdomains),
        )

        logger.debug("Lexical features for %s: %s", host, features.model_dump())
        return features

    # ── Отдельные извлекатели признаков ──────────────────────────

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

        Старая регулярка `^(\\d{1,3}\\.){3}\\d{1,3}$` принимала
        999.999.999.999 (октеты не проверялись) и не знала про IPv6
        в квадратных скобках — http://[::1]/ проходил мимо детектора.
        `ipaddress` проверяет и то, и другое корректно.
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

        В старой версии 8080 считался стандартным (он был в белом
        списке), хотя конфиг прямо называл его подозрительным —
        противоречие между config.py и кодом.  Стандартными считаем
        только 80 и 443; 8080 на «банковском» сайте — это аномалия.
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
    def _find_keywords(path_and_query: str, host: str,
                       is_trusted: bool) -> list[str]:
        """
        Ищет слова-маркеры в пути и в хосте.

        Результат ОТСОРТИРОВАН — иначе ответ API недетерминирован
        (порядок обхода frozenset зависит от хеш-сида процесса).

        Для доверенных доменов не ищем вовсе: `google.com/login` и
        `sberbank.ru/payment` — это нормальные страницы входа
        и оплаты, а не фишинг.
        """
        if is_trusted:
            return []
        haystack = f"{path_and_query} {host}"
        found = {m.group(1).lower() for m in _KEYWORD_RE.finditer(haystack)}
        return sorted(found)

    @staticmethod
    def _match_brand(host: str, decoded_host: str, sld: str,
                     registered_domain: str,
                     subdomains: list[str]) -> Optional[BrandMatch]:
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
           `paypa1` → `paypal` (0 после leet), `gogle` → 1, `arnazon` → 2.
           Порог зависит от длины: для коротких имён допускаем 1,
           иначе `visa` совпало бы с `vista`, `viva`, `vias`.

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

        for brand, owned in BRAND_DOMAINS.items():
            # 1. Гомоглифная атака: после свёртки получился ровно бренд,
            #    но исходный хост содержал не-ASCII или punycode.
            if was_obfuscated and homoglyph_sld == brand:
                return BrandMatch(
                    brand=brand,
                    kind="homograph",
                    evidence=f"{decoded_host or host} → {brand}",
                )

            # 2. Опечаточный домен.
            #    Порог расстояния зависит от длины бренда. Для коротких
            #    имён допускаем только точное совпадение после свёртки:
            #    иначе «ozone.com» ловился бы как опечатка «ozon»,
            #    а «vista» — как «visa».
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

            # 4. Бренд подстрокой в чужом домене. Только для длинных
            #    имён: «vtb» или «visa» подстрокой дают шум.
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
