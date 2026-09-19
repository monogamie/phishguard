"""Уровень 5: анализ содержимого страницы.

Закрывает главный пробел остальных уровней: они читают только адрес.
В истории с угоном Telegram половина улик была на странице — кнопка
«войти через Telegram», форма, фотографии, — а в адресе стояло
безобидное `/deti/9`.

Разбор ведётся штатным html.parser: сторонний парсер здесь не нужен,
а лишняя зависимость в сервисе безопасности — лишняя поверхность атаки.
"""

from __future__ import annotations

import logging
import re
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlsplit

import httpx

from cache import TTLCache, cache_key
from config import settings
from http_client import get_client
from models import PageResult
from net_guard import BlockedTargetError, assert_url_is_safe
from url_resolver import REDIRECT_STATUSES

logger = logging.getLogger(__name__)

_cache: TTLCache[PageResult] = TTLCache(
    ttl_seconds=settings.CACHE_TTL_PAGE,
    max_size=settings.CACHE_MAX_SIZE,
)

# Провайдеры входа, которыми пользуются мошеннические страницы.
# Легитимный сайт тоже может предлагать вход через VK, поэтому вес у
# признака средний: опасным он становится в связке с остальными.
_MESSENGER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("telegram", re.compile(
        r"(?i)(telegram[\s_-]*(login|widget|auth|oauth)"
        r"|oauth\.telegram\.org"
        r"|(войти|вход|авторизация)\s+через\s+telegram"
        r"|(войти|вход)\s+через\s+телеграм)")),
    ("vk", re.compile(
        r"(?i)(vk[\s_-]*(login|oauth)\b"
        r"|oauth\.vk\.com"
        r"|(войти|вход)\s+через\s+(вконтакте|vk))")),
    ("whatsapp", re.compile(
        r"(?i)((войти|вход)\s+через\s+whatsapp|whatsapp[\s_-]*auth)")),
    ("gosuslugi", re.compile(
        r"(?i)((войти|вход)\s+через\s+госуслуги|esia[\s_-]*auth)")),
)

# Упоминание бренда в тексте страницы. Ключ — как это пишут люди,
# значение — наш внутренний идентификатор бренда из data/brands.py.
_BRAND_TEXT: dict[str, str] = {
    "сбербанк": "sberbank", "сбер": "sberbank", "sberbank": "sberbank",
    "тинькофф": "tinkoff", "tinkoff": "tinkoff", "т-банк": "tinkoff",
    "альфа-банк": "alfabank", "альфабанк": "alfabank", "alfabank": "alfabank",
    "втб": "vtb", "vtb": "vtb",
    "госуслуги": "gosuslugi", "gosuslugi": "gosuslugi",
    "райффайзен": "raiffeisen", "raiffeisen": "raiffeisen",
    "газпром": "gazprom", "gazprom": "gazprom",
    "wildberries": "wildberries", "вайлдберриз": "wildberries",
    "ozon": "ozon", "озон": "ozon",
    "яндекс": "yandex", "yandex": "yandex",
    "telegram": "telegram", "телеграм": "telegram",
    "вконтакте": "vkontakte", "vkontakte": "vkontakte",
    "авито": "avito", "avito": "avito",
    "почта россии": "pochta", "почта-россии": "pochta", "pochta": "pochta",
    "мвд": "mvd", "мосэнергосбыт": "mosenergo",
    "втб": "vtb", "райффайзен": "raiffeisen",
    "paypal": "paypal", "microsoft": "microsoft", "apple": "apple",
    "amazon": "amazon", "netflix": "netflix", "binance": "binance",
}

# По одному выражению на бренд, альтернативы — от длинной к короткой.
# Длинная первой обязательна: иначе «сбербанк» посчитается дважды —
# сам и как вложенное «сбер», и порог упоминаний для кириллицы
# окажется вдвое ниже, чем для латиницы. Границы слова не дают
# «сбережениям» стать Сбербанком, а «озонотерапии» — Ozon.
_WORD_CHAR = r"0-9A-Za-z\u0400-\u04ff"


def _brand_patterns() -> dict[str, re.Pattern[str]]:
    by_brand: dict[str, list[str]] = {}
    for needle, brand in _BRAND_TEXT.items():
        by_brand.setdefault(brand, []).append(needle)
    return {
        brand: re.compile(
            f"(?<![{_WORD_CHAR}])(?:"
            + "|".join(re.escape(n) for n in sorted(needles, key=len, reverse=True))
            + f")(?![{_WORD_CHAR}])",
            re.IGNORECASE)
        for brand, needles in by_brand.items()
    }


_BRAND_TEXT_RE = _brand_patterns()

# Типы, которые точно не HTML. Всё остальное пробуем разобрать:
# требовать text/html нельзя, поддельные страницы часто отдаются
# с типом application/octet-stream или вообще без него.
_BINARY_TYPES: tuple[str, ...] = (
    "image/", "video/", "audio/", "font/",
    "application/pdf", "application/zip", "application/x-", "application/gzip",
    "application/vnd.", "application/msword", "application/json",
)

# Сколько раз бренд должен встретиться, чтобы это считалось заявкой
# «мы и есть этот бренд», а не случайным упоминанием в тексте.
_BRAND_MENTION_THRESHOLD = 3


class _PageParser(HTMLParser):
    """Собирает только нужные признаки. Ничего не исполняет."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self.form_actions: list[str] = []
        self.has_password = False
        self.hidden_inputs = 0
        self.form_count = 0
        self._in_title = False
        self._skip_depth = 0

    def handle_starttag(self, tag: str,
                        attrs: list[tuple[str, Optional[str]]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag in ("script", "style"):
            # Содержимое скриптов в текст не берём: там служебные слова,
            # дающие ложные совпадения с брендами.
            self._skip_depth += 1
        elif tag == "input":
            itype = attr.get("type", "text").lower()
            if itype == "password":
                self.has_password = True
            elif itype == "hidden":
                self.hidden_inputs += 1
        elif tag == "form":
            self.form_count += 1
            if attr.get("action"):
                self.form_actions.append(attr["action"])
        elif tag in ("a", "button", "div", "span"):
            # Текст кнопки входа часто лежит в атрибутах, а не внутри тега.
            for key in ("aria-label", "title", "alt", "data-provider"):
                if attr.get(key):
                    self.text_parts.append(attr[key])

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag in ("script", "style") and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._in_title:
            self.title_parts.append(data)
        stripped = data.strip()
        if stripped:
            self.text_parts.append(stripped)

    # HTMLParser по умолчанию падает на битой разметке в строгом режиме;
    # мошеннические страницы битые часто, поэтому ошибки глотаем.
    def error(self, message: str) -> None:  # pragma: no cover
        pass


def _registrable(host: str) -> str:
    from pipeline.lexical_analyzer import _extract
    ext = _extract(host)
    return f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else host.lower()


def _cross_domain_form(page_url: str, actions: list[str]) -> Optional[str]:
    """
    Ищет форму, которая отправляет введённое на другой домен.

    Нормальный сайт принимает свои формы сам. Отправка на сторону —
    это либо сторонняя аналитика, либо сбор данных в чужие руки.
    """
    own = _registrable(urlsplit(page_url).hostname or "")
    for action in actions:
        # urljoin внутри try: он сам зовёт urlsplit и бросает ValueError
        # на битом action вида "//[" — одна такая форма на странице
        # иначе валит весь уровень.
        try:
            target = urljoin(page_url, action.strip())
            host = urlsplit(target).hostname
        except ValueError:
            continue
        if not host:
            continue
        other = _registrable(host)
        if other and other != own:
            return target[:200]
    return None


def _brands_in_text(text: str) -> list[str]:
    """
    Бренды, заявленные в тексте страницы.

    Порог на число упоминаний отсекает случайные: новость со словом
    «Сбербанк» это не поддельный сайт Сбербанка, а вот страница, где
    он написан десять раз рядом с формой входа, — уже да.
    """
    return sorted(brand for brand, pattern in _BRAND_TEXT_RE.items()
                  if len(pattern.findall(text)) >= _BRAND_MENTION_THRESHOLD)


async def analyze_page(url: str) -> PageResult:
    """
    Скачивает начало страницы и извлекает признаки.

    Ошибки не выбрасываются: недоступная страница — это нормальный
    исход, скан продолжается по остальным уровням.
    """
    if not settings.PAGE_ENABLED:
        return PageResult(checked=False, skipped=True,
                          error="Уровень страницы выключен")

    async def _fetch() -> PageResult:
        # Редиректы разворачиваем сами. С follow_redirects=True httpx идёт
        # по Location без наших проверок, и мошеннический сервер уводит
        # запрос на внутренний адрес хостинга — это SSRF в обход net_guard.
        current = url
        seen = {url}
        status: Optional[int] = None
        raw = b""
        encoding = "utf-8"

        for _ in range(settings.MAX_REDIRECTS + 1):
            try:
                await assert_url_is_safe(
                    current, enabled=settings.BLOCK_PRIVATE_ADDRESSES,
                    dns_timeout=settings.DNS_TIMEOUT,
                )
            except BlockedTargetError as exc:
                return PageResult(checked=False, status_code=status, error=str(exc))

            try:
                async with get_client().stream(
                    "GET", current,
                    timeout=settings.PAGE_TIMEOUT,
                    follow_redirects=False,
                    headers={"Accept": "text/html,application/xhtml+xml"},
                ) as resp:
                    status = resp.status_code

                    if status in REDIRECT_STATUSES:
                        location = resp.headers.get("location")
                        if not location:
                            return PageResult(checked=False, status_code=status,
                                              error="Редирект без адреса")
                        try:
                            target = urljoin(current, location.strip())
                            scheme = urlsplit(target).scheme.lower()
                        except ValueError:
                            return PageResult(checked=False, status_code=status,
                                              error="Некорректный адрес редиректа")
                        if scheme not in ("http", "https"):
                            return PageResult(checked=False, status_code=status,
                                              error=f"Редирект на схему {scheme[:12]}")
                        if target in seen:
                            return PageResult(checked=False, status_code=status,
                                              error="Циклический редирект")
                        seen.add(target)
                        current = target
                        continue

                    content_type = resp.headers.get("content-type", "").lower()
                    # Отсекаем только заведомо двоичное. Требовать text/html
                    # нельзя: мошеннические страницы часто отдаются с кривым
                    # или отсутствующим типом, и такую страницу мы потеряем.
                    if any(content_type.startswith(prefix) for prefix in _BINARY_TYPES):
                        return PageResult(checked=False, status_code=status,
                                          error=f"Не страница ({content_type[:40]})")

                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in resp.aiter_bytes():
                        chunks.append(chunk)
                        size += len(chunk)
                        # Читаем только начало: формы и метатеги всегда в
                        # первых килобайтах, а полная загрузка — подарок
                        # тому, кто подсунет ссылку на гигабайтный файл.
                        if size >= settings.PAGE_MAX_BYTES:
                            break
                    raw = b"".join(chunks)[: settings.PAGE_MAX_BYTES]
                    encoding = resp.encoding or "utf-8"
                    break
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                return PageResult(checked=False, status_code=status,
                                  error=f"Страница недоступна: {type(exc).__name__}")
            except Exception:                              # noqa: BLE001
                logger.exception("Page fetch failed for %s", current[:100])
                return PageResult(checked=False, status_code=status,
                                  error="Ошибка загрузки страницы")
        else:
            return PageResult(checked=False, status_code=status,
                              error="Слишком много редиректов")

        try:
            html = raw.decode(encoding, errors="replace")
        except (LookupError, UnicodeDecodeError):
            html = raw.decode("utf-8", errors="replace")

        # Нюхаем содержимое: если разметки нет вообще, разбирать нечего.
        if "<" not in html[:2000]:
            return PageResult(checked=False, status_code=status,
                              bytes_read=len(raw),
                              error="Содержимое не похоже на HTML")

        parser = _PageParser()
        try:
            parser.feed(html)
            parser.close()
        except Exception:                              # noqa: BLE001
            # Битая разметка не должна ронять уровень: разбираем то,
            # что успели прочитать до ошибки.
            logger.info("HTML parse interrupted for %s", current[:80])

        text = " ".join(parser.text_parts)
        messengers = [name for name, pattern in _MESSENGER_PATTERNS
                      if pattern.search(text) or pattern.search(html[:20000])]

        return PageResult(
            checked=True,
            status_code=status,
            final_url=(current if current != url else None),
            title=(" ".join(parser.title_parts).strip() or None),
            has_password_field=parser.has_password,
            messenger_login=messengers,
            cross_domain_form=_cross_domain_form(current, parser.form_actions),
            brands_in_text=_brands_in_text(text),
            hidden_input_count=parser.hidden_inputs,
            form_count=parser.form_count,
            bytes_read=len(raw),
        )

    try:
        return await _cache.single_flight(cache_key(url), _fetch)
    except Exception:                                  # noqa: BLE001
        logger.exception("Page stage failed")
        return PageResult(checked=False, error="Сбой уровня страницы")


def cache_stats() -> dict:
    return _cache.stats()


__all__ = ["analyze_page", "cache_stats"]
