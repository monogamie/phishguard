"""Уровень 0: разворачивание сокращённых ссылок до конечного адреса.

Анализировать надо цель, а не обёртку: bit.ly по всем структурным
признакам идеален. Каждый хоп проверяется на SSRF."""

from __future__ import annotations

import logging
import time
from urllib.parse import urljoin, urlsplit

import httpx

from config import settings
from http_client import get_client
from models import RedirectInfo
from net_guard import BlockedTargetError, assert_url_is_safe

logger = logging.getLogger(__name__)

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def _registrable_host(url: str) -> str:
    """
    Регистрируемый домен (eTLD+1) в нижнем регистре.

    Именно домен, а не хост целиком: раньше возвращался полный хост, и
    переход `e1.ru → www.e1.ru` — обычная канонизация, которую делает
    половина интернета — считался сменой домена и давал 20 баллов
    честным сайтам.
    """
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""
    if not host:
        return ""
    from pipeline.lexical_analyzer import _extract
    ext = _extract(host)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix and ext.domain else host


async def _one_hop(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    """
    Делает один запрос и возвращает ответ, не читая тело.

    stream() читает статус и заголовки, тело не качается — иначе
    ссылка на файл в 4 ГБ кладёт процесс по памяти.
    """
    for method in ("HEAD", "GET"):
        try:
            async with client.stream(
                method, url,
                timeout=settings.RESOLVE_HOP_TIMEOUT,
                follow_redirects=False,
            ) as resp:
                # 405/501 — сервер не умеет HEAD, повторяем через GET.
                if method == "HEAD" and resp.status_code in (403, 405, 501):
                    continue
                return resp
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            # Хост недоступен — GET не поможет, а стоит второго
            # таймаута на каждой мёртвой ссылке.
            logger.info("Redirect hop failed (%s %s): %s",
                        method, url[:80], type(exc).__name__)
            return None
        except Exception:                              # noqa: BLE001
            logger.exception("Unexpected error on redirect hop")
            return None
    return None


async def resolve_final_url(url: str) -> RedirectInfo:
    """
    Разворачивает цепочку редиректов до конечного URL.

    Возвращает RedirectInfo. Ошибки не выбрасываются: если развернуть
    не удалось, возвращается исходный URL и заполненное поле error —
    анализ продолжится по тому, что есть.
    """
    from pipeline.lexical_analyzer import _SHORTENER_DOMAINS, _extract

    ext = _extract(url)
    start_domain = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ""
    was_shortener = start_domain in _SHORTENER_DOMAINS

    info = RedirectInfo(
        final_url=url,
        chain=[url],
        was_shortener=was_shortener,
    )

    if not settings.ENABLE_URL_RESOLUTION:
        info.error = "Разворачивание редиректов отключено"
        return info

    client = get_client()
    current = url
    seen = {url}
    deadline = time.monotonic() + settings.RESOLVE_TOTAL_TIMEOUT

    for hop in range(settings.MAX_REDIRECTS):
        if time.monotonic() > deadline:
            info.error = "Превышен общий лимит времени на разворачивание"
            break

        # SSRF-проверка на КАЖДОМ хопе: проверять только первый
        # бесполезно, сайт ответит Location: http://127.0.0.1/.
        try:
            await assert_url_is_safe(
                current,
                enabled=settings.BLOCK_PRIVATE_ADDRESSES,
                dns_timeout=settings.DNS_TIMEOUT,
            )
        except BlockedTargetError as exc:
            logger.warning("Blocked unsafe redirect target: %s", exc)
            info.error = f"Небезопасный адрес назначения: {exc}"
            break

        resp = await _one_hop(client, current)
        if resp is None:
            if hop == 0:
                info.error = "Сайт не отвечает"
            break

        if resp.status_code not in REDIRECT_STATUSES:
            info.resolved = True
            break

        location = resp.headers.get("location")
        if not location:
            info.resolved = True
            break

        # urljoin: обрабатывает и //evil.com/x, и /x, и x.
        next_url = urljoin(current, location.strip())

        try:
            scheme = urlsplit(next_url).scheme.lower()
        except ValueError:
            info.error = "Некорректный адрес в заголовке Location"
            break

        if scheme not in ("http", "https"):
            # Редирект на intent://, market://, javascript: и т.п. —
            # дальше не идём, но факт фиксируем.
            info.error = f"Редирект на неподдерживаемую схему: {scheme}"
            info.final_url = next_url
            info.chain.append(next_url)
            break

        if next_url in seen:
            info.error = "Обнаружен цикл редиректов"
            break

        seen.add(next_url)
        info.chain.append(next_url)
        current = next_url
    else:
        info.error = f"Превышен лимит в {settings.MAX_REDIRECTS} редиректов"

    # Конечный URL — всегда последний элемент цепочки: даже если обход
    # прервался на середине, анализировать надо самый глубокий адрес,
    # до которого мы дошли.
    info.final_url = info.chain[-1] if info.chain else url
    info.hops = max(0, len(info.chain) - 1)
    info.changed_domain = (
        _registrable_host(info.chain[0]) != _registrable_host(info.chain[-1])
    )

    if info.hops:
        logger.info("Resolved %s -> %s (%d hops)", url, info.final_url, info.hops)

    return info


__all__ = ["resolve_final_url"]
