"""
url_resolver.py — Уровень 0: разворачивание сокращённых и
замаскированных ссылок до реального адреса назначения.

ЗАЧЕМ ЭТОТ УРОВЕНЬ ВООБЩЕ СУЩЕСТВУЕТ
────────────────────────────────────
`https://bit.ly/3xK9pQ` — по всем структурным признакам идеальная
ссылка: короткая, HTTPS, зона .ly, домен зарегистрирован в 2008 году,
ни одного ключевого слова.  Эвристики дадут 0 баллов.
А ведёт она на `http://sber-bonus-2026.top/verify`.

Поэтому анализировать надо ЦЕЛЬ, а не обёртку. Сокращатель —
это и есть основной способ обойти все четыре уровня сразу.

ГЛАВНОЕ ИСПРАВЛЕНИЕ: SSRF
─────────────────────────
Старая версия брала URL от анонимного пользователя и делала по нему
GET без каких-либо проверок адреса назначения. Это полноценный
Server-Side Request Forgery: попросив просканировать
`http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
атакующий заставлял НАШ сервер сходить в сервис метаданных облака.
Подробный разбор — в net_guard.py.

Теперь каждый хоп проверяется через `assert_url_is_safe`: и первый,
и все последующие. Проверять только первый бесполезно — публичный
сайт просто ответит `Location: http://127.0.0.1:6379/`.

ОСТАЛЬНЫЕ ИСПРАВЛЕННЫЕ БАГИ
───────────────────────────
1. НЕВЕРНАЯ СКЛЕЙКА ОТНОСИТЕЛЬНЫХ РЕДИРЕКТОВ.
   Старый код:  if location.startswith("/"): location = scheme://netloc + location
   Протокол-относительный редирект `//evil.com/x` тоже начинается
   со слеша — и превращался в `https://good.com//evil.com/x`.
   То есть цель атаки терялась, а анализировался безобидный домен.
   Относительные пути без слеша (`Location: next.html`) не
   обрабатывались вовсе. Теперь стандартный `urljoin`.

2. СКАЧИВАНИЕ ТЕЛА ОТВЕТА ЦЕЛИКОМ.
   `client.get(url)` тянет весь ответ в память. Ссылка на ISO-образ
   в 4 ГБ — и процесс убит OOM-киллером. Теперь стриминговый запрос,
   который читает только заголовки и обрывает соединение.

3. ОТСУТСТВИЕ ОБЩЕГО ДЕДЛАЙНА.
   10 хопов × 5 с таймаута = до 50 секунд на один скан, при том что
   у фронтенда таймаут был 8 с. Теперь есть общий бюджет времени.

4. ЦИКЛЫ РЕДИРЕКТОВ.
   A → B → A → B … честно тратил все хопы. Теперь цикл детектируется
   и останавливает обход сразу.

ПОЧЕМУ HEAD, А НЕ GET
─────────────────────
HEAD не передаёт тело и потому дешевле. Но часть сокращателей
отвечает на HEAD 405-й ошибкой, поэтому при неудаче делается
стриминговый GET.
"""

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

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def _registrable_host(url: str) -> str:
    """Хост URL в нижнем регистре, без порта. Пустая строка при ошибке."""
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


async def _one_hop(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    """
    Делает один запрос и возвращает ответ, не читая тело.

    `client.stream` открывает соединение, получает статус и заголовки
    и отдаёт управление нам. Выходя из контекстного менеджера, мы
    закрываем соединение, так и не скачав тело, — именно это и нужно
    для разворачивания редиректов.
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
            # Транспортная ошибка означает, что хост недоступен как
            # таковой — повторять тот же запрос методом GET смысла нет,
            # а стоит это второго полного таймаута на каждой мёртвой
            # ссылке. Выходим сразу; GET пробуем только когда сервер
            # ОТВЕТИЛ, но отказался обслуживать HEAD (см. ниже).
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

        # SSRF-проверка на КАЖДОМ хопе, включая самый первый.
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

        if resp.status_code not in _REDIRECT_STATUSES:
            info.resolved = True
            break

        location = resp.headers.get("location")
        if not location:
            info.resolved = True
            break

        # urljoin корректно обрабатывает все три формы Location:
        #   абсолютную      https://evil.com/x
        #   протокол-относ.  //evil.com/x   ← её и ломала старая версия
        #   относительную    /x  и  x
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
