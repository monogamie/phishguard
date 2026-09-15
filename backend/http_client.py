"""
http_client.py — общий HTTP-клиент приложения.

ЗАЧЕМ
─────
Старый код создавал `httpx.AsyncClient` внутри каждой функции:

    async with httpx.AsyncClient(timeout=...) as client:
        resp = await client.post(...)

На каждый скан это означало новый TCP-хендшейк и новый TLS-хендшейк
к каждому из внешних сервисов.  TLS-хендшейк — это 2 RTT плюс
асимметричная криптография; на дистанции до Google это ~100-200 мс
чистых накладных расходов на запрос, которых можно избежать.

Один переиспользуемый клиент держит пул keep-alive соединений:
второй и последующие запросы к тому же хосту идут по уже открытому
соединению.  На практике это срезает 30-50 % времени скана.

Клиент создаётся в lifespan приложения и закрывается при остановке —
создавать его на уровне модуля нельзя, потому что httpx привязывает
пул к текущему event loop, а на момент импорта модуля цикла ещё нет.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_client: Optional[httpx.AsyncClient] = None

# Общий User-Agent. Представляемся честно: некоторые сервисы
# (в т.ч. abuse.ch) банят анонимные скрипты, но пропускают
# идентифицируемых ботов с контактной информацией.
USER_AGENT = "PhishGuardBot/1.1 (+https://github.com/detectoranalizeai/phishguard)"


async def init_client(timeout: float = 10.0,
                      max_connections: int = 50) -> httpx.AsyncClient:
    """Создаёт общий клиент. Вызывается один раз, из lifespan."""
    global _client
    if _client is not None and not _client.is_closed:
        return _client

    _client = httpx.AsyncClient(
        timeout=httpx.Timeout(timeout, connect=5.0),
        limits=httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=20,
            keepalive_expiry=30.0,
        ),
        headers={"User-Agent": USER_AGENT},
        follow_redirects=False,   # редиректы разворачиваем сами, с проверками
        http2=False,
    )
    logger.info("Shared HTTP client initialised")
    return _client


def get_client() -> httpx.AsyncClient:
    """
    Возвращает общий клиент.

    Если lifespan не отработал (например, в юнит-тесте, который
    импортирует пайплайн напрямую), создаём клиент лениво —
    это безопасно, потому что здесь event loop уже точно есть.
    """
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            timeout=httpx.Timeout(10.0, connect=5.0),
            headers={"User-Agent": USER_AGENT},
            follow_redirects=False,
        )
    return _client


async def close_client() -> None:
    """Закрывает клиент и освобождает сокеты пула."""
    global _client
    if _client is not None and not _client.is_closed:
        await _client.aclose()
        logger.info("Shared HTTP client closed")
    _client = None


__all__ = ["USER_AGENT", "close_client", "get_client", "init_client"]
