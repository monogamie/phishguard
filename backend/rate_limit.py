"""Ограничение частоты запросов (скользящее окно).

/scan делает до пяти исходящих запросов на вызов, поэтому без лимита
сервис сжигает чужие квоты и работает усилителем трафика."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict, deque

from fastapi import Request
from fastapi.responses import JSONResponse

from config import settings

logger = logging.getLogger(__name__)


class SlidingWindowRateLimiter:
    """Ограничитель частоты со скользящим окном и вытеснением по LRU."""

    def __init__(self, limit: int, window_seconds: float,
                 max_clients: int = 10_000) -> None:
        self.limit = limit
        self.window = window_seconds
        self.max_clients = max_clients
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = asyncio.Lock()

    async def check(self, client_id: str) -> tuple[bool, int, float]:
        """
        Возвращает (разрешено, осталось_запросов, секунд_до_сброса).
        """
        now = time.monotonic()
        async with self._lock:
            timestamps = self._hits.get(client_id)
            if timestamps is None:
                timestamps = deque()
                self._hits[client_id] = timestamps

            # Выбрасываем всё, что вышло за окно.
            cutoff = now - self.window
            while timestamps and timestamps[0] < cutoff:
                timestamps.popleft()

            self._hits.move_to_end(client_id)

            # Ограничиваем словарь, иначе он растёт на каждый новый IP.
            while len(self._hits) > self.max_clients:
                self._hits.popitem(last=False)

            if len(timestamps) >= self.limit:
                retry_after = self.window - (now - timestamps[0])
                return False, 0, max(retry_after, 0.0)

            timestamps.append(now)
            return True, self.limit - len(timestamps), self.window


limiter = SlidingWindowRateLimiter(
    limit=settings.RATE_LIMIT_REQUESTS,
    window_seconds=settings.RATE_LIMIT_WINDOW,
)


def client_identifier(request: Request) -> str:
    """Определяет клиента для учёта лимита."""
    if settings.TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # Берём адрес СПРАВА, а не слева. X-Forwarded-For прокси
            # дописывают в конец, поэтому левые значения подставляет сам
            # клиент: с первым элементом лимит обходится одной строкой
            # `curl -H "X-Forwarded-For: 1.2.3.$RANDOM"`.
            # TRUSTED_PROXY_HOPS — сколько прокси стоит перед нами.
            chain = [part.strip() for part in forwarded.split(",") if part.strip()]
            if chain:
                index = min(settings.TRUSTED_PROXY_HOPS, len(chain))
                return chain[-index]
        # X-Real-IP НЕ читаем. Его прокси перезаписывает, а вот клиент
        # может прислать свой — и, не отправив X-Forwarded-For, обойти
        # лимит той же строкой, от которой мы закрылись выше. Когда
        # цепочки нет, честнее взять адрес того, кто реально подключился.
    return request.client.host if request.client else "unknown"


async def rate_limit_middleware(request: Request, call_next):
    """Лимит только на /scan и /batch: мониторинг не должен ловить 429."""
    if not settings.RATE_LIMIT_ENABLED or request.method == "OPTIONS":
        return await call_next(request)

    if not request.url.path.startswith(("/scan", "/batch")):
        return await call_next(request)

    client_id = client_identifier(request)
    allowed, remaining, retry_after = await limiter.check(client_id)

    if not allowed:
        logger.info("Rate limit exceeded for %s", client_id)
        return JSONResponse(
            status_code=429,
            content={
                "detail": (
                    f"Слишком много запросов. Лимит — "
                    f"{settings.RATE_LIMIT_REQUESTS} запросов за "
                    f"{settings.RATE_LIMIT_WINDOW} с. "
                    f"Повторите через {int(retry_after) + 1} с."
                ),
                "code": "rate_limited",
            },
            headers={
                "Retry-After": str(int(retry_after) + 1),
                "X-RateLimit-Limit": str(settings.RATE_LIMIT_REQUESTS),
                "X-RateLimit-Remaining": "0",
            },
        )

    response = await call_next(request)
    response.headers["X-RateLimit-Limit"] = str(settings.RATE_LIMIT_REQUESTS)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    return response


__all__ = ["SlidingWindowRateLimiter", "client_identifier",
           "limiter", "rate_limit_middleware"]
