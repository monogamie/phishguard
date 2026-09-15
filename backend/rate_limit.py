"""
rate_limit.py — ограничение частоты запросов (алгоритм «скользящее окно»).

ЗАЧЕМ
─────
/scan — это публичный эндпоинт без авторизации, который на КАЖДЫЙ
вызов делает до пяти исходящих сетевых запросов (разворачивание
редиректов, GSB, URLhaus, RDAP, WHOIS). Без ограничителя:

  • одна машина с `while true; do curl ...; done` за час сжигает
    суточную квоту Google Safe Browsing (10 000 запросов) и
    выключает главный источник сигнала для всех пользователей;
  • сервис превращается в усилитель трафика: один HTTP-запрос к нам
    порождает пять запросов к жертве, то есть в нас можно стрелять
    чужим сайтом;
  • abuse.ch и RDAP-серверы банят по IP за флуд — и банят НАС.

АЛГОРИТМ
────────
Скользящее окно на deque временных меток. Для каждого клиента
храниммоменты его запросов; на новом запросе выкидываем всё
старше окна и сравниваем длину с лимитом.

Почему не «токенное ведро»: скользящее окно не допускает всплеска
в 2× лимита на стыке окон (классическая проблема fixed-window) и при
этом тривиально объясняется. Память — O(лимит) на клиента, при
30 запросах в минуту это ничтожно.

ОПРЕДЕЛЕНИЕ КЛИЕНТА
───────────────────
За балансировщиком (Render, Railway, nginx) request.client.host — это
IP балансировщика, один на всех. Реальный адрес приходит в
X-Forwarded-For. Доверять этому заголовку можно ТОЛЬКО когда мы
действительно стоим за прокси: иначе любой клиент подделает
заголовок и обойдёт лимит. Поэтому поведение управляется флагом
TRUST_PROXY_HEADERS, и берётся ПЕРВЫЙ адрес из списка — тот, что
добавил наш собственный прокси.
"""

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
            # Первый в списке — клиент, остальные — цепочка прокси.
            return forwarded.split(",")[0].strip()
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
    return request.client.host if request.client else "unknown"


async def rate_limit_middleware(request: Request, call_next):
    """
    Middleware, применяющий лимит только к «дорогим» эндпоинтам.

    /health и /docs не ограничиваем: мониторинг не должен получать
    429 и поднимать ложную тревогу.
    """
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
