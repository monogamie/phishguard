"""TTL-кеш в памяти с LRU-вытеснением и дедупликацией одновременных
одинаковых запросов (single-flight)."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from typing import Any, Awaitable, Callable, Generic, Optional, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class TTLCache(Generic[T]):
    """LRU-кеш с TTL. max_size обязателен: без него публичный
    эндпоинт течёт памятью на каждый уникальный URL."""

    def __init__(self, ttl_seconds: float, max_size: int = 4096) -> None:
        self._ttl = ttl_seconds
        self._max_size = max_size
        self._data: OrderedDict[str, tuple[float, T]] = OrderedDict()
        self._lock = asyncio.Lock()
        # Незавершённые запросы — для дедупликации (см. single_flight).
        self._inflight: dict[str, asyncio.Future[T]] = {}
        self.hits = 0
        self.misses = 0

    async def get(self, key: str) -> Optional[T]:
        async with self._lock:
            entry = self._data.get(key)
            if entry is None:
                self.misses += 1
                return None
            expires_at, value = entry
            if time.monotonic() > expires_at:
                del self._data[key]
                self.misses += 1
                return None
            # Обновляем позицию — это и делает кеш LRU.
            self._data.move_to_end(key)
            self.hits += 1
            return value

    async def set(self, key: str, value: T, ttl: Optional[float] = None) -> None:
        async with self._lock:
            self._data[key] = (time.monotonic() + (ttl or self._ttl), value)
            self._data.move_to_end(key)
            while len(self._data) > self._max_size:
                self._data.popitem(last=False)   # выкидываем самый старый

    async def single_flight(
        self,
        key: str,
        factory: Callable[[], Awaitable[T]],
        ttl: Optional[float] = None,
    ) -> T:
        """Кеш + дедупликация: 100 одновременных сканов одного домена
        дают один запрос наружу, а не сто (cache stampede)."""
        cached = await self.get(key)
        if cached is not None:
            return cached

        async with self._lock:
            existing = self._inflight.get(key)
            if existing is None:
                future: asyncio.Future[T] = asyncio.get_running_loop().create_future()
                self._inflight[key] = future
                leader = True
            else:
                future, leader = existing, False

        if not leader:
            # Ждём результат лидера. shield не нужен: если наша
            # корутина отменена, лидер продолжит работу сам.
            return await asyncio.shield(future)

        try:
            value = await factory()
        except BaseException as exc:
            async with self._lock:
                self._inflight.pop(key, None)
            if not future.done():
                future.set_exception(exc)
            # Забираем исключение из future, чтобы asyncio не ругался
            # на "Future exception was never retrieved", если ждущих нет.
            future.exception()
            raise

        await self.set(key, value, ttl=ttl)
        async with self._lock:
            self._inflight.pop(key, None)
        if not future.done():
            future.set_result(value)
        return value

    async def clear(self) -> None:
        async with self._lock:
            self._data.clear()

    def stats(self) -> dict[str, Any]:
        total = self.hits + self.misses
        return {
            "size": len(self._data),
            "max_size": self._max_size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(self.hits / total, 3) if total else 0.0,
        }


__all__ = ["TTLCache"]
