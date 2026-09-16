"""Уровень 1b: база вредоносных URL URLhaus (abuse.ch).

На сервере, а не в браузере: abuse.ch не отдаёт CORS-заголовки и
требует Auth-Key, который нельзя публиковать в HTML."""

from __future__ import annotations

import logging

import httpx

from cache import TTLCache
from config import settings
from http_client import get_client
from models import ReputationResult

logger = logging.getLogger(__name__)

_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"

_cache: TTLCache[ReputationResult] = TTLCache(
    ttl_seconds=settings.CACHE_TTL_THREAT,
    max_size=settings.CACHE_MAX_SIZE,
)


async def _post(endpoint: str, field: str, value: str) -> dict | None:
    """Один POST к URLhaus. Любая ошибка → None (мягкая деградация)."""
    headers = {"Accept": "application/json"}
    if settings.URLHAUS_AUTH_KEY:
        headers["Auth-Key"] = settings.URLHAUS_AUTH_KEY

    try:
        resp = await get_client().post(
            endpoint,
            data={field: value},
            headers=headers,
            timeout=settings.URLHAUS_TIMEOUT,
        )
    except (httpx.TimeoutException, httpx.TransportError) as exc:
        logger.info("URLhaus transport error: %s", type(exc).__name__)
        return None
    except Exception:                                  # noqa: BLE001
        logger.exception("URLhaus unexpected error")
        return None

    if resp.status_code == 401:
        logger.warning("URLhaus rejected the Auth-Key (401) — "
                       "получите бесплатный ключ на https://auth.abuse.ch/")
        return None
    if resp.status_code != 200:
        logger.info("URLhaus HTTP %s", resp.status_code)
        return None

    try:
        return resp.json()
    except ValueError:
        return None


async def check_urlhaus(url: str, host: str) -> ReputationResult:
    """Проверяет и URL, и хост: ссылка может быть новой, но если хост
    уже раздавал вредоносы — это тот же приговор."""
    if not url:
        return ReputationResult(checked=False, error="empty url")

    async def _lookup() -> ReputationResult:
        url_data = await _post(_URL_ENDPOINT, "url", url)
        host_data = await _post(_HOST_ENDPOINT, "host", host) if host else None

        if url_data is None and host_data is None:
            return ReputationResult(checked=False, error="URLhaus недоступен")

        result = ReputationResult(checked=True)

        if url_data and url_data.get("query_status") == "ok":
            result.url_listed = True
            result.threat = url_data.get("threat") or "malware_download"

        if host_data and host_data.get("query_status") == "ok":
            urls = host_data.get("urls") or []
            # url_count приходит строкой — приводим аккуратно.
            raw_count = host_data.get("url_count") or len(urls)
            try:
                result.host_url_count = int(raw_count)
            except (TypeError, ValueError):
                result.host_url_count = len(urls)
            result.host_listed = result.host_url_count > 0

        return result

    try:
        return await _cache.single_flight(f"{host}|{url}", _lookup)
    except Exception:                                  # noqa: BLE001
        logger.exception("URLhaus lookup failed")
        return ReputationResult(checked=False, error="Ошибка проверки URLhaus")


def cache_stats() -> dict:
    return _cache.stats()


__all__ = ["cache_stats", "check_urlhaus"]
