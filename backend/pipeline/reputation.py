"""
pipeline/reputation.py — Уровень 1b: база вредоносных URL URLhaus (abuse.ch).

ПОЧЕМУ ЭТО ПЕРЕЕХАЛО ИЗ БРАУЗЕРА НА СЕРВЕР
──────────────────────────────────────────
В первой версии URLhaus дёргался прямо из index.html:

    fetch('https://urlhaus-api.abuse.ch/v1/url/', {method:'POST', ...})

Это не работало и не могло работать по трём причинам:

  1. CORS. Браузер шлёт preflight OPTIONS на кросс-доменный POST с
     Content-Type. abuse.ch не отдаёт Access-Control-Allow-Origin для
     произвольных сайтов, поэтому ответ блокируется браузером. Ошибка
     ловилась пустым `catch{}` — и движок молча считался «недоступным».
  2. Авторизация. С 2024 года abuse.ch требует заголовок Auth-Key даже
     на бесплатном тарифе (регистрация на https://auth.abuse.ch/).
     Положить ключ в HTML — значит опубликовать его.
  3. Приватность. Запрос из браузера пользователя раскрывает
     abuse.ch его IP и проверяемый URL напрямую.

На сервере всех трёх проблем нет: CORS браузерная политика, ключ
лежит в переменной окружения, а наружу идёт IP сервера.

ЧТО ДАЁТ URLhaus
────────────────
Это база именно РАЗДАЮЩИХ вредоносное ПО URL, пополняемая
исследователями почти в реальном времени. Она дополняет GSB:
Google ориентирован на массовый веб и фишинг, URLhaus — на
malware-дистрибуцию, C2-панели и загрузчики. Пересечение между
базами далеко не полное, поэтому имеет смысл спрашивать обе.
"""

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
    """
    Проверяет URL и его хост по базе URLhaus.

    Две проверки нужны обе: конкретная ссылка может быть новой,
    но если ХОСТ уже раздавал десяток вредоносов — это тот же
    приговор. Ключ кеша включает и URL, и хост.
    """
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
