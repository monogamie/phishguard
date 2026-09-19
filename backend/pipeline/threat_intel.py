"""Уровень 1: Google Safe Browsing.

Совпадение здесь — факт, а не эвристика, поэтому вес максимальный.
Ограничение: база узнаёт о новом домене с задержкой в часы."""

from __future__ import annotations

import asyncio
import logging

import httpx

from config import settings
from http_client import get_client
from models import ThreatIntelResult

logger = logging.getLogger(__name__)

_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",             # собственно фишинг
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

_GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Человеческие названия категорий — для интерфейса.
THREAT_TYPE_LABELS = {
    "MALWARE": "вредоносное ПО",
    "SOCIAL_ENGINEERING": "фишинг / социальная инженерия",
    "UNWANTED_SOFTWARE": "нежелательное ПО",
    "POTENTIALLY_HARMFUL_APPLICATION": "потенциально опасное приложение",
}

_MAX_ATTEMPTS = 3


async def check_google_safe_browsing(url: str) -> ThreatIntelResult:
    """Спрашивает Google. Любая ошибка — checked=False: сканер не должен
    отказывать из-за недоступности одного источника."""
    api_key = settings.GOOGLE_SAFE_BROWSING_KEY
    if not api_key:
        logger.debug("GSB key not configured — skipping")
        # Ключа нет — уровень выключен НАРОЧНО. Это не «источник не
        # ответил»: достоверность от этого падать не должна, иначе
        # сервис сам себе занижает оценку за собственную настройку.
        return ThreatIntelResult(checked=False, skipped=True,
                                 source="google_safe_browsing",
                                 error="API key not configured")

    payload = {
        "client": {
            "clientId": "phishguard",
            "clientVersion": settings.APP_VERSION,
        },
        "threatInfo": {
            "threatTypes": _THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    client = get_client()
    last_error = "unknown error"

    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            resp = await client.post(
                _GSB_ENDPOINT,
                params={"key": api_key},
                json=payload,
                timeout=settings.GSB_TIMEOUT,
            )

            # 429 и 5xx — временные. Ждём и пробуем снова.
            if resp.status_code == 429 or resp.status_code >= 500:
                last_error = f"HTTP {resp.status_code}"
                if attempt < _MAX_ATTEMPTS:
                    # Экспоненциальная пауза: 0.5 с, 1 с.
                    await asyncio.sleep(0.5 * 2 ** (attempt - 1))
                    continue
                logger.warning("GSB unavailable after %d attempts: %s",
                               attempt, last_error)
                return ThreatIntelResult(checked=False,
                                         source="google_safe_browsing",
                                         error=last_error)

            if resp.status_code >= 400:
                # 400/403 — почти всегда неверный или незаактивированный
                # ключ. Логируем подробно для оператора, но НЕ отдаём
                # тело ответа наружу: там бывают детали запроса.
                logger.error("GSB client error %s: %s",
                             resp.status_code, resp.text[:300])
                return ThreatIntelResult(
                    checked=False,
                    source="google_safe_browsing",
                    error=f"HTTP {resp.status_code} (проверьте ключ API)",
                )

            data = resp.json()
            matches = data.get("matches") or []

            if not matches:
                # Пустой ответ = URL чист по базе Google.
                return ThreatIntelResult(checked=True, is_threat=False,
                                         source="google_safe_browsing")

            # Дедуплицируем и сортируем — ответ API должен быть
            # стабильным при одинаковом входе.
            threat_types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
            logger.warning("GSB hit for %s: %s", url, threat_types)
            return ThreatIntelResult(
                checked=True,
                is_threat=True,
                threat_types=threat_types,
                source="google_safe_browsing",
            )

        except (httpx.TimeoutException, httpx.TransportError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt < _MAX_ATTEMPTS:
                await asyncio.sleep(0.5 * 2 ** (attempt - 1))
                continue
        except Exception as exc:                       # noqa: BLE001
            logger.exception("GSB unexpected error")
            return ThreatIntelResult(checked=False,
                                     source="google_safe_browsing",
                                     error=type(exc).__name__)

    logger.warning("GSB failed after %d attempts: %s", _MAX_ATTEMPTS, last_error)
    return ThreatIntelResult(checked=False, source="google_safe_browsing",
                             error=last_error)


__all__ = ["THREAT_TYPE_LABELS", "check_google_safe_browsing"]
