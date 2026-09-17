"""Уровень 2c: журналы Certificate Transparency (crt.sh).

Каждый выпущенный сертификат попадает в публичные журналы, которые
ведутся независимо от владельца домена. Поэтому дата первого
сертификата — это независимая оценка возраста домена, и она работает
там, где RDAP и WHOIS молчат (часть ccTLD не отдаёт дату регистрации).

Для доклада это прямой ответ на ограничение, которое мы сами назвали:
Google узнаёт о фишинге через часы, а домен виден в журналах почти
сразу после выпуска сертификата.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

from cache import TTLCache
from config import settings
from http_client import get_client
from models import CtResult

logger = logging.getLogger(__name__)

_cache: TTLCache[CtResult] = TTLCache(
    ttl_seconds=settings.CACHE_TTL_CT,
    max_size=settings.CACHE_MAX_SIZE,
)

# Крупный домен накапливает десятки тысяч сертификатов, и ответ может
# весить десятки мегабайт. Читаем с ограничением: превышение лимита
# само по себе означает «домен давно живёт», а это не риск.
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def _parse_ts(raw: Optional[str]) -> Optional[datetime]:
    if not raw:
        return None
    text = raw.strip().replace(" ", "T", 1)
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


async def check_ct_logs(registered_domain: str) -> CtResult:
    """Ищет самый ранний сертификат домена. Ошибки не выбрасываются."""
    if not settings.CT_ENABLED:
        return CtResult(checked=False, skipped=True, error="Уровень CT выключен")
    if not registered_domain or "." not in registered_domain:
        return CtResult(checked=False, error="Не удалось выделить домен")

    domain = registered_domain.lower().strip(".")

    async def _fetch() -> CtResult:
        try:
            async with get_client().stream(
                "GET", settings.CT_ENDPOINT,
                params={"q": domain, "output": "json", "deduplicate": "Y"},
                headers={"Accept": "application/json"},
                timeout=settings.CT_TIMEOUT,
                follow_redirects=True,
            ) as resp:
                if resp.status_code == 404:
                    return CtResult(checked=True, total_certs=0,
                                    error="Домена нет в журналах")
                if resp.status_code != 200:
                    logger.info("crt.sh HTTP %s for %s", resp.status_code, domain)
                    return CtResult(checked=False,
                                    error=f"HTTP {resp.status_code}")

                chunks: list[bytes] = []
                size = 0
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    if size > _MAX_RESPONSE_BYTES:
                        # Столько сертификатов бывает только у домена с
                        # историей. Признака риска здесь нет.
                        logger.info("crt.sh response too large for %s — "
                                    "считаем домен зрелым", domain)
                        return CtResult(checked=True, first_seen_days=None,
                                        error="Слишком много сертификатов "
                                              "(домен с историей)")
                    chunks.append(chunk)
                body = b"".join(chunks)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            logger.info("crt.sh transport error: %s", type(exc).__name__)
            return CtResult(checked=False, error="Журналы недоступны")
        except Exception:                              # noqa: BLE001
            logger.exception("crt.sh unexpected error")
            return CtResult(checked=False, error="Ошибка обращения к журналам")

        try:
            entries = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return CtResult(checked=False, error="Ответ журналов не разобран")

        if not isinstance(entries, list):
            return CtResult(checked=False, error="Неожиданный формат ответа")
        if not entries:
            # Значимый результат: на домен никогда не выпускали
            # сертификат. Для https-сайта это странно.
            return CtResult(checked=True, total_certs=0,
                            error="Сертификаты на домен не выпускались")

        earliest: Optional[datetime] = None
        issuers: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            issued = _parse_ts(entry.get("not_before") or entry.get("entry_timestamp"))
            if issued and (earliest is None or issued < earliest):
                earliest = issued
            issuer = entry.get("issuer_name")
            if issuer:
                issuers.add(str(issuer)[:120])

        first_seen_days = None
        if earliest:
            delta = (datetime.now(timezone.utc) - earliest).days
            # Дата из будущего — мусор в журнале, а не свежий домен.
            first_seen_days = delta if delta >= 0 else None

        return CtResult(
            checked=True,
            first_seen_days=first_seen_days,
            first_seen_at=earliest.isoformat() if earliest else None,
            total_certs=len(entries),
            issuers=sorted(issuers)[:5],
        )

    try:
        return await _cache.single_flight(domain, _fetch)
    except Exception:                                  # noqa: BLE001
        logger.exception("CT stage failed")
        return CtResult(checked=False, error="Сбой уровня CT")


def cache_stats() -> dict:
    return _cache.stats()


__all__ = ["cache_stats", "check_ct_logs"]
