"""Уровень 2: возраст домена через RDAP, с WHOIS как запасным источником.

Большинство фишинговых доменов моложе 30 дней. RDAP предпочтительнее:
HTTPS и JSON против текстового протокола, который парсится регулярками."""

from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from cache import TTLCache
from config import settings
from http_client import get_client
from models import DomainAgeResult

logger = logging.getLogger(__name__)

# rdap.org сам находит сервер регистратуры по домену.
_RDAP_ENDPOINT = "https://rdap.org/domain/{domain}"

# Отдельный пул: wait_for не убивает поток, и дефолтный executor
# исчерпался бы висящими WHOIS-запросами.
_whois_executor = ThreadPoolExecutor(max_workers=4,
                                     thread_name_prefix="whois")
_whois_semaphore = asyncio.Semaphore(4)

_cache: TTLCache[DomainAgeResult] = TTLCache(
    ttl_seconds=settings.CACHE_TTL_DOMAIN_AGE,
    max_size=settings.CACHE_MAX_SIZE,
)


# ── Разбор дат ───────────────────────────────────────────────────

def _coerce_datetime(value: Any) -> Optional[datetime]:
    """
    Приводит что угодно к timezone-aware datetime или к None.

    WHOIS-парсеры возвращают разнородный мусор, поэтому любой
    неожиданный тип — None.
    """
    if value is None:
        return None

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        # ISO 8601 с 'Z' — fromisoformat до Python 3.11 его не понимал.
        try:
            return _ensure_utc(datetime.fromisoformat(text.replace("Z", "+00:00")))
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d.%m.%Y",
                        "%Y.%m.%d", "%d-%b-%Y"):
                try:
                    return _ensure_utc(datetime.strptime(text, fmt))
                except ValueError:
                    continue
            return None

    if isinstance(value, datetime):
        return _ensure_utc(value)

    return None


def _ensure_utc(dt: datetime) -> datetime:
    """Наивные даты в WHOIS почти всегда UTC — доопределяем явно."""
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _earliest_creation_date(raw: Any) -> Optional[datetime]:
    """
    Выбирает самую раннюю корректную дату из значения WHOIS.

    Элементы сначала приводятся к aware: список может смешивать
    naive и aware datetime, и min() на нём падает TypeError.
    """
    if isinstance(raw, (list, tuple, set)):
        candidates = [d for d in (_coerce_datetime(v) for v in raw) if d]
        return min(candidates) if candidates else None
    return _coerce_datetime(raw)


def _age_days(creation: datetime) -> Optional[int]:
    """
    Возраст в днях или None, если дата невалидна.

    Даты из будущего и абсурдно старые — битая запись регистратора.
    """
    now = datetime.now(timezone.utc)
    delta_days = (now - creation).days
    if delta_days < 0:
        logger.warning("Creation date in the future: %s — ignoring", creation)
        return None
    if creation.year < 1985:
        logger.warning("Implausible creation date: %s — ignoring", creation)
        return None
    return delta_days


# ── Источник 1: RDAP ─────────────────────────────────────────────

async def _lookup_rdap(domain: str) -> Optional[DomainAgeResult]:
    """None означает «RDAP не смог» — вызывающий попробует WHOIS."""
    client = get_client()
    try:
        resp = await client.get(
            _RDAP_ENDPOINT.format(domain=domain),
            headers={"Accept": "application/rdap+json, application/json"},
            timeout=settings.RDAP_TIMEOUT,
            follow_redirects=True,   # rdap.org отдаёт 302 на сервер регистратуры
        )
    except (httpx.TimeoutException, httpx.TransportError) as exc:
        logger.info("RDAP transport error for %s: %s", domain, type(exc).__name__)
        return None
    except Exception:                                  # noqa: BLE001
        logger.exception("RDAP unexpected error for %s", domain)
        return None

    if resp.status_code == 404:
        # Домен не зарегистрирован. Это ЗНАЧИМЫЙ результат, а не ошибка:
        # ссылка ведёт на несуществующий домен.
        return DomainAgeResult(checked=True, age_days=None, source="rdap",
                               error="Домен не зарегистрирован")
    if resp.status_code != 200:
        logger.info("RDAP HTTP %s for %s", resp.status_code, domain)
        return None

    try:
        data = resp.json()
    except ValueError:
        return None

    events = data.get("events") or []
    creation = None
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("eventAction") in {"registration", "created"}:
            creation = _coerce_datetime(event.get("eventDate"))
            if creation:
                break

    if creation is None:
        return None

    age = _age_days(creation)
    if age is None:
        return None

    return DomainAgeResult(
        checked=True,
        age_days=age,
        creation_date=creation.isoformat(),
        registrar=_rdap_registrar(data),
        source="rdap",
    )


def _rdap_registrar(data: dict) -> Optional[str]:
    """
    Достаёт имя регистратора из RDAP-ответа.

    vcardArray = ["vcard", [["fn",{},"text","Registrar Name"], ...]]
    """
    try:
        for entity in data.get("entities") or []:
            if "registrar" not in (entity.get("roles") or []):
                continue
            vcard = entity.get("vcardArray")
            if not (isinstance(vcard, list) and len(vcard) > 1):
                continue
            for field in vcard[1]:
                if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                    return str(field[3])[:200]
    except Exception:                                  # noqa: BLE001
        pass
    return None


# ── Источник 2: WHOIS (запасной) ─────────────────────────────────

def _fetch_whois_sync(domain: str) -> Any:
    """Синхронный WHOIS. Выполняется в выделенном пуле потоков."""
    import whois                       # импорт внутри — библиотека тяжёлая
    return whois.whois(domain)


async def _lookup_whois(domain: str, budget: float) -> Optional[DomainAgeResult]:
    """
    WHOIS-запрос с изоляцией от общего пула потоков.

    `budget` — остаток времени у уровня. Израсходован RDAP'ом —
    к WHOIS не идём: таймауты иначе складываются.
    """
    if budget <= 1.0:
        logger.info("No time budget left for WHOIS on %s", domain)
        return None

    timeout = min(settings.WHOIS_TIMEOUT, budget)

    # Если все слоты заняты, не встаём в бесконечную очередь: ждём
    # слот ограниченное время и отказываемся.
    try:
        await asyncio.wait_for(_whois_semaphore.acquire(), timeout=timeout / 2)
    except asyncio.TimeoutError:
        logger.info("WHOIS pool saturated — skipping lookup for %s", domain)
        return None

    try:
        loop = asyncio.get_running_loop()
        future = loop.run_in_executor(_whois_executor, _fetch_whois_sync, domain)
        try:
            record = await asyncio.wait_for(asyncio.shield(future), timeout=timeout)
        except asyncio.TimeoutError:
            # wait_for не убивает поток — он освободит слот сам.
            logger.warning("WHOIS timeout for %s", domain)
            return None
        except Exception as exc:                       # noqa: BLE001
            logger.info("WHOIS failed for %s: %s", domain, type(exc).__name__)
            return None
    finally:
        _whois_semaphore.release()

    creation = _earliest_creation_date(getattr(record, "creation_date", None))
    if creation is None:
        return None

    age = _age_days(creation)
    if age is None:
        return None

    registrar = getattr(record, "registrar", None)
    if isinstance(registrar, (list, tuple)):
        registrar = registrar[0] if registrar else None

    return DomainAgeResult(
        checked=True,
        age_days=age,
        creation_date=creation.isoformat(),
        registrar=str(registrar)[:200] if registrar else None,
        source="whois",
    )


# ── Публичная точка входа ────────────────────────────────────────

async def check_domain_age(registered_domain: str) -> DomainAgeResult:
    """Принимает уже извлечённый eTLD+1, а не URL: иначе дублировали бы
    работу лексического анализатора и могли разойтись в результате."""
    if not registered_domain or "." not in registered_domain:
        return DomainAgeResult(checked=False,
                               error="Не удалось выделить регистрируемый домен")

    domain = registered_domain.lower().strip(".")

    async def _lookup() -> DomainAgeResult:
        deadline = time.monotonic() + settings.DOMAIN_AGE_TOTAL_TIMEOUT

        rdap_result = await _lookup_rdap(domain)
        if rdap_result is not None and rdap_result.age_days is not None:
            return rdap_result

        # WHOIS — только на остаток общего бюджета уровня.
        whois_result = await _lookup_whois(domain, deadline - time.monotonic())
        if whois_result is not None:
            return whois_result

        # RDAP мог вернуть значимый «домен не зарегистрирован».
        if rdap_result is not None:
            return rdap_result

        return DomainAgeResult(
            checked=False,
            error="Дата регистрации недоступна (RDAP и WHOIS не ответили)",
        )

    try:
        return await _cache.single_flight(domain, _lookup)
    except Exception:                                  # noqa: BLE001
        logger.exception("Domain age lookup failed for %s", domain)
        return DomainAgeResult(checked=False, error="Ошибка проверки возраста домена")


def cache_stats() -> dict:
    return _cache.stats()


def shutdown() -> None:
    """Останавливает пул потоков при завершении приложения."""
    _whois_executor.shutdown(wait=False, cancel_futures=True)


__all__ = ["cache_stats", "check_domain_age", "shutdown"]
