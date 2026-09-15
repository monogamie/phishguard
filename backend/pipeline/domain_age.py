"""
pipeline/domain_age.py — Уровень 2: возраст домена.

ПОЧЕМУ ВОЗРАСТ ДОМЕНА — СИЛЬНЕЙШАЯ ОДИНОЧНАЯ ЭВРИСТИКА
──────────────────────────────────────────────────────
Фишинговая инфраструктура одноразовая по своей экономике.
Домен стоит 1-2 доллара, живёт от нескольких часов до нескольких
дней — ровно до попадания в блоклисты — и бросается.  По данным
APWG и отраслевых отчётов, подавляющее большинство фишинговых
доменов моложе 30 дней на момент атаки.

Обратное неверно: новый домен ≠ фишинг (любой стартап начинает
с нулевого возраста).  Поэтому вес «< 30 дней» = 35 баллов —
подозрительно, но само по себе не вердикт.  А вот «< 30 дней» +
имя банка в домене + зона .top — это уже 90+.

ДВА ИСТОЧНИКА: RDAP И WHOIS
───────────────────────────
Первая версия использовала только `python-whois`, и это была
главная её проблема на этом уровне:

  • WHOIS — текстовый протокол 1982 года без схемы.  Каждый
    регистратор форматирует ответ по-своему, а библиотека разбирает
    его набором регулярок. Результат: «дата создания» то datetime,
    то список, то строка, то None.
  • `python-whois` вызывает СИСТЕМНУЮ утилиту `whois`.  В slim-образах
    Docker её просто нет — и весь уровень молча отключался.
  • Порт 43/tcp часто закрыт исходящим фаерволом PaaS.

RDAP (RFC 7482/9082) — официальная замена WHOIS: HTTPS, JSON,
единая схема, обязателен для всех gTLD с 2019 года.  Делаем его
основным источником, а WHOIS оставляем запасным для зон,
которые RDAP ещё не поддерживают (часть ccTLD, например .ru
обслуживается RDAP не полностью).

ИСПРАВЛЕННЫЕ БАГИ
─────────────────
1. ПАДЕНИЕ НА `min(raw)`.
   `python-whois` возвращает creation_date списком, когда дат в
   записи несколько.  Старый код делал `min(raw)` — и если в списке
   лежали datetime с таймзоной и без (а это обычное дело), Python
   бросал TypeError: "can't compare offset-naive and offset-aware
   datetimes".  Вызов стоял ВНЕ try/except → HTTP 500.
   Теперь список нормализуется поэлементно, мусор отбрасывается.

2. ИСТОЩЕНИЕ ПУЛА ПОТОКОВ.
   `asyncio.wait_for(loop.run_in_executor(None, ...))` НЕ убивает
   поток по таймауту — он отменяет только ожидание.  Сам поток
   продолжает висеть на сокете до своего таймаута и держит слот
   в ДЕФОЛТНОМ пуле, который в asyncio один на всё приложение.
   Десяток «висящих» WHOIS — и любой другой run_in_executor встаёт
   в очередь.  Лечим двумя способами: отдельный пул только под
   WHOIS (не отравляем общий) и семафор, ограничивающий число
   одновременных запросов.

3. ОТРИЦАТЕЛЬНЫЙ ВОЗРАСТ.
   Битые данные регистратора (дата в будущем) давали age_days < 0,
   что проходило проверку `age < 7` и помечало домен как
   «зарегистрирован только что».  Теперь такие записи отбрасываются.

4. ОТСУТСТВИЕ КЕША.
   Дата регистрации домена не меняется. Кешируем на сутки —
   это снимает нагрузку с RDAP-серверов, которые за флуд банят.
"""

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

# Агрегатор RDAP: сам находит нужный сервер регистратуры по домену
# и проксирует запрос. Альтернатива — ходить в IANA bootstrap и
# резолвить сервер самим, но для нашей нагрузки это избыточно.
_RDAP_ENDPOINT = "https://rdap.org/domain/{domain}"

# Отдельный пул только под WHOIS.  Размер намеренно мал: WHOIS —
# это не то, ради чего стоит держать сотню потоков.
_whois_executor = ThreadPoolExecutor(max_workers=4,
                                     thread_name_prefix="whois")
# Семафор не даёт очереди задач расти бесконечно: если все 4 слота
# заняты, пятый запрос сразу получит отказ, а не будет ждать минуту.
_whois_semaphore = asyncio.Semaphore(4)

_cache: TTLCache[DomainAgeResult] = TTLCache(
    ttl_seconds=settings.CACHE_TTL_DOMAIN_AGE,
    max_size=settings.CACHE_MAX_SIZE,
)


# ── Разбор дат ───────────────────────────────────────────────────

def _coerce_datetime(value: Any) -> Optional[datetime]:
    """
    Приводит что угодно к timezone-aware datetime или к None.

    WHOIS-парсеры возвращают крайне разнородные данные, поэтому
    функция намеренно параноидальная: любой неожиданный тип — None.
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

    Здесь и жил баг с `min()`: список мог содержать
    naive и aware datetime вперемешку, и сравнение падало
    TypeError'ом ВНЕ обработчика исключений.  Теперь каждый
    элемент сначала приводится к aware, мусор отбрасывается,
    и только потом берётся минимум.
    """
    if isinstance(raw, (list, tuple, set)):
        candidates = [d for d in (_coerce_datetime(v) for v in raw) if d]
        return min(candidates) if candidates else None
    return _coerce_datetime(raw)


def _age_days(creation: datetime) -> Optional[int]:
    """
    Возраст в днях или None, если дата невалидна.

    Отбрасываем даты из будущего (битая запись регистратора) и
    абсурдно старые (до появления DNS — тоже мусор в записи).
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
    """
    Запрашивает дату регистрации через RDAP (HTTPS + JSON).

    Возвращает None, если RDAP не смог ответить — тогда вызывающий
    код попробует WHOIS.
    """
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

    Структура entities/vcardArray в RDAP довольно вывернутая:
    vcardArray = ["vcard", [["version",{},"text","4.0"],
                            ["fn",{},"text","Registrar Name"], ...]]
    Идём по ней аккуратно, любая неожиданность → None.
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

    `budget` — сколько секунд осталось у уровня. Если бюджет уже
    израсходован RDAP'ом, к WHOIS даже не идём: лучше вернуть
    «возраст неизвестен» за секунду, чем правильный ответ за
    четырнадцать, когда фронтенд уже отвалился по таймауту.
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
            # Поток продолжит работу и освободит слот сам — мы просто
            # перестаём его ждать. shield нужен, чтобы отмена ожидания
            # не пыталась (безуспешно) отменить уже запущенный поток.
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
    """
    Возвращает возраст регистрируемого домена в днях.

    Принимает УЖЕ извлечённый eTLD+1 (например "evil.ru"), а не URL:
    раньше функция сама дёргала tldextract, дублируя работу
    лексического анализатора и рискуя получить другой результат.

    Деградация мягкая: если оба источника молчат, возвращаем
    checked=False, и скорер добавит лишь небольшой штраф за
    неизвестность вместо того, чтобы отказать в скане.
    """
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
