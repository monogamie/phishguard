"""HTTP-слой: маршруты и оркестрация пайплайна.

Уровень 0 идёт первым и отдельно (пока не знаем конечный адрес,
спрашивать про него базы бессмысленно), уровни 1/1b/1c/2 —
параллельно, уровень 3 без I/O, уровень 4 агрегирует."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager
from typing import Awaitable, Callable, Optional

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from cache import TTLCache
from config import settings
from http_client import close_client, init_client
from models import (
    AiVerdictResult,
    BatchScanRequest,
    CtResult,
    DomainAgeResult,
    ReputationResult,
    PageResult,
    ScanRequest,
    ScanResponse,
    ThreatIntelResult,
    TlsResult,
)
from pipeline import ai_analyzer as ai_module
from pipeline import ct_logs as ct_module
from pipeline import page_analyzer as page_module
from pipeline import tls_check as tls_module
from pipeline import domain_age as domain_age_module
from pipeline import reputation as reputation_module
from pipeline.ai_analyzer import analyze_with_ai
from pipeline.ct_logs import check_ct_logs
from pipeline.page_analyzer import analyze_page
from pipeline.tls_check import check_tls
from pipeline.domain_age import check_domain_age
from pipeline.lexical_analyzer import lexical_analyzer
from pipeline.reputation import check_urlhaus
from pipeline.scorer import calculate_risk_score
from pipeline.threat_intel import check_google_safe_browsing
from rate_limit import rate_limit_middleware
from url_resolver import resolve_final_url

# ── Логирование ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

# Кеш итоговых вердиктов: повторный скан того же URL в пределах TTL
# не выполняет ни одного внешнего запроса.
_scan_cache: TTLCache[ScanResponse] = TTLCache(
    ttl_seconds=settings.CACHE_TTL_SCAN,
    max_size=settings.CACHE_MAX_SIZE,
)

# Глобальное ограничение одновременных сканов. Защищает и нас (пул
# соединений, память), и внешние сервисы от залпового трафика.
_scan_semaphore = asyncio.Semaphore(20)


# ── Жизненный цикл приложения ─────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("PhishGuard backend %s starting…", settings.APP_VERSION)
    await init_client()

    if not settings.GOOGLE_SAFE_BROWSING_KEY:
        logger.warning(
            "GOOGLE_SAFE_BROWSING_KEY не задан — уровень Google Safe Browsing "
            "отключён. Получите бесплатный ключ в Google Cloud Console."
        )
    if not settings.URLHAUS_AUTH_KEY:
        logger.warning(
            "URLHAUS_AUTH_KEY не задан — URLhaus, скорее всего, ответит 401. "
            "Бесплатная регистрация: https://auth.abuse.ch/"
        )
    if not settings.ANTHROPIC_API_KEY:
        logger.info(
            "ANTHROPIC_API_KEY не задан — уровень анализа моделью отключён. "
            "Это единственный платный источник, остальные четыре работают без него."
        )
    if not settings.BLOCK_PRIVATE_ADDRESSES:
        logger.warning(
            "BLOCK_PRIVATE_ADDRESSES=False — защита от SSRF ОТКЛЮЧЕНА. "
            "Допустимо только для локальной разработки."
        )

    yield

    await close_client()
    domain_age_module.shutdown()
    logger.info("PhishGuard backend stopped.")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Многоуровневый сервис проверки ссылок на фишинг и мошенничество. "
        "Объединяет Google Safe Browsing, базу URLhaus, возраст домена по "
        "RDAP/WHOIS и структурный анализ URL в один объяснимый риск-балл."
    ),
    lifespan=lifespan,
)

# CORS. В проде ALLOWED_ORIGINS надо сузить до домена фронтенда:
# "*" означает, что любой сайт может дёргать наш API от имени
# браузера пользователя и расходовать наши квоты.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
    expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After"],
    max_age=600,
)

app.middleware("http")(rate_limit_middleware)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """
    Заголовки безопасности для ответов API.

    nosniff не даёт браузеру «угадать» тип и исполнить JSON как HTML;
    frame-options запрещает встраивание в iframe (кликджекинг);
    Referrer-Policy не даёт утечь проверяемому URL в Referer.
    """
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


# ── Обработчики ошибок ────────────────────────────────────────────

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request,
                                       exc: RequestValidationError):
    """Человекочитаемая 422 вместо простыни pydantic."""
    messages = []
    for error in exc.errors():
        location = " → ".join(str(p) for p in error.get("loc", ()) if p != "body")
        message = error.get("msg", "некорректное значение")
        messages.append(f"{location}: {message}" if location else message)
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "; ".join(messages) or "Некорректный запрос",
                 "code": "validation_error"},
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Последний рубеж. Текст исключения наружу не отдаём: в нём бывают
    внутренние пути и фрагменты конфигурации."""
    logger.error("Unhandled exception on %s %s: %s",
                 request.method, request.url.path, exc, exc_info=True)
    detail = str(exc) if settings.DEBUG_DETAILS else (
        "Внутренняя ошибка сервера. Попробуйте позже."
    )
    return JSONResponse(status_code=500,
                        content={"detail": detail, "code": "internal_error"})


# ── Ядро: один скан ───────────────────────────────────────────────

async def _skip(model_cls):
    """Заглушка для уровня, который решили не запускать."""
    return model_cls(checked=False, skipped=True,
                     error="Пропущено: доверенный домен")


# Порядок — как человек их видит на экране ожидания. Имена уходят
# в поток прогресса; подписи к ним живут во фронтенде, в обоих языках.
PIPELINE_STAGES = ("redirects", "lexical", "gsb", "urlhaus",
                   "domain_age", "ai", "tls", "ct", "page", "score")

# Докладчик о ходе проверки. Необязателен нарочно: обычный /scan
# передаёт None и работает ровно как раньше. Второго пути исполнения
# у нас быть не должно — ровно на этом мы горели с двумя движками
# подсчёта, которые разъехались.
ProgressReporter = Optional[Callable[[str], Awaitable[None]]]


async def _report(progress: ProgressReporter, stage: str) -> None:
    if progress is None:
        return
    try:
        await progress(stage)
    except Exception:                                  # noqa: BLE001
        # Оборвался читатель потока — это не повод ронять проверку:
        # результат ещё пригодится кешу и следующему запросу.
        logger.debug("Progress reporter failed on stage %s", stage)


async def _staged(stage: str, coro, progress: ProgressReporter):
    """Ждёт уровень и докладывает о нём, чем бы он ни кончился."""
    try:
        return await coro
    finally:
        await _report(progress, stage)


async def _run_pipeline(original_url: str,
                        progress: ProgressReporter = None) -> ScanResponse:
    """Прогоняет URL через все уровни. Каждый уровень деградирует
    сам и возвращает checked=False — ошибки здесь не ловятся."""
    started = time.perf_counter()

    # ── Уровень 0: разворачиваем редиректы ───────────────────────
    redirects = await resolve_final_url(original_url)
    scanned_url = redirects.final_url or original_url
    await _report(progress, "redirects")

    # ── Уровень 3 первым: он мгновенный и даёт хост для остальных ─
    lexical = lexical_analyzer.analyze(scanned_url)
    await _report(progress, "lexical")

    # ── Уровни 1, 1b, 1c, 2 — параллельно ────────────────────────
    # Уровень AI идёт в этом же gather, а не после: ему нужны только
    # URL и структурные признаки, которые уже посчитаны. Запусти мы
    # его следом — он добавил бы свою задержку к общей, а так она
    # прячется за ожиданием остальных источников.
    #
    # return_exceptions=True гарантирует, что падение одного уровня
    # не отменит остальные: gather по умолчанию пробрасывает первое
    # исключение и бросает результаты других задач.
    # Доверенные домены не гоняем через дорогие уровни: там уже всё
    # решено потолком доверия, а страница и журналы стоят времени.
    # На площадке, где публикует кто угодно, содержимое смотреть НАДО,
    # даже если сам домен доверенный: `docs.google.com` и `telegra.ph`
    # — это чужие страницы, а не страницы Google и Telegram.
    heavy = lexical.on_shared_platform or not lexical.is_trusted_domain

    results = await asyncio.gather(
        _staged("gsb", check_google_safe_browsing(scanned_url), progress),
        _staged("urlhaus", check_urlhaus(scanned_url, lexical.host), progress),
        _staged("domain_age", check_domain_age(lexical.registered_domain), progress),
        _staged("ai", analyze_with_ai(scanned_url, lexical), progress),
        _staged("tls", check_tls(scanned_url), progress),
        _staged("ct", check_ct_logs(lexical.registered_domain)
                if heavy else _skip(CtResult), progress),
        _staged("page", analyze_page(scanned_url)
                if heavy else _skip(PageResult), progress),
        return_exceptions=True,
    )
    (gsb_result, rep_result, age_result, ai_result,
     tls_result, ct_result, page_result) = results

    def _unwrap(result, fallback, name):
        if isinstance(result, BaseException):
            logger.error("Pipeline stage %s failed: %r", name, result)
            return fallback
        return result

    gsb = _unwrap(gsb_result, ThreatIntelResult(checked=False, error="stage failed"), "gsb")
    reputation = _unwrap(rep_result, ReputationResult(checked=False, error="stage failed"), "urlhaus")
    age = _unwrap(age_result, DomainAgeResult(checked=False, error="stage failed"), "domain_age")
    ai = _unwrap(ai_result, AiVerdictResult(checked=False, error="stage failed"), "ai")
    tls = _unwrap(tls_result, TlsResult(checked=False, error="stage failed"), "tls")
    ct = _unwrap(ct_result, CtResult(checked=False, error="stage failed"), "ct")
    page = _unwrap(page_result, PageResult(checked=False, error="stage failed"), "page")

    # ── Уровень 4: агрегация ─────────────────────────────────────
    response = calculate_risk_score(
        url=scanned_url,
        original_url=original_url,
        gsb=gsb,
        reputation=reputation,
        domain_age=age,
        lexical=lexical,
        redirects=redirects,
        ai=ai,
        tls=tls,
        ct=ct,
        page=page,
    )
    response.elapsed_ms = int((time.perf_counter() - started) * 1000)
    await _report(progress, "score")
    return response


async def _scan(url: str, progress: ProgressReporter = None) -> ScanResponse:
    """Скан с кешем, дедупликацией и общим дедлайном."""
    async def _factory() -> ScanResponse:
        # Дедлайн охватывает И ожидание очереди, и саму работу.
        # Пока `wait_for` стоял внутри `async with`, ограничена была
        # только работа: под нагрузкой запрос спокойно висел в очереди
        # к семафору сколько угодно, и заявленные 30 секунд не
        # соблюдались — замерено, 23 запроса из 120 шли дольше.
        async def _queued() -> ScanResponse:
            async with _scan_semaphore:
                return await _run_pipeline(url, progress)

        return await asyncio.wait_for(_queued(),
                                      timeout=settings.SCAN_TOTAL_TIMEOUT)

    cached = await _scan_cache.get(url)
    if cached is not None:
        # Копируем, чтобы пометка cached не «залипла» в самом кеше.
        result = cached.model_copy(update={"cached": True})
        return result

    try:
        return await _scan_cache.single_flight(url, _factory,
                                               already_missed=True)
    except asyncio.TimeoutError:
        logger.warning("Scan timed out for %s", url)
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=("Проверка заняла слишком много времени. "
                    "Возможно, сайт не отвечает."),
        ) from None


# ── Маршруты ──────────────────────────────────────────────────────

@app.get("/", tags=["meta"])
async def root():
    """Краткая справка по API."""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "endpoints": {
            "POST /scan": "проверить один URL",
            "POST /batch": f"проверить до {settings.BATCH_MAX_URLS} URL за раз",
            "GET /health": "состояние сервиса",
            "GET /stats": "статистика кешей",
        },
    }


@app.get("/health", tags=["meta"])
async def health_check():
    """Liveness-проба для балансировщика и мониторинга."""
    return {
        "status": "ok",
        "version": settings.APP_VERSION,
        "sources": {
            "google_safe_browsing": bool(settings.GOOGLE_SAFE_BROWSING_KEY),
            "urlhaus": bool(settings.URLHAUS_AUTH_KEY),
            "rdap": True,
            "lexical": True,
            "ai": bool(settings.ANTHROPIC_API_KEY) and settings.AI_ENABLED,
            "tls": settings.TLS_ENABLED,
            "ct_logs": settings.CT_ENABLED,
            "page_content": settings.PAGE_ENABLED,
        },
        "ssrf_protection": settings.BLOCK_PRIVATE_ADDRESSES,
    }


@app.get("/stats", tags=["meta"])
async def stats():
    """Статистика кешей — помогает понять, работает ли кеширование."""
    return {
        "scan_cache": _scan_cache.stats(),
        "domain_age_cache": domain_age_module.cache_stats(),
        "reputation_cache": reputation_module.cache_stats(),
        "ai_cache": ai_module.cache_stats(),
        "tls_cache": tls_module.cache_stats(),
        "ct_cache": ct_module.cache_stats(),
        "page_cache": page_module.cache_stats(),
    }


@app.post("/scan", response_model=ScanResponse, tags=["scan"])
async def scan_url(request: ScanRequest) -> ScanResponse:
    """Основной эндпоинт. В ответе `url` — что прислал пользователь,
    `scanned_url` — что реально анализировалось после редиректов."""
    logger.info("Scan requested: %s", request.url)
    return await _scan(request.url)


# ── Поток прогресса ──────────────────────────────────────────────
# Зачем: сервер делает все проверки разом и отвечает один раз, поэтому
# экран ожидания двигал шаги по таймеру — то есть показывал не ход
# работы, а правдоподобную анимацию. Здесь он показывает настоящий.
#
# Транспорт — Server-Sent Events поверх POST, а не EventSource: тому
# нужен GET, то есть адрес проверки уехал бы в строку запроса, а с ним
# и в логи прокси. Читается обычным fetch со стороны страницы.

# Задачи сканов, у которых читатель мог отвалиться. Держим ссылку,
# иначе сборщик мусора вправе убить задачу на полпути — и результат
# не доедет до кеша, хотя работа уже сделана.
_detached_scans: set[asyncio.Task] = set()


def _sse(payload: dict) -> str:
    return "data: " + json.dumps(payload, ensure_ascii=False) + "\n\n"


async def _scan_events(url: str):
    queue: asyncio.Queue[str] = asyncio.Queue()

    async def report(stage: str) -> None:
        queue.put_nowait(stage)

    task = asyncio.create_task(_scan(url, progress=report))
    _detached_scans.add(task)
    # Исключение задачи кто-то обязан забрать, иначе asyncio ругается
    # в лог при сборке мусора. Забираем ниже, а здесь — страховка.
    task.add_done_callback(lambda t: (_detached_scans.discard(t), t.exception()
                                      if not t.cancelled() else None))

    # Первое событие уходит сразу: для человека после холодного старта
    # Render это первый признак, что сервер вообще проснулся.
    yield _sse({"event": "start", "stages": list(PIPELINE_STAGES)})

    done = 0
    while not task.done():
        getter = asyncio.ensure_future(queue.get())
        finished, _ = await asyncio.wait({getter, task},
                                         return_when=asyncio.FIRST_COMPLETED)
        if getter in finished:
            done += 1
            yield _sse({"event": "stage", "name": getter.result(),
                        "done": done, "total": len(PIPELINE_STAGES)})
        else:
            getter.cancel()

    # Этапы, успевшие доложиться, пока мы смотрели на завершение задачи.
    while not queue.empty():
        done += 1
        yield _sse({"event": "stage", "name": queue.get_nowait(),
                    "done": done, "total": len(PIPELINE_STAGES)})

    try:
        result = task.result()
    except HTTPException as exc:
        # Поток уже отдан с кодом 200, поэтому об ошибке сообщаем
        # внутри него, а не статусом.
        yield _sse({"event": "error", "status": exc.status_code,
                    "detail": exc.detail})
        return
    except asyncio.CancelledError:
        raise
    except Exception:                                  # noqa: BLE001
        logger.exception("Streaming scan failed for %s", url)
        yield _sse({"event": "error", "status": 500,
                    "detail": "Внутренняя ошибка сервиса"})
        return

    yield _sse({"event": "done", "result": result.model_dump(mode="json")})


@app.post("/scan/stream", tags=["scan"])
async def scan_stream(request: ScanRequest) -> StreamingResponse:
    """То же, что POST /scan, но с докладом о ходе проверки.

    Результат собирает тот же `_run_pipeline` — двух путей подсчёта
    быть не должно, это проверяется тестом."""
    logger.info("Streaming scan requested: %s", request.url)
    return StreamingResponse(
        _scan_events(request.url),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            # Иначе прокси копит ответ в буфере и отдаёт разом —
            # и весь смысл потока пропадает.
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/batch", response_model=list[ScanResponse], tags=["scan"])
async def scan_batch(request: BatchScanRequest) -> list[ScanResponse]:
    """Пакетная проверка. Конкурентность ограничена семафором: без него
    батч из 20 ссылок даёт до сотни исходящих соединений."""
    if len(request.urls) > settings.BATCH_MAX_URLS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"За один запрос можно проверить не более "
                   f"{settings.BATCH_MAX_URLS} ссылок.",
        )

    # Валидируем ВСЕ ссылки до начала работы: лучше отказать сразу,
    # чем отсканировать половину и упасть на середине.
    validated: list[str] = []
    for raw in request.urls:
        try:
            validated.append(ScanRequest(url=raw).url)
        except Exception as exc:                       # noqa: BLE001
            message = getattr(exc, "errors", None)
            reason = (message()[0]["msg"] if callable(message) and message()
                      else str(exc))
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Некорректная ссылка {raw!r}: {reason}",
            ) from None

    gate = asyncio.Semaphore(settings.BATCH_CONCURRENCY)

    async def _guarded(u: str) -> ScanResponse:
        async with gate:
            return await _scan(u)

    # У пачки свой дедлайн: 20 ссылок по 5 за раз — это четыре волны,
    # и без общего ограничения запрос мог висеть кратно дольше, чем
    # обещано для одиночной проверки. Ждём столько, сколько нужно на
    # все волны, но не больше — и не бесконечно.
    waves = -(-len(validated) // max(settings.BATCH_CONCURRENCY, 1))
    batch_deadline = settings.SCAN_TOTAL_TIMEOUT * waves + 5

    try:
        results = await asyncio.wait_for(
            asyncio.gather(*(_guarded(u) for u in validated),
                           return_exceptions=True),
            timeout=batch_deadline,
        )
    except asyncio.TimeoutError:
        logger.warning("Batch of %d timed out after %.0fs",
                       len(validated), batch_deadline)
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=("Проверка пачки заняла слишком много времени. "
                    "Попробуйте меньше ссылок за раз."),
        ) from None

    # Один упавший URL не должен рушить весь батч: возвращаем для
    # него «неизвестно» с пояснением, остальные отдаём как есть.
    output: list[ScanResponse] = []
    for url, result in zip(validated, results):
        if isinstance(result, BaseException):
            logger.error("Batch item failed for %s: %r", url, result)
            output.append(ScanResponse(
                url=url, scanned_url=url, is_phishing=False, risk_score=0,
                verdict="SUSPICIOUS", confidence=0.0,
                reasons=["Проверка не завершилась — повторите попытку"],
            ))
        else:
            output.append(result)
    return output
