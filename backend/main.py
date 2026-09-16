"""
main.py — HTTP-слой PhishGuard.

Здесь только оркестрация: приём запроса, запуск уровней пайплайна в
правильном порядке и сборка ответа. Вся логика анализа живёт в
пакете pipeline/, вся конфигурация — в config.py.

ПОРЯДОК УРОВНЕЙ И ПОЧЕМУ ОН ИМЕННО ТАКОЙ
────────────────────────────────────────
  Уровень 0  Разворачивание редиректов      (последовательно, первым)
  Уровень 1  Google Safe Browsing  ┐
  Уровень 1b URLhaus               ├ параллельно: это независимый I/O
  Уровень 2  Возраст домена (RDAP) ┘
  Уровень 3  Лексический анализ             (без I/O, мгновенно)
  Уровень 4  Агрегация в балл и вердикт

Уровень 0 обязан быть первым и отдельным: пока мы не знаем конечный
адрес, спрашивать про него Google бессмысленно — мы спросим про
обёртку bit.ly, которая заведомо чистая.

Уровни 1, 1b и 2 запускаются через asyncio.gather. Это не
«оптимизация ради оптимизации»: три последовательных сетевых запроса
по 2 с — это 6 с ожидания, параллельно — 2 с. Именно ради этого в
сервисе вообще используется async.

ЧТО ИСПРАВЛЕНО В HTTP-СЛОЕ
──────────────────────────
  • добавлен rate limiting (был публичный эндпоинт без ограничений,
    сжигающий чужие квоты и работающий усилителем трафика);
  • добавлен общий дедлайн скана — раньше запрос мог висеть
    десятками секунд, пока фронтенд уже отвалился по таймауту;
  • /batch больше не запускает 20 сканов разом: конкурентность
    ограничена семафором, иначе батч выедал весь пул соединений;
  • HTTP-клиент создаётся один раз в lifespan, а не на каждый вызов;
  • обработчик ошибок больше не отдаёт наружу текст исключения;
  • добавлены /, /stats и корректные коды ошибок.
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from cache import TTLCache
from config import settings
from http_client import close_client, init_client
from models import (
    AiVerdictResult,
    BatchScanRequest,
    DomainAgeResult,
    ReputationResult,
    ScanRequest,
    ScanResponse,
    ThreatIntelResult,
)
from pipeline import ai_analyzer as ai_module
from pipeline import domain_age as domain_age_module
from pipeline import reputation as reputation_module
from pipeline.ai_analyzer import analyze_with_ai
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
    """
    Последний рубеж.

    Текст исключения наружу НЕ отдаём: он может содержать внутренние
    пути, имена хостов и фрагменты конфигурации. В лог — полностью,
    клиенту — нейтральное сообщение.
    """
    logger.error("Unhandled exception on %s %s: %s",
                 request.method, request.url.path, exc, exc_info=True)
    detail = str(exc) if settings.DEBUG_DETAILS else (
        "Внутренняя ошибка сервера. Попробуйте позже."
    )
    return JSONResponse(status_code=500,
                        content={"detail": detail, "code": "internal_error"})


# ── Ядро: один скан ───────────────────────────────────────────────

async def _run_pipeline(original_url: str) -> ScanResponse:
    """
    Прогоняет URL через все уровни. Здесь нет обработки ошибок
    отдельных уровней: каждый уровень обязан деградировать мягко
    и вернуть результат с checked=False.
    """
    started = time.perf_counter()

    # ── Уровень 0: разворачиваем редиректы ───────────────────────
    redirects = await resolve_final_url(original_url)
    scanned_url = redirects.final_url or original_url

    # ── Уровень 3 первым: он мгновенный и даёт хост для остальных ─
    lexical = lexical_analyzer.analyze(scanned_url)

    # ── Уровни 1, 1b, 1c, 2 — параллельно ────────────────────────
    # Уровень AI идёт в этом же gather, а не после: ему нужны только
    # URL и структурные признаки, которые уже посчитаны. Запусти мы
    # его следом — он добавил бы свою задержку к общей, а так она
    # прячется за ожиданием остальных источников.
    #
    # return_exceptions=True гарантирует, что падение одного уровня
    # не отменит остальные: gather по умолчанию пробрасывает первое
    # исключение и бросает результаты других задач.
    gsb_result, rep_result, age_result, ai_result = await asyncio.gather(
        check_google_safe_browsing(scanned_url),
        check_urlhaus(scanned_url, lexical.host),
        check_domain_age(lexical.registered_domain),
        analyze_with_ai(scanned_url, lexical),
        return_exceptions=True,
    )

    def _unwrap(result, fallback, name):
        if isinstance(result, BaseException):
            logger.error("Pipeline stage %s failed: %r", name, result)
            return fallback
        return result

    gsb = _unwrap(gsb_result, ThreatIntelResult(checked=False, error="stage failed"), "gsb")
    reputation = _unwrap(rep_result, ReputationResult(checked=False, error="stage failed"), "urlhaus")
    age = _unwrap(age_result, DomainAgeResult(checked=False, error="stage failed"), "domain_age")
    ai = _unwrap(ai_result, AiVerdictResult(checked=False, error="stage failed"), "ai")

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
    )
    response.elapsed_ms = int((time.perf_counter() - started) * 1000)
    return response


async def _scan(url: str) -> ScanResponse:
    """Скан с кешем, дедупликацией и общим дедлайном."""
    async def _factory() -> ScanResponse:
        async with _scan_semaphore:
            return await asyncio.wait_for(_run_pipeline(url),
                                          timeout=settings.SCAN_TOTAL_TIMEOUT)

    cached = await _scan_cache.get(url)
    if cached is not None:
        # Копируем, чтобы пометка cached не «залипла» в самом кеше.
        result = cached.model_copy(update={"cached": True})
        return result

    try:
        return await _scan_cache.single_flight(url, _factory)
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
    }


@app.post("/scan", response_model=ScanResponse, tags=["scan"])
async def scan_url(request: ScanRequest) -> ScanResponse:
    """
    Основной эндпоинт проверки.

    Тело запроса:
        {"url": "https://suspicious-site.xyz/login"}

    В ответе `url` — то, что прислал пользователь, а `scanned_url` —
    адрес, который реально анализировался (они различаются, если
    ссылка вела через редиректы).
    """
    logger.info("Scan requested: %s", request.url)
    return await _scan(request.url)


@app.post("/batch", response_model=list[ScanResponse], tags=["scan"])
async def scan_batch(request: BatchScanRequest) -> list[ScanResponse]:
    """
    Пакетная проверка нескольких ссылок.

    Тело запроса:
        {"urls": ["https://a.com", "https://b.org"]}

    Сканы идут параллельно, но не все разом: одновременных —
    не больше BATCH_CONCURRENCY. Без этого ограничения батч из 20
    ссылок порождал до сотни одновременных исходящих соединений и
    гарантированно ловил rate limit у внешних сервисов.
    """
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

    results = await asyncio.gather(*(_guarded(u) for u in validated),
                                   return_exceptions=True)

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
