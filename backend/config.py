"""Конфигурация сервиса. Любое поле переопределяется переменной
окружения с тем же именем или файлом .env рядом с кодом."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent

# Веса риска: сырые баллы, сумма режется по 100.
DEFAULT_WEIGHTS: dict[str, int] = {
    # ── Внешняя разведка — наивысшая достоверность ──────────────
    "google_safe_browsing":  90,   # прямое совпадение в базе Google
    "urlhaus_url":           70,   # URL в базе вредоносов abuse.ch
    "urlhaus_host":          45,   # хост раздавал вредоносы

    # ── Возраст домена (RDAP / WHOIS) ───────────────────────────
    "domain_very_new":       50,   # < 7 дней
    "domain_new":            35,   # < 30 дней
    "domain_recent":         15,   # < 90 дней
    "domain_age_unknown":     5,   # данные недоступны — слабый сигнал

    # ── Структура URL ───────────────────────────────────────────
    "ip_in_url":             40,   # IP вместо доменного имени
    "at_symbol":             50,   # http://real@evil.com
    "punycode":              30,   # xn-- сам по себе (без совпадения бренда)
    "non_ascii_host":        35,   # сырой юникод в хосте
    "mixed_scripts":         45,   # латиница + кириллица в одной метке
    "non_standard_port":     25,   # :4433, :1337 и т.п.
    "excessive_subdomains":  20,   # больше MAX_SUBDOMAINS
    "long_url":              15,   # длиннее MAX_URL_LENGTH
    "long_domain":           15,   # SLD длиннее MAX_DOMAIN_LENGTH
    "excessive_hyphens":     15,   # больше MAX_HYPHENS
    "redirect_params":       20,   # ?url=, ?goto=, ?redirect=
    "encoded_host":          25,   # процентное кодирование в хосте
    "insecure_scheme":       15,   # http:// вместо https://
    "shortener":             10,   # ссылка через сокращатель
    "long_redirect_chain":   15,   # цепочка редиректов > 2 хопов
    "cross_domain_redirect": 20,   # редирект уводит на другой домен

    # ── Лексика и имперсонация ──────────────────────────────────
    "trigger_keywords":      12,   # базовый вес за первое слово
    "trigger_keywords_many": 22,   # два и более слов — сильнее
    "suspicious_tld":        20,   # .xyz, .tk, .top, … (бесплатные)
    "abused_tld":            10,   # .shop, .online, .site (дешёвые)
    "scam_pattern":          35,   # готовая схема: голосование+дети и т.п.
    "digits_in_domain":      10,   # g00gle.com
    "brand_impersonation":   45,   # бренд в чужом регистрируемом домене
    "brand_typosquat":       50,   # paypa1.com, gogle.com
    "brand_homograph":       60,   # аpple.com (кириллица)
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ── Ключи API ───────────────────────────────────────────────
    # Бесплатный ключ: https://console.cloud.google.com/
    # → включить "Safe Browsing API" → Credentials → Create API key
    GOOGLE_SAFE_BROWSING_KEY: str = ""
    # abuse.ch с 2024 г. требует Auth-Key даже для бесплатного доступа:
    # https://auth.abuse.ch/  (регистрация бесплатна)
    URLHAUS_AUTH_KEY: str = ""
    # Ключ Anthropic для уровня 1c. Единственный ПЛАТНЫЙ источник в
    # пайплайне: без ключа уровень просто выключается.
    # https://console.anthropic.com/settings/keys
    ANTHROPIC_API_KEY: str = ""

    # ── Метаданные сервиса ──────────────────────────────────────
    APP_NAME: str = "PhishGuard Backend"
    APP_VERSION: str = "1.1.0"
    ENVIRONMENT: str = "production"        # production | development
    DEBUG_DETAILS: bool = False            # отдавать ли внутренние ошибки клиенту

    # ── CORS ────────────────────────────────────────────────────
    # В проде сюда надо вписать домен фронтенда, а не "*".
    ALLOWED_ORIGINS: list[str] = Field(default_factory=lambda: ["*"])

    # ── Пороги риска ────────────────────────────────────────────
    PHISHING_THRESHOLD: int = 60           # >= → is_phishing = True
    SUSPICIOUS_MIN: int = 30               # [30, 60) → SUSPICIOUS

    # ── Пороги возраста домена (дни) ────────────────────────────
    DOMAIN_AGE_VERY_NEW: int = 7
    DOMAIN_AGE_NEW: int = 30
    DOMAIN_AGE_RECENT: int = 90

    # ── Структурные лимиты URL ──────────────────────────────────
    MAX_SUBDOMAINS: int = 3                # paypal.com.evil.ru → 4 метки
    MAX_URL_LENGTH: int = 100
    MAX_DOMAIN_LENGTH: int = 35            # длина SLD
    MAX_HYPHENS: int = 3

    # ── Лимиты входных данных (защита от DoS) ───────────────────
    MAX_INPUT_URL_LENGTH: int = 2048       # RFC-практика для URL
    BATCH_MAX_URLS: int = 20
    BATCH_CONCURRENCY: int = 5             # одновременных сканов в батче

    # ── Таймауты HTTP-клиентов (секунды) ────────────────────────
    GSB_TIMEOUT: float = 5.0
    URLHAUS_TIMEOUT: float = 6.0
    RDAP_TIMEOUT: float = 6.0
    WHOIS_TIMEOUT: float = 5.0
    # Общий бюджет уровня «возраст домена»: RDAP и WHOIS идут
    # последовательно, и без общего лимита их таймауты
    # складываются, делая этот уровень самым медленным в пайплайне.
    DOMAIN_AGE_TOTAL_TIMEOUT: float = 9.0
    DNS_TIMEOUT: float = 3.0
    RESOLVE_HOP_TIMEOUT: float = 4.0       # таймаут одного хопа редиректа
    RESOLVE_TOTAL_TIMEOUT: float = 10.0    # общий дедлайн разворачивания
    SCAN_TOTAL_TIMEOUT: float = 25.0       # дедлайн всего /scan

    # ── Разворачивание редиректов ───────────────────────────────
    ENABLE_URL_RESOLUTION: bool = True
    MAX_REDIRECTS: int = 8
    MAX_DOWNLOAD_BYTES: int = 65536        # не тянем тело целиком

    # ── Безопасность исходящих запросов ─────────────────────────
    # Выключать ТОЛЬКО для локальной разработки: это защита от SSRF.
    BLOCK_PRIVATE_ADDRESSES: bool = True

    # ── Уровень 1c: анализ языковой моделью ─────────────────────
    AI_ENABLED: bool = True                # ключ всё равно обязателен
    AI_MODEL: str = "claude-opus-5"
    AI_TIMEOUT: float = 12.0
    # Низкий effort: классификация короткой строки — простая задача,
    # и глубокое рассуждение здесь не окупается ни деньгами, ни временем.
    AI_EFFORT: str = "low"
    # Границы влияния модели на балл. ЭТО ГЛАВНАЯ ЗАЩИТА от инъекций
    # через URL: что бы модель ни вернула, дальше этих чисел она балл
    # не сдвинет. Расширять их — значит отдавать модели больше власти,
    # чем имеет любой другой одиночный признак.
    AI_MAX_DELTA: int = 35
    AI_MIN_DELTA: int = -15

    # ── Кеширование ─────────────────────────────────────────────
    CACHE_TTL_SCAN: int = 900              # 15 мин на итоговый вердикт
    CACHE_TTL_DOMAIN_AGE: int = 86400      # сутки — дата регистрации не меняется
    CACHE_TTL_THREAT: int = 300            # 5 мин — угрозы меняются быстро
    CACHE_TTL_AI: int = 3600               # час: ответ модели платный
    CACHE_MAX_SIZE: int = 4096

    # ── Rate limiting ───────────────────────────────────────────
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS: int = 30          # запросов
    RATE_LIMIT_WINDOW: int = 60            # за столько секунд
    TRUST_PROXY_HEADERS: bool = True       # читать X-Forwarded-For (Render/Railway)

    # ── Веса ────────────────────────────────────────────────────
    WEIGHTS: dict[str, int] = Field(default_factory=lambda: dict(DEFAULT_WEIGHTS))

    # ── Валидаторы ──────────────────────────────────────────────

    @field_validator("WEIGHTS", mode="after")
    @classmethod
    def _merge_weights(cls, value: dict[str, int]) -> dict[str, int]:
        """WEIGHTS из окружения мержится с дефолтами: иначе частичное
        переопределение даёт KeyError в скорере."""
        merged = dict(DEFAULT_WEIGHTS)
        merged.update(value or {})
        return merged

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def _split_origins(cls, value: Any) -> Any:
        """Позволяет задать ALLOWED_ORIGINS='https://a.com,https://b.com'."""
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith("["):     # это JSON — разберёт pydantic
                return stripped
            return [o.strip() for o in stripped.split(",") if o.strip()]
        return value

    @field_validator("SUSPICIOUS_MIN", mode="after")
    @classmethod
    def _check_thresholds(cls, value: int, info: Any) -> int:
        threshold = info.data.get("PHISHING_THRESHOLD")
        if threshold is not None and value >= threshold:
            raise ValueError(
                "SUSPICIOUS_MIN must be lower than PHISHING_THRESHOLD"
            )
        return value

    # ── Производные свойства ────────────────────────────────────

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT.lower() in {"dev", "development", "local"}

    def weight(self, key: str) -> int:
        """Неизвестный ключ — 0 баллов и предупреждение, а не KeyError."""
        if key not in self.WEIGHTS:
            import logging
            logging.getLogger(__name__).warning("Unknown risk weight %r → 0", key)
        return int(self.WEIGHTS.get(key, 0))


settings = Settings()
