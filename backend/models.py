"""Схемы запросов и ответов (Pydantic v2).

Signal несёт машиночитаемый code вместо эмодзи в тексте — это
позволяет фронтенду раскрашивать и переводить результат."""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator

from normalize import normalize_authority

MAX_URL_LENGTH = 2048


# ── Перечисления ─────────────────────────────────────────────────

class Severity(str, Enum):
    """Степень опасности одного признака."""
    OK = "ok"        # признак проверен, всё в порядке
    INFO = "info"    # нейтральная информация
    WARN = "warn"    # подозрительно
    DANGER = "danger"  # явный признак атаки


class Verdict(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"


# ── Входящие ─────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """Запрос на скан. Валидатор отбивает всё, что раньше давало 500:
    нестроковый ввод, битый порт, не-http схему, управляющие символы."""
    url: str = Field(..., max_length=MAX_URL_LENGTH,
                     examples=["https://paypal.com.evil.ru/login"])

    @field_validator("url", mode="before")
    @classmethod
    def normalise_url(cls, v: Any) -> str:
        # 1. Тип. Всё, что не строка, — это 422, а не 500.
        if not isinstance(v, str):
            raise ValueError("URL must be a string")

        v = v.strip()
        if not v:
            raise ValueError("URL must not be empty")
        if len(v) > MAX_URL_LENGTH:
            raise ValueError(f"URL is longer than {MAX_URL_LENGTH} characters")

        # 2. Управляющие символы. \r\n в URL — это CRLF-инъекция
        #    в исходящий HTTP-запрос (request splitting).
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in v):
            raise ValueError("URL must not contain control characters")

        # 3. Схема. Дописываем https:// только если схемы нет вообще.
        #    Если схема есть, но она не http(s) — отказ.
        lowered = v.lower()
        if "://" in v[:16] or lowered.startswith(("javascript:", "data:",
                                                  "file:", "vbscript:",
                                                  "blob:", "about:")):
            if not lowered.startswith(("http://", "https://")):
                scheme = v.split(":", 1)[0]
                raise ValueError(
                    f"Unsupported URL scheme {scheme!r}: only http and https are allowed"
                )
        else:
            v = "https://" + v

        # 4. Обратный слеш в адресной части браузер считает разделителем,
        #    а urlsplit — нет. Приводим здесь, на входе, чтобы ВСЕ уровни
        #    (и проверка SSRF, и скачивание страницы) шли туда же, куда
        #    уйдёт жертва, а не на домен, спрятанный справа от слеша.
        v = normalize_authority(v)

        # 5. Хост обязан существовать и быть разбираемым.
        #    urlsplit ленив: .hostname/.port бросают ValueError только
        #    при обращении, поэтому трогаем их здесь, а не в пайплайне.
        try:
            parts = urlsplit(v)
            host = parts.hostname
            _ = parts.port          # ValueError, если порт не число
        except ValueError as exc:
            raise ValueError(f"Malformed URL: {exc}") from exc

        if not host:
            raise ValueError(f"Cannot extract hostname from: {v!r}")
        if "." not in host and host != "localhost" and not host.startswith("["):
            raise ValueError(f"Hostname {host!r} has no TLD")

        return v


class BatchScanRequest(BaseModel):
    """Тело для /batch."""
    urls: list[str] = Field(..., min_length=1, max_length=20)


# ── Внутренние результаты этапов пайплайна ───────────────────────

class ThreatIntelResult(BaseModel):
    checked: bool = False
    is_threat: bool = False
    threat_types: list[str] = Field(default_factory=list)
    source: Optional[str] = None
    error: Optional[str] = None


class ReputationResult(BaseModel):
    """Результат проверки по базе URLhaus (abuse.ch)."""
    checked: bool = False
    url_listed: bool = False
    host_listed: bool = False
    threat: Optional[str] = None
    host_url_count: int = 0
    error: Optional[str] = None


class AiVerdictResult(BaseModel):
    """Мнение модели. `raw_delta` — ответ до зажима: если в логах он
    регулярно упирается в границы, это либо плохие границы, либо
    попытки инъекции через URL."""
    checked: bool = False
    skipped: bool = False   # не запускали нарочно, а не сбой
    delta: int = 0
    raw_delta: int = 0
    confidence: Optional[str] = None       # low | medium | high
    brand: Optional[str] = None
    summary: Optional[str] = None
    model: Optional[str] = None
    input_tokens: int = 0
    output_tokens: int = 0
    error: Optional[str] = None


class _AiModelOutput(BaseModel):
    """Сырой ответ модели до валидации."""
    delta: int
    confidence: str
    brand: str = ""
    summary: str = ""


class DomainAgeResult(BaseModel):
    """Возраст домена. `source` — rdap или whois: RDAP структурирован
    и надёжнее, WHOIS парсится эвристиками."""
    checked: bool = False
    age_days: Optional[int] = None
    creation_date: Optional[str] = None
    registrar: Optional[str] = None
    source: Optional[str] = None
    error: Optional[str] = None


class TlsResult(BaseModel):
    """Данные сертификата. Мы его ИНСПЕКТИРУЕМ, а не доверяем ему."""
    checked: bool = False
    skipped: bool = False   # не запускали нарочно, а не сбой
    age_days: Optional[int] = None          # сколько дней назад выпущен
    issued_at: Optional[str] = None
    expires_at: Optional[str] = None
    issuer: Optional[str] = None
    covers_domain: Optional[bool] = None    # домен есть в SAN сертификата
    self_signed: bool = False
    expired: bool = False
    handshake_failed: bool = False
    error: Optional[str] = None


class CtResult(BaseModel):
    """
    Журналы Certificate Transparency.

    `first_seen_days` — сколько дней назад на домен впервые выпустили
    сертификат. Это независимая оценка возраста домена: работает даже
    когда RDAP и WHOIS молчат, что для части ccTLD обычное дело.
    """
    checked: bool = False
    skipped: bool = False   # не запускали нарочно, а не сбой
    first_seen_days: Optional[int] = None
    first_seen_at: Optional[str] = None
    # None — «мы не дочитали ответ», 0 — «журналы ответили: записей нет».
    # Разница важна: без неё домен с десятками тысяч сертификатов
    # получал признак «сертификат не выпускали ни разу».
    total_certs: Optional[int] = None
    issuers: list[str] = Field(default_factory=list)
    error: Optional[str] = None


class PageResult(BaseModel):
    """
    Признаки, найденные в HTML страницы.

    Закрывает главный пробел остальных уровней: они смотрят только на
    адрес, а половина улик мошеннической страницы — в её содержимом.
    """
    checked: bool = False
    skipped: bool = False   # не запускали нарочно, а не сбой
    status_code: Optional[int] = None
    final_url: Optional[str] = None            # если был редирект
    title: Optional[str] = None
    has_password_field: bool = False
    messenger_login: list[str] = Field(default_factory=list)   # telegram, vk, …
    cross_domain_form: Optional[str] = None    # куда уходит форма
    brands_in_text: list[str] = Field(default_factory=list)
    hidden_input_count: int = 0
    form_count: int = 0
    bytes_read: int = 0
    error: Optional[str] = None


class BrandMatch(BaseModel):
    """Найденная имперсонация бренда."""
    brand: str
    kind: str          # "impersonation" | "typosquat" | "homograph"
    evidence: str      # что именно совпало — для объяснения пользователю


class LexicalFeatures(BaseModel):
    """Сырые признаки, извлечённые из URL до скоринга."""
    scheme:                str = "https"
    host:                  str = ""
    registered_domain:     str = ""
    trust_domain:          str = ""    # единица доверия (приватный PSL)
    tld:                   str = ""
    has_ip_address:        bool = False
    has_at_symbol:         bool = False
    has_punycode:          bool = False
    idn_is_native:         bool = False    # .рф и подобные: нелатиница тут норма
    has_non_ascii_host:    bool = False
    has_mixed_scripts:     bool = False
    has_non_standard_port: bool = False
    has_encoded_host:      bool = False
    has_redirect_params:   bool = False
    has_digits_in_domain:  bool = False
    is_insecure_scheme:    bool = False
    is_shortener:          bool = False
    subdomain_count:       int = 0
    url_length:            int = 0
    domain_length:         int = 0
    hyphen_count:          int = 0
    trigger_keywords:      list[str] = Field(default_factory=list)
    suspicious_tld:        bool = False
    abused_tld:            bool = False
    scam_pattern:          Optional[str] = None   # fake_vote | fake_payout | fake_prize
    is_trusted_domain:     bool = False
    brand_match:           Optional[BrandMatch] = None
    decoded_host:          Optional[str] = None   # хост после punycode-декода


class RedirectInfo(BaseModel):
    """Цепочка редиректов."""
    resolved: bool = False
    final_url: Optional[str] = None
    chain: list[str] = Field(default_factory=list)
    hops: int = 0
    was_shortener: bool = False
    changed_domain: bool = False
    error: Optional[str] = None


# ── Исходящие ────────────────────────────────────────────────────

class Signal(BaseModel):
    """Одно сработавшее правило. `code` — стабильный идентификатор,
    на который опирается фронтенд вместо разбора текста."""
    code: str
    severity: Severity
    weight: int = 0
    title: str
    detail: str


class ScanResponse(BaseModel):
    """Итоговый JSON ответа."""
    url:          str
    scanned_url:  str
    is_phishing:  bool
    risk_score:   int = Field(..., ge=0, le=100)
    verdict:      Verdict
    confidence:   float = Field(0.0, ge=0.0, le=1.0)
    signals:      list[Signal] = Field(default_factory=list)
    reasons:      list[str] = Field(default_factory=list)
    redirects:    Optional[RedirectInfo] = None
    details:      dict = Field(default_factory=dict)
    elapsed_ms:   int = 0
    cached:       bool = False


class ErrorResponse(BaseModel):
    detail: str
    code: str = "internal_error"
