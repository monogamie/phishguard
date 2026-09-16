"""
models.py — схемы запросов и ответов (Pydantic v2).

Главное архитектурное изменение относительно первой версии:
появился тип `Signal` с МАШИНОЧИТАЕМЫМ кодом.

Раньше бэкенд отдавал только `reasons: list[str]` — строки на русском
с эмодзи, а фронтенд определял степень опасности так:

    const lvl = reason.includes('🚨') ? 'bad'
              : reason.includes('⚠')  ? 'warn' : 'ok';

Это плохо по трём причинам:
  1. Протокол завязан на эмодзи. Убрали эмодзи из строки — сломалась
     раскраска интерфейса.
  2. Локализация невозможна: перевести ответ на английский нельзя,
     не поломав парсинг.
  3. Интеграторам (а у нас заявлен «открытый API») не с чем работать
     программно: нельзя написать `if signal.code == "BRAND_HOMOGRAPH"`.

Теперь каждое срабатывание — объект с полями code/severity/weight,
а `reasons` остаётся как есть ради обратной совместимости.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator

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
    """
    Провалидированный запрос на скан.

    Исправленные баги первой версии:
      • Валидатор падал с AttributeError (→ HTTP 500) на любом
        нестроковом входе: {"url": 123} вызывало 123.strip().
        Pydantic превращает в 422 только ValueError/AssertionError.
      • Не было ограничения длины → можно было прислать 10 МБ строку
        и заставить сервер гонять по ней десяток регулярок.
      • Схема не проверялась: `javascript:alert(1)` превращалось в
        `https://javascript:alert(1)`, а дальше urlparse(...).port
        бросал ValueError уже внутри пайплайна — снова 500.
    """
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

        # 4. Хост обязан существовать и быть разбираемым.
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
    """
    Тело для /batch.

    Раньше эндпоинт принимал голый `list[str]`, из-за чего в OpenAPI
    он выглядел нетипизированным, а лимит в 20 URL проверялся руками
    уже внутри обработчика. Теперь ограничение описано схемой и
    отдаётся клиенту как честная 422 с указанием поля.
    """
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
    """
    Мнение языковой модели о ссылке.

    `delta` — уже зажатая поправка, которая пойдёт в балл.
    `raw_delta` — то, что вернула модель до зажима. Хранится отдельно
    специально для диагностики: если в логах видно, что raw_delta
    регулярно упирается в границы, это либо плохо подобранные границы,
    либо попытки инъекции через URL.
    """
    checked: bool = False
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
    """
    Схема того, что возвращает модель.

    Нужна отдельно от AiVerdictResult: сюда попадает сырой,
    непроверенный ответ внешней системы, и он обязан пройти
    валидацию прежде, чем что-то из него дойдёт до скорера.
    """
    delta: int
    confidence: str
    brand: str = ""
    summary: str = ""


class DomainAgeResult(BaseModel):
    """
    Возраст домена.

    `source` показывает, откуда взята дата: rdap или whois.
    Это важно для доверия к результату — RDAP структурирован и
    надёжен, WHOIS парсится эвристиками и врёт чаще.
    """
    checked: bool = False
    age_days: Optional[int] = None
    creation_date: Optional[str] = None
    registrar: Optional[str] = None
    source: Optional[str] = None
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
    tld:                   str = ""
    has_ip_address:        bool = False
    has_at_symbol:         bool = False
    has_punycode:          bool = False
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
    """
    Цепочка редиректов.

    В первой версии это возвращалось строкой, вклеенной в reasons —
    фронтенд не мог показать цепочку как список и подсветить смену
    домена.  Теперь это отдельная структура.
    """
    resolved: bool = False
    final_url: Optional[str] = None
    chain: list[str] = Field(default_factory=list)
    hops: int = 0
    was_shortener: bool = False
    changed_domain: bool = False
    error: Optional[str] = None


# ── Исходящие ────────────────────────────────────────────────────

class Signal(BaseModel):
    """
    Одно сработавшее правило.

    code     — стабильный машиночитаемый идентификатор (SCREAMING_SNAKE)
    severity — ok / info / warn / danger
    weight   — сколько баллов добавило это правило
    title    — короткая подпись для интерфейса
    detail   — человеческое объяснение «почему это плохо»
    """
    code: str
    severity: Severity
    weight: int = 0
    title: str
    detail: str


class ScanResponse(BaseModel):
    """
    Итоговый JSON.

    url          — то, что прислал пользователь
    scanned_url  — то, что реально анализировалось (после редиректов)
    is_phishing  — булев вердикт (risk_score >= PHISHING_THRESHOLD)
    risk_score   — агрегированный балл 0–100
    verdict      — SAFE | SUSPICIOUS | PHISHING
    confidence   — насколько мы уверены: сколько источников ответило
    signals      — структурированный список срабатываний
    reasons      — те же срабатывания строками (обратная совместимость)
    details      — сырые результаты этапов, для отладки и прозрачности
    """
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
