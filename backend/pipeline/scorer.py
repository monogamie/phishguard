"""Уровень 4: агрегация улик в балл 0-100 и вердикт.

Аддитивная модель с тремя переопределяющими правилами: пол 90 по
внешним базам, потолок для доверенных доменов, смягчение для
неразвёрнутых сокращателей."""

from __future__ import annotations

import logging
from typing import Optional

from config import settings
from models import (
    AiVerdictResult,
    DomainAgeResult,
    LexicalFeatures,
    RedirectInfo,
    ReputationResult,
    ScanResponse,
    Severity,
    Signal,
    ThreatIntelResult,
    Verdict,
)
from pipeline.threat_intel import THREAT_TYPE_LABELS

logger = logging.getLogger(__name__)

# Максимальный балл, который может получить домен из списка доверенных,
# если против него нет прямых улик от внешней разведки.
TRUSTED_DOMAIN_SCORE_CAP = 15

# Балл, выше которого не поднимается неразвёрнутая короткая ссылка:
# «мы не знаем, куда она ведёт» — это подозрение, а не приговор.
UNRESOLVED_SHORTENER_CAP = 45


class _SignalCollector:
    """Накопитель сигналов: балл и объяснение добавляются одной
    операцией, рассинхронизировать их нельзя."""

    def __init__(self) -> None:
        self.signals: list[Signal] = []
        self.score: int = 0

    def add(self, code: str, severity: Severity, title: str, detail: str,
            weight_key: Optional[str] = None, weight: Optional[int] = None) -> None:
        points = weight if weight is not None else (
            settings.weight(weight_key) if weight_key else 0
        )
        self.score += points
        self.signals.append(Signal(code=code, severity=severity,
                                   weight=points, title=title, detail=detail))

    def ok(self, code: str, title: str, detail: str) -> None:
        """Признак проверен, нарушений нет: интерфейс должен показывать
        не только плохое, но и что именно проверялось."""
        self.signals.append(Signal(code=code, severity=Severity.OK,
                                   weight=0, title=title, detail=detail))


def _verdict(score: int) -> Verdict:
    if score >= settings.PHISHING_THRESHOLD:
        return Verdict.PHISHING
    if score >= settings.SUSPICIOUS_MIN:
        return Verdict.SUSPICIOUS
    return Verdict.SAFE


def _confidence(gsb: ThreatIntelResult, reputation: ReputationResult,
                age: DomainAgeResult, redirects: Optional[RedirectInfo],
                ai: Optional[AiVerdictResult] = None) -> float:
    """Доля ответивших источников: пользователь должен отличать
    «проверено всеми, чисто» от «почти все недоступны»."""
    available = 1.0                       # лексика работает всегда
    total = 4.0
    if ai is not None:
        total += 1
        if ai.checked:
            available += 1
    if gsb.checked:
        available += 1
    if reputation.checked:
        available += 1
    if age.checked:
        available += 1
    if redirects is not None and redirects.resolved:
        total += 1
        available += 1
    return round(min(available / total, 1.0), 2)


def calculate_risk_score(
    url: str,
    original_url: str,
    gsb: ThreatIntelResult,
    reputation: ReputationResult,
    domain_age: DomainAgeResult,
    lexical: LexicalFeatures,
    redirects: Optional[RedirectInfo] = None,
    ai: Optional[AiVerdictResult] = None,
) -> ScanResponse:
    """
    Собирает улики всех уровней в итоговый ScanResponse.

    Args:
        url:          адрес, который реально анализировался (после редиректов)
        original_url: то, что ввёл пользователь
        gsb:          Google Safe Browsing (уровень 1)
        reputation:   URLhaus (уровень 1b)
        domain_age:   RDAP/WHOIS (уровень 2)
        lexical:      структурные признаки (уровень 3)
        redirects:    цепочка редиректов (уровень 0)
        ai:           мнение языковой модели (уровень 1c)
    """
    c = _SignalCollector()
    external_hit = False

    # ── Уровень 0: редиректы ─────────────────────────────────────
    if redirects is not None and redirects.hops > 0:
        chain_text = " → ".join(redirects.chain[-3:])
        if redirects.was_shortener:
            c.add("SHORTENER", Severity.WARN, "Сокращатель ссылок",
                  f"Ссылка скрыта сервисом сокращения и ведёт на: {redirects.final_url}",
                  weight_key="shortener")
        if redirects.changed_domain:
            c.add("CROSS_DOMAIN_REDIRECT", Severity.WARN, "Смена домена",
                  f"Переадресация уводит на другой домен: {chain_text}",
                  weight_key="cross_domain_redirect")
        if redirects.hops > 2:
            c.add("LONG_REDIRECT_CHAIN", Severity.WARN, "Длинная цепочка",
                  f"{redirects.hops} последовательных переадресаций — "
                  f"типичный приём сокрытия конечного адреса",
                  weight_key="long_redirect_chain")
    elif redirects is not None and redirects.was_shortener and not redirects.resolved:
        c.add("SHORTENER_UNRESOLVED", Severity.WARN, "Ссылка не развёрнута",
              "Это сокращённая ссылка, но развернуть её не удалось — "
              "конечный адрес неизвестен",
              weight_key="shortener")

    # ── Уровень 1: Google Safe Browsing ──────────────────────────
    if gsb.is_threat:
        external_hit = True
        labels = ", ".join(THREAT_TYPE_LABELS.get(t, t) for t in gsb.threat_types)
        c.add("GSB_MATCH", Severity.DANGER, "Google Safe Browsing",
              f"Адрес числится в базе угроз Google. Категории: {labels}",
              weight_key="google_safe_browsing")
        logger.warning("GSB confirmed threat for %s: %s", url, gsb.threat_types)
    elif gsb.checked:
        c.ok("GSB_CLEAN", "Google Safe Browsing", "В базе угроз Google не найден")

    # ── Уровень 1b: URLhaus ──────────────────────────────────────
    if reputation.url_listed:
        external_hit = True
        c.add("URLHAUS_URL", Severity.DANGER, "URLhaus",
              f"Ссылка есть в базе вредоносных URL abuse.ch. "
              f"Тип угрозы: {reputation.threat or 'malware'}",
              weight_key="urlhaus_url")
    if reputation.host_listed:
        external_hit = True
        c.add("URLHAUS_HOST", Severity.DANGER, "URLhaus: хост",
              f"С этого хоста уже раздавали вредоносное ПО "
              f"(зафиксировано ссылок: {reputation.host_url_count})",
              weight_key="urlhaus_host")
    if reputation.checked and not (reputation.url_listed or reputation.host_listed):
        c.ok("URLHAUS_CLEAN", "URLhaus", "В базе вредоносных URL не найден")

    # ── Уровень 2: возраст домена ────────────────────────────────
    age_days = domain_age.age_days
    if domain_age.checked and age_days is not None:
        if age_days < settings.DOMAIN_AGE_VERY_NEW:
            c.add("DOMAIN_VERY_NEW", Severity.DANGER, "Возраст домена",
                  f"Домен зарегистрирован {age_days} дн. назад. Легитимные "
                  f"сервисы не запускаются на домене возрастом в несколько дней",
                  weight_key="domain_very_new")
        elif age_days < settings.DOMAIN_AGE_NEW:
            c.add("DOMAIN_NEW", Severity.WARN, "Возраст домена",
                  f"Домену {age_days} дн. — меньше месяца. Большинство "
                  f"фишинговых доменов моложе 30 дней",
                  weight_key="domain_new")
        elif age_days < settings.DOMAIN_AGE_RECENT:
            c.add("DOMAIN_RECENT", Severity.WARN, "Возраст домена",
                  f"Домену {age_days} дн. — меньше трёх месяцев",
                  weight_key="domain_recent")
        else:
            years = age_days / 365.25
            c.ok("DOMAIN_MATURE", "Возраст домена",
                 f"Домену {years:.1f} г. — зрелый домен с историей")
    elif domain_age.checked and domain_age.error:
        c.add("DOMAIN_NOT_REGISTERED", Severity.WARN, "Регистрация домена",
              domain_age.error, weight_key="domain_age_unknown")
    else:
        # Недоступность WHOIS/RDAP — слабый сигнал: у одноразовых
        # доменов данные часто скрыты, но и у нормальных ccTLD тоже.
        c.add("DOMAIN_AGE_UNKNOWN", Severity.INFO, "Возраст домена",
              "Дату регистрации получить не удалось",
              weight_key="domain_age_unknown")

    # ── Уровень 3: структура и лексика ───────────────────────────
    if lexical.has_ip_address:
        c.add("IP_IN_URL", Severity.DANGER, "IP вместо домена",
              "Адрес задан IP-адресом. У легитимных сервисов есть доменное "
              "имя и сертификат на него",
              weight_key="ip_in_url")

    if lexical.has_at_symbol:
        c.add("AT_SYMBOL", Severity.DANGER, "Символ @ в адресе",
              "Всё, что стоит до @, браузер считает логином и игнорирует. "
              "В http://sberbank.ru@evil.top настоящий сайт — evil.top",
              weight_key="at_symbol")

    # Бренд-имперсонация: три разных веса под три разные техники.
    brand = lexical.brand_match
    if brand:
        if brand.kind == "homograph":
            c.add("BRAND_HOMOGRAPH", Severity.DANGER, "Подмена символов",
                  f"Домен визуально неотличим от «{brand.brand}», но записан "
                  f"другими символами: {brand.evidence}",
                  weight_key="brand_homograph")
        elif brand.kind == "typosquat":
            c.add("BRAND_TYPOSQUAT", Severity.DANGER, "Опечаточный домен",
                  f"Домен отличается от «{brand.brand}» на пару символов: "
                  f"{brand.evidence}",
                  weight_key="brand_typosquat")
        else:
            c.add("BRAND_IMPERSONATION", Severity.DANGER, "Чужой бренд в домене",
                  f"Имя «{brand.brand}» использовано в домене, который бренду "
                  f"не принадлежит: {brand.evidence}",
                  weight_key="brand_impersonation")
    elif not lexical.is_trusted_domain:
        c.ok("BRAND_CLEAN", "Имитация брендов", "Имитации известных брендов не обнаружено")

    if lexical.has_punycode and not (brand and brand.kind == "homograph"):
        c.add("PUNYCODE", Severity.WARN, "Punycode (IDN)",
              f"Домен закодирован как xn--… и отображается как "
              f"«{lexical.decoded_host or lexical.host}»",
              weight_key="punycode")

    if lexical.has_mixed_scripts:
        c.add("MIXED_SCRIPTS", Severity.DANGER, "Смешение алфавитов",
              "В одном слове домена соседствуют символы разных алфавитов "
              "(например, латиница и кириллица) — признак подмены",
              weight_key="mixed_scripts")
    elif lexical.has_non_ascii_host:
        c.add("NON_ASCII_HOST", Severity.WARN, "Не-ASCII символы в домене",
              "Домен содержит символы вне латиницы",
              weight_key="non_ascii_host")

    if lexical.has_encoded_host:
        c.add("ENCODED_HOST", Severity.WARN, "Кодирование в домене",
              "В доменной части использовано процентное кодирование (%XX) — "
              "легитимные домены так не записывают",
              weight_key="encoded_host")

    if lexical.has_non_standard_port:
        c.add("NON_STANDARD_PORT", Severity.WARN, "Нестандартный порт",
              "Веб-сервисы работают на портах 80 и 443. Другой порт означает "
              "самодельный сервер, а не хостинг компании",
              weight_key="non_standard_port")

    if lexical.is_insecure_scheme:
        c.add("INSECURE_SCHEME", Severity.WARN, "Соединение без шифрования",
              "Используется http:// — данные, введённые на странице, "
              "передаются открытым текстом",
              weight_key="insecure_scheme")

    if lexical.has_redirect_params:
        c.add("REDIRECT_PARAMS", Severity.WARN, "Параметры переадресации",
              "В адресе есть параметры вида ?url= / ?goto= / ?redirect= — "
              "через них легитимный сайт используют как трамплин",
              weight_key="redirect_params")

    if lexical.subdomain_count > settings.MAX_SUBDOMAINS:
        c.add("EXCESSIVE_SUBDOMAINS", Severity.WARN, "Много поддоменов",
              f"Уровней поддоменов: {lexical.subdomain_count}. Настоящий домен — "
              f"всегда последние две части адреса, остальное подставляет владелец",
              weight_key="excessive_subdomains")

    if lexical.url_length > settings.MAX_URL_LENGTH:
        c.add("LONG_URL", Severity.INFO, "Длинный адрес",
              f"{lexical.url_length} символов — длинный адрес мешает разглядеть "
              f"настоящий домен в адресной строке",
              weight_key="long_url")

    if lexical.domain_length > settings.MAX_DOMAIN_LENGTH:
        c.add("LONG_DOMAIN", Severity.INFO, "Длинное имя домена",
              f"{lexical.domain_length} символов в имени домена",
              weight_key="long_domain")

    if lexical.hyphen_count > settings.MAX_HYPHENS:
        c.add("EXCESSIVE_HYPHENS", Severity.WARN, "Много дефисов",
              f"{lexical.hyphen_count} дефисов в домене — обычный приём "
              f"«склейки» правдоподобного имени",
              weight_key="excessive_hyphens")

    if lexical.trigger_keywords:
        words = ", ".join(lexical.trigger_keywords[:6])
        many = len(lexical.trigger_keywords) >= 2
        c.add("TRIGGER_KEYWORDS", Severity.WARN if many else Severity.INFO,
              "Тревожные слова в адресе",
              f"Найдено: {words}. Такие слова создают ощущение срочности "
              f"и подталкивают ввести данные",
              weight_key="trigger_keywords_many" if many else "trigger_keywords")

    if lexical.suspicious_tld:
        c.add("SUSPICIOUS_TLD", Severity.WARN, "Подозрительная зона",
              f"Зона .{lexical.tld} раздаётся бесплатно или почти бесплатно, "
              f"поэтому её массово используют для одноразовых доменов",
              weight_key="suspicious_tld")

    elif lexical.abused_tld:
        c.add("ABUSED_TLD", Severity.INFO, "Дешёвая доменная зона",
              f"Зона .{lexical.tld} стоит копейки, поэтому в ней много "
              f"одноразовых сайтов. Сама по себе не опасна, но в сочетании "
              f"с другими признаками — повод насторожиться",
              weight_key="abused_tld")

    if lexical.scam_pattern:
        from pipeline.lexical_analyzer import SCAM_PATTERN_LABELS
        label = SCAM_PATTERN_LABELS.get(lexical.scam_pattern, lexical.scam_pattern)
        c.add("SCAM_PATTERN", Severity.DANGER, "Узнаваемая схема обмана",
              f"Адрес построен по известной схеме: {label}. Отдельные слова тут "
              f"безобидны, опасна именно их связка — так устроены массовые "
              f"рассылки, ворующие аккаунты",
              weight_key="scam_pattern")

    if lexical.has_digits_in_domain:
        c.add("DIGITS_IN_DOMAIN", Severity.INFO, "Цифры в домене",
              "Цифры в имени домена часто заменяют похожие буквы (0 → o, 1 → l)",
              weight_key="digits_in_domain")

    # ── Уровень 1c: мнение языковой модели ───────────────────────
    # Вес не фиксирован: им СЛУЖИТ сама поправка, уже зажатая в
    # границы конфига внутри ai_analyzer. Скорер к этому числу
    # относится как к любому другому весу и ничего не пересчитывает.
    if ai is not None and ai.checked:
        if ai.delta > 0:
            severity = Severity.DANGER if ai.delta >= 25 else Severity.WARN
            title = ("Имитация бренда «%s»" % ai.brand) if ai.brand else "Анализ модели"
            c.add("AI_SUSPICIOUS", severity, title,
                  ai.summary or "Модель считает адрес подозрительным",
                  weight=ai.delta)
        elif ai.delta < 0:
            c.add("AI_REASSURING", Severity.INFO, "Анализ модели",
                  ai.summary or "Модель не нашла признаков мошенничества",
                  weight=ai.delta)
        else:
            c.ok("AI_CLEAN", "Анализ модели",
                 ai.summary or "Модель не нашла признаков мошенничества")

    # ── Финальная нормализация ───────────────────────────────────
    score = c.score

    # Правило 1: пол по внешней разведке.
    if external_hit:
        score = max(score, 90)

    # Правило 2: потолок доверия (не применяется поверх внешних улик).
    if lexical.is_trusted_domain and not external_hit:
        if score > TRUSTED_DOMAIN_SCORE_CAP:
            logger.info("Trusted domain %s: capping score %d → %d",
                        lexical.registered_domain, score, TRUSTED_DOMAIN_SCORE_CAP)
        score = min(score, TRUSTED_DOMAIN_SCORE_CAP)
        c.ok("TRUSTED_DOMAIN", "Репутация домена",
             f"{lexical.registered_domain} — известный домен с проверенной репутацией")

    # Правило 3: смягчение для неразвёрнутых сокращателей.
    if (lexical.is_shortener and redirects is not None
            and not redirects.resolved and not external_hit):
        score = min(score, UNRESOLVED_SHORTENER_CAP)

    score = max(0, min(score, 100))
    verdict = _verdict(score)

    # Сортируем по весу: самое важное — первым. Без этого порядок
    # зависел бы от порядка правил в коде, а не от значимости.
    c.signals.sort(key=lambda s: (-s.weight, s.code))

    logger.info("Score for %s: %d (%s), signals=%d, confidence=%.2f",
                url, score, verdict.value, len(c.signals),
                _confidence(gsb, reputation, domain_age, redirects, ai))

    details = {
        "threat_intel": gsb.model_dump(),
        "reputation": reputation.model_dump(),
        "domain_age": domain_age.model_dump(),
        "lexical": lexical.model_dump(),
    }
    if ai is not None:
        details["ai"] = ai.model_dump()

    return ScanResponse(
        url=original_url,
        scanned_url=url,
        is_phishing=score >= settings.PHISHING_THRESHOLD,
        risk_score=score,
        verdict=verdict,
        confidence=_confidence(gsb, reputation, domain_age, redirects, ai),
        signals=c.signals,
        # reasons сохранён для обратной совместимости со старым фронтендом.
        reasons=[f"{s.title}: {s.detail}" for s in c.signals
                 if s.severity != Severity.OK],
        redirects=redirects,
        details=details,
    )


__all__ = ["calculate_risk_score"]
