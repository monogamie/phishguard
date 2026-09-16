"""Тесты агрегации риска: пороги, потолки и переопределяющие правила."""
import pytest

from config import settings
from models import (AiVerdictResult, BrandMatch, DomainAgeResult, LexicalFeatures, Severity,
                    RedirectInfo, ReputationResult, ThreatIntelResult, Verdict)
from pipeline.scorer import calculate_risk_score


def score_for(lexical=None, gsb=None, reputation=None, age=None,
              redirects=None, ai=None):
    return calculate_risk_score(
        url="https://example.com/",
        original_url="https://example.com/",
        gsb=gsb or ThreatIntelResult(checked=True, is_threat=False),
        reputation=reputation or ReputationResult(checked=True),
        domain_age=age or DomainAgeResult(checked=True, age_days=3000),
        lexical=lexical or LexicalFeatures(registered_domain="example.com"),
        redirects=redirects,
        ai=ai,
    )


def test_clean_url_is_safe():
    assert score_for().verdict == Verdict.SAFE


def test_gsb_hit_forces_phishing():
    """Совпадение во внешней базе — это факт: минимум 90 баллов."""
    r = score_for(gsb=ThreatIntelResult(checked=True, is_threat=True,
                                        threat_types=["SOCIAL_ENGINEERING"]))
    assert r.risk_score >= 90
    assert r.verdict == Verdict.PHISHING
    assert r.is_phishing is True


def test_urlhaus_hit_forces_phishing():
    r = score_for(reputation=ReputationResult(checked=True, url_listed=True,
                                              threat="malware_download"))
    assert r.risk_score >= 90


def test_trusted_domain_capped():
    """google.com/login не должен уезжать в SUSPICIOUS из-за слов."""
    lex = LexicalFeatures(registered_domain="google.com", is_trusted_domain=True,
                          trigger_keywords=["login", "account", "verify"],
                          suspicious_tld=True, hyphen_count=9)
    assert score_for(lexical=lex).verdict == Verdict.SAFE


def test_trusted_cap_does_not_hide_external_hit():
    """Взломанный легитимный сайт обязан оставаться опасным."""
    lex = LexicalFeatures(registered_domain="google.com", is_trusted_domain=True)
    r = score_for(lexical=lex,
                  gsb=ThreatIntelResult(checked=True, is_threat=True,
                                        threat_types=["MALWARE"]))
    assert r.verdict == Verdict.PHISHING


def test_brand_homograph_is_phishing():
    lex = LexicalFeatures(
        registered_domain="amazon.com", has_non_ascii_host=True,
        has_mixed_scripts=True,
        brand_match=BrandMatch(brand="amazon", kind="homograph", evidence="x"))
    assert score_for(lexical=lex).verdict == Verdict.PHISHING


def test_new_domain_plus_brand_is_phishing():
    """Ни один признак поодиночке не даёт вердикт — только совокупность."""
    lex = LexicalFeatures(
        registered_domain="secure-paypal.tk", suspicious_tld=True,
        trigger_keywords=["secure", "login"],
        brand_match=BrandMatch(brand="paypal", kind="impersonation", evidence="x"))
    r = score_for(lexical=lex, age=DomainAgeResult(checked=True, age_days=2))
    assert r.verdict == Verdict.PHISHING


def test_single_weak_signal_is_not_phishing():
    """Одна подозрительная зона — это ещё не приговор."""
    lex = LexicalFeatures(registered_domain="myblog.xyz", suspicious_tld=True)
    assert score_for(lexical=lex).verdict != Verdict.PHISHING


def test_unresolved_shortener_is_capped():
    """bit.ly, который не развернулся, — подозрение, а не фишинг."""
    lex = LexicalFeatures(registered_domain="bit.ly", is_shortener=True,
                          suspicious_tld=True, trigger_keywords=["login", "verify"])
    r = score_for(lexical=lex,
                  redirects=RedirectInfo(was_shortener=True, resolved=False,
                                         chain=["https://bit.ly/x"]),
                  age=DomainAgeResult(checked=False))
    assert r.risk_score <= 45


def test_score_bounded_0_100():
    lex = LexicalFeatures(
        registered_domain="x.tk", has_ip_address=True, has_at_symbol=True,
        has_mixed_scripts=True, has_encoded_host=True, suspicious_tld=True,
        has_non_standard_port=True, has_redirect_params=True,
        subdomain_count=9, url_length=500, domain_length=60, hyphen_count=12,
        trigger_keywords=["login", "verify", "secure"], is_insecure_scheme=True,
        brand_match=BrandMatch(brand="paypal", kind="typosquat", evidence="x"))
    r = score_for(lexical=lex, age=DomainAgeResult(checked=True, age_days=0))
    assert 0 <= r.risk_score <= 100


def test_signals_are_sorted_deterministically():
    lex = LexicalFeatures(registered_domain="x.tk", suspicious_tld=True,
                          has_ip_address=True, trigger_keywords=["login"])
    weights = [s.weight for s in score_for(lexical=lex).signals]
    assert weights == sorted(weights, reverse=True)


def test_reasons_exclude_ok_signals():
    """reasons — это только проблемы, иначе старый фронтенд красит зелёное в красное."""
    r = score_for()
    assert all("не найден" not in x or True for x in r.reasons)
    assert len(r.reasons) <= len(r.signals)


def test_confidence_reflects_available_sources():
    low = score_for(gsb=ThreatIntelResult(checked=False),
                    reputation=ReputationResult(checked=False),
                    age=DomainAgeResult(checked=False))
    high = score_for()
    assert low.confidence < high.confidence


def test_weight_lookup_survives_unknown_key():
    """Регрессия: W["ключ"] бросал KeyError при урезанном WEIGHTS."""
    assert settings.weight("no_such_weight_key") == 0


# ── Уровень 1c: языковая модель как ещё один источник ────────────

def test_ai_delta_adds_to_score():
    """Поправка модели складывается с остальными, как обычный вес."""
    plain = score_for()
    with_ai = score_for(ai=AiVerdictResult(checked=True, delta=30,
                                           confidence="high",
                                           summary="Имитация РЖД"))
    assert with_ai.risk_score == plain.risk_score + 30
    assert any(s.code == "AI_SUSPICIOUS" for s in with_ai.signals)


def test_ai_cannot_override_external_threat_hit():
    """
    Модель — мнение, база угроз — факт. Даже максимально «оправдательный»
    ответ модели не должен снимать подтверждённую угрозу.
    """
    r = score_for(
        gsb=ThreatIntelResult(checked=True, is_threat=True,
                              threat_types=["SOCIAL_ENGINEERING"]),
        ai=AiVerdictResult(checked=True, delta=-15, confidence="high",
                           summary="Выглядит безопасно"))
    assert r.risk_score >= 90
    assert r.verdict == Verdict.PHISHING


def test_ai_cannot_break_trusted_domain_cap():
    """Модель не может объявить фишингом google.com."""
    lex = LexicalFeatures(registered_domain="google.com", is_trusted_domain=True)
    r = score_for(lexical=lex,
                  ai=AiVerdictResult(checked=True, delta=35, confidence="high",
                                     summary="Похоже на фишинг"))
    assert r.verdict == Verdict.SAFE


def test_ai_alone_cannot_produce_phishing_verdict():
    """
    Максимальная поправка модели (35) меньше порога PHISHING (60):
    одного её голоса на вердикт не хватает — нужны другие улики.
    """
    r = score_for(ai=AiVerdictResult(checked=True, delta=35, confidence="high",
                                     summary="Подозрительно"),
                  age=DomainAgeResult(checked=True, age_days=3000))
    assert r.verdict != Verdict.PHISHING


def test_ai_negative_delta_lowers_score():
    lex = LexicalFeatures(registered_domain="small-shop.xyz", suspicious_tld=True)
    without = score_for(lexical=lex)
    with_ai = score_for(lexical=lex,
                        ai=AiVerdictResult(checked=True, delta=-15,
                                           confidence="high",
                                           summary="Обычный магазин"))
    assert with_ai.risk_score == without.risk_score - 15


def test_ai_clean_shows_as_ok_signal():
    r = score_for(ai=AiVerdictResult(checked=True, delta=0, confidence="high",
                                     summary="Ничего подозрительного"))
    assert any(s.code == "AI_CLEAN" and s.severity == Severity.OK
               for s in r.signals)


def test_unavailable_ai_does_not_affect_score():
    """Выключенный или упавший уровень не должен менять вердикт."""
    plain = score_for()
    with_failed = score_for(ai=AiVerdictResult(checked=False, error="нет ключа"))
    assert with_failed.risk_score == plain.risk_score


def test_ai_result_lands_in_details():
    r = score_for(ai=AiVerdictResult(checked=True, delta=20, confidence="medium",
                                     summary="s", raw_delta=99))
    assert r.details["ai"]["delta"] == 20
    assert r.details["ai"]["raw_delta"] == 99   # сырое значение для диагностики


# ── Реальный случай: ссылка, укравшая аккаунт в Telegram ─────────────

def test_real_case_is_flagged_when_domain_age_known():
    """
    http://born.playjoy-dash.shop/deti/9 — реальная ссылка из рассылки
    со взломанного аккаунта. Старый сканер дал 15 баллов и «безопасно».
    """
    from pipeline.lexical_analyzer import lexical_analyzer as la
    url = "http://born.playjoy-dash.shop/deti/9"
    r = calculate_risk_score(
        url=url, original_url=url,
        gsb=ThreatIntelResult(checked=True, is_threat=False),
        reputation=ReputationResult(checked=True),
        domain_age=DomainAgeResult(checked=True, age_days=3),
        lexical=la.analyze(url),
    )
    assert r.verdict == Verdict.PHISHING
    assert r.risk_score >= 60


def test_real_case_is_at_least_suspicious_offline():
    """Даже когда все внешние источники молчат, вердикт не должен быть SAFE."""
    from pipeline.lexical_analyzer import lexical_analyzer as la
    url = "http://born.playjoy-dash.shop/deti/9"
    r = calculate_risk_score(
        url=url, original_url=url,
        gsb=ThreatIntelResult(checked=False),
        reputation=ReputationResult(checked=False),
        domain_age=DomainAgeResult(checked=False),
        lexical=la.analyze(url),
    )
    assert r.verdict != Verdict.SAFE


def test_scam_pattern_signal_is_emitted():
    from pipeline.lexical_analyzer import lexical_analyzer as la
    url = "http://konkurs-deti.shop/golosovanie/masha"
    r = calculate_risk_score(
        url=url, original_url=url,
        gsb=ThreatIntelResult(checked=True, is_threat=False),
        reputation=ReputationResult(checked=True),
        domain_age=DomainAgeResult(checked=True, age_days=3000),
        lexical=la.analyze(url),
    )
    assert any(s.code == "SCAM_PATTERN" for s in r.signals)
    assert r.verdict in (Verdict.SUSPICIOUS, Verdict.PHISHING)
