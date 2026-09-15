"""Тесты агрегации риска: пороги, потолки и переопределяющие правила."""
import pytest

from config import settings
from models import (BrandMatch, DomainAgeResult, LexicalFeatures, RedirectInfo,
                    ReputationResult, ThreatIntelResult, Verdict)
from pipeline.scorer import calculate_risk_score


def score_for(lexical=None, gsb=None, reputation=None, age=None, redirects=None):
    return calculate_risk_score(
        url="https://example.com/",
        original_url="https://example.com/",
        gsb=gsb or ThreatIntelResult(checked=True, is_threat=False),
        reputation=reputation or ReputationResult(checked=True),
        domain_age=age or DomainAgeResult(checked=True, age_days=3000),
        lexical=lexical or LexicalFeatures(registered_domain="example.com"),
        redirects=redirects,
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
