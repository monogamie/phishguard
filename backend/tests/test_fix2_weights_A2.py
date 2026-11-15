"""
G-02 / H-05, вариант А2: цифры и скрытые поля — пометки без веса;
«возраст неизвестен» весит, только когда его не знает никто.
Сильный признак не должен становиться приговором от того, что реестр
промолчал, в имени есть цифра или в форме есть скрытые поля.
"""
import pytest

from models import (CtResult, DomainAgeResult, PageResult, ReputationResult,
                    ThreatIntelResult, TlsResult, Verdict)
from pipeline.lexical_analyzer import lexical_analyzer as la
from pipeline.scorer import calculate_risk_score

SILENT = DomainAgeResult(checked=False, error="реестр молчит")
NO_CT = CtResult(checked=False, error="журналы недоступны")
HIDDEN = PageResult(checked=True, status_code=200, form_count=1,
                    hidden_input_count=5, bytes_read=8000)


def score(url, **kw):
    base = dict(
        gsb=ThreatIntelResult(checked=True),
        reputation=ReputationResult(checked=True),
        domain_age=DomainAgeResult(checked=True, age_days=4000),
        tls=TlsResult(checked=True, age_days=120, covers_domain=True),
        ct=CtResult(checked=True, first_seen_days=4000, total_certs=30),
    )
    base.update(kw)
    return calculate_risk_score(url=url, original_url=url,
                                lexical=la.analyze(url), **base)


@pytest.mark.parametrize("extra", [
    dict(domain_age=SILENT),
    dict(page=HIDDEN),
], ids=["реестр молчит, возраст знают журналы", "скрытые поля"])
@pytest.mark.parametrize("url", [
    "https://sberbank-insurance.ru/",      # бренд в имени, 55
    "https://paypa1.com/",                 # опечатка, 55
])
def test_a_trifle_does_not_change_the_verdict(url, extra):
    assert score(url, **extra).verdict == score(url).verdict


def test_brand_with_a_digit_in_the_name_is_not_red_by_the_digit():
    r = score("https://sberbank24-info.ru/")
    assert r.verdict == Verdict.SUSPICIOUS, r.risk_score


def test_trifles_stay_visible_as_notes():
    r = score("https://shop24.ru/", domain_age=SILENT, page=HIDDEN)
    codes = {s.code: s.weight for s in r.signals}
    assert codes["DIGITS_IN_DOMAIN"] == 0
    assert codes["DOMAIN_AGE_UNKNOWN"] == 0
    assert codes["PAGE_HIDDEN_INPUTS"] == 0
    assert r.risk_score == 0


def test_hidden_inputs_do_not_lift_the_trust_ceiling():
    r = score("https://vk.com/away.php?to=https://zloy-sayt.top/vhod", page=HIDDEN)
    assert r.risk_score <= 15


@pytest.mark.parametrize("url", [
    "https://sberbank-login.ru/",          # бренд + слово входа
    "https://sber-vhod.top/",
    "https://ozon-bonus.ru/",
])
def test_brand_plus_a_real_second_clue_is_still_red(url):
    assert score(url).verdict == Verdict.PHISHING


def test_age_nobody_knows_is_still_a_weak_clue():
    """Ссылка из истории проекта держится на «ПОДОЗРИТЕЛЬНО» именно
    этими баллами, когда молчат все (test_real_case_is_at_least_suspicious_offline)."""
    r = score("https://shop24.ru/", domain_age=SILENT, ct=NO_CT)
    assert {s.code: s.weight for s in r.signals}["DOMAIN_AGE_UNKNOWN"] == 5
