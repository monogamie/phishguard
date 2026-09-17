"""Тесты уровней 2b (сертификат), 2c (журналы CT) и 5 (страница)."""
import ssl
from datetime import datetime, timedelta, timezone

import pytest

from config import settings
from models import (CtResult, DomainAgeResult, LexicalFeatures, PageResult,
                    ReputationResult, Severity, ThreatIntelResult, TlsResult,
                    Verdict)
from pipeline.scorer import calculate_risk_score


# ── Уровень 2b: разбор сертификата ───────────────────────────────

from pipeline import tls_check as tc


def test_cert_date_parsed():
    assert tc._parse_cert_date("Jun  1 12:00:00 2026 GMT") is not None
    assert tc._parse_cert_date("мусор") is None
    assert tc._parse_cert_date(None) is None


@pytest.mark.parametrize("host,names,expected", [
    ("example.com", ["example.com"], True),
    ("a.example.com", ["*.example.com"], True),
    ("a.b.example.com", ["*.example.com"], False),   # маска на один уровень
    ("evil.top", ["example.com"], False),
    ("example.com", [], False),
])
def test_host_matches_cert_names(host, names, expected):
    assert tc._host_matches(host, names) is expected


def test_self_signed_detected():
    same = (( ("commonName", "x"), ),)
    assert tc._is_self_signed({"subject": same, "issuer": same}) is True
    assert tc._is_self_signed({
        "subject": ((("commonName", "x"),),),
        "issuer": ((("commonName", "CA"),),),
    }) is False


async def test_tls_skipped_for_http():
    r = await tc.check_tls("http://example.com/")
    assert r.checked is False


# ── Уровень 2c: разбор ответа журналов ───────────────────────────

from pipeline import ct_logs as ct


def test_ct_timestamps_parsed():
    assert ct._parse_ts("2026-09-10T12:00:00") is not None
    assert ct._parse_ts("2026-09-10 12:00:00") is not None
    assert ct._parse_ts("") is None
    assert ct._parse_ts("nonsense") is None


async def test_ct_rejects_bad_domain():
    assert (await ct.check_ct_logs("")).checked is False
    assert (await ct.check_ct_logs("localhost")).checked is False


# ── Уровень 5: разбор страницы ───────────────────────────────────

from pipeline import page_analyzer as pa

FAKE_PAGE = """<html><head><title>Голосование</title></head><body>
<p>Сбербанк поддерживает конкурс. Сбербанк партнёр. При поддержке Сбербанк.</p>
<form action="https://collector.top/save"><input type="hidden" name="a">
<input type="hidden" name="b"><input type="hidden" name="c">
<input type="password" name="p">
<button aria-label="Войти через Telegram">ОК</button></form></body></html>"""


def _parse(html):
    p = pa._PageParser()
    p.feed(html)
    p.close()
    return p


def test_password_field_found():
    assert _parse(FAKE_PAGE).has_password is True


def test_hidden_inputs_counted():
    assert _parse(FAKE_PAGE).hidden_inputs == 3


def test_cross_domain_form_detected():
    p = _parse(FAKE_PAGE)
    target = pa._cross_domain_form("https://born.playjoy-dash.shop/deti/9",
                                   p.form_actions)
    assert target and "collector.top" in target


def test_same_domain_form_is_not_flagged():
    p = _parse('<form action="/login"><input type="password"></form>')
    assert pa._cross_domain_form("https://shop.ru/login", p.form_actions) is None


def test_messenger_login_detected():
    text = " ".join(_parse(FAKE_PAGE).text_parts)
    found = [n for n, r in pa._MESSENGER_PATTERNS if r.search(text)]
    assert "telegram" in found


def test_brand_needs_several_mentions():
    """Одно упоминание бренда в тексте — это не поддельный сайт."""
    assert pa._brands_in_text("вчера читал новость про Сбербанк") == []
    assert "sberbank" in pa._brands_in_text("Сбербанк Сбербанк Сбербанк")


def test_script_contents_ignored():
    """Слова из скриптов не должны давать ложных совпадений."""
    p = _parse('<html><body><script>var a="Сбербанк Сбербанк Сбербанк";'
               '</script><p>привет</p></body></html>')
    assert pa._brands_in_text(" ".join(p.text_parts)) == []


def test_broken_markup_does_not_crash():
    p = _parse("<html><body><form><input type=password><div><p>не закрыто")
    assert p.has_password is True


async def test_page_level_can_be_disabled(monkeypatch):
    monkeypatch.setattr(settings, "PAGE_ENABLED", False)
    assert (await pa.analyze_page("https://example.com/")).checked is False


# ── Как новые уровни влияют на балл ──────────────────────────────

def _score(lexical=None, **kw):
    return calculate_risk_score(
        url="https://x.top/", original_url="https://x.top/",
        gsb=kw.pop("gsb", ThreatIntelResult(checked=True, is_threat=False)),
        reputation=ReputationResult(checked=True),
        domain_age=kw.pop("age", DomainAgeResult(checked=True, age_days=3000)),
        lexical=lexical or LexicalFeatures(registered_domain="x.top", scheme="https"),
        **kw,
    )


def test_cert_mismatch_raises_score():
    plain = _score()
    with_bad = _score(tls=TlsResult(checked=True, covers_domain=False))
    assert with_bad.risk_score > plain.risk_score
    assert any(s.code == "CERT_MISMATCH" for s in with_bad.signals)


def test_fresh_cert_flagged():
    r = _score(tls=TlsResult(checked=True, age_days=1, covers_domain=True))
    assert any(s.code == "CERT_VERY_NEW" for s in r.signals)


def test_old_cert_is_an_ok_signal():
    r = _score(tls=TlsResult(checked=True, age_days=400, covers_domain=True,
                             issuer="Let's Encrypt"))
    assert any(s.code == "CERT_OK" and s.severity == Severity.OK
               for s in r.signals)


def test_ct_used_only_when_domain_age_unknown():
    """
    Один факт «домен свежий» не должен считаться дважды: если RDAP
    уже сказал возраст, вес журналов не начисляется.
    """
    fresh_ct = CtResult(checked=True, first_seen_days=2)

    age_known = _score(age=DomainAgeResult(checked=True, age_days=2), ct=fresh_ct)
    assert not any(s.code == "CT_FIRST_SEEN_VERY_NEW" for s in age_known.signals)

    age_unknown = _score(age=DomainAgeResult(checked=False), ct=fresh_ct)
    assert any(s.code == "CT_FIRST_SEEN_VERY_NEW" for s in age_unknown.signals)


def test_ct_rescues_unknown_domain_age():
    """Главная польза журналов: возраст там, где RDAP молчит."""
    r = _score(age=DomainAgeResult(checked=False),
               ct=CtResult(checked=True, first_seen_days=1))
    assert r.verdict != Verdict.SAFE


def test_messenger_login_flagged():
    r = _score(page=PageResult(checked=True, messenger_login=["telegram"]))
    assert any(s.code == "PAGE_MESSENGER_LOGIN" for s in r.signals)


def test_cross_domain_form_flagged():
    r = _score(page=PageResult(checked=True,
                               cross_domain_form="https://collector.top/x"))
    assert any(s.code == "PAGE_CROSS_DOMAIN_FORM" for s in r.signals)


def test_foreign_brand_on_page_flagged():
    r = _score(page=PageResult(checked=True, brands_in_text=["sberbank"]))
    assert any(s.code == "PAGE_BRAND_MISMATCH" for s in r.signals)


def test_own_brand_on_page_not_flagged():
    """sberbank.ru имеет право писать «Сбербанк» у себя на странице."""
    lex = LexicalFeatures(registered_domain="sberbank.ru", scheme="https")
    r = _score(lexical=lex, page=PageResult(checked=True,
                                            brands_in_text=["sberbank"]))
    assert not any(s.code == "PAGE_BRAND_MISMATCH" for s in r.signals)


def test_password_form_not_flagged_on_trusted_domain():
    lex = LexicalFeatures(registered_domain="google.com", scheme="https",
                          is_trusted_domain=True)
    r = _score(lexical=lex, page=PageResult(checked=True,
                                            has_password_field=True))
    assert not any(s.code == "PAGE_PASSWORD_FORM" for s in r.signals)


def test_clean_page_is_an_ok_signal():
    r = _score(page=PageResult(checked=True))
    assert any(s.code == "PAGE_CLEAN" and s.severity == Severity.OK
               for s in r.signals)


def test_unavailable_levels_do_not_change_score():
    plain = _score()
    with_failed = _score(tls=TlsResult(checked=False),
                         ct=CtResult(checked=False),
                         page=PageResult(checked=False))
    assert with_failed.risk_score == plain.risk_score


def test_confidence_counts_new_sources():
    few = _score()
    many = _score(tls=TlsResult(checked=True, age_days=400),
                  ct=CtResult(checked=True, first_seen_days=500),
                  page=PageResult(checked=True))
    assert many.confidence >= few.confidence


def test_new_results_land_in_details():
    r = _score(tls=TlsResult(checked=True, age_days=5),
               ct=CtResult(checked=True, total_certs=7),
               page=PageResult(checked=True, form_count=2))
    assert r.details["tls"]["age_days"] == 5
    assert r.details["ct"]["total_certs"] == 7
    assert r.details["page"]["form_count"] == 2
