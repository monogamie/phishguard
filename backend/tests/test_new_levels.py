"""Тесты уровней 2b (сертификат), 2c (журналы CT) и 5 (страница)."""
import ssl
from pathlib import Path
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


def test_fresh_cert_counts_only_when_registry_is_silent():
    """Сертификат получают вместе с доменом — это один факт, не два.
    Пока обе ветки считались, свежий домен набирал 50 за домен плюс 30
    за сертификат: 80 из 60 нужных для «ОПАСНО» без единой улики."""
    fresh = TlsResult(checked=True, age_days=1, covers_domain=True)

    age_known = _score(age=DomainAgeResult(checked=True, age_days=2), tls=fresh)
    assert not any(s.code == "CERT_VERY_NEW" for s in age_known.signals)

    age_unknown = _score(age=DomainAgeResult(checked=False), tls=fresh)
    assert any(s.code == "CERT_VERY_NEW" for s in age_unknown.signals)


def test_renewed_cert_on_an_old_site_is_not_suspicious():
    """Let's Encrypt перевыпускает каждые 60–90 дней. Сайт с историей
    получал «ПОДОЗРИТЕЛЬНО» за вчерашнее продление сертификата."""
    r = _score(age=DomainAgeResult(checked=True, age_days=5000),
               tls=TlsResult(checked=True, age_days=4, covers_domain=True,
                             issuer="Let's Encrypt"))
    assert r.risk_score == 0
    assert r.verdict == Verdict.SAFE


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


def test_messenger_login_alone_costs_nothing():
    """Вход через ВК или Telegram есть у множества нормальных сайтов.
    Сам по себе он не улика: форум с таким входом получал 57 баллов,
    молодой стартап — 72, то есть «ОПАСНО»."""
    plain = _score()
    r = _score(page=PageResult(checked=True, status_code=200,
                               messenger_login=["vk"]))
    assert r.risk_score == plain.risk_score
    assert any(s.code == "PAGE_MESSENGER_LOGIN_OK" for s in r.signals)


def test_messenger_login_counts_next_to_real_evidence():
    """Рядом с чужим брендом он объясняет, КАК уведут аккаунт."""
    r = _score(page=PageResult(checked=True, status_code=200,
                               messenger_login=["telegram"],
                               brands_in_text=["sberbank"]))
    assert any(s.code == "PAGE_MESSENGER_LOGIN" and s.weight > 0
               for s in r.signals)


def test_password_field_alone_costs_nothing():
    """Поле пароля есть на любой странице входа."""
    plain = _score()
    r = _score(page=PageResult(checked=True, status_code=200,
                               has_password_field=True))
    assert r.risk_score == plain.risk_score


def test_password_field_counts_on_a_brand_new_domain():
    r = _score(age=DomainAgeResult(checked=True, age_days=2),
               page=PageResult(checked=True, status_code=200,
                               has_password_field=True))
    assert any(s.code == "PAGE_PASSWORD_FORM" and s.weight > 0
               for s in r.signals)


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
    r = _score(page=PageResult(checked=True, status_code=200))
    assert any(s.code == "PAGE_CLEAN" and s.severity == Severity.OK
               for s in r.signals)


def test_page_behind_bot_protection_is_not_called_clean():
    """403 от бот-защиты — это заглушка, а не «форм нет»."""
    r = _score(page=PageResult(checked=True, status_code=403,
                               title="Access denied"))
    assert not any(s.code == "PAGE_CLEAN" for s in r.signals)
    assert any(s.code == "PAGE_NOT_SEEN" for s in r.signals)


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


# ── Регрессии по ревью от 17 сентября ────────────────────────────

def test_ct_truncated_response_is_not_no_records():
    """Домен с десятками тысяч сертификатов — самый зрелый, а не
    «сертификат не выпускали ни разу». Раньше обрезанный по размеру
    ответ crt.sh давал ровно обратный вывод."""
    truncated = CtResult(checked=True, first_seen_days=None,
                         error="Слишком много сертификатов (домен с историей)")
    assert truncated.total_certs is None
    r = _score(ct=truncated)
    assert not any(s.code == "CT_NO_RECORDS" for s in r.signals)

    # А честный ответ «ноль» признак по-прежнему даёт.
    zero = _score(ct=CtResult(checked=True, total_certs=0))
    assert any(s.code == "CT_NO_RECORDS" for s in zero.signals)


def test_expired_cert_is_not_also_called_valid():
    r = _score(tls=TlsResult(checked=True, age_days=800, expired=True,
                             issuer="Let's Encrypt", covers_domain=True))
    codes = {s.code for s in r.signals}
    assert "CERT_EXPIRED" in codes
    assert "CERT_OK" not in codes


def test_fresh_domain_gets_no_reassuring_ct_signal():
    """Зелёное «домен известен 3 дн.» рядом с красным «домен только
    появился» читается как оправдание."""
    r = _score(age=DomainAgeResult(checked=True, age_days=3),
               ct=CtResult(checked=True, first_seen_days=3, total_certs=1))
    assert not any(s.code == "CT_CONFIRMS" for s in r.signals)


def test_deliberate_skip_does_not_lower_confidence():
    """Уровни, пропущенные нарочно, не должны выглядеть как упавшие:
    у доверенного домена достоверность выходила ниже, чем у случайного."""
    skipped = _score(ct=CtResult(checked=False, skipped=True, error="пропущено"),
                     page=PageResult(checked=False, skipped=True, error="пропущено"))
    failed = _score(ct=CtResult(checked=False, error="журналы недоступны"),
                    page=PageResult(checked=False, error="страница недоступна"))
    assert skipped.confidence == 1.0
    assert failed.confidence < skipped.confidence


def test_broken_form_action_does_not_kill_the_level():
    """`<form action="//[">` заставляет urljoin бросить ValueError.
    Раньше он летел из уровня целиком, и мошеннику хватало одной
    пустой формы, чтобы страница вообще не проверялась."""
    p = _parse('<form action="//["></form>'
               '<form action="https://collector.top/x"></form>')
    target = pa._cross_domain_form("https://shop.ru/", p.form_actions)
    assert target and "collector.top" in target


@pytest.mark.parametrize("text,expected", [
    # Порог одинаков для латиницы и кириллицы: раньше «сбербанк»
    # считался дважды (сам и как вложенное «сбер»), и двух упоминаний
    # хватало, тогда как для «tinkoff» требовалось три.
    ("Сбербанк повысил ставку. Сбербанк сообщил.", []),
    ("Tinkoff raised rates. Tinkoff said so.", []),
    # Границы слова: обычные русские слова — не бренды.
    ("Сбережения, сберегательный счёт, сберкнижка", []),
    ("Озонотерапия, озонотерапия, озонирование", []),
    (["ozon"], ["ozon"]),
])
def test_brand_text_matching_has_word_boundaries(text, expected):
    if isinstance(text, list):
        text = " ".join(f"{w} страница {w} вход {w}" for w in text)
    assert pa._brands_in_text(text) == expected


async def test_page_redirect_to_blocked_address_is_not_followed(monkeypatch):
    """
    Главная дыра из ревью: уровень страницы шёл по Location сам,
    через httpx, и проверка SSRF применялась только к первому адресу.
    Мошеннический сервер отвечал `302 Location: http://169.254.169.254/`
    и мы читали внутренний сервис хостинга, а его заголовок уходил
    клиенту в details.page.title.
    """
    checked: list[str] = []

    async def spy(url, **kw):
        checked.append(url)
        if "169.254.169.254" in url:
            raise pa.BlockedTargetError("внутренний адрес заблокирован")

    class FakeResponse:
        status_code = 302
        headers = {"location": "http://169.254.169.254/latest/meta-data/"}
        encoding = "utf-8"

        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def aiter_bytes(self):                    # pragma: no cover
            raise AssertionError("тело редиректа читать не должны")

    requested: list[str] = []

    class FakeClient:
        def stream(self, method, url, **kw):
            requested.append(url)
            assert kw["follow_redirects"] is False, \
                "httpx не должен ходить по редиректам сам"
            return FakeResponse()

    monkeypatch.setattr(pa, "assert_url_is_safe", spy)
    monkeypatch.setattr(pa, "get_client", lambda: FakeClient())
    monkeypatch.setattr(pa._cache, "_data", {})

    r = await pa.analyze_page("https://phish.top/start")

    assert r.checked is False
    assert r.title is None
    assert len(checked) == 2, "цель редиректа обязана проверяться тоже"
    assert requested == ["https://phish.top/start"], \
        "к внутреннему адресу запроса быть не должно"


def test_rdap_404_for_an_unserved_zone_is_not_a_missing_domain():
    """
    `rdap.org` отвечает 404 и на «домена нет», и на «эту зону я не
    обслуживаю». Для `.рф` верно второе, а сервис заявлял пользователю,
    что домен МВД не зарегистрирован — то есть врал про проверяемый факт.
    """
    import re
    source = (Path(__file__).resolve().parents[1]
              / "pipeline" / "domain_age.py").read_text(encoding="utf-8")
    branch = source[source.index("if resp.status_code == 404:"):]
    branch = branch[:branch.index("if resp.status_code != 200:")]
    assert "no rdap service" in branch.lower(), (
        "ветка 404 снова считает любой 404 доказательством, что домена нет"
    )
    assert re.search(r"return None", branch), (
        "при неизвестной зоне надо возвращать None, чтобы отработал WHOIS"
    )
