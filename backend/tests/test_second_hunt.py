"""
Находки второй охоты агентами (20 сентября), отчёт — `FINDINGS.md`.

Каждый тест назван по номеру находки, чтобы падение читалось вместе
с отчётом.
"""
import pytest

from models import (CtResult, DomainAgeResult, PageResult, ReputationResult,
                    ScanRequest, ThreatIntelResult, TlsResult)
from normalize import decode_punycode, mixed_scripts
from pipeline.lexical_analyzer import lexical_analyzer
from pipeline.scorer import calculate_risk_score

OLD = DomainAgeResult(checked=True, age_days=4000, source="rdap")
MATURE_CT = CtResult(checked=True, first_seen_days=3500, total_certs=500)
OFF = dict(checked=False, error="offline")


def score(url, **over):
    kw = dict(
        gsb=ThreatIntelResult(**OFF), reputation=ReputationResult(**OFF),
        domain_age=over.pop("age", OLD), tls=over.pop("tls", TlsResult(**OFF)),
        ct=over.pop("ct", MATURE_CT), page=over.pop("page", PageResult(**OFF)),
    )
    kw.update(over)
    normalised = ScanRequest(url=url).url
    return calculate_risk_score(url=normalised, original_url=normalised,
                                lexical=lexical_analyzer.analyze(normalised), **kw)


def weighted(result):
    return {s.code: s.weight for s in result.signals if s.weight}


def heavy(result):
    return {s.code for s in result.signals if s.weight >= 20}


# ── F-01. Одно имя в двух написаниях — один вердикт ──────────────

@pytest.mark.parametrize("ace,human", [
    # Обычный дефис и неразрывный: браузер оба сводит к одному домену,
    # а `idna.decode` второй разворачивать отказывается.
    ("xn----7sbbbax6afkrcdiwm.xn--p1ai", "сбербанк-онлайн.рф"),
    ("xn--80aabat1afiqbdhvl6097h.xn--p1ai", "сбербанк‐онлайн.рф"),
])
def test_f01_same_domain_same_verdict(ace, human):
    a = score(f"https://{ace}/vhod")
    b = score(f"https://{human}/vhod")
    assert a.risk_score == b.risk_score, (
        f"{ace} и {human} — один домен, а баллы разные: "
        f"{a.risk_score} против {b.risk_score}"
    )
    assert "BRAND_IMPERSONATION" in weighted(a)


def test_f01_decoder_does_not_give_up_on_idna2008():
    """Отказ `idna.decode` не должен оставлять нас с ACE-мусором:
    бренда в нём нет, зато есть цифры, которых в имени не было."""
    assert decode_punycode("xn--80aabat1afiqbdhvl6097h.xn--p1ai").startswith("сбербанк")
    assert decode_punycode("xn--micrsoft-zwg.com") == "Љmicrsoft.com"
    # Битый ACE по-прежнему остаётся как есть, а не роняет разбор.
    assert decode_punycode("xn--zzz-!!!.com") == "xn--zzz-!!!.com"


# ── F-02. Японский язык — не гомоглифная атака ───────────────────

@pytest.mark.parametrize("word", ["例え", "お名前", "日本語", "テスト", "한국어"])
def test_f02_asian_scripts_are_not_mixed(word):
    assert not mixed_scripts(word), f"«{word}» — живой язык, а не подмена"


@pytest.mark.parametrize("url", [
    "https://お名前.com",          # крупнейший регистратор Японии
    "https://日本語ドメイン.jp",
    "https://例え.テスト",          # официальный тестовый домен IANA
])
def test_f02_japanese_domains_are_clean(url):
    assert weighted(score(url)) == {}


@pytest.mark.parametrize("word", ["аpple", "сбeрбанк", "Љmicrsoft"])
def test_f02_latin_with_cyrillic_still_caught(word):
    assert mixed_scripts(word)


# ── F-03. Свой бренд в своей зоне — не подделка ──────────────────

@pytest.mark.parametrize("url", [
    "https://госуслуги.рф", "https://сбербанк.рф", "https://газпром.рф",
    "https://яндекс.рф", "https://сбер.рф", "https://vk.company",
    "https://vk.team", "https://alfa.travel",
])
def test_f03_brand_in_its_own_domain_is_clean(url):
    assert weighted(score(url, ct=MATURE_CT)) == {}


def test_f03_but_cheap_zone_is_still_a_grab():
    """Оговорка не должна покрывать захват имени в бесплатной зоне."""
    assert "BRAND_IMPERSONATION" in weighted(score("https://paypal.tk/"))


# ── F-04. Короткие синонимы совпадают с обычными словами ─────────

@pytest.mark.parametrize("url", [
    "https://alfa-remont.ru", "https://vk-service.ru", "https://wb-group.ru",
    "https://tg-stroy.ru", "https://icloud-repair.ru",
    "https://альфа-ремонт.рф", "https://pochta-service.ru",
])
def test_f04_ordinary_companies_are_not_impersonators(url):
    assert weighted(score(url)) == {}, "честная фирма, а не подделка бренда"


@pytest.mark.parametrize("url", [
    "https://sber-vhod.ru", "https://vk-login.ru", "https://alfa-vhod.ru",
    "https://wb-vyplata.ru", "https://pochta-vyplata.ru",
    "https://ozon-bonus.top", "https://сбербанк-онлайн.рф",
])
def test_f04_lure_next_to_the_name_is_still_caught(url):
    assert "BRAND_IMPERSONATION" in weighted(score(url))


# ── F-05. Схема из истории проекта — и кириллицей тоже ───────────

@pytest.mark.parametrize("url", [
    "https://детский-конкурс.рф/голосование",
    "https://голосование-за-детей.рф",
    "https://конкурс-рисунок.рф/голос",
    "https://golosovanie-za-rebenka.ru",
])
def test_f05_vote_scam_caught_in_both_spellings(url):
    assert lexical_analyzer.analyze(url).scam_pattern == "fake_vote"


@pytest.mark.parametrize("url", [
    "https://культура.рф/конкурс",
    "https://нацпроекты.рф/голосование",
    "https://детсад-ромашка.рф/",
])
def test_f05_honest_contests_stay_clean(url):
    assert lexical_analyzer.analyze(url).scam_pattern is None


# ── F-06. Поддомен — это тоже имя, которое видно ─────────────────

@pytest.mark.parametrize("url", [
    "https://update-billing.suspended-account.mydomain.ru/",
    "https://login.verify.confirm-account.example-cdn.com/signin",
])
def test_f06_keyword_subdomains_weigh(url):
    assert lexical_analyzer.analyze(url).keywords_in_host is True
    assert "TRIGGER_KEYWORDS" in weighted(score(url))


@pytest.mark.parametrize("url", [
    "https://id.rbc.ru/", "https://lk.megafon.ru/",
    "https://cabinet.tele2.ru/security/password/recovery",
    "https://login.example.com/",
    "https://mydomain.ru/secure/login/verify/account/update/confirm",
])
def test_f06_one_service_label_is_not_an_accusation(url):
    assert lexical_analyzer.analyze(url).keywords_in_host is False
    assert "TRIGGER_KEYWORDS" not in weighted(score(url))


# ── F-10, F-13. Один факт — один весомый признак ─────────────────

def test_f10_server_sees_the_microsoft_lookalike():
    assert "BRAND_TYPOSQUAT" in weighted(score("https://xn--micrsoft-zwg.com/"))


@pytest.mark.parametrize("url", [
    "https://xn--micrsoft-zwg.com/",   # бренд + смешение + punycode
    "https://сбeрбанк.com/",           # смешение + punycode
    "https://аpple.com/",              # гомоглиф бренда
    "https://xn--80aabat1afiqbdhvl6097h.xn--p1ai/vhod",
])
def test_f13_one_heavy_signal_per_host(url):
    found = heavy(score(url))
    assert len(found) == 1, f"одну подменённую букву посчитали несколько раз: {found}"


# ── F-08. Нераскрытый сокращатель: пол и его объяснение ──────────

def test_f08_unresolved_shortener_is_not_safe():
    from models import RedirectInfo
    from pipeline.scorer import UNRESOLVED_SHORTENER_FLOOR

    ri = RedirectInfo(resolved=False, final_url="https://bit.ly/xyz",
                      chain=["https://bit.ly/xyz"], hops=0,
                      was_shortener=True, error="нет ответа")
    result = score("https://bit.ly/xyz", redirects=ri)
    assert result.risk_score >= UNRESOLVED_SHORTENER_FLOOR


def test_f08_the_floor_explains_itself():
    """Видимых улик на 15, а показываем 35 — надбавку надо назвать,
    иначе объяснимость, ради которой всё затевалось, врёт."""
    from models import RedirectInfo

    ri = RedirectInfo(resolved=False, final_url="https://bit.ly/xyz",
                      chain=["https://bit.ly/xyz"], hops=0,
                      was_shortener=True, error="нет ответа")
    result = score("https://bit.ly/xyz", redirects=ri)
    said = [s.detail for s in result.signals if s.code == "SHORTENER_UNRESOLVED"]
    assert said and "балл поднят" in said[0], (
        "балл подняли молча: сумма признаков не сходится с итогом"
    )


# ── F-15, F-16. Отказ не должен врать про причину ────────────────

@pytest.mark.parametrize("url", [
    "https://[2001:db8::1]/", "https://[::1]/",
    "https://[2606:4700:4700::1111]/",
    "http://3232235777/",       # десятичная запись 192.168.1.1
    "http://0xC0A80001/",       # шестнадцатеричная
])
def test_f15_ip_addresses_are_accepted(url):
    """IP — это тоже адрес. Говорить ему «нет доменной зоны» бессмысленно."""
    assert ScanRequest(url=url).url


@pytest.mark.parametrize("raw,host", [
    ("https:" + chr(92) * 2 + "evil.top/", "evil.top"),
    ("https:/" + chr(92) + "evil.top/", "evil.top"),
    ("http:" + chr(92) * 2 + "evil.top/", "evil.top"),
])
def test_f16_backslash_after_scheme_goes_where_the_browser_goes(raw, host):
    """Браузер после схемы съедает любые слеши, прямые и обратные.
    Мы отказывались проверять и ссылались на отсутствующую зону."""
    from urllib.parse import urlsplit
    assert urlsplit(ScanRequest(url=raw).url).hostname == host


@pytest.mark.parametrize("url", ["https://nodot/", "javascript:alert(1)",
                                 "data:text/html,x"])
def test_f15_junk_is_still_refused(url):
    with pytest.raises(Exception):
        ScanRequest(url=url)
