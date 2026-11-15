"""
Четвёртый заход (FINDINGS-4, часть 1) и хвосты третьей охоты.
Каждый тест падает на коде до правок и проходит после. Сеть не нужна.
"""
import pytest

from models import (CtResult, DomainAgeResult, PageResult, RedirectInfo,
                    ReputationResult, ThreatIntelResult, TlsResult, Verdict)
from pipeline import page_analyzer as pa
from pipeline.lexical_analyzer import lexical_analyzer as la
from pipeline.scorer import calculate_risk_score


def score(url, orig=None, **kw):
    base = dict(
        gsb=ThreatIntelResult(checked=True),
        reputation=ReputationResult(checked=True),
        domain_age=DomainAgeResult(checked=True, age_days=4000),
        tls=TlsResult(checked=True, age_days=120, covers_domain=True),
        ct=CtResult(checked=True, first_seen_days=4000, total_certs=30),
    )
    base.update(kw)
    if orig and "origin_lexical" not in base:
        try:
            return calculate_risk_score(url=url, original_url=orig,
                                        lexical=la.analyze(url),
                                        origin_lexical=la.analyze(orig), **base)
        except TypeError:          # код до правки параметра не знает
            pass
    return calculate_risk_score(url=url, original_url=orig or url,
                                lexical=la.analyze(url), **base)


def weighted(result):
    return {s.code for s in result.signals if s.weight}


def hop(orig, final, hops=1, chain=None, shortener=False):
    return RedirectInfo(resolved=True, final_url=final,
                        chain=chain or [orig, final], hops=hops,
                        changed_domain=True, was_shortener=shortener)


# ── H-01. «Доставка и оплата» — раздел магазина, а не схема ──────

@pytest.mark.parametrize("url", [
    "https://www.onlinetrade.ru/about/delivery_and_payment/",
    "https://www.lamoda.ru/help/delivery-and-payment/",
    "https://www.vseinstrumenti.ru/dostavka-i-oplata/",
    "https://detsad-solnyshko.ru/konkurs-risunkov",
    "https://dostavka-edy.ru/oplata",
])
def test_h01_scheme_words_in_the_path_of_an_ordinary_site(url):
    assert la.analyze(url).scam_pattern is None, url


@pytest.mark.parametrize("url", [
    "https://x.top/golosuy-za-malysha",          # дешёвая зона: путь в счёт
    "https://dostavka-posylka.top/oplatit",
    "https://gibdd-shtrafy.online/oplata",
    "https://golosovanie-za-rebenka.ru/",        # обе половины в имени
    "https://детский-конкурс.рф/голосование",
])
def test_h01_real_schemes_are_still_caught(url):
    assert la.analyze(url).scam_pattern is not None, url


# ── G-09. «Проголосуй» — с приставкой ────────────────────────────

@pytest.mark.parametrize("url", [
    "https://проголосуй-за-ребенка.рф/",
    "https://progolosuy-za-rebenka.ru/",
    "https://проголосуй-за-малыша.рф/",
])
def test_g09_imperative_vote_is_the_founding_scheme(url):
    assert la.analyze(url).scam_pattern == "fake_vote", url
    assert score(url).verdict != Verdict.SAFE


def test_g09_prefix_does_not_open_the_word_in_the_middle():
    assert la.analyze("https://всероссийскийконкурс.рф/").scam_pattern is None


# ── H-06, H-10. Параметр переадресации — по значению ─────────────

@pytest.mark.parametrize("url", [
    "https://www.aviasales.ru/search?from=MOW&to=LED",
    "https://site.ru/list?next=3",
    "https://site.ru/page?target=_blank&back=1",
    "https://site.ru/p?link=doc.pdf",
    "https://account.bbc.com/auth?ptrt=https%3A%2F%2Fwww.bbc.com%2F",      # свой домен
    "https://myaccount.nytimes.com/auth/login?redirect_uri=https%3A%2F%2Fwww.nytimes.com%2F",
])
def test_h06_ordinary_parameters_are_not_a_redirect(url):
    assert la.analyze(url).has_redirect_params is False, url


@pytest.mark.parametrize("url", [
    "https://ok.com/go?url=http://evil.ru",
    "https://vk.com/away.php?to=https://zloy-sayt.top/vhod",
    "https://x.ru/?to=https%3A%2F%2Fzloy.top",
    "https://x.ru/?next=zloy.top/vhod",
    "https://x.ru/?anything=https://zloy.top",
    "https://x.ru/?goto=aHR0cHM6Ly9ldmlsLnRvcA==",       # адрес спрятан в base64
])
def test_h06_real_redirect_parameters_still_count(url):
    assert la.analyze(url).has_redirect_params is True, url


def test_h10_a_long_chain_inside_one_site_is_not_concealment():
    chain = ["https://bbc.com/signin", "https://www.bbc.com/signin",
             "https://account.bbc.com/signin", "https://account.bbc.com/auth"]
    r = score(chain[-1], orig=chain[0],
              redirects=RedirectInfo(resolved=True, final_url=chain[-1],
                                     chain=chain, hops=3, changed_domain=False))
    assert "LONG_REDIRECT_CHAIN" not in weighted(r)


def test_h10_a_long_chain_across_domains_still_counts():
    chain = ["https://a-site.ru/", "https://b-site.ru/", "https://c-site.ru/",
             "https://d-site.ru/"]
    r = score(chain[-1], orig=chain[0], redirects=hop(chain[0], chain[-1], 3, chain))
    assert "LONG_REDIRECT_CHAIN" in weighted(r)


# ── H-09. Зона бренда — его собственная ──────────────────────────

@pytest.mark.parametrize("url", ["https://blog.google/", "https://dns.google/",
                                 "https://cloud.microsoft/"])
def test_h09_brand_tld_is_the_brand(url):
    assert la.analyze(url).brand_match is None, url


# ── H-07. Сокращатель без переадресации ──────────────────────────

def test_h07_dead_short_link_is_not_safe():
    url = "https://bit.ly/zzzzqqqq-nope-123"
    r = score(url, redirects=RedirectInfo(resolved=True, final_url=url, chain=[url],
                                          hops=0, was_shortener=True))
    assert r.verdict != Verdict.SAFE, r.risk_score
    assert "SHORTENER_UNRESOLVED" in weighted(r)


def test_h07_shortener_home_page_is_not_a_short_link():
    url = "https://bit.ly/"
    r = score(url, redirects=RedirectInfo(resolved=True, final_url=url, chain=[url],
                                          hops=0, was_shortener=True))
    assert r.verdict == Verdict.SAFE


def test_h07_short_link_to_an_honest_site_is_safe():
    r = score("https://www.dns-shop.ru/", orig="https://bit.ly/abc",
              redirects=hop("https://bit.ly/abc", "https://www.dns-shop.ru/", shortener=True))
    assert r.verdict == Verdict.SAFE, r.risk_score
    assert weighted(r) == {"SHORTENER"}


# ── H-02. Переадресация на доверенный сайт не стирает исходный адрес ─

def test_h02_lure_address_redirecting_to_the_real_bank():
    orig, final = "https://sberbank-vhod-online.top/login", "https://www.sberbank.ru/"
    r = score(final, orig=orig, redirects=hop(orig, final))
    assert r.verdict == Verdict.PHISHING, r.risk_score
    assert "BRAND_IMPERSONATION" in weighted(r)


@pytest.mark.parametrize("orig,final", [
    ("http://gmail.com/", "https://accounts.google.com/v3/signin/identifier?continue="
                          "https%3A%2F%2Fmail.google.com%2Fmail%2F&service=mail&flowName=GlifWebSignIn"),
    ("https://bit.ly/abc", "https://www.youtube.com/watch?v=1"),
    ("https://old-company.ru/", "https://vk.com/company"),
])
def test_h02_honest_redirects_to_trusted_sites_keep_the_ceiling(orig, final):
    r = score(final, orig=orig,
              redirects=hop(orig, final, shortener=la.analyze(orig).is_shortener))
    assert r.verdict == Verdict.SAFE, (r.risk_score, weighted(r))


def test_h02_one_fact_is_not_counted_for_both_addresses():
    orig, final = "https://sber-vhod.top/", "https://sber-vhod2.top/"
    r = score(final, orig=orig, redirects=hop(orig, final))
    assert [s.code for s in r.signals if s.weight].count("BRAND_IMPERSONATION") == 1


# ── H-03. «Ответил» — не «узнал» ─────────────────────────────────

def test_h03_a_403_stub_is_not_a_page_we_saw():
    url = "https://new-shop-xyz.ru/"
    common = dict(domain_age=DomainAgeResult(checked=False, error="x"),
                  redirects=RedirectInfo(resolved=True, final_url=url, chain=[url]))
    seen = score(url, page=PageResult(checked=True, status_code=200, bytes_read=300), **common)
    stub = score(url, page=PageResult(checked=True, status_code=403, bytes_read=300), **common)
    assert stub.confidence < seen.confidence


# ── H-11. «Нет нормального https» — один весомый признак ─────────

def test_h11_self_signed_cert_is_one_fact():
    r = score("https://obychnyy-sayt-bez-primet.ru/",
              tls=TlsResult(checked=True, age_days=200, self_signed=True, covers_domain=False))
    assert weighted(r) == {"CERT_SELF_SIGNED"}


def test_h11_https_on_a_bare_ip_is_one_fact():
    r = score("https://185.23.44.9/",
              tls=TlsResult(checked=True, age_days=200, covers_domain=False),
              ct=CtResult(checked=True, total_certs=0))
    assert weighted(r) == {"IP_IN_URL"}


def test_h11_no_https_at_all_is_one_fact():
    r = score("https://obychnyy-sayt-bez-primet.ru/",
              tls=TlsResult(checked=False, handshake_failed=True),
              ct=CtResult(checked=True, total_certs=0))
    assert weighted(r) == {"TLS_BROKEN"}


def test_h11_cert_for_another_name_still_counts():
    r = score("https://obychnyy-sayt-bez-primet.ru/",
              tls=TlsResult(checked=True, age_days=200, covers_domain=False))
    assert weighted(r) == {"CERT_MISMATCH"}


# ── H-12 / G-04. Ссылки и кнопки — не заявка «мы и есть этот бренд» ─

def _brands(html):
    p = pa._PageParser()
    p.feed(html)
    return pa._brands_in_text(" ".join(getattr(p, "own_text_parts", p.text_parts)))


def test_h12_social_buttons_and_headlines_are_not_a_claim():
    html = ("<title>Новости</title>"
            "<a href='/1'>Сбербанк повысил ставки</a><a href='/2'>Сбербанк открыл офис</a>"
            "<a href='/3'>Что сказал Сбербанк</a>"
            "<button>Войти с помощью Яндекс ID</button><a>Мы в Яндекс.Дзен</a>"
            "<a aria-label='Яндекс'>Яндекс</a>")
    assert _brands(html) == []


def test_h12_a_page_speaking_as_the_brand_is_still_a_claim():
    html = ("<title>Сбербанк Онлайн — вход</title><h1>Сбербанк Онлайн</h1>"
            "<p>Введите пароль от Сбербанк Онлайн</p><form><input type=password></form>")
    assert _brands(html) == ["sberbank"]


# ── G-11. Обычные слова — не опечатки ────────────────────────────

@pytest.mark.parametrize("url", [
    "https://www.telegraph.co.uk/", "https://finance.ua/", "https://www.telegraaf.nl/",
    "https://www.stem.org.uk/", "https://paypay.ne.jp/", "https://www.team.blue/",
])
def test_g11_dictionary_words_are_not_typosquats(url):
    assert la.analyze(url).brand_match is None, url


@pytest.mark.parametrize("url", ["https://paypa1.com/", "https://gogle.com/",
                                 "https://arnazon.com/", "https://g00gle.com/"])
def test_g11_real_typosquats_are_still_caught(url):
    assert la.analyze(url).brand_match.kind == "typosquat", url


# ── G-12. Бренд внутри слова и служебные домены брендов ──────────

@pytest.mark.parametrize("url", [
    "https://www.applebees.com/", "https://steamdb.info/", "https://appleinsider.com/",
    "https://www.googlewatchblog.de/",
    "https://www.githubstatus.com/", "https://microsoft365.com/", "https://yandex.cloud/",
    "https://yandex-team.ru/", "https://aboutamazon.com/",
    "https://rr1---sn-abc.googlevideo.com/videoplayback",
])
def test_g12_brand_inside_a_word_or_on_its_own_side_domain(url):
    assert la.analyze(url).brand_match is None, url


@pytest.mark.parametrize("url", [
    "https://paypalsecure.com/", "https://sberbankonline.ru/", "https://secure-paypal.xyz/",
    "https://paypal.com.evil.ru/", "https://sberbank-login.ru/", "https://googlelogin.top/",
    "https://mypaypal.evil.ru/",
])
def test_g12_glued_or_separate_with_a_lure_is_still_caught(url):
    assert la.analyze(url).brand_match is not None, url


def test_g12_side_domains_get_no_trust_ceiling():
    assert la.analyze("https://www.githubstatus.com/").is_trusted_domain is False


# ── G-13. visa — ещё и виза ──────────────────────────────────────

def test_g13_visa_centre_is_not_visa_the_card():
    assert la.analyze("https://visa.vfsglobal.com/rus/ru/fra/login").brand_match is None


@pytest.mark.parametrize("url", ["https://visa.secure-pay.top/", "https://visa.login-verify.ru/"])
def test_g13_visa_next_to_a_lure_is_still_caught(url):
    assert la.analyze(url).brand_match is not None, url


# ── G-14. Приманки рядом с коротким написанием ───────────────────

@pytest.mark.parametrize("url", [
    "https://vk-auth.ru/", "https://alfa-click.ru/", "https://tg-premium.ru/",
    "https://wb-pay.ru/", "https://icloud-find.com/", "https://вк-авторизация.рф/",
])
def test_g14_short_name_with_a_lure_is_caught(url):
    assert la.analyze(url).brand_match is not None, url


@pytest.mark.parametrize("url", ["https://alfa-remont.ru/", "https://wb-group.ru/",
                                 "https://pochta-service.ru/", "https://vk-studio.ru/"])
def test_g14_ordinary_firms_stay_clean(url):
    assert la.analyze(url).brand_match is None, url
