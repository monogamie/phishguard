"""Тесты извлечения признаков: детекты и, что важнее, отсутствие ложных."""
import pytest

from pipeline.lexical_analyzer import lexical_analyzer as la


# ── Регрессии: URL, которые раньше роняли анализатор ──────────────

@pytest.mark.parametrize("url", [
    "https://example.com:99999/",     # порт вне диапазона
    "https://example.com:abc/",       # порт не число
    "http://[::1]/",                  # IPv6-литерал
    "https://",                       # пустой хост
    "not a url at all",
    "https://" + "a" * 300 + ".com",
])
def test_never_raises(url):
    """Анализатор обязан деградировать, а не падать."""
    assert la.analyze(url) is not None


# ── Ключевые признаки ────────────────────────────────────────────

def test_ip_host_detected():
    assert la.analyze("http://185.220.101.5/login").has_ip_address is True


def test_invalid_octets_are_not_ip():
    """Раньше регулярка принимала 999.999.999.999 как IP."""
    assert la.analyze("http://999.999.999.999/").has_ip_address is False


def test_ipv6_detected():
    assert la.analyze("http://[2001:db8::1]/x").has_ip_address is True


def test_at_symbol_detected():
    assert la.analyze("http://sberbank.ru@evil.top/").has_at_symbol is True


def test_encoded_host_detected():
    """Регрессия: раньше unquote() выполнялся ДО проверки, и признак
    не мог сработать никогда."""
    assert la.analyze("https://a.com%2eevil.ru/").has_encoded_host is True


def test_non_standard_port_detected():
    assert la.analyze("https://example.com:1337/").has_non_standard_port is True
    assert la.analyze("https://example.com:443/").has_non_standard_port is False
    assert la.analyze("http://example.com:80/").has_non_standard_port is False


def test_insecure_scheme_detected():
    assert la.analyze("http://example.org/").is_insecure_scheme is True
    assert la.analyze("https://example.org/").is_insecure_scheme is False


def test_redirect_params_detected():
    assert la.analyze("https://ok.com/go?url=http://evil.ru").has_redirect_params is True


def test_shortener_detected():
    assert la.analyze("https://bit.ly/abc123").is_shortener is True


# ── Ключевые слова ───────────────────────────────────────────────

def test_keywords_found():
    kws = la.analyze("https://evil-site.xyz/secure/login/verify").trigger_keywords
    assert {"secure", "login", "verify"} <= set(kws)


def test_keywords_are_word_bounded():
    """Регрессия: 'account' находился в 'accountant', 'free' — в 'freelancer'."""
    assert "account" not in la.analyze("https://accountant-firm.ru/").trigger_keywords


def test_keywords_deterministic():
    """Регрессия: обход frozenset давал разный порядок между запусками."""
    url = "https://evil.xyz/login/verify/account/secure"
    assert la.analyze(url).trigger_keywords == sorted(la.analyze(url).trigger_keywords)


def test_keywords_skipped_for_trusted():
    assert la.analyze("https://google.com/account/login").trigger_keywords == []


# ── Бренды ───────────────────────────────────────────────────────

@pytest.mark.parametrize("url,brand,kind", [
    ("https://paypa1.com/login", "paypal", "typosquat"),
    ("https://gogle.com", "google", "typosquat"),
    ("https://arnazon.com", "amazon", "typosquat"),
    ("https://аmazon.com/login", "amazon", "homograph"),
    ("https://paypal.com.account-verify.ru/", "paypal", "impersonation"),
    ("https://secure-paypal-update.tk/", "paypal", "impersonation"),
])
def test_brand_attacks_detected(url, brand, kind):
    match = la.analyze(url).brand_match
    assert match is not None, f"не задетектирован: {url}"
    assert match.brand == brand
    assert match.kind == kind


@pytest.mark.parametrize("url", [
    "https://google.com", "https://mail.google.com", "https://googleapis.com",
    "https://googleusercontent.com", "https://microsoftonline.com",
    "https://login.microsoftonline.com", "https://amazonaws.com",
    "https://aws.amazon.com", "https://www.amazon.co.uk",
    "https://github.com/x/y", "https://ozone.com", "https://vista.com",
    "https://accounts.google.com/signin", "https://sberbank.ru/person",
])
def test_no_false_brand_positives(url):
    """Главная регрессия старой версии: `brand in sld` метил
    googleapis.com и microsoftonline.com как фишинг."""
    assert la.analyze(url).brand_match is None, f"ложное срабатывание: {url}"


def test_trusted_flag_uses_etld_plus_one():
    """`google.com.evil.ru` не должен считаться доверенным."""
    assert la.analyze("https://google.com.evil.ru/").is_trusted_domain is False
    assert la.analyze("https://www.amazon.co.uk/").is_trusted_domain is True


# ── Регрессия по реальному случаю: угон Telegram через «голосование» ──
# Ссылка http://born.playjoy-dash.shop/deti/9 украла аккаунт у живого
# человека и получила от сканера 15 баллов и вердикт «безопасно».
# Разбор промаха: зона .shop не считалась подозрительной, а список
# тревожных слов был чисто английским и не знал слова «deti».

REAL_CASE_URL = "http://born.playjoy-dash.shop/deti/9"


def test_real_case_russian_keyword_found():
    assert "deti" in la.analyze(REAL_CASE_URL).trigger_keywords


def test_real_case_abused_tld_detected():
    f = la.analyze(REAL_CASE_URL)
    assert f.abused_tld is True          # .shop — дешёвая зона
    assert f.suspicious_tld is False     # но не бесплатная, вес меньше


@pytest.mark.parametrize("url,keyword", [
    ("https://x.shop/golosovanie/masha", "golosovanie"),
    ("https://x.site/vyplata", "vyplata"),
    ("https://x.top/podarok", "podarok"),
    ("https://x.top/podtverdit-vhod", "podtverdit"),
    ("https://x.top/конкурс", "конкурс"),
])
def test_russian_keywords_found(url, keyword):
    assert keyword in la.analyze(url).trigger_keywords


@pytest.mark.parametrize("url,pattern", [
    ("http://konkurs-deti-2026.shop/golosovanie/masha", "fake_vote"),
    ("https://golosovanie-detskiy-konkurs.top/", "fake_vote"),
    ("https://vozvrat-nalog.site/oformit-vyplatu", "fake_payout"),
    ("https://podarok-akciya.online/poluchit-priz", "fake_prize"),
])
def test_scam_patterns_detected(url, pattern):
    """Связка слов из двух групп — это узнаваемая схема, а не догадка."""
    assert la.analyze(url).scam_pattern == pattern


@pytest.mark.parametrize("url", [
    "https://ozon.ru/category/deti",          # детские товары — не мошенничество
    "https://google.com/vote",
    "https://github.com/x/y",
    "https://www.amazon.co.uk/gp/cart",
    "https://school-konkurs.edu.ru/",         # одно слово из группы А, без Б
])
def test_scam_patterns_no_false_positives(url):
    assert la.analyze(url).scam_pattern is None


@pytest.mark.parametrize("url", [
    "https://google.com", "https://github.com/x", "https://sberbank.ru/person",
])
def test_abused_tld_not_flagged_for_normal_zones(url):
    assert la.analyze(url).abused_tld is False


# ── Регрессия: домены в зоне .рф считались фишингом ──────────────
# Дефисы и цифры считались по punycode-форме, где они появляются от
# самой кодировки: `xn--d1abbgf6aiiy.xn--p1ai` — четыре дефиса и две
# цифры, которых в имени «президент.рф» нет. Плюс балл за сам
# punycode, без которого национальный домен не записать. Итого ровно
# 60 баллов и вердикт «ОПАСНО» для каждого сайта в зоне.

@pytest.mark.parametrize("url,human", [
    ("https://xn--d1abbgf6aiiy.xn--p1ai/", "президент.рф"),
    ("https://xn--b1aew.xn--p1ai/", "мвд.рф"),
    ("https://xn--80aesfpebagmfblc0a.xn--p1ai/", "стопкоронавирус.рф"),
])
def test_national_domain_is_not_suspicious(url, human):
    f = la.analyze(url)
    assert f.decoded_host == human
    assert f.idn_is_native is True
    assert f.hyphen_count == human.count("-")
    assert f.has_digits_in_domain is False


def test_same_domain_scores_the_same_typed_either_way():
    """Адрес можно набрать русскими буквами или через xn-- — это один
    и тот же сайт, и признаки обязаны выйти одинаковые. Раньше
    «мвд.рф» получал +35 за нелатиницу, а его же punycode-запись 0."""
    human = la.analyze("https://мвд.рф/")
    puny = la.analyze("https://xn--b1aew.xn--p1ai/")
    for field in ("has_non_ascii_host", "has_mixed_scripts", "idn_is_native",
                  "hyphen_count", "has_digits_in_domain", "registered_domain"):
        assert getattr(human, field) == getattr(puny, field), field
    assert human.has_non_ascii_host is False


def test_cyrillic_under_latin_tld_is_still_suspicious():
    """Кириллица под .com прячется под латиницу — это не «родной» IDN."""
    f = la.analyze("https://xn--80ak6aa92e.com/")
    assert f.has_punycode is True
    assert f.idn_is_native is False


def test_russian_keywords_found_in_punycode_domain():
    """В `xn--`-форме русских слов не видно, а жертва видит именно их."""
    # голосование-конкурс.рф
    f = la.analyze("https://xn----7sbfdmrqacwedbah8afm0b.xn--p1ai/")
    assert "голосование" in f.trigger_keywords
    assert f.scam_pattern == "fake_vote"


# ── Регрессия: фишинг на чужой площадке получал «БЕЗОПАСНО» ──────

def test_subdomain_of_hosting_platform_is_not_trusted():
    """`github.io` доверенный, но заведённый за минуту поддомен на нём
    доверенным быть не должен: иначе потолок доверия обнулял все улики
    страницы и фишинг получал «БЕЗОПАСНО» навсегда."""
    assert la.analyze("https://github.io/").is_trusted_domain is True
    theirs = la.analyze("https://sber-vhod.github.io/login/")
    assert theirs.trust_domain == "sber-vhod.github.io"
    assert theirs.is_trusted_domain is False


@pytest.mark.parametrize("url", [
    "https://s3.amazonaws.com/bucket/vhod.html",
    "https://storage.googleapis.com/bucket/sber.html",
    "https://arendator.sharepoint.com/doc",
])
def test_multi_tenant_platforms_get_no_trust_ceiling(url):
    """Файл в чужом бакете — обычный способ положить фишинг на
    приличный домен. Имперсонацией это не считаем, но и потолка не даём."""
    f = la.analyze(url)
    assert f.is_trusted_domain is False
    assert f.brand_match is None
