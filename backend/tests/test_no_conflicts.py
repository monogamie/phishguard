"""
Страховка от конфликтов между уровнями проверки.

Уровней много, и каждый новый — это не просто +1 умение, а ещё N
способов передраться с теми, кто уже есть. Дерутся они молча: балл
поехал, вердикт сменился, никто не заметил.

Здесь две сетки:

1. `test_one_fact_one_signal` — один факт должен зажигать ровно один
   весомый признак. Если правка добавила второй, тест падает и автор
   обязан объяснить, почему это правда два разных факта.
2. `test_honest_sites_stay_below_suspicion` — список заведомо обычных
   сайтов, которые не имеют права подняться до «ПОДОЗРИТЕЛЬНО».
   Так ловится накопление веса от количества признаков.
"""
import pytest

from config import settings
from models import (CtResult, DomainAgeResult, PageResult, RedirectInfo,
                    ReputationResult, ThreatIntelResult, TlsResult, Verdict)
from pipeline.lexical_analyzer import lexical_analyzer
from pipeline.scorer import calculate_risk_score

NEUTRAL_URL = "https://obychnyy-sayt-bez-primet.ru/"


def _score(url=NEUTRAL_URL, **over):
    """Скан зрелого ничем не примечательного сайта, кроме того, что
    подменили в `over`. Всё, что всплывёт сверх эталона, — следствие
    ровно одной подмены."""
    kw = dict(
        gsb=ThreatIntelResult(checked=True, is_threat=False),
        reputation=over.pop("reputation", ReputationResult(checked=True)),
        domain_age=DomainAgeResult(checked=True, age_days=3000),
        tls=TlsResult(checked=True, age_days=200, expired=False,
                      self_signed=False, covers_domain=True, issuer="Let's Encrypt"),
        ct=CtResult(checked=True, first_seen_days=3000, total_certs=30),
        page=PageResult(checked=True, status_code=200, form_count=1, bytes_read=5000),
    )
    lexical = over.pop("lexical", None) or lexical_analyzer.analyze(url)
    if "age" in over:
        kw["domain_age"] = over.pop("age")
    kw.update(over)
    return calculate_risk_score(url=url, original_url=url, lexical=lexical, **kw)


def _weighted(result):
    return {s.code for s in result.signals if s.weight}


def test_neutral_baseline_is_clean():
    """Эталон обязан быть пустым, иначе остальные тесты меряют мусор."""
    assert _weighted(_score()) == set()
    assert _score().risk_score == 0


# Факт -> чем его создаём -> какие признаки он ИМЕЕТ ПРАВО зажечь.
ONE_FACT = [
    ("домен свежий, знает реестр",
     dict(domain_age=DomainAgeResult(checked=True, age_days=3),
          tls=TlsResult(checked=True, age_days=3, covers_domain=True, issuer="LE"),
          ct=CtResult(checked=True, first_seen_days=3, total_certs=1)),
     {"DOMAIN_VERY_NEW"}),

    ("домен свежий, реестр молчит — считают журналы",
     dict(domain_age=DomainAgeResult(checked=False, error="нет данных"),
          tls=TlsResult(checked=True, age_days=3, covers_domain=True, issuer="LE"),
          ct=CtResult(checked=True, first_seen_days=3, total_certs=1)),
     {"CT_FIRST_SEEN_VERY_NEW", "DOMAIN_AGE_UNKNOWN"}),

    ("домен свежий, молчат все — остаётся сертификат",
     dict(domain_age=DomainAgeResult(checked=False, error="нет данных"),
          tls=TlsResult(checked=True, age_days=3, covers_domain=True, issuer="LE"),
          ct=CtResult(checked=False, error="журналы недоступны")),
     {"CERT_VERY_NEW", "DOMAIN_AGE_UNKNOWN"}),

    ("сертификат продлён вчера на зрелом сайте",
     dict(tls=TlsResult(checked=True, age_days=1, covers_domain=True, issuer="LE")),
     set()),

    ("сертификат просрочен",
     dict(tls=TlsResult(checked=True, age_days=800, expired=True,
                        covers_domain=True, issuer="LE")),
     {"CERT_EXPIRED"}),

    ("сертификат на чужое имя",
     dict(tls=TlsResult(checked=True, age_days=200, covers_domain=False, issuer="LE")),
     {"CERT_MISMATCH"}),

    ("форма шлёт данные на чужой домен",
     dict(page=PageResult(checked=True, status_code=200, form_count=1,
                          cross_domain_form="http://sbor.top/x", bytes_read=5000)),
     {"PAGE_CROSS_DOMAIN_FORM"}),

    ("чужой бренд в тексте страницы",
     dict(page=PageResult(checked=True, status_code=200, form_count=1,
                          brands_in_text=["sberbank"], bytes_read=5000)),
     {"PAGE_BRAND_MISMATCH"}),

    ("вход через мессенджер и больше ничего",
     dict(page=PageResult(checked=True, status_code=200, form_count=1,
                          messenger_login=["telegram"], bytes_read=5000)),
     set()),

    ("поле пароля и больше ничего",
     dict(page=PageResult(checked=True, status_code=200, form_count=1,
                          has_password_field=True, bytes_read=5000)),
     set()),
]


@pytest.mark.parametrize("name,over,expected", ONE_FACT,
                         ids=[c[0] for c in ONE_FACT])
def test_one_fact_one_signal(name, over, expected):
    got = _weighted(_score(**over))
    assert got == expected, (
        f"{name}: ожидали {sorted(expected) or 'ничего'}, "
        f"а загорелось {sorted(got)}. Лишний признак — это либо "
        f"двойной счёт одного факта, либо его надо внести в список "
        f"осознанно."
    )


# То же для признаков, которые берутся из адреса.
ONE_FACT_URL = [
    ("IP вместо домена", "https://185.23.44.9/", {"IP_IN_URL"}),
    ("гомоглиф бренда", "https://аpple.com/", {"BRAND_HOMOGRAPH"}),
    ("опечатка бренда", "https://paypa1.com/", {"BRAND_TYPOSQUAT"}),
    ("@ в адресе", "https://google.com@evil-domain.ru/", {"AT_SYMBOL"}),
    ("http вместо https", "http://obychnyy-sayt-bez-primet.ru/", {"INSECURE_SCHEME"}),
]


@pytest.mark.parametrize("name,url,expected", ONE_FACT_URL,
                         ids=[c[0] for c in ONE_FACT_URL])
def test_one_fact_one_signal_from_url(name, url, expected):
    got = _weighted(_score(url=url))
    assert got == expected, f"{name}: загорелось {sorted(got)}, ждали {sorted(expected)}"


# ── Честные сайты не имеют права стать подозрительными ───────────

HONEST_SITES = [
    "https://habr.com/ru/articles/123456/",
    "https://nalog.ru/rn77/service/",
    "https://www.sberbank.ru/person/credits",
    "https://мвд.рф/",
    "https://xn--d1abbgf6aiiy.xn--p1ai/",          # президент.рф
    "https://ozon.ru/product/telefon-12345/",
    "https://moy-internet-magazin.ru/catalog/",
    "https://some-company.ru/account/login",        # обычная страница входа
    "https://forum-lyubiteley-rybalki.ru/vhod",
    "https://shop24.ru/",
    "https://storage.googleapis.com/bucket/report.pdf",
    "https://my-team.sharepoint.com/sites/docs",
]


@pytest.mark.parametrize("url", HONEST_SITES)
def test_honest_sites_stay_below_suspicion(url):
    """
    Каждый новый признак сдвигает порог для всех остальных. Этот тест
    падает, когда от количества проверок обычный сайт начинает
    набирать баллы просто так.

    Условия щедрые нарочно: зрелый домен, нормальный сертификат,
    страница с формой входа. Если при таких вводных сайт поднялся до
    «ПОДОЗРИТЕЛЬНО» — виноваты мы, а не сайт.
    """
    result = _score(
        url=url,
        page=PageResult(checked=True, status_code=200, form_count=1,
                        has_password_field=True, messenger_login=["vk"],
                        bytes_read=8000),
    )
    assert result.risk_score < settings.SUSPICIOUS_MIN, (
        f"{url}: {result.risk_score} баллов — "
        f"{[(s.code, s.weight) for s in result.signals if s.weight]}"
    )
    assert result.verdict == Verdict.SAFE


def test_shortener_cap_does_not_hide_page_evidence():
    """«Не знаем, куда ведёт» — это про неизвестность. Если страницу
    всё-таки прочитали и нашли улики, глушить их потолком нельзя."""
    redirects = RedirectInfo(final_url="https://bit.ly/x", chain=["https://bit.ly/x"],
                             was_shortener=True, resolved=False)
    result = _score(
        url="https://bit.ly/x", redirects=redirects,
        domain_age=DomainAgeResult(checked=True, age_days=2),
        page=PageResult(checked=True, status_code=200, form_count=2,
                        has_password_field=True, messenger_login=["telegram"],
                        cross_domain_form="http://sbor.top/x",
                        brands_in_text=["sberbank"], bytes_read=9000),
    )
    assert result.verdict == Verdict.PHISHING, (
        f"полный набор улик упёрся в потолок сокращателя: {result.risk_score}")


# ── Регрессии 19 сентября: подмена анализируемого домена ─────────
# Обе находки — про одно: жертва уходит на один сайт, мы проверяем
# другой и говорим «безопасно». Разными способами, чинятся по-разному.

@pytest.mark.parametrize("url,real_host", [
    # `%2F` раскодируется в `/`, граница логин/хост уезжает, и вместо
    # злого сайта разбирается доверенный домен из логина.
    ("https://sberbank.ru%2Flogin@evil-phish.top/verify", "evil-phish.top"),
    ("https://google.com%2Fsearch@192.168.0.1/admin", "192.168.0.1"),
    ("https://gosuslugi.ru%3Fx@zloy-sayt.top/", "zloy-sayt.top"),
    # Обратный слеш браузер считает разделителем, а urlsplit — нет.
    ("https://evil.top\\@sberbank.ru/", "evil.top"),
    ("https://zloy.top\\x\\@google.com/a", "zloy.top"),
])
def test_we_analyze_the_host_the_browser_goes_to(url, real_host):
    features = lexical_analyzer.analyze(url)
    assert features.host == real_host, (
        f"жертва уйдёт на {real_host}, а мы разбираем {features.host}"
    )
    assert features.is_trusted_domain is False, (
        "домен из логина не должен давать потолок доверия"
    )


@pytest.mark.parametrize("url", [
    "https://sberbank.ru%2Flogin@evil-phish.top/verify",
    "https://evil.top\\@sberbank.ru/",
])
def test_hidden_host_does_not_come_out_safe(url):
    """Худший исход — не пропуск, а уверенное «БЕЗОПАСНО»: именно так
    выглядела дыра на живом сайте (0 баллов, достоверность 1.0)."""
    result = _score(url=url, age=DomainAgeResult(checked=True, age_days=3))
    assert result.verdict != Verdict.SAFE, f"{url}: {result.risk_score}"


def test_shared_platform_is_not_condemned_by_other_peoples_malware():
    """
    URLhaus ведёт учёт по ХОСТУ, а на github.com и docs.google.com
    пользовательских вредоносных ссылок тысячи. С полом в 90 баллов
    «ОПАСНО» получали github.com, t.me и dropbox.com — проверено живьём.
    """
    from models import LexicalFeatures
    trusted = LexicalFeatures(registered_domain="github.com", scheme="https",
                              trust_domain="github.com", is_trusted_domain=True)
    result = _score(lexical=trusted,
                    reputation=ReputationResult(checked=True, host_listed=True,
                                                host_url_count=4200))
    assert result.verdict == Verdict.SAFE, f"github.com: {result.risk_score}"

    # А сама ссылка в базе — по-прежнему приговор, даже на GitHub.
    exact = _score(lexical=trusted,
                   reputation=ReputationResult(checked=True, url_listed=True,
                                               host_listed=True, threat="malware"))
    assert exact.verdict == Verdict.PHISHING


# ── Ложные тревоги на честных сайтах ─────────────────────────────

@pytest.mark.parametrize("url", [
    "https://github.blog/",      # блог самого GitHub
    "https://yandex.by/",
    "https://alfabank.by/",
    "https://ozon.travel/",
    "https://google.de/",
])
def test_brand_on_its_own_other_domain_is_not_impersonation(url):
    """
    Полного списка доменов Google не существует, и всё, что не попало
    в словарь, объявлялось подделкой: `github.blog` получал 45 баллов
    за имперсонацию GitHub, а живьём — 75 и «ОПАСНО».

    Признак: имя домена — РОВНО бренд, а зона приличная.
    """
    assert lexical_analyzer.analyze(url).brand_match is None, url


@pytest.mark.parametrize("url", [
    "https://paypal.tk/",        # то же имя, но зона бесплатная
    "https://sberbank.top/",
    "https://paypa1.com/",       # опечатка: имя НЕ равно бренду
    "https://sberbank-vhod.top/",
    "https://paypal.com.evil.ru/",
])
def test_squatting_is_still_caught(url):
    """Оговорка выше не должна открыть дорогу захватчикам."""
    assert lexical_analyzer.analyze(url).brand_match is not None, url


def test_www_is_not_a_domain_change():
    """`e1.ru → www.e1.ru` — обычная канонизация, её делает половина
    интернета. Сравнение шло по полному хосту, и честные сайты вне
    списка доверия получали за это 20 баллов."""
    from url_resolver import _registrable_host
    assert _registrable_host("https://e1.ru/") == _registrable_host("https://www.e1.ru/")
    assert _registrable_host("https://tele2.ru/") == _registrable_host("https://msk.tele2.ru/lk")
    # А настоящая смена домена должна остаться сменой.
    assert _registrable_host("https://bit.ly/x") != _registrable_host("https://zloy.top/")


@pytest.mark.parametrize("url", [
    "https://cabinet.tele2.ru/security/password/recovery",
    "https://id.rbc.ru/auth/login",
    "https://lk.megafon.ru/login",
    "https://passport.yandex.ru/auth",
])
def test_an_honest_login_page_is_not_suspicious(url):
    """
    На настоящей странице входа всегда есть `login`, `password`,
    `security`, `recovery` — потому что это страница входа. Пока слова
    в ПУТИ весили столько же, сколько в имени домена, личные кабинеты
    половины страны набирали на «ПОДОЗРИТЕЛЬНО».
    """
    result = _score(url=url, age=DomainAgeResult(checked=True, age_days=4000))
    assert result.verdict == Verdict.SAFE, (
        f"{url}: {result.risk_score}, "
        f"{[(s.code, s.weight) for s in result.signals if s.weight]}"
    )


@pytest.mark.parametrize("url", [
    "https://secure-login-verify.top/",
    "https://sberbank-vhod-online.top/",
    "https://bank-of-america.secure-login.xyz/verify",
])
def test_keywords_in_the_domain_name_still_count(url):
    """А вот так мошенник называет СВОЙ домен, чтобы он выглядел
    служебным. Это разные вещи, и оговорка выше сюда не тянется."""
    result = _score(url=url, age=DomainAgeResult(checked=True, age_days=20))
    assert result.verdict == Verdict.PHISHING, f"{url}: {result.risk_score}"
