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
        reputation=ReputationResult(checked=True),
        domain_age=DomainAgeResult(checked=True, age_days=3000),
        tls=TlsResult(checked=True, age_days=200, expired=False,
                      self_signed=False, covers_domain=True, issuer="Let's Encrypt"),
        ct=CtResult(checked=True, first_seen_days=3000, total_certs=30),
        page=PageResult(checked=True, status_code=200, form_count=1, bytes_read=5000),
    )
    kw.update(over)
    return calculate_risk_score(url=url, original_url=url,
                                lexical=lexical_analyzer.analyze(url), **kw)


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
