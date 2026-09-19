"""Уровень 4: агрегация улик в балл 0-100 и вердикт.

Аддитивная модель с тремя переопределяющими правилами: пол 90 по
внешним базам, потолок для доверенных доменов, смягчение для
неразвёрнутых сокращателей."""

from __future__ import annotations

import logging
from typing import Optional

from config import settings
from models import (
    AiVerdictResult,
    CtResult,
    DomainAgeResult,
    PageResult,
    LexicalFeatures,
    RedirectInfo,
    ReputationResult,
    ScanResponse,
    Severity,
    Signal,
    ThreatIntelResult,
    TlsResult,
    Verdict,
)
from pipeline.threat_intel import THREAT_TYPE_LABELS

logger = logging.getLogger(__name__)

# Максимальный балл, который может получить домен из списка доверенных,
# если против него нет прямых улик от внешней разведки.
TRUSTED_DOMAIN_SCORE_CAP = 15

# Балл, выше которого не поднимается неразвёрнутая короткая ссылка:
# «мы не знаем, куда она ведёт» — это подозрение, а не приговор.
UNRESOLVED_SHORTENER_CAP = 45


class _SignalCollector:
    """Накопитель сигналов: балл и объяснение добавляются одной
    операцией, рассинхронизировать их нельзя."""

    def __init__(self) -> None:
        self.signals: list[Signal] = []
        self.score: int = 0

    def add(self, code: str, severity: Severity, title: str, detail: str,
            weight_key: Optional[str] = None, weight: Optional[int] = None) -> None:
        points = weight if weight is not None else (
            settings.weight(weight_key) if weight_key else 0
        )
        self.score += points
        self.signals.append(Signal(code=code, severity=severity,
                                   weight=points, title=title, detail=detail))

    def ok(self, code: str, title: str, detail: str) -> None:
        """Признак проверен, нарушений нет: интерфейс должен показывать
        не только плохое, но и что именно проверялось."""
        self.signals.append(Signal(code=code, severity=Severity.OK,
                                   weight=0, title=title, detail=detail))


def _verdict(score: int) -> Verdict:
    if score >= settings.PHISHING_THRESHOLD:
        return Verdict.PHISHING
    if score >= settings.SUSPICIOUS_MIN:
        return Verdict.SUSPICIOUS
    return Verdict.SAFE


def _confidence(gsb: ThreatIntelResult, reputation: ReputationResult,
                age: DomainAgeResult, redirects: Optional[RedirectInfo],
                ai: Optional[AiVerdictResult] = None,
                tls: Optional[TlsResult] = None,
                ct: Optional[CtResult] = None,
                page: Optional[PageResult] = None) -> float:
    """Доля ответивших источников: пользователь должен отличать
    «проверено всеми, чисто» от «почти все недоступны».

    Уровни, пропущенные НАРОЧНО (доверенный домен, выключен в
    настройках), в знаменатель не идут. Иначе шкала переворачивалась:
    у google.com, где половину уровней гонять незачем, достоверность
    выходила 0.62, а у неизвестного магазина — 1.0."""
    available = 1.0                       # лексика работает всегда
    total = 4.0
    for extra in (ai, tls, ct, page):
        if extra is None or getattr(extra, "skipped", False):
            continue
        total += 1
        if extra.checked:
            available += 1
    if gsb.checked:
        available += 1
    if reputation.checked:
        available += 1
    if age.checked:
        available += 1
    if redirects is not None and redirects.resolved:
        total += 1
        available += 1
    return round(min(available / total, 1.0), 2)


def calculate_risk_score(
    url: str,
    original_url: str,
    gsb: ThreatIntelResult,
    reputation: ReputationResult,
    domain_age: DomainAgeResult,
    lexical: LexicalFeatures,
    redirects: Optional[RedirectInfo] = None,
    ai: Optional[AiVerdictResult] = None,
    tls: Optional[TlsResult] = None,
    ct: Optional[CtResult] = None,
    page: Optional[PageResult] = None,
) -> ScanResponse:
    """
    Собирает улики всех уровней в итоговый ScanResponse.

    Args:
        url:          адрес, который реально анализировался (после редиректов)
        original_url: то, что ввёл пользователь
        gsb:          Google Safe Browsing (уровень 1)
        reputation:   URLhaus (уровень 1b)
        domain_age:   RDAP/WHOIS (уровень 2)
        lexical:      структурные признаки (уровень 3)
        redirects:    цепочка редиректов (уровень 0)
        ai:           мнение языковой модели (уровень 1c)
        tls:          сертификат (уровень 2b)
        ct:           журналы Certificate Transparency (уровень 2c)
        page:         содержимое страницы (уровень 5)
    """
    c = _SignalCollector()
    external_hit = False

    # ── Уровень 0: редиректы ─────────────────────────────────────
    if redirects is not None and redirects.hops > 0:
        chain_text = " → ".join(redirects.chain[-3:])
        if redirects.was_shortener:
            c.add("SHORTENER", Severity.WARN, "Сокращатель ссылок",
                  f"Ссылка скрыта сервисом сокращения и ведёт на: {redirects.final_url}",
                  weight_key="shortener")
        if redirects.changed_domain:
            c.add("CROSS_DOMAIN_REDIRECT", Severity.WARN, "Смена домена",
                  f"Переадресация уводит на другой домен: {chain_text}",
                  weight_key="cross_domain_redirect")
        if redirects.hops > 2:
            c.add("LONG_REDIRECT_CHAIN", Severity.WARN, "Длинная цепочка",
                  f"{redirects.hops} последовательных переадресаций — "
                  f"типичный приём сокрытия конечного адреса",
                  weight_key="long_redirect_chain")
    elif redirects is not None and redirects.was_shortener and not redirects.resolved:
        c.add("SHORTENER_UNRESOLVED", Severity.WARN, "Ссылка не развёрнута",
              "Это сокращённая ссылка, но развернуть её не удалось — "
              "конечный адрес неизвестен",
              weight_key="shortener")

    # ── Уровень 1: Google Safe Browsing ──────────────────────────
    if gsb.is_threat:
        external_hit = True
        labels = ", ".join(THREAT_TYPE_LABELS.get(t, t) for t in gsb.threat_types)
        c.add("GSB_MATCH", Severity.DANGER, "Google Safe Browsing",
              f"Адрес числится в базе угроз Google. Категории: {labels}",
              weight_key="google_safe_browsing")
        logger.warning("GSB confirmed threat for %s: %s", url, gsb.threat_types)
    elif gsb.checked:
        c.ok("GSB_CLEAN", "Google Safe Browsing", "В базе угроз Google не найден")

    # ── Уровень 1b: URLhaus ──────────────────────────────────────
    if reputation.url_listed:
        external_hit = True
        c.add("URLHAUS_URL", Severity.DANGER, "URLhaus",
              f"Ссылка есть в базе вредоносных URL abuse.ch. "
              f"Тип угрозы: {reputation.threat or 'malware'}",
              weight_key="urlhaus_url")
    if reputation.host_listed:
        # ВАЖНО: попадание по ХОСТУ — это не приговор самой ссылке, и
        # `external_hit` тут не ставится. URLhaus ведёт учёт по хосту, а
        # на любой крупной площадке с пользовательским контентом чужих
        # вредоносных ссылок тысячи. С полом в 90 баллов «ОПАСНО»
        # получали github.com, docs.google.com, t.me и dropbox.com —
        # проверено на живом сайте.
        #
        # У доверенных площадок это вообще норма жизни, поэтому им
        # признак показываем, но без веса: пусть человек видит, что мы
        # смотрели, и понимает, что чужая зараза на GitHub — не повод
        # не открывать GitHub.
        if lexical.is_trusted_domain:
            c.add("URLHAUS_HOST_SHARED", Severity.INFO, "URLhaus: хост",
                  f"На этом хосте когда-то находили вредоносные ссылки "
                  f"({reputation.host_url_count}), но это большая площадка "
                  f"с пользовательским содержимым — к самой ссылке это "
                  f"отношения не имеет",
                  weight=0)
        else:
            c.add("URLHAUS_HOST", Severity.DANGER, "URLhaus: хост",
                  f"С этого хоста уже раздавали вредоносное ПО "
                  f"(зафиксировано ссылок: {reputation.host_url_count})",
                  weight_key="urlhaus_host")
    if reputation.checked and not (reputation.url_listed or reputation.host_listed):
        c.ok("URLHAUS_CLEAN", "URLhaus", "В базе вредоносных URL не найден")

    # ── Уровень 2: возраст домена ────────────────────────────────
    age_days = domain_age.age_days
    if domain_age.checked and age_days is not None:
        if age_days < settings.DOMAIN_AGE_VERY_NEW:
            c.add("DOMAIN_VERY_NEW", Severity.DANGER, "Возраст домена",
                  f"Домен зарегистрирован {age_days} дн. назад. Легитимные "
                  f"сервисы не запускаются на домене возрастом в несколько дней",
                  weight_key="domain_very_new")
        elif age_days < settings.DOMAIN_AGE_NEW:
            c.add("DOMAIN_NEW", Severity.WARN, "Возраст домена",
                  f"Домену {age_days} дн. — меньше месяца. Большинство "
                  f"фишинговых доменов моложе 30 дней",
                  weight_key="domain_new")
        elif age_days < settings.DOMAIN_AGE_RECENT:
            c.add("DOMAIN_RECENT", Severity.WARN, "Возраст домена",
                  f"Домену {age_days} дн. — меньше трёх месяцев",
                  weight_key="domain_recent")
        else:
            years = age_days / 365.25
            c.ok("DOMAIN_MATURE", "Возраст домена",
                 f"Домену {years:.1f} г. — зрелый домен с историей")
    elif domain_age.checked and domain_age.error:
        c.add("DOMAIN_NOT_REGISTERED", Severity.WARN, "Регистрация домена",
              domain_age.error, weight_key="domain_age_unknown")
    else:
        # Недоступность WHOIS/RDAP — слабый сигнал: у одноразовых
        # доменов данные часто скрыты, но и у нормальных ccTLD тоже.
        c.add("DOMAIN_AGE_UNKNOWN", Severity.INFO, "Возраст домена",
              "Дату регистрации получить не удалось",
              weight_key="domain_age_unknown")

    # Возраст сайта умеют оценить три источника, и это один и тот же
    # факт, а не три. Считает ровно один — лучший из доступных:
    #
    #   реестр (RDAP/WHOIS) — дата регистрации, первоисточник;
    #   журналы CT          — дата первого в мире сертификата;
    #   живой сертификат    — дата текущего, самая грубая оценка
    #                         (его перевыпускают каждые 60–90 дней).
    #
    # Пока считали все, свежий домен без записи в реестре набирал
    # 35 за журналы плюс 30 за сертификат — 65 баллов за один факт.
    age_known = domain_age.checked and domain_age.age_days is not None
    ct_knows_age = (ct is not None and ct.checked
                    and ct.first_seen_days is not None)
    age_covered = age_known or ct_knows_age

    # ── Уровень 2b: сертификат ───────────────────────────────────
    if tls is not None and tls.checked:
        if tls.covers_domain is False:
            c.add("CERT_MISMATCH", Severity.DANGER, "Сертификат не тот",
                  "Сертификат выдан на другое имя. Браузер на такой странице "
                  "показывает предупреждение, которое легко проскочить",
                  weight_key="cert_mismatch")
        if tls.self_signed:
            c.add("CERT_SELF_SIGNED", Severity.DANGER, "Самоподписанный сертификат",
                  "Сертификат выписан сам себе, а не удостоверяющим центром. "
                  "Настоящие сервисы так не делают",
                  weight_key="cert_self_signed")
        if tls.expired:
            c.add("CERT_EXPIRED", Severity.WARN, "Сертификат просрочен",
                  "Срок действия сертификата истёк — сайт заброшен или сделан "
                  "на скорую руку",
                  weight_key="cert_expired")
        if tls.age_days is not None:
            # Возраст сертификата — это косвенная оценка возраста сайта,
            # и вес ей даём ТОЛЬКО когда реестр молчит. Иначе один факт
            # «домен свежий» засчитывается дважды: 50 за домен плюс 30
            # за сертификат — 80 баллов из 60 нужных для «ОПАСНО», ещё
            # до единой настоящей улики.
            #
            # Хуже того, на зрелом домене свежий сертификат — это
            # обычное продление: Let's Encrypt перевыпускает каждые
            # 60–90 дней. Тринадцатилетний сайт получал «ПОДОЗРИТЕЛЬНО»
            # просто за то, что вчера продлил сертификат.
            #
            # Для журналов CT такая же развилка уже стояла ниже, а для
            # сертификата её забыли — асимметрия была случайной.
            if tls.age_days < settings.CERT_VERY_NEW_DAYS and not age_covered:
                c.add("CERT_VERY_NEW", Severity.WARN, "Свежий сертификат",
                      f"Сертификат выпущен {tls.age_days} дн. назад. "
                      f"Сертификат получают вместе с доменом, значит и сайт "
                      f"появился только что",
                      weight_key="cert_very_new")
            elif tls.age_days < settings.CERT_NEW_DAYS and not age_covered:
                c.add("CERT_NEW", Severity.INFO, "Сертификат новый",
                      f"Сертификату {tls.age_days} дн.",
                      weight_key="cert_new")
            elif not tls.expired:
                # Иначе в одном списке оказывались «просрочен» и
                # «действующий» — балл верный, объяснение противоречивое.
                c.ok("CERT_OK", "Сертификат",
                     f"Действующий сертификат, выпущен {tls.age_days} дн. назад"
                     + (f", издатель: {tls.issuer}" if tls.issuer else ""))
    elif tls is not None and tls.handshake_failed and lexical.scheme == "https":
        c.add("TLS_BROKEN", Severity.WARN, "Защищённое соединение не работает",
              "Адрес заявлен как https, но установить защищённое соединение "
              "не удалось",
              weight_key="tls_broken")

    # ── Уровень 2c: журналы сертификатов ─────────────────────────
    # Независимая оценка возраста домена. Даём её вес ТОЛЬКО когда
    # RDAP и WHOIS молчат: иначе один и тот же факт «домен свежий»
    # засчитывается дважды.
    if ct is not None and ct.checked:
        if ct.first_seen_days is not None and not age_known:
            if ct.first_seen_days < settings.DOMAIN_AGE_VERY_NEW:
                c.add("CT_FIRST_SEEN_VERY_NEW", Severity.DANGER,
                      "Домен только появился",
                      f"Первый сертификат на этот домен выпущен "
                      f"{ct.first_seen_days} дн. назад. Дату регистрации "
                      f"узнать не удалось, но журналы сертификатов её выдают",
                      weight_key="ct_first_seen_very_new")
            elif ct.first_seen_days < settings.DOMAIN_AGE_NEW:
                c.add("CT_FIRST_SEEN_NEW", Severity.WARN, "Домен недавний",
                      f"Первый сертификат выпущен {ct.first_seen_days} дн. назад",
                      weight_key="ct_first_seen_new")
            else:
                c.ok("CT_MATURE", "История домена",
                     f"В журналах сертификатов домен известен "
                     f"{ct.first_seen_days} дн.")
        elif ct.total_certs == 0 and lexical.scheme == "https":
            # Именно `== 0`, не `not ct.total_certs`: None означает
            # «ответ не дочитан», а не «сертификатов нет».
            c.add("CT_NO_RECORDS", Severity.INFO, "Нет в журналах сертификатов",
                  "На домен никогда не выпускали сертификат, хотя адрес "
                  "заявлен как https",
                  weight_key="ct_no_records")
        elif ct.first_seen_days is not None:
            if ct.first_seen_days < settings.DOMAIN_AGE_NEW:
                # Зелёный сигнал про трёхдневный домен рядом с красным
                # «домен только появился» читается как оправдание.
                c.add("CT_FIRST_SEEN_NEW", Severity.INFO, "История домена",
                      f"В журналах сертификатов домен известен всего "
                      f"{ct.first_seen_days} дн.", weight=0)
            else:
                c.ok("CT_CONFIRMS", "История домена",
                     f"Журналы сертификатов подтверждают: домен известен "
                     f"{ct.first_seen_days} дн.")

    # Домен для показа человеку: xn--форма верна технически, но
    # «мвд.рф» читается, а «xn--b1aew.xn--p1ai» — нет.
    shown_domain = lexical.decoded_host or lexical.registered_domain

    # ── Уровень 5: содержимое страницы ───────────────────────────
    if page is not None and page.checked:
        from data.brands import BRAND_DOMAINS

        # Бренд заявлен в тексте, но домен ему не принадлежит.
        foreign_brands = []
        if page.brands_in_text and not lexical.is_trusted_domain:
            foreign_brands = [
                b for b in page.brands_in_text
                if lexical.registered_domain not in BRAND_DOMAINS.get(b, ())
            ]

        # Поле пароля и кнопка «войти через Telegram» есть у множества
        # нормальных сайтов: у форумов, магазинов, сервисов. Сами по
        # себе они не улика, а описание обычной страницы входа.
        #
        # Уликой они становятся рядом с чем-то настоящим: чужим брендом
        # на странице, формой на сторонний адрес или доменом, заведённым
        # на прошлой неделе. Тогда кнопка «войти через Telegram»
        # объясняет, КАК именно уведут аккаунт.
        #
        # Без этой оговорки форум с входом через ВК получал 57 баллов,
        # а молодой стартап — 72, то есть «ОПАСНО». На поимку реального
        # фишинга признак при этом не влиял никак: в том случае с угоном
        # Telegram балл был 100 и с ним, и без него.
        hard_evidence = bool(foreign_brands) or bool(page.cross_domain_form) or (
            domain_age.checked and domain_age.age_days is not None
            and domain_age.age_days < settings.DOMAIN_AGE_VERY_NEW
        )

        if page.cross_domain_form:
            c.add("PAGE_CROSS_DOMAIN_FORM", Severity.DANGER,
                  "Данные уходят на другой сайт",
                  f"Форма отправляет введённое на посторонний адрес: "
                  f"{page.cross_domain_form}",
                  weight_key="page_cross_domain_form")

        if foreign_brands:
            c.add("PAGE_BRAND_MISMATCH", Severity.DANGER,
                  "Чужой бренд на странице",
                  f"Страница выдаёт себя за «{', '.join(foreign_brands)}», "
                  f"но домен {shown_domain} этой компании "
                  f"не принадлежит",
                  weight_key="page_brand_mismatch")

        if page.messenger_login:
            names = ", ".join(page.messenger_login)
            if hard_evidence:
                c.add("PAGE_MESSENGER_LOGIN", Severity.DANGER,
                      "Вход через мессенджер",
                      f"Страница предлагает войти через {names}. Именно так "
                      f"угоняют аккаунты: вы подтверждаете вход, который "
                      f"запустил не вы",
                      weight_key="page_messenger_login")
            else:
                c.add("PAGE_MESSENGER_LOGIN_OK", Severity.INFO,
                      "Вход через мессенджер",
                      f"Страница предлагает войти через {names}. Так делают "
                      f"и обычные сайты, поэтому сам по себе этот способ "
                      f"входа ни о чём не говорит",
                      weight=0)

        if page.has_password_field and not lexical.is_trusted_domain:
            if hard_evidence:
                c.add("PAGE_PASSWORD_FORM", Severity.WARN, "Просит пароль",
                      "На странице есть поле для пароля. Вместе с остальными "
                      "признаками — повод не вводить ничего",
                      weight_key="page_password_form")
            else:
                c.add("PAGE_PASSWORD_FORM_OK", Severity.INFO, "Просит пароль",
                      "На странице есть поле для пароля — как на любой "
                      "странице входа. Ничего подозрительного рядом с ним "
                      "мы не нашли",
                      weight=0)

        if page.hidden_input_count >= 3:
            c.add("PAGE_HIDDEN_INPUTS", Severity.INFO, "Скрытые поля в форме",
                  f"В форме {page.hidden_input_count} скрытых полей — так "
                  f"передают метки кампании в массовых рассылках",
                  weight_key="page_hidden_inputs")

        if not any([page.messenger_login, page.cross_domain_form,
                    page.has_password_field]):
            if page.status_code is not None and 200 <= page.status_code < 300:
                c.ok("PAGE_CLEAN", "Содержимое страницы",
                     "Форм для ввода паролей и подозрительных кнопок входа нет")
            else:
                # При 403 от бот-защиты мы видели заглушку, а не сайт.
                # Говорить «форм нет» — успокаивать на пустом месте.
                c.add("PAGE_NOT_SEEN", Severity.INFO, "Страница не показана",
                      f"Сайт ответил кодом {page.status_code} — "
                      f"настоящее содержимое проверить не удалось",
                      weight=0)

    # ── Уровень 3: структура и лексика ───────────────────────────
    if lexical.has_ip_address:
        c.add("IP_IN_URL", Severity.DANGER, "IP вместо домена",
              "Адрес задан IP-адресом. У легитимных сервисов есть доменное "
              "имя и сертификат на него",
              weight_key="ip_in_url")

    if lexical.has_at_symbol:
        c.add("AT_SYMBOL", Severity.DANGER, "Символ @ в адресе",
              "Всё, что стоит до @, браузер считает логином и игнорирует. "
              "В http://sberbank.ru@evil.top настоящий сайт — evil.top",
              weight_key="at_symbol")

    # Бренд-имперсонация: три разных веса под три разные техники.
    brand = lexical.brand_match
    if brand:
        if brand.kind == "homograph":
            c.add("BRAND_HOMOGRAPH", Severity.DANGER, "Подмена символов",
                  f"Домен визуально неотличим от «{brand.brand}», но записан "
                  f"другими символами: {brand.evidence}",
                  weight_key="brand_homograph")
        elif brand.kind == "typosquat":
            c.add("BRAND_TYPOSQUAT", Severity.DANGER, "Опечаточный домен",
                  f"Домен отличается от «{brand.brand}» на пару символов: "
                  f"{brand.evidence}",
                  weight_key="brand_typosquat")
        else:
            c.add("BRAND_IMPERSONATION", Severity.DANGER, "Чужой бренд в домене",
                  f"Имя «{brand.brand}» использовано в домене, который бренду "
                  f"не принадлежит: {brand.evidence}",
                  weight_key="brand_impersonation")
    elif not lexical.is_trusted_domain:
        c.ok("BRAND_CLEAN", "Имитация брендов", "Имитации известных брендов не обнаружено")

    if lexical.has_punycode and not (brand and brand.kind == "homograph"):
        if lexical.idn_is_native:
            # Национальный домен иначе не записать: `мвд.рф` — это
            # всегда xn--. Балл здесь давал ложное «ОПАСНО» каждому
            # домену в зоне .рф.
            c.ok("PUNYCODE_NATIVE", "Национальный домен",
                 f"Адрес записан как «{lexical.decoded_host or lexical.host}» — "
                 f"для этой зоны это обычная запись, а не подмена")
        else:
            c.add("PUNYCODE", Severity.WARN, "Punycode (IDN)",
                  f"Домен закодирован как xn--… и отображается как "
                  f"«{lexical.decoded_host or lexical.host}»",
                  weight_key="punycode")

    # Гомоглиф бренда — это И ЕСТЬ смешение алфавитов и нелатиница,
    # только названные точнее и весом больше. Дублировать его двумя
    # общими признаками значит считать одну букву трижды.
    brand_is_homograph = (lexical.brand_match is not None
                          and lexical.brand_match.kind == "homograph")
    if brand_is_homograph:
        pass
    elif lexical.has_mixed_scripts:
        c.add("MIXED_SCRIPTS", Severity.DANGER, "Смешение алфавитов",
              "В одном слове домена соседствуют символы разных алфавитов "
              "(например, латиница и кириллица) — признак подмены",
              weight_key="mixed_scripts")
    elif lexical.has_non_ascii_host:
        c.add("NON_ASCII_HOST", Severity.WARN, "Не-ASCII символы в домене",
              "Домен содержит символы вне латиницы",
              weight_key="non_ascii_host")

    if lexical.has_encoded_host:
        c.add("ENCODED_HOST", Severity.WARN, "Кодирование в домене",
              "В доменной части использовано процентное кодирование (%XX) — "
              "легитимные домены так не записывают",
              weight_key="encoded_host")

    if lexical.has_non_standard_port:
        c.add("NON_STANDARD_PORT", Severity.WARN, "Нестандартный порт",
              "Веб-сервисы работают на портах 80 и 443. Другой порт означает "
              "самодельный сервер, а не хостинг компании",
              weight_key="non_standard_port")

    if lexical.is_insecure_scheme:
        c.add("INSECURE_SCHEME", Severity.WARN, "Соединение без шифрования",
              "Используется http:// — данные, введённые на странице, "
              "передаются открытым текстом",
              weight_key="insecure_scheme")

    if lexical.has_redirect_params:
        c.add("REDIRECT_PARAMS", Severity.WARN, "Параметры переадресации",
              "В адресе есть параметры вида ?url= / ?goto= / ?redirect= — "
              "через них легитимный сайт используют как трамплин",
              weight_key="redirect_params")

    if lexical.subdomain_count > settings.MAX_SUBDOMAINS:
        c.add("EXCESSIVE_SUBDOMAINS", Severity.WARN, "Много поддоменов",
              f"Уровней поддоменов: {lexical.subdomain_count}. Настоящий домен — "
              f"всегда последние две части адреса, остальное подставляет владелец",
              weight_key="excessive_subdomains")

    if lexical.url_length > settings.MAX_URL_LENGTH:
        c.add("LONG_URL", Severity.INFO, "Длинный адрес",
              f"{lexical.url_length} символов — длинный адрес мешает разглядеть "
              f"настоящий домен в адресной строке",
              weight_key="long_url")

    if lexical.domain_length > settings.MAX_DOMAIN_LENGTH:
        c.add("LONG_DOMAIN", Severity.INFO, "Длинное имя домена",
              f"{lexical.domain_length} символов в имени домена",
              weight_key="long_domain")

    if lexical.hyphen_count > settings.MAX_HYPHENS:
        c.add("EXCESSIVE_HYPHENS", Severity.WARN, "Много дефисов",
              f"{lexical.hyphen_count} дефисов в домене — обычный приём "
              f"«склейки» правдоподобного имени",
              weight_key="excessive_hyphens")

    if lexical.trigger_keywords:
        words = ", ".join(lexical.trigger_keywords[:6])
        many = len(lexical.trigger_keywords) >= 2
        if lexical.keywords_in_host:
            # Слова в ИМЕНИ домена — так мошенник называет свой сайт,
            # чтобы тот выглядел служебным: `secure-login-verify.top`.
            c.add("TRIGGER_KEYWORDS", Severity.WARN if many else Severity.INFO,
                  "Тревожные слова в имени домена",
                  f"Найдено: {words}. В самом имени домена такие слова "
                  f"ставят, чтобы он выглядел официальным",
                  weight_key="trigger_keywords_many" if many else "trigger_keywords")
        else:
            # А в пути они есть у КАЖДОЙ честной страницы входа:
            # `tele2.ru/security/password/recovery`. Показываем, но не
            # ставим в вину — иначе личные кабинеты половины страны
            # получают «ПОДОЗРИТЕЛЬНО» за то, что они личные кабинеты.
            c.add("TRIGGER_KEYWORDS_PATH", Severity.INFO,
                  "Слова входа в адресе страницы",
                  f"Найдено: {words}. На странице входа это обычное дело, "
                  f"само по себе ни о чём не говорит",
                  weight=0)

    if lexical.suspicious_tld:
        c.add("SUSPICIOUS_TLD", Severity.WARN, "Подозрительная зона",
              f"Зона .{lexical.tld} раздаётся бесплатно или почти бесплатно, "
              f"поэтому её массово используют для одноразовых доменов",
              weight_key="suspicious_tld")

    elif lexical.abused_tld:
        c.add("ABUSED_TLD", Severity.INFO, "Дешёвая доменная зона",
              f"Зона .{lexical.tld} стоит копейки, поэтому в ней много "
              f"одноразовых сайтов. Сама по себе не опасна, но в сочетании "
              f"с другими признаками — повод насторожиться",
              weight_key="abused_tld")

    if lexical.scam_pattern:
        from pipeline.lexical_analyzer import SCAM_PATTERN_LABELS
        label = SCAM_PATTERN_LABELS.get(lexical.scam_pattern, lexical.scam_pattern)
        c.add("SCAM_PATTERN", Severity.DANGER, "Узнаваемая схема обмана",
              f"Адрес построен по известной схеме: {label}. Отдельные слова тут "
              f"безобидны, опасна именно их связка — так устроены массовые "
              f"рассылки, ворующие аккаунты",
              weight_key="scam_pattern")

    if lexical.has_digits_in_domain:
        c.add("DIGITS_IN_DOMAIN", Severity.INFO, "Цифры в домене",
              "Цифры в имени домена часто заменяют похожие буквы (0 → o, 1 → l)",
              weight_key="digits_in_domain")

    # ── Уровень 1c: мнение языковой модели ───────────────────────
    # Вес не фиксирован: им СЛУЖИТ сама поправка, уже зажатая в
    # границы конфига внутри ai_analyzer. Скорер к этому числу
    # относится как к любому другому весу и ничего не пересчитывает.
    if ai is not None and ai.checked:
        if ai.delta > 0:
            severity = Severity.DANGER if ai.delta >= 25 else Severity.WARN
            title = ("Имитация бренда «%s»" % ai.brand) if ai.brand else "Анализ модели"
            c.add("AI_SUSPICIOUS", severity, title,
                  ai.summary or "Модель считает адрес подозрительным",
                  weight=ai.delta)
        elif ai.delta < 0:
            c.add("AI_REASSURING", Severity.INFO, "Анализ модели",
                  ai.summary or "Модель не нашла признаков мошенничества",
                  weight=ai.delta)
        else:
            c.ok("AI_CLEAN", "Анализ модели",
                 ai.summary or "Модель не нашла признаков мошенничества")

    # ── Финальная нормализация ───────────────────────────────────
    score = c.score

    # Правило 1: пол по внешней разведке.
    if external_hit:
        score = max(score, 90)

    # Правило 2: потолок доверия (не применяется поверх внешних улик).
    if lexical.is_trusted_domain and not external_hit:
        if score > TRUSTED_DOMAIN_SCORE_CAP:
            logger.info("Trusted domain %s: capping score %d → %d",
                        lexical.registered_domain, score, TRUSTED_DOMAIN_SCORE_CAP)
        score = min(score, TRUSTED_DOMAIN_SCORE_CAP)
        c.ok("TRUSTED_DOMAIN", "Репутация домена",
             f"{shown_domain} — известный домен с проверенной репутацией")

    # Правило 3: смягчение для неразвёрнутых сокращателей.
    # Потолок означает «мы не знаем, куда она ведёт». Если уровень
    # страницы всё-таки дочитал её до конца и принёс улики, мы знаем —
    # и глушить их нечестно: полный набор признаков обмана упирался
    # в 45 баллов только потому, что адрес начинался с bit.ly.
    page_saw_something = page is not None and page.checked and bool(
        page.cross_domain_form or page.messenger_login
        or page.brands_in_text or page.has_password_field)
    if (lexical.is_shortener and redirects is not None
            and not redirects.resolved and not external_hit
            and not page_saw_something):
        score = min(score, UNRESOLVED_SHORTENER_CAP)

    score = max(0, min(score, 100))
    verdict = _verdict(score)

    # Сортируем по весу: самое важное — первым. Без этого порядок
    # зависел бы от порядка правил в коде, а не от значимости.
    c.signals.sort(key=lambda s: (-s.weight, s.code))

    confidence = _confidence(gsb, reputation, domain_age, redirects,
                             ai, tls, ct, page)
    logger.info("Score for %s: %d (%s), signals=%d, confidence=%.2f",
                url, score, verdict.value, len(c.signals), confidence)

    details = {
        "threat_intel": gsb.model_dump(),
        "reputation": reputation.model_dump(),
        "domain_age": domain_age.model_dump(),
        "lexical": lexical.model_dump(),
    }
    if ai is not None:
        details["ai"] = ai.model_dump()
    if tls is not None:
        details["tls"] = tls.model_dump()
    if ct is not None:
        details["ct"] = ct.model_dump()
    if page is not None:
        details["page"] = page.model_dump()

    return ScanResponse(
        url=original_url,
        scanned_url=url,
        is_phishing=score >= settings.PHISHING_THRESHOLD,
        risk_score=score,
        verdict=verdict,
        confidence=confidence,
        signals=c.signals,
        # reasons сохранён для обратной совместимости со старым фронтендом.
        reasons=[f"{s.title}: {s.detail}" for s in c.signals
                 if s.severity != Severity.OK],
        redirects=redirects,
        details=details,
    )


__all__ = ["calculate_risk_score"]
