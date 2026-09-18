# Находки агентов — 18 сентября 2026

**Сеть:** открыта. `/health` живого сайта отвечает, `crt.sh` и RDAP доступны напрямую из контейнера.
**Агентов запущено:** 4. **Отчитался 1** — остальные три убиты лимитом сессии (HTTP 429, «session limit resets 8:10pm UTC») до того, как успели что-либо записать.
**Уровней реально работало:** 7 из 8. `ANTHROPIC_API_KEY` не задан → уровень Claude выключен. **`URLHAUS_AUTH_KEY` теперь ЗАДАН** — `/health` отдаёт `"urlhaus": true`, в CLAUDE.md записано обратное, надо поправить.
**Ничего не чинилось:** да. Ни одной правки в файлах проекта. Тесты как были — 270 проходят.

## Что покрыто, а что нет

| Зона | Кто делал | Статус |
|------|-----------|--------|
| 2. Пропуски | агент | **покрыто**, 13 находок, все перепроверены мной запуском |
| 5. Ревью кода | я сам | **покрыто**, 4 находки |
| 1. Ложные тревоги | агент убит лимитом | **почти не покрыто** — но я сам наткнулся на F-02, и она тяжёлая |
| 3. Кривой ввод и падения | агент убит лимитом | **не покрыто** (агент успел написать «нашёл падение», но отчёт не сохранился) |
| 4. Интерфейс | агент убит лимитом | **не покрыто вообще** |

Зоны 1, 3 и 4 надо переигрывать отдельной сессией. Зона 3 особенно: агент перед смертью написал «Found a crash», но что именно — неизвестно.

## Сводка

| № | Зона | Коротко | Серьёзность | Проверил сам |
|---|------|---------|-------------|--------------|
| F-01 | пропуски | `%2F` в логине адреса подменяет анализируемый домен на доверенный: любой фишинг → 0 баллов, «БЕЗОПАСНО», достоверность 1.0 | **критическая** | да, в т.ч. на живом сайте |
| F-02 | ложные тревоги | `github.com`, `docs.google.com`, `dropbox.com`, `t.me`, `discord.com` на живом сайте = **ОПАСНО** (90 баллов) | **высокая** | да, на живом сайте |
| F-03 | пропуски | доверенная площадка выключает уровень страницы и режет балл до 15 | высокая | да |
| F-04 | пропуски | форма пароля и вход через Telegram весят 0 баллов на зрелом домене | высокая | да |
| F-05 | пропуски | `github.io` / `amazonaws.com` / `googleapis.com` полностью выключают детект брендов | высокая | да |
| F-06 | пропуски | неразвёрнутый сокращатель = 15 баллов «БЕЗОПАСНО», потолок 45 недостижим | высокая | да |
| F-07 | пропуски | схема из истории проекта не ловится в падежах: `golosovanie-za-rebenka.ru` → 17 SAFE | высокая | да |
| F-08 | ревью кода | кеш уровня страницы ключуется по `url[:500]` — длинные адреса получают чужие улики | средняя | да |
| F-09 | пропуски | кириллические бренды в `.рф` не опознаются | средняя | да |
| F-10 | пропуски | короткие бренды (`sber`, `vk`, `ozon`, `vtb`) в дефисных доменах не ловятся | средняя | да |
| F-11 | пропуски | бренд в пути адреса не проверяется вообще | средняя | да |
| F-12 | пропуски | нет слов доставки и штрафов — две массовые схемы мимо | средняя | да |
| F-13 | пропуски | открытый редирект: параметров нет в словаре + сверху потолок доверия | средняя | да |
| F-14 | пропуски | IP в десятичной и шестнадцатеричной записи не считается IP | средняя | да |
| F-15 | пропуски | в брендах страницы нет ВКонтакте, Авито, Почты России | средняя | да |
| F-16 | ревью кода | тест-сторож не проверяет второй язык: сигнал только в `ru` пройдёт проверку | средняя | да |
| F-17 | ревью кода | `TRUSTED_PROXY_HOPS=0` разворачивает лимит запросов на клиентское значение | низкая | да |
| F-18 | ревью кода | уровень, выключенный отсутствием ключа, занижает достоверность | низкая | да |

Серьёзность: **высокая** — врёт пользователю или падает; **средняя** — портит объяснение или ухудшает балл; **низкая** — косметика.

## Общий харнесс для воспроизведения

Почти все команды ниже опираются на один хелпер. Положи его один раз, проект он не трогает:

```bash
mkdir -p /tmp/pg && cat > /tmp/pg/verify.py <<'EOF'
import sys; sys.path.insert(0, '/home/user/phishguard/backend')
from pipeline.lexical_analyzer import lexical_analyzer as L
from pipeline.scorer import calculate_risk_score as S
from models import *
OFF = dict(checked=False, error='offline')
def sc(u, **kw):
    return S(url=u, original_url=u,
             gsb=kw.get('gsb', ThreatIntelResult(**OFF)), reputation=kw.get('rep', ReputationResult(**OFF)),
             domain_age=kw.get('age', DomainAgeResult(**OFF)), lexical=L.analyze(u), redirects=kw.get('ri'),
             ai=AiVerdictResult(**OFF), tls=kw.get('tls', TlsResult(**OFF)),
             ct=kw.get('ct', CtResult(**OFF)), page=kw.get('page', PageResult(**OFF)))
EOF
```

---

## Находка F-01. `%2F` в логине адреса подменяет анализируемый домен на доверенный

- **Зона:** пропуски
- **Серьёзность:** критическая
- **Проверил сам запуском:** да, локально и на живом сайте
- **Что не так:** лексический уровень делает `unquote()` ДО `urlsplit()`, поэтому `%2F` превращается в `/`, граница между логином и хостом уезжает, и разбирается `sberbank.ru` вместо настоящего хоста — со всеми последствиями: потолок доверия 15, уровень страницы не запускается, `AT_SYMBOL` и `ENCODED_HOST` молчат.
- **Как воспроизвести (локально):**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import *
import httpx
for u in ['https://sberbank.ru%2Flogin@evil-phish.top/verify',
          'https://sberbank.ru%3Fx@evil-phish.top/verify',
          'https://google.com%2Fsearch@192.168.0.1/admin']:
    f = L.analyze(u); r = sc(u)
    print(f'браузер пойдёт на {httpx.URL(u).host:18s} | lexical видит {f.host:14s} | trusted={f.is_trusted_domain} -> {r.risk_score:3d} {r.verdict.value}')
"
```

- **Как воспроизвести (живой сайт; цель — зарезервированный IANA `example.com`, никуда вредного не ходим):**

```bash
cd /home/user/phishguard/backend && python3 -c "
import httpx
d = httpx.post('https://phishguard-ayrt.onrender.com/scan',
               json={'url':'https://sberbank.ru%2Flogin@example.com/verify'}, timeout=150).json()
print(d['risk_score'], d['verdict'], 'conf=', d['confidence'])
print('lexical host =', d['details']['lexical']['host'], '| trusted =', d['details']['lexical']['is_trusted_domain'])
print('page:', d['details']['page']['error'])
print('signals:', [(s['code'], s['weight']) for s in d['signals']])
"
```

- **Ожидали:** ≥ 60 и сигнал `AT_SYMBOL` весом 50 — «всё до @ браузер считает логином».
- **Получили** (реальный вывод живого сайта):

```
0 SAFE conf= 1.0
lexical host = sberbank.ru | trusted = True
page: Пропущено: доверенный домен
signals: [('CERT_OK', 0), ('DOMAIN_MATURE', 0), ('GSB_CLEAN', 0), ('TRUSTED_DOMAIN', 0), ('URLHAUS_CLEAN', 0)]
```

Хуже некуда: ноль баллов, зелёное «БЕЗОПАСНО», достоверность **1.0** и текст «sberbank.ru — известный домен с проверенной репутацией». Сервис не просто пропустил — он уверенно успокоил.

- **Где в коде:** `backend/pipeline/lexical_analyzer.py:224` (`decoded_url = unquote(raw)`) и `:229` (`parsed = urlsplit(decoded_url)`). Сетевые уровни разбирают адрес правильно (`tls_check.py:113`, `page_analyzer.py:184`, `url_resolver.py:26` — все через голый `urlsplit`), поэтому пайплайн раздваивается: сертификат проверили у одного домена, доверие присвоили другому.
- **Заметка:** страховка `has_encoded_host` тут не помогает, потому что `lexical_analyzer.py:219` делает `raw_netloc.split("@")[-1]` — берёт часть ПОСЛЕ `@`, где процентов уже нет. Работают одинаково `%2F`, `%3F` и `%23`. Приставка `https://<любой-доверенный>%2F@` обнуляет что угодно, включая `BRAND_TYPOSQUAT`+`MIXED_SCRIPTS`+`PUNYCODE` разом.

---

## Находка F-02. Площадки общего пользования на живом сайте помечены как ОПАСНО

- **Зона:** ложные тревоги
- **Серьёзность:** высокая
- **Проверил сам запуском:** да, на живом сайте
- **Что не так:** URLhaus ведёт учёт вредоносных ссылок ПО ХОСТУ, и у любой крупной площадки с пользовательским контентом этих ссылок тысячи; признак `URLHAUS_HOST` считается внешней разведкой, поднимает балл до пола 90 и заодно отменяет потолок доверия — в итоге `github.com` и `docs.google.com` получают вердикт «ОПАСНО».
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import httpx
urls=['https://docs.google.com/document/d/abc/edit','https://github.com/torvalds/linux',
      'https://raw.githubusercontent.com/a/b/main/c.txt','https://www.dropbox.com/s/abc/file.pdf',
      'https://t.me/durov','https://discord.com/channels/1','https://sites.google.com/view/team',
      'https://firebasestorage.googleapis.com/v0/b/x/o/y','https://drive.google.com/file/d/xyz/view',
      'https://vk.com/id1']
with httpx.Client(timeout=120) as c:
    for u in urls:
        d = c.post('https://phishguard-ayrt.onrender.com/scan', json={'url':u}).json()
        print(f\"{d['risk_score']:3d} {d['verdict']:10s} {u[:52]:52s} {[s['code'] for s in d['signals'] if s['weight']>0][:3]}\")
"
```

- **Ожидали:** SAFE. Это буквально GitHub и Google Docs.
- **Получили** (реальный вывод):

```
 90 PHISHING   https://docs.google.com/document/d/abc/edit          ['URLHAUS_HOST']
  0 SAFE       https://drive.google.com/file/d/xyz/view             []
 90 PHISHING   https://github.com/torvalds/linux                    ['URLHAUS_HOST']
 90 PHISHING   https://raw.githubusercontent.com/a/b/main/c.txt     ['URLHAUS_HOST']
 90 PHISHING   https://www.dropbox.com/s/abc/file.pdf               ['URLHAUS_HOST']
 90 PHISHING   https://t.me/durov                                   ['URLHAUS_HOST']
 90 PHISHING   https://discord.com/channels/1                       ['URLHAUS_HOST']
 90 PHISHING   https://sites.google.com/view/team                   ['URLHAUS_HOST']
  0 SAFE       https://vk.com/id1                                   []
 90 PHISHING   https://firebasestorage.googleapis.com/v0/b/x/o/y    ['URLHAUS_HOST']
```

Восемь из десяти честных адресов — «ОПАСНО». Текст объяснения: «С этого хоста уже раздавали вредоносное ПО (зафиксировано ссылок: 1537)». Формально правда, по смыслу — вранье: раздавали не `docs.google.com`, а те, кто на нём публиковался.

- **Где в коде:** `backend/pipeline/scorer.py:178-183` — `reputation.host_listed` выставляет `external_hit = True`; пол 90 на `:595`, отмена потолка доверия на `:599`.
- **Заметка:** появилось ровно вчера-сегодня, вместе с ключом `URLHAUS_AUTH_KEY`. Пока ключа не было, уровень молчал и этой ложной тревоги не существовало. По философии проекта («ложная тревога хуже пропуска») это, возможно, срочнее всего остального, кроме F-01. Направление: `URLHAUS_HOST` не должен считаться внешней разведкой — либо смотреть долю вредоносных ссылок к общему объёму хоста, либо не применять его к площадкам с пользовательским контентом, либо снять с него статус `external_hit` и оставить как обычный признак с весом.

---

## Находка F-03. На доверенной площадке страница даже не открывается

- **Зона:** пропуски
- **Серьёзность:** высокая
- **Проверил сам запуском:** да
- **Что не так:** `telegra.ph`, `t.me`, `docs.google.com` / `sites.google.com` (через `google.com`), `medium.com`, `mail.ru` попали в `TRUSTED_DOMAINS`, а на доверенном домене `main.py:211` выключает уровни страницы и CT целиком — сервис физически не смотрит, что там опубликовано, и режет балл до 15.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import *
AGE = DomainAgeResult(checked=True, age_days=4000, source='rdap')
PAGE = PageResult(checked=True, status_code=200, has_password_field=True, messenger_login=['telegram'],
                  cross_domain_form='https://evil-collector.top/save',
                  brands_in_text=['sberbank','gosuslugi'], hidden_input_count=5, form_count=1)
for u in ['https://telegra.ph/Golosovanie-za-rebenka','https://docs.google.com/forms/d/e/1F/viewform',
          'https://sites.google.com/view/gosuslugi-vyplata','https://phish.medium.com/sber-login',
          'https://evil-nobrand.ru/page']:
    r = sc(u, age=AGE, page=PAGE); print(f'{r.risk_score:3d} {r.verdict.value:10s} {u}')
"
```

- **Ожидали:** одинаковые улики — одинаковый балл.
- **Получили:** первые четыре → `15 SAFE`, последний с ТЕМИ ЖЕ уликами → `100 PHISHING`.
- **Где в коде:** `backend/data/brands.py:73` — в `MULTI_TENANT_DOMAINS` всего четыре записи (`amazonaws.com`, `googleapis.com`, `sharepoint.com`, `wordpress.com`); `telegra.ph`, `t.me`, `google.com`, `medium.com`, `mail.ru`, `ok.ru`, `github.io`, `notion.so` — не в нём. Потолок: `scorer.py:599-603`. Выключение уровней: `main.py:211` и `:216-217`. Подавление признаков страницы: `scorer.py:336` и `:392`.
- **Заметка:** на живом сайте `telegra.ph` сейчас даёт 90, но ТОЛЬКО из-за F-02 — URLhaus сам числит его раздающим вредонос. Не будь ключа, было бы 5 SAFE. Две ошибки случайно гасят друг друга.

---

## Находка F-04. Форма пароля и вход через Telegram весят ноль

- **Зона:** пропуски
- **Серьёзность:** высокая
- **Проверил сам запуском:** да
- **Что не так:** веса `page_password_form` и `page_messenger_login` начисляются только при `hard_evidence`; на бесплатном хостинге возраст берётся у площадки (`pages.dev` — годы), чужого бренда в тексте нет, формы на чужой домен нет — и оба признака превращаются в `..._OK` с весом 0. Та самая кнопка «войти через Telegram» из истории проекта не даёт ни балла.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import *
AGE = DomainAgeResult(checked=True, age_days=2000, source='rdap')
CT  = CtResult(checked=True, first_seen_days=1900, total_certs=99999)
PAGE= PageResult(checked=True, status_code=200, has_password_field=True,
                 messenger_login=['telegram'], form_count=1)
for u in ['https://sber-vhod.pages.dev/login','https://auth-vk.workers.dev/',
          'https://sberbank-lk.github.io/vhod','https://paypal.s3.amazonaws.com/signin.html']:
    r = sc(u, age=AGE, ct=CT, page=PAGE)
    print(f'{r.risk_score:3d} {r.verdict.value:10s} {u} | {[(s.code,s.weight) for s in r.signals if s.code.startswith(\"PAGE\")]}')
"
```

- **Ожидали:** ≥ 60 — страница просит пароль и предлагает вход через мессенджер на домене, где публиковать может кто угодно.
- **Получили:**

```
 22 SAFE       https://sber-vhod.pages.dev/login | [('PAGE_MESSENGER_LOGIN_OK', 0), ('PAGE_PASSWORD_FORM_OK', 0)]
  0 SAFE       https://auth-vk.workers.dev/ | [('PAGE_MESSENGER_LOGIN_OK', 0), ('PAGE_PASSWORD_FORM_OK', 0)]
 12 SAFE       https://sberbank-lk.github.io/vhod | [('PAGE_MESSENGER_LOGIN_OK', 0), ('PAGE_PASSWORD_FORM_OK', 0)]
 12 SAFE       https://paypal.s3.amazonaws.com/signin.html | [('PAGE_MESSENGER_LOGIN_OK', 0), ('PAGE_PASSWORD_FORM_OK', 0)]
```

- **Где в коде:** `backend/pipeline/scorer.py:363-370` — `hard_evidence` требует чужого бренда в тексте, формы на чужой домен или домена моложе 7 дней; возраст берётся у площадки (`main.py:213` → `check_domain_age(lexical.registered_domain)`), поэтому третье условие на бесплатном хостинге не выполняется никогда.
- **Заметка:** оговорка добавлялась против ложных тревог (форум с входом через ВК) — и заодно закрыла целый класс настоящего фишинга. Чинить вместе с F-03 и F-05: корень один.

---

## Находка F-05. `github.io`, `amazonaws.com`, `googleapis.com` полностью выключают детект брендов

- **Зона:** пропуски
- **Серьёзность:** высокая
- **Проверил сам запуском:** да
- **Что не так:** `_match_brand` первым делом проверяет, не принадлежит ли регистрируемый домен самому бренду, и при попадании возвращает `None`, не дойдя до остальных проверок. Для площадок это значит: любой фишинговый поддомен на них невидим для всех трёх техник — гомоглифов, опечаток и подстановки.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import *
for u in ['https://sberbank.github.io/login','https://sberbank.netlify.app/login',
          'https://paypal.s3.amazonaws.com/signin.html']:
    f = L.analyze(u); r = sc(u)
    print(f'{r.risk_score:3d} {r.verdict.value:10s} brand={f.brand_match and f.brand_match.brand} {u}')
"
```

- **Ожидали:** `sberbank.github.io` ведёт себя как `sberbank.netlify.app`.
- **Получили:**

```
 17 SAFE       brand=None https://sberbank.github.io/login
 62 PHISHING   brand=sberbank https://sberbank.netlify.app/login
 17 SAFE       brand=None https://paypal.s3.amazonaws.com/signin.html
```

Разница ровно в том, что `github.io` записан доменом бренда «github», а `netlify.app` никому не принадлежит.

- **Где в коде:** `backend/pipeline/lexical_analyzer.py:465-468`. `MULTI_TENANT_DOMAINS` (`data/brands.py:73`) вычитается только из `TRUSTED_DOMAINS` (`data/brands.py:99`), но НЕ из `BRAND_DOMAINS` — поэтому от потолка доверия площадки защищены, а от этого раннего `return None` нет.

---

## Находка F-06. Неразвёрнутый сокращатель = 15 баллов «БЕЗОПАСНО»

- **Зона:** пропуски
- **Серьёзность:** высокая
- **Проверил сам запуском:** да
- **Что не так:** `UNRESOLVED_SHORTENER_CAP = 45` — это ПОТОЛОК, а не пол, и он не срабатывает никогда: у `shortener` вес 10, у `domain_age_unknown` — 5, итого 15, и до потолка балл не доходит. Прямое нарушение принципа «не смогли проверить ≠ безопасно».
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import *
for u in ['https://bit.ly/3xPhish','https://vk.cc/xyz999','https://clck.ru/ab12','https://tinyurl.com/vote']:
    r = sc(u, ri=RedirectInfo(resolved=False, final_url=u, chain=[u], hops=0,
                              was_shortener=True, error='нет ответа'))
    print(f'{r.risk_score:3d} {r.verdict.value:10s} {u} | {[(s.code,s.weight) for s in r.signals]}')
"
```

- **Ожидали:** минимум SUSPICIOUS (≥ 30) — конечный адрес неизвестен.
- **Получили:**

```
 15 SAFE       https://bit.ly/3xPhish | [('SHORTENER_UNRESOLVED', 10), ('DOMAIN_AGE_UNKNOWN', 5), ('BRAND_CLEAN', 0)]
 15 SAFE       https://vk.cc/xyz999 | [('SHORTENER_UNRESOLVED', 10), ('DOMAIN_AGE_UNKNOWN', 5), ('TRUSTED_DOMAIN', 0)]
 15 SAFE       https://clck.ru/ab12 | [('SHORTENER_UNRESOLVED', 10), ('DOMAIN_AGE_UNKNOWN', 5), ('BRAND_CLEAN', 0)]
 27 SAFE       https://tinyurl.com/vote | [('TRIGGER_KEYWORDS', 12), ('SHORTENER_UNRESOLVED', 10), ...]
```

- **Где в коде:** `backend/pipeline/scorer.py:38` (`UNRESOLVED_SHORTENER_CAP = 45`), `:153-157` (сигнал с весом `shortener` = 10), `:614-618` (применение потолка), `config.py` → `DEFAULT_WEIGHTS["shortener"] = 10`.
- **Заметка:** отдельно противно для `vk.cc`, `goo.gl`, `youtu.be`, `t.me` — они одновременно и сокращатели, и доверенные домены, поэтому рядом с «развернуть не удалось» человек читает зелёное «известный домен с проверенной репутацией». В выводе видно: у `vk.cc` есть сигнал `TRUSTED_DOMAIN`, у `bit.ly` — нет. Это ровно сценарий из истории проекта: ссылку прислали в мессенджере сокращённой, Render не смог развернуть (холодный старт, SSRF-щит, мёртвый хост) — человек видит галочку. Нужен пол, а не потолок.

---

## Находка F-07. Схема из истории проекта не ловится в падежах

- **Зона:** пропуски
- **Серьёзность:** высокая
- **Проверил сам запуском:** да
- **Что не так:** `_SCAM_PATTERNS` сверяется со словарём словоформ в именительном падеже, а регулярка требует, чтобы после слова не было букв. Реальные адреса пишут «за ребенка», «конкурс детей» — связка не находится.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import *
for u in ['https://golosovanie-deti.ru/','https://golosovanie-za-rebenka.ru/',
          'https://konkurs-detey.ru/golos','https://vote-for-kids.ru/']:
    f = L.analyze(u); r = sc(u)
    print(f'{r.risk_score:3d} {r.verdict.value:10s} scam={f.scam_pattern} {u}')
"
```

- **Ожидали:** `SCAM_PATTERN` весом 35 — это дословно тот адрес, из-за которого проект появился.
- **Получили:**

```
 62 PHISHING   scam=fake_vote https://golosovanie-deti.ru/
 17 SAFE       scam=None https://golosovanie-za-rebenka.ru/
 27 SAFE       scam=None https://konkurs-detey.ru/golos
 17 SAFE       scam=None https://vote-for-kids.ru/
```

- **Где в коде:** `backend/pipeline/lexical_analyzer.py:146-172` (`_SCAM_PATTERNS`), границы слов — `:177` (`_group_pattern`, `(?<![a-z])`).
- **Заметка:** не хватает форм `rebenka`, `rebyonka`, `detey`, `detej`, `detei`, `detok`, `malysha`, `golosovaniya`, `konkursa` и английских `kid`, `kids`, `child`, `children`, `baby`. Кириллица отрабатывает лучше: `голосование-за-ребенка.рф` даёт 52, потому что «конкурс» и «голосование» перечислены в обеих группах сразу. Самая дешёвая правка из всего списка, и бьёт ровно в ту ссылку, ради которой всё затевалось.

---

## Находка F-08. Кеш уровня страницы ключуется по обрезанному адресу

- **Зона:** ревью кода
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** `analyze_page` кладёт результат в кеш под ключом `url[:500]`, а на вход принимаются адреса до 2048 символов — два разных длинных адреса с общим началом получают улики друг друга.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import asyncio
from pipeline import page_analyzer
from models import PageResult
pref = 'https://example.com/?x=' + 'a'*600
u1, u2 = pref + '&id=ODIN', pref + '&id=DVA'
print('адреса разные:', u1 != u2, '| первые 500 символов совпадают:', u1[:500] == u2[:500])
async def main():
    await page_analyzer._cache.set(u1[:500], PageResult(
        checked=True, status_code=200, title='СТРАНИЦА ОДИН',
        has_password_field=True, messenger_login=['telegram']))
    r = await page_analyzer.analyze_page(u2)
    print('запросили u2, уровень вернул:', repr(r.title), '| пароль:', r.has_password_field, '| мессенджер:', r.messenger_login)
asyncio.run(main())
"
```

- **Ожидали:** уровень сходит за страницей `u2`.
- **Получили:**

```
адреса разные: True | первые 500 символов совпадают: True
запросили u2, уровень вернул: 'СТРАНИЦА ОДИН' | пароль: True | мессенджер: ['telegram']
```

- **Где в коде:** `backend/pipeline/page_analyzer.py:345` (`_cache.single_flight(url[:500], _fetch)`). То же самое в `backend/pipeline/ai_analyzer.py:203` (`cache_key = f"{settings.AI_MODEL}|{url[:500]}"`) — там сейчас не стреляет только потому, что уровень выключен отсутствием ключа.
- **Заметка:** работает в обе стороны — и приписать чистому адресу чужие улики, и наоборот, погасить настоящие. Обрезка, видимо, делалась ради памяти; лечится хешем от полного адреса, он всё равно короче.

---

## Находка F-09. Кириллические написания брендов в зоне `.рф`

- **Зона:** пропуски
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** `BRAND_DOMAINS` содержит только латиницу, а домен в `.рф` справедливо считается «родным IDN» и не получает ни `NON_ASCII_HOST`, ни `PUNYCODE` — в итоге остаётся вообще без признаков.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import *
for u in ['https://сбербанк-онлайн.рф/vhod','https://тинькофф-банк.рф/login','https://госуслуги-вход.ru/']:
    r = sc(u); print(f'{r.risk_score:3d} {r.verdict.value:10s} {u}')
"
```

- **Ожидали:** `BRAND_IMPERSONATION` весом 45.
- **Получили:** `17 SAFE`, `17 SAFE`, а вот `госуслуги-вход.ru` (кириллица под `.ru`) — `82 PHISHING`. То есть зона `.рф`, самая естественная для русской подделки, единственная и проходит мимо.
- **Где в коде:** `backend/data/brands.py:11-56` (ключи только на латинице), `backend/pipeline/lexical_analyzer.py:479-520` (`_match_brand` сравнивает с латинскими ключами).
- **Заметка:** это тот самый пункт 2 из «Следующих шагов» в CLAUDE.md, который был предложен и ждал ответа. Теперь он подтверждён цифрами — не мелочь.

---

## Находка F-10. Короткие бренды в дефисных доменах не ловятся

- **Зона:** пропуски
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** подстрочный поиск работает только для брендов от 5 букв, а расстояние Левенштейна для бренда ≤ 4 букв требует точного совпадения. При этом в словаре бренд записан как `sberbank` и `vkontakte` — народные сокращения `sber` и `vk`, которыми подделки и пользуются, не описаны вообще.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import *
for u in ['https://sber-vhod.ru/','https://vk-login.ru/','https://sberbank-online-vhod.ru/']:
    r = sc(u); print(f'{r.risk_score:3d} {r.verdict.value:10s} {u}')
"
```

- **Ожидали:** `sber-vhod.ru` ≈ `sberbank-online-vhod.ru`.
- **Получили:** `17 SAFE`, `17 SAFE`, `62 PHISHING`.
- **Где в коде:** `backend/data/brands.py:60` (`MIN_SUBSTRING_BRAND_LEN = 5`), `backend/pipeline/lexical_analyzer.py:487-490` и `:513-519`.
- **Заметка:** осторожно с правкой — именно этот порог спасает от «озонотерапии». Короткие имена стоит добавлять не подстрокой, а отдельным списком «метка целиком»: `sber`, `vk`, `wb`, `gosuslugi`.

---

## Находка F-11. Бренд в пути адреса не проверяется вообще

- **Зона:** пропуски
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** `_match_brand` получает только хост и поддомены; путь не смотрит никто, хотя `https://что-угодно.com/sberbank/online/login` — обычная раскладка фишинга на взломанном или арендованном сайте.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import *
for u in ['https://cdn-storage-42.com/sberbank/online/login','https://static-cdn.net/gosuslugi/auth']:
    r = sc(u); print(f'{r.risk_score:3d} {r.verdict.value:10s} {u}')
"
```

- **Ожидали:** отдельный признак «имя бренда в пути чужого домена» весом порядка 20–25.
- **Получили:** `27 SAFE` и `5 SAFE` — за бренд ноль.
- **Где в коде:** `backend/pipeline/lexical_analyzer.py:295-296` — в `_match_brand` передаются `host, decoded_host, sld, registered_domain, subdomains`; `path_and_query` не передаётся.

---

## Находка F-12. Нет слов доставки и штрафов

- **Зона:** пропуски
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** в словаре тревожных слов есть голосование, деньги, давление — но ни одного слова из двух массовых схем: «посылка задержана, доплатите» и «у вас штраф ГИБДД».
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import *
for u in ['https://pochta-rf-dostavka.top/track','https://shtraf-gibdd-oplata.ru/','https://cdek-tracking.site/parcel']:
    f = L.analyze(u); r = sc(u)
    print(f'{r.risk_score:3d} {r.verdict.value:10s} слова={f.trigger_keywords} {u}')
"
```

- **Ожидали:** `TRIGGER_KEYWORDS`, в идеале новые схемы `fake_delivery` / `fake_fine`.
- **Получили:** `25 SAFE слова=[]`, `17 SAFE слова=['oplata']`, `15 SAFE слова=[]`.
- **Где в коде:** `backend/pipeline/lexical_analyzer.py:66-84` (`_TRIGGER_KEYWORDS_RU`) и `:146-172` (`_SCAM_PATTERNS`, схем всего три).
- **Заметка:** не хватает `dostavka`, `posylka`, `otpravlenie`, `trek`, `track`, `pochta`, `cdek`, `shtraf`, `shtrafy`, `gibdd`, `gai`, `narushenie`, `postanovlenie` и кириллических пар.

---

## Находка F-13. Открытый редирект на честном домене

- **Зона:** пропуски
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** два дефекта складываются: словарь параметров переадресации не знает `to=`, `q=`, `from=`, `back=`, `redirect_to=`; а там, где знает, сверху всё равно ложится потолок доверия.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import *
for u in ['https://yandex.ru/redirect?url=https://evil.top',
          'https://vk.com/away.php?to=https%3A%2F%2Fphish.top',
          'https://google.com/url?q=https://phish.top']:
    f = L.analyze(u); r = sc(u)
    print(f'{r.risk_score:3d} {r.verdict.value:10s} redir_params={f.has_redirect_params} {u}')
"
```

- **Ожидали:** как минимум SUSPICIOUS и сигнал про параметры переадресации.
- **Получили:**

```
 15 SAFE       redir_params=True  https://yandex.ru/redirect?url=https://evil.top
  5 SAFE       redir_params=False https://vk.com/away.php?to=https%3A%2F%2Fphish.top
  5 SAFE       redir_params=False https://google.com/url?q=https://phish.top
```

- **Где в коде:** `backend/pipeline/lexical_analyzer.py:118-122` (`_REDIRECT_PARAMS_RE`), потолок — `backend/pipeline/scorer.py:599-603`.
- **Заметка:** если редирект реально разворачивается, `main.py:194-198` анализирует уже конечный адрес и проблема снимается. Остаётся она там, где разворачивание не сработало: Render не достучался, ссылка требует куки или JS, сервер отдал 200 вместо 302.

---

## Находка F-14. IP в десятичной и шестнадцатеричной записи не считается IP

- **Зона:** пропуски
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** проверка использует `ipaddress.ip_address`, который принимает только точечно-десятичную форму. Браузер и `socket` принимают все формы.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys, socket; sys.path.insert(0,'/tmp/pg')
from verify import *
for h in ['3109064507','0xB9.0x17.0x2D.0x43']:
    u = 'http://' + h + '/sber/login'
    print(f'{h:22s} -> реально {socket.inet_ntoa(socket.inet_aton(h)):15s} | has_ip_address={L.analyze(u).has_ip_address} | балл {sc(u).risk_score}')
"
```

- **Ожидали:** `IP_IN_URL` весом 40.
- **Получили:**

```
3109064507             -> реально 185.80.143.59   | has_ip_address=False | балл 42
0xB9.0x17.0x2D.0x43    -> реально 185.23.45.67    | has_ip_address=False | балл 42
```

42 набралось только из `INSECURE_SCHEME` и соседей; обычный `http://185.23.45.67/gosuslugi/auth` даёт 60 PHISHING.

- **Где в коде:** `backend/pipeline/lexical_analyzer.py:389-398` (`_is_ip_host`).
- **Заметка:** лечится добавлением `socket.inet_aton` — но осторожно: `inet_aton` принимает и просто число, так что применять только к хосту без букв.

---

## Находка F-15. В брендах страницы нет ВКонтакте, Авито и Почты России

- **Зона:** пропуски
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** словарь брендов текста страницы покрывает Сбер, Тинькофф, Госуслуги, Telegram, Ozon, Wildberries — но не ВКонтакте/ВК, не Авито, не Почту России, не Мэйл.ру. А `PAGE_BRAND_MISMATCH` — единственный признак, включающий `hard_evidence` (см. F-04), так что без него поддельная страница входа ВК остаётся на нуле.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
from pipeline.page_analyzer import _brands_in_text
print('сбербанк x3 :', _brands_in_text('Сбербанк Сбербанк Сбербанк вход'))
print('вконтакте x3:', _brands_in_text('ВКонтакте ВКонтакте ВКонтакте вход'))
print('авито x3    :', _brands_in_text('Авито Авито Авито'))
"
```

- **Ожидали:** `['vkontakte']` — бренд есть в `data/brands.py`, просто не описан в таблице текста страницы.
- **Получили:** `['sberbank']`, `[]`, `[]`.
- **Где в коде:** `backend/pipeline/page_analyzer.py:57-71` (`_BRAND_TEXT`).

---

## Находка F-16. Тест-сторож не проверяет второй язык

- **Зона:** ревью кода
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** `test_every_signal_code_is_translated` схлопывает весь `index.html` в одну строку и ищет `КОД:{` где угодно. Сигнал, добавленный только в русский словарь, проходит проверку — хотя тест написан ровно ради того, чтобы этого не случилось («добавь в словарь SIG, в оба языка» в его же тексте ошибки).
- **Как воспроизвести** (проверка на КОПИИ в памяти, файл не меняется):

```bash
cd /home/user/phishguard && python3 -c "
import re, pathlib
html   = pathlib.Path('index.html').read_text(encoding='utf-8')
scorer = pathlib.Path('backend/pipeline/scorer.py').read_text(encoding='utf-8')
codes  = set(re.findall(r'c\.(?:add|ok)\(\s*\"([A-Z_0-9]+)\"', scorer))
start  = html.index('const SIG = {'); en_i = html.index('en: {', start); en_end = html.index('\n};', en_i)
broken = html[:en_i] + re.sub(r'\s*PAGE_BRAND_MISMATCH\s*:\s*\{[^}]*\},', '', html[en_i:en_end]) + html[en_end:]
compact = broken.replace(' ', '')
print('PAGE_BRAND_MISMATCH выкинут из английского словаря')
print('тест нашёл бы:', sorted(c for c in codes if f'{c}:{{' not in compact) or 'НИЧЕГО — тест проходит')
"
```

- **Ожидали:** тест падает с «нет описания во фронтенде: PAGE_BRAND_MISMATCH».
- **Получили:** `тест нашёл бы: НИЧЕГО — тест проходит`.
- **Где в коде:** `backend/tests/test_frontend_sync.py`, функция `test_every_signal_code_is_translated`.
- **Заметка:** прямо сейчас словари синхронны — 63 кода из скорера есть и в `ru`, и в `en` (в каждом по 66 записей). То есть это дыра в страховке, а не живой баг. Но именно эту страховку CLAUDE.md называет сторожем от «пользователь видит `PAGE_NOT_SEEN`». Лечится разбором двух блоков по отдельности.

---

## Находка F-17. `TRUSTED_PROXY_HOPS=0` разворачивает лимит запросов на клиентское значение

- **Зона:** ревью кода
- **Серьёзность:** низкая
- **Проверил сам запуском:** да
- **Что не так:** клиент определяется как `chain[-index]`, где `index = min(TRUSTED_PROXY_HOPS, len(chain))`. При `TRUSTED_PROXY_HOPS=0` получается `chain[-0]`, то есть `chain[0]` — самое левое, клиентом же подставленное значение. Ровно тот обход, от которого комментарий строкой выше и защищается.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
chain = ['1.2.3.4', '9.9.9.9', '10.0.0.5']   # слева подставил клиент, справа дописал наш прокси
for hops in (2, 1, 0, -1):
    index = min(hops, len(chain))
    print(f'TRUSTED_PROXY_HOPS={hops:2d} -> chain[-{index}] = {chain[-index]}')
"
```

- **Ожидали:** значение вне диапазона отвергается или трактуется безопасно.
- **Получили:**

```
TRUSTED_PROXY_HOPS= 2 -> chain[-2] = 9.9.9.9
TRUSTED_PROXY_HOPS= 1 -> chain[-1] = 10.0.0.5
TRUSTED_PROXY_HOPS= 0 -> chain[-0] = 1.2.3.4      ← подставляет клиент
TRUSTED_PROXY_HOPS=-1 -> chain[--1] = 9.9.9.9
```

- **Где в коде:** `backend/rate_limit.py`, функция `client_identifier`; значение по умолчанию — `backend/config.py:203` (`TRUSTED_PROXY_HOPS: int = 1`).
- **Заметка:** сегодня не стреляет — по умолчанию 1. Это ловушка на будущее: `0` выглядит естественным значением для «прокси перед нами нет», а даёт обход лимита одной строкой `curl -H "X-Forwarded-For: 1.2.3.$RANDOM"`. Лечится валидатором `ge=1` в конфиге.

---

## Находка F-18. Уровень, выключенный отсутствием ключа, занижает достоверность

- **Зона:** ревью кода
- **Серьёзность:** низкая
- **Проверил сам запуском:** да
- **Что не так:** `_confidence` исключает из знаменателя только уровни с флагом `skipped` (AI, TLS, CT, страница), а Google Safe Browsing, URLhaus и возраст домена сидят в знаменателе всегда. У `ThreatIntelResult` поля `skipped` вообще нет, поэтому «ключ не настроен» неотличимо от «источник не ответил».
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import asyncio
from pipeline.threat_intel import check_google_safe_browsing
r = asyncio.run(check_google_safe_browsing('https://example.com'))
print('GSB без ключа: checked =', r.checked, '| skipped =', getattr(r, 'skipped', 'ПОЛЯ НЕТ'), '| error =', r.error)
"
```

- **Ожидали:** уровень, выключенный настройкой, не должен считаться «недоступным источником» — так написано в докстринге самой функции достоверности.
- **Получили:** `checked = False | skipped = ПОЛЯ НЕТ | error = API key not configured`.
- **Где в коде:** `backend/pipeline/scorer.py:73-104` (`_confidence`), `backend/pipeline/threat_intel.py:43-46`, `backend/models.py` (у `ThreatIntelResult` нет поля `skipped`).
- **Заметка:** на бою сейчас не бьёт — ключ GSB задан. Стрельнет, если ключ снимут: достоверность просядет на 1/8 без причины, а фронтенд ниже 0.5 прячет зелёный вердикт.

---

## Что агенты заявили, но НЕ подтвердилось

| Заявка агента | Почему отбросили |
|---------------|------------------|
| «Punycode-форма и юникодная дают разный балл» (`xn--…` → 20 против 52) | Агент сам собрал недействительный punycode руками. С настоящим ACE через `idna.encode` обе формы совпадают до балла: `52/52`, `5/5`, `62/62`. Фикс с `decoded_host` работает как задумано — **не трогать**. |
| «Потолок сокращателя (45) глушит улики со страницы» | Не воспроизводится. Защита `page_saw_something` (`scorer.py:610-613`) отрабатывает, а главное — до потолка балл вообще не доходит (F-06). Проблема ровно обратная: нужен пол. |
| «Потолок доверия можно получить, заведя поддомен на чужой площадке» (`sber-vhod.github.io`) | Не воспроизводится: `_extract_trust` с приватным PSL честно отдаёт `sber-vhod.github.io` как отдельную единицу, `is_trusted_domain = False`. Механика доверия сделана правильно; дыра в другом месте — F-05. |
| «Схемы `data:`, `javascript:`, `file:` дают пропуск» | Не доходят до скорера: отбиваются валидатором на входе (`models.py:41-70`), это 422, а не зелёный вердикт. |
| «Двойное кодирование `%25` ломает разбор хоста» | Не воспроизводится: `https://evil.top/%2525/login` разбирается нормально, хост `evil.top`, балл 37. Опасны именно `%2F`/`%3F`/`%23` в части ДО `@` — это F-01. |
| «Уровень Claude выключен в бою — это пропуск» | Не баг: ключ не задан, автор в курсе и решает сам. |
| (моё) «DNS rebinding в защите от SSRF» | Уже описано в `ARCHITECTURE.md:55-56` как известное ограничение с указанным лечением. Не находка. Сам классификатор адресов проверен 21 случаем (приватные, CGNAT, метаданные облаков, IPv4-mapped IPv6, 6to4, NAT64, восьмеричные) — ни одного промаха. |

## Чего проверить НЕ удалось

Три агента из четырёх убиты лимитом сессии (HTTP 429) до того, как успели что-либо записать. Их зоны остались непокрытыми:

- **Ложные тревоги (зона 1)** — систематический прогон 60–80 честных адресов не сделан. F-02 я нашёл случайно, попутно; сколько там ещё такого — неизвестно. **Это самая нужная зона для следующего захода**, учитывая, что по философии проекта ложная тревога хуже пропуска.
- **Кривой ввод и падения (зона 3)** — не сделано вообще. Агент перед смертью написал «Found a crash. Let me confirm it over HTTP», но отчёт не сохранился, и что именно за падение — неизвестно. Локальный сервер мусором не бомбили.
- **Интерфейс (зона 4)** — не сделано вообще. Ни мобильная вёрстка, ни настольная, ни сверка балла страницы с баллом сервера, ни XSS через адрес.

Также не проверялось:

- **Уровень Claude** — ключ `ANTHROPIC_API_KEY` не задан ни локально, ни на Render.
- **Поведение под нагрузкой** — лимит запросов, дедупликация, кеш под параллельными обращениями.
