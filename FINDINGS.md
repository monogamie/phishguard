# Находки агентов — 18 сентября 2026

**Сеть:** открыта. `/health` живого сайта отвечает, `crt.sh` и RDAP доступны напрямую из контейнера.
**Агентов запущено:** 4 в первом заходе (отчитался 1, троих убил лимит сессии) + 3 во втором заходе.
**Уровней реально работало:** 7 из 8. `ANTHROPIC_API_KEY` не задан → уровень Claude выключен. **`URLHAUS_AUTH_KEY` теперь ЗАДАН** — `/health` отдаёт `"urlhaus": true`, в CLAUDE.md записано обратное, надо поправить.
**Ничего не чинилось:** да. Ни одной правки в файлах проекта. Тесты как были — 270 проходят.

## Что покрыто

| Зона | Статус |
|------|--------|
| 1. Ложные тревоги | **покрыто**: 240 честных адресов, 26 набрали ≥ 30 баллов, 8 находок |
| 2. Пропуски | **покрыто**: 85 адресов по мотивам схем, 13 находок |
| 3. Кривой ввод и падения | **покрыто**: ~150 адресов и ~30 кривых тел, нагрузочный прогон, 7 находок |
| 4. Интерфейс | **покрыто**: обе вёрстки, сверка движков, XSS, 10 находок |
| 5. Ревью кода | **покрыто**: 4 находки |

Всего **43 находки**, каждая перепроверена мной запуском — часть на живом сайте и в настоящем браузере.

Две хорошие новости, которые тоже стоит знать: **HTTP 500 не получен ни разу** за весь фаззинг, и **обхода защиты от SSRF не нашлось** — подробности в разделе «Что агенты заявили, но НЕ подтвердилось».

## Самое срочное, если времени мало

1. **F-01** — `%2F` в логине адреса делает любой фишинг «БЕЗОПАСНЫМ» с достоверностью 1.0.
2. **F-19** — `www.мвд.рф` на живом сайте = **90 «ОПАСНО»**. Приставка `www.` ломает всю зону `.рф`.
3. **F-20** — весь международный IDN (`société.fr`, `한국.kr`, `bücher.de`) = 70–75 «ОПАСНО».
4. **F-02** — `github.com`, `docs.google.com`, `dropbox.com`, `t.me` на живом сайте = «ОПАСНО».
5. **F-37** — обратный слеш (`https://evil.top\@sberbank.ru/`) делает то же, что F-01, но по другой причине и лечится отдельно.
6. **F-29** — на десктопе шире 768px нет ни меню, ни переключателя языка. Мобильный слой убил настольную шапку.

Первые пять — это вранье пользователю в обе стороны, шестое — сломанный интерфейс на защите проекта.

## Сводка

| № | Зона | Коротко | Серьёзность | Проверил сам |
|---|------|---------|-------------|--------------|
| F-01 | пропуски | `%2F` в логине адреса подменяет анализируемый домен на доверенный: любой фишинг → 0 баллов, «БЕЗОПАСНО», достоверность 1.0 | **критическая** | да, и на живом сайте |
| F-19 | ложные тревоги | `www.мвд.рф` → **90 «ОПАСНО»** живьём, а `мвд.рф` → 25 SAFE. Латинский поддомен снимает послабление зоны `.рф` | **критическая** | да, и на живом сайте |
| F-20 | ложные тревоги | весь IDN под латинской зоной: `société.fr` → 75 «ОПАСНО» живьём, `한국.kr`, `bücher.de`, `україна.ua` — 70 | **критическая** | да, и на живом сайте |
| F-02 | ложные тревоги | `github.com`, `docs.google.com`, `dropbox.com`, `t.me`, `discord.com` живьём = **ОПАСНО** | высокая | да, на живом сайте |
| F-21 | ложные тревоги | `культура.рф/конкурс` → 72 «ОПАСНО» живьём: слова схемы стоят в обеих группах, хватает одного | высокая | да, и на живом сайте |
| F-22 | ложные тревоги | сервис утверждает, что домен МВД **не зарегистрирован** — 404 от RDAP «не знаю такую зону» читается как «домена нет» | высокая | да, и на живом сайте |
| F-23 | ложные тревоги | `github.blog` → 75 «ОПАСНО» живьём: бренд на собственном домене бренда считается подделкой | высокая | да, и на живом сайте |
| F-37 | кривой ввод | обратный слеш в адресе: браузер идёт на `evil.top`, мы проверяем `sberbank.ru` → «БЕЗОПАСНО» | высокая | да, сверкой с браузером |
| F-29 | интерфейс | на десктопе ≥768px нет ни меню, ни переключателя RU/EN — мобильный `.hidden` перебивает Tailwind | высокая | да |
| F-30 | интерфейс | смена языка не перерисовывает уже показанный результат на десктопе | высокая | да |
| F-31 | интерфейс | гомоглиф считается дважды в копии движка: страница 100, сервер 65 | высокая | да |
| F-03 | пропуски | доверенная площадка выключает уровень страницы и режет балл до 15 | высокая | да |
| F-04 | пропуски | форма пароля и вход через Telegram весят 0 баллов на зрелом домене | высокая | да |
| F-05 | пропуски | `github.io` / `amazonaws.com` / `googleapis.com` полностью выключают детект брендов | высокая | да |
| F-06 | пропуски | неразвёрнутый сокращатель = 15 баллов «БЕЗОПАСНО», потолок 45 недостижим | высокая | да |
| F-07 | пропуски | схема из истории проекта не ловится в падежах: `golosovanie-za-rebenka.ru` → 17 SAFE | высокая | да |
| F-24 | ложные тревоги | честные страницы входа и сброса пароля: `cabinet.tele2.ru/security/password/recovery` → 57 | высокая | да |
| F-25 | ложные тревоги | `tele2.ru` и `e1.ru` → 30 «ПОДОЗРИТЕЛЬНО» живьём: переход на `www` объявлен сменой домена | средняя | да, и на живом сайте |
| F-32 | интерфейс | `DIGITS_IN_DOMAIN` горит на IP-адресе: фикс 18 сентября доехал до питона, но не до страницы | средняя | да |
| F-33 | интерфейс | в копии движка нет кириллических тревожных слов: `пример.рф/вход` → страница 0, сервер 17 | средняя | да |
| F-34 | интерфейс | в списке главных причин два несуществующих кода — база угроз Google никогда не станет главной причиной | средняя | да |
| F-08 | ревью кода | кеш уровня страницы ключуется по `url[:500]` — длинные адреса получают чужие улики | средняя | да |
| F-09 | пропуски | кириллические бренды в `.рф` не опознаются | средняя | да |
| F-10 | пропуски | короткие бренды (`sber`, `vk`, `ozon`, `vtb`) в дефисных доменах не ловятся | средняя | да |
| F-11 | пропуски | бренд в пути адреса не проверяется вообще | средняя | да |
| F-12 | пропуски | нет слов доставки и штрафов — две массовые схемы мимо | средняя | да |
| F-13 | пропуски | открытый редирект: параметров нет в словаре + сверху потолок доверия | средняя | да |
| F-14 | пропуски | IP в десятичной и шестнадцатеричной записи не считается IP | средняя | да |
| F-15 | пропуски | в брендах страницы нет ВКонтакте, Авито, Почты России | средняя | да |
| F-16 | ревью кода | тест-сторож не проверяет второй язык | средняя | да |
| F-35 | интерфейс | без Tailwind настольная вёрстка разваливается, мобильная держится | средняя | да |
| F-26 | ложные тревоги | тест-сторож `test_no_conflicts.py` держит только `мвд.рф` без `www` — F-19 и F-20 он не видит | средняя | да |
| F-27 | интерфейс | на двух мобильных экранах из пяти нет переключателя языка, подробности не перерисовываются | низкая | да |
| F-28 | интерфейс | метка схемы обмана застревает в языке первой проверки (кеш) | низкая | да |
| F-36 | интерфейс | история пишется с компьютера, но показать её на десктопе негде | низкая | да |
| F-38 | кривой ввод | лимит запросов обходится одним заголовком `X-Real-IP` | средняя | да |
| F-39 | кривой ввод | забракованный сервером адрес показывается как обычный вердикт с подписью «сервер недоступен» | средняя | да |
| F-40 | кривой ввод | заявленный дедлайн 30 с под нагрузкой не действует: 23 запроса из 120 дольше, ни одного 504 | средняя | да |
| F-41 | кривой ввод | все IPv6-адреса отбиваются, кроме `[::ffff:127.0.0.1]` — единственного, ведущего на localhost | средняя | да |
| F-42 | кривой ввод | адрес с полноширинным слешем браузер открывает, а сервис проверять отказывается | средняя | да |
| F-43 | кривой ввод | слот пула WHOIS освобождается раньше потока, лог засоряется | низкая | частично, см. находку |
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

Для интерфейса нужен браузер и Tailwind (с CDN в контейнере он не грузится, качаем копию):

```bash
curl -s --max-time 45 -o /tmp/tw.js https://cdn.tailwindcss.com/3.4.16   # ~450 КБ
# запускать node с NODE_PATH=/opt/node22/lib/node_modules
# браузер: /opt/pw-browsers/chromium-1194/chrome-linux/chrome
# в скрипте Tailwind подставляется через page.route, файл проекта не меняется
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

## Находка F-19. `www.мвд.рф` — 90 баллов и красное «ОПАСНО» на живом сайте

- **Зона:** ложные тревоги
- **Серьёзность:** критическая
- **Проверил сам запуском:** да, локально и на живом сайте
- **Что не так:** послабление для зоны `.рф` снимается, если хоть одна метка домена написана латиницей — а `www` латиницей написана всегда. Голый `мвд.рф` проходит, `www.мвд.рф` получает `NON_ASCII_HOST` 35 и `PUNYCODE` 30 за один и тот же факт.
- **Как воспроизвести (локально):**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import *
for u in ['https://мвд.рф','https://www.мвд.рф','https://www.гибдд.рф','https://lk.налог.рф','https://www.почта.рф']:
    r = sc(u)
    print(f'{r.risk_score:3d} {r.verdict.value:10s} {u:22s} {[(s.code,s.weight) for s in r.signals if s.weight]}')
"
```

- **Как воспроизвести (живой сайт):**

```bash
cd /home/user/phishguard/backend && python3 -c "
import httpx, time
for u in ['https://www.мвд.рф','https://мвд.рф']:
    d = httpx.post('https://phishguard-ayrt.onrender.com/scan', json={'url':u}, timeout=150).json()
    print(d['risk_score'], d['verdict'], [(s['code'],s['weight']) for s in d['signals'] if s['weight']])
    time.sleep(3)
"
```

- **Ожидали:** сайт МВД России — SAFE в любой форме записи.
- **Получили** (локально):

```
  5 SAFE       https://мвд.рф         [('DOMAIN_AGE_UNKNOWN', 5)]
 70 PHISHING   https://www.мвд.рф     [('NON_ASCII_HOST', 35), ('PUNYCODE', 30), ('DOMAIN_AGE_UNKNOWN', 5)]
 70 PHISHING   https://www.гибдд.рф   [('NON_ASCII_HOST', 35), ('PUNYCODE', 30), ('DOMAIN_AGE_UNKNOWN', 5)]
 70 PHISHING   https://lk.налог.рф    [('NON_ASCII_HOST', 35), ('PUNYCODE', 30), ('DOMAIN_AGE_UNKNOWN', 5)]
```

На живом сайте `www.мвд.рф` → **90 PHISHING**, `мвд.рф` → 25 SAFE.

- **Где в коде:** `backend/pipeline/lexical_analyzer.py:352-361` — `_idn_is_native` склеивает все метки кроме зоны и требует однородности письменности; латинское `www` эту однородность ломает.
- **Заметка:** это тот же двойной счёт, от которого 18 сентября ставили защиту, — просто фикс закрыл только голый `мвд.рф`. Один факт («в имени домена нерусские буквы») зажигает два весомых признака. Сторож `test_no_conflicts.py` этого не видит, см. F-26.

---

## Находка F-20. Весь международный IDN помечается как «ОПАСНО»

- **Зона:** ложные тревоги
- **Серьёзность:** критическая
- **Проверил сам запуском:** да, локально и на живом сайте
- **Что не так:** послабление завязано на совпадение письменности имени и зоны, а не на факт «это национальный домен». Поэтому любой IDN под обычной ASCII-зоной (`.de`, `.fr`, `.jp`, `.kr`, `.ua`, `.gr`) получает тот же двойной счёт, что и F-19.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import *
for u in ['https://bücher.de','https://société.fr','https://한국.kr','https://україна.ua','https://ελλάδα.gr']:
    r = sc(u)
    print(f'{r.risk_score:3d} {r.verdict.value:10s} {u:20s} {[(s.code,s.weight) for s in r.signals if s.weight]}')
"
```

- **Ожидали:** обычные национальные домены — SAFE.
- **Получили:** все пять → `70 PHISHING` с `NON_ASCII_HOST` 35 + `PUNYCODE` 30. На живом сайте `société.fr` → **75 PHISHING**.
- **Где в коде:** там же, `backend/pipeline/lexical_analyzer.py:352-361`.
- **Заметка:** для школьного проекта с русской аудиторией это, может, и не первоочередное, но на защите вопрос «а немецкий сайт вы почему считаете фишингом» прозвучит. Чинится вместе с F-19 одной правкой: смотреть не на однородность письменности, а на то, что имя домена целиком принадлежит одной непустой письменности, игнорируя технические метки вроде `www`.

---

## Находка F-21. Слова схемы стоят в обеих группах — хватает одного

- **Зона:** ложные тревоги
- **Серьёзность:** высокая
- **Проверил сам запуском:** да, локально и на живом сайте
- **Что не так:** схема `fake_vote` задумана как «опасна связка двух слов из разных групп», но `"конкурс"` и `"голосование"` перечислены и в группе А, и в группе Б. Одного слова достаточно, чтобы схема сработала.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import *
for u in ['https://культура.рф/конкурс','https://нацпроекты.рф/голосование/итоги',
          'https://культура.рф/konkurs','https://xn--80aafgvbvbecbn5c8b.ru/всероссийскийконкурс']:
    f = L.analyze(u); r = sc(u)
    print(f'{r.risk_score:3d} {r.verdict.value:12s} scam={f.scam_pattern} {u}')
"
```

- **Ожидали:** одно слово «конкурс» на сайте культуры — не схема угона аккаунтов.
- **Получили:**

```
 52 SUSPICIOUS   scam=fake_vote https://культура.рф/конкурс
 52 SUSPICIOUS   scam=fake_vote https://нацпроекты.рф/голосование/итоги
 17 SAFE         scam=None      https://культура.рф/konkurs
100 PHISHING     scam=fake_vote https://xn--80aafgvbvbecbn5c8b.ru/всероссийскийконкурс
```

На живом сайте `культура.рф/конкурс` → **72 PHISHING**.

- **Где в коде:** `backend/pipeline/lexical_analyzer.py:143-152` — кортеж `fake_vote`, слова `"конкурс"` и `"голосование"` в обоих `frozenset`.
- **Заметка:** три штуки в одном. Во-первых, дубль слов. Во-вторых, латинские `konkurs`/`golosovanie` не продублированы — один и тот же сайт получает разные вердикты в зависимости от того, кириллицей записан путь или транслитом (52 против 17). В-третьих, граница слова в `_group_pattern` ставится только слева и только для латиницы, поэтому «конкурс» находится ВНУТРИ слова `всероссийскийконкурс`. Чинить надо всё три, иначе правка одного вылезет другим.

---

## Находка F-22. Сервис утверждает, что домен МВД не зарегистрирован

- **Зона:** ложные тревоги
- **Серьёзность:** высокая
- **Проверил сам запуском:** да, локально и на живом сайте
- **Что не так:** `rdap.org` отвечает HTTP 404 не только на «домена нет», но и на «я не знаю такой зоны» — а для `.рф` он её не знает. Код считает любой 404 достоверным фактом «домен не зарегистрирован» и ставит `checked=True`.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import httpx
for name, dom in [('мвд.рф','xn--b1aew.xn--p1ai'), ('культура.рф','xn--80aefy1a.xn--p1ai'), ('google.com','google.com')]:
    r = httpx.get(f'https://rdap.org/domain/{dom}', timeout=30)
    print(f'{name:14s} HTTP {r.status_code}  {r.text[:100]}')
"
```

- **Ожидали:** «источник не знает эту зону» → уровень молчит, достоверность падает.
- **Получили:**

```
мвд.рф         HTTP 404  {"rdapConformance":["rdap_level_0"],...,"title":"No RDAP service is available for this
культура.рф    HTTP 404  {"rdapConformance":["rdap_level_0"],...,"title":"No RDAP service is available for this
google.com     HTTP 302
```

На живом сайте в разборе `мвд.рф` стоит `DOMAIN_NOT_REGISTERED` и текст «Домен не зарегистрирован», `source: rdap`.

- **Где в коде:** `backend/pipeline/domain_age.py:127-131`.
- **Заметка:** это прямое нарушение второго принципа проекта, причём в самой неприятной форме: «не смогли проверить» превратилось не в молчание, а в ложное утверждение о факте. Для `.ru` спасает запасной WHOIS, для `.рф` — нет. Отличить можно по телу ответа: настоящий «домен не зарегистрирован» приходит с другим `title`.

---

## Находка F-23. Бренд на собственном домене бренда считается подделкой

- **Зона:** ложные тревоги
- **Серьёзность:** высокая
- **Проверил сам запуском:** да, локально и на живом сайте
- **Что не так:** в словаре у каждого бренда перечислено по нескольку доменов, и всё, что в список не попало, объявляется чужим — даже если это официальный домен того же бренда.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import *
for u in ['https://google-analytics.com','https://githubstatus.com','https://github.blog',
          'https://blog.google','https://yandex.by','https://alfabank.by']:
    f = L.analyze(u); r = sc(u)
    print(f'{r.risk_score:3d} {r.verdict.value:12s} brand={f.brand_match and f.brand_match.brand} {u}')
"
```

- **Ожидали:** SAFE — это домены самих Google, GitHub, Яндекса и Альфа-банка.
- **Получили:** все шесть → `50 SUSPICIOUS` с `BRAND_IMPERSONATION` 45. На живом сайте `github.blog` → **75 PHISHING**.
- **Где в коде:** `backend/data/brands.py` — списки доменов брендов; сравнение в `backend/pipeline/lexical_analyzer.py:479-520`.
- **Заметка:** дописать десять доменов не поможет — полного списка доменов Google не существует. Направление: снижать вес, когда бренд стоит в НАЧАЛЕ домена, а остальное — обычное слово (`github.blog`, `yandex.by`), в отличие от `sberbank-vhod-online.top`, где бренд закопан в середину мусора.

---

## Находка F-24. Честные страницы входа и сброса пароля

- **Зона:** ложные тревоги
- **Серьёзность:** высокая
- **Проверил сам запуском:** да, локально и на живом сайте
- **Что не так:** на настоящей странице входа всегда есть слова `login`, `id`, `security`, `password`, `recovery` и параметр возврата — и они складываются в «ПОДОЗРИТЕЛЬНО». Доверенные домены это гасит потолком, все остальные честные сайты — нет.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import *
for u in ['https://id.rbc.ru/?landing=myrbc&from=login_topline&redirect_uri=https%3A%2F%2Fwww.rbc.ru%2F',
          'https://cabinet.tele2.ru/security/password/recovery?next=/main',
          'https://online.sberbank.ru/CSAFront/index.do',
          'https://passport.yandex.ru/auth?retpath=https%3A%2F%2Fmail.yandex.ru%2F']:
    r = sc(u)
    print(f'{r.risk_score:3d} {r.verdict.value:12s} {[(s.code,s.weight) for s in r.signals if s.weight]}')
"
```

- **Ожидали:** SAFE — это страницы входа настоящих РБК и Tele2.
- **Получили:**

```
 47 SUSPICIOUS   [('TRIGGER_KEYWORDS', 22), ('REDIRECT_PARAMS', 20), ('DOMAIN_AGE_UNKNOWN', 5)]   id.rbc.ru
 57 SUSPICIOUS   [('TRIGGER_KEYWORDS', 22), ('REDIRECT_PARAMS', 20), ('DIGITS_IN_DOMAIN', 10), ...]  cabinet.tele2.ru
  5 SAFE         [('DOMAIN_AGE_UNKNOWN', 5)]   online.sberbank.ru
  5 SAFE         [('DOMAIN_AGE_UNKNOWN', 5)]   passport.yandex.ru
```

Сбербанк и Яндекс спасает только потолок доверия. На живом сайте полный адрес РБК даёт 42 SUSPICIOUS.

- **Где в коде:** `backend/pipeline/lexical_analyzer.py:66-84` (тревожные слова), `:118-122` (параметры переадресации).
- **Заметка:** цифра в домене (`tele2`, `e1`, `2gis`) добавляет ровно ту десятку, которой не хватает до порога. Сама по себе она не находка, но в стеке решает.

---

## Находка F-25. Переход на `www` объявлен переадресацией на другой домен

- **Зона:** ложные тревоги
- **Серьёзность:** средняя
- **Проверил сам запуском:** да, на живом сайте
- **Что не так:** функция называется `_registrable_host`, но возвращает полный хост, а не регистрируемый домен. Поэтому `e1.ru → www.e1.ru` — самая обычная канонизация — считается сменой домена и даёт 20 баллов.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import httpx, time
for u in ['https://tele2.ru','https://e1.ru']:
    d = httpx.post('https://phishguard-ayrt.onrender.com/scan', json={'url':u}, timeout=150).json()
    print(d['risk_score'], d['verdict'], [(s['code'],s['weight']) for s in d['signals'] if s['weight']])
    time.sleep(3)
"
```

- **Ожидали:** SAFE.
- **Получили:** оба → `30 SUSPICIOUS` с `CROSS_DOMAIN_REDIRECT` 20 и `DIGITS_IN_DOMAIN` 10.
- **Где в коде:** `backend/url_resolver.py:24-29` — `return (urlsplit(url).hostname or "").lower()` вместо регистрируемого домена.
- **Заметка:** у доверенных доменов потолок 15 это гасит, поэтому на `mos.ru` не видно. Вылезает ровно на честных сайтах вне списка доверия.

---

## Находка F-26. Тест-сторож не видит F-19 и F-20

- **Зона:** ложные тревоги / ревью кода
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** `test_no_conflicts.py` — страховка «один факт = один весомый признак», поставленная 18 сентября именно против двойного счёта. В её списке честных сайтов из IDN только `https://мвд.рф/` и его punycode-форма, обе БЕЗ `www`. Случая «IDN + латинская метка» в списке «один факт — один признак» нет вообще.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && grep -n "мвд\|xn--\|ONE_FACT_URL" tests/test_no_conflicts.py | head -20
python3 -m pytest tests/test_no_conflicts.py -q   # проходит, хотя F-19 и F-20 живые
```

- **Ожидали:** тест падает на `www.мвд.рф`.
- **Получили:** тест зелёный — этих адресов в нём нет.
- **Где в коде:** `backend/tests/test_no_conflicts.py:145-147`.
- **Заметка:** чиня F-19 и F-20, добавь в список `www.мвд.рф`, `lk.налог.рф` и пару международных IDN — иначе через месяц вернётся.

---

## Находка F-29. На десктопе шире 768px нет ни меню, ни переключателя языка

- **Зона:** интерфейс
- **Серьёзность:** высокая
- **Проверил сам запуском:** да, в браузере, с загруженным Tailwind и без него
- **Что не так:** собственное правило мобильного слоя `.hidden { display:none !important; }` перебивает Tailwind'овский `md:flex` у блока шапки — у `md:flex` нет `!important`. Ниже 768px это незаметно, там работает бургер; с 768px бургер прячется, и не остаётся ничего.
- **Как воспроизвести:**

```bash
curl -s --max-time 45 -o /tmp/tw.js https://cdn.tailwindcss.com/3.4.16
cat > /tmp/hdr.js <<'EOF'
const {chromium}=require('playwright'); const fs=require('fs');
(async()=>{
  const b=await chromium.launch({executablePath:'/opt/pw-browsers/chromium-1194/chrome-linux/chrome'});
  const tw=fs.readFileSync('/tmp/tw.js','utf8');
  for (const file of ['index.html','api.html']) for (const w of [640,767,768,1280]) {
    const p=await b.newPage({viewport:{width:w,height:800}});
    await p.route('**cdn.tailwindcss.com**', r=>r.fulfill({contentType:'application/javascript', body:tw}));
    await p.goto('file:///home/user/phishguard/'+file); await p.waitForTimeout(700);
    const r=await p.evaluate(()=>{
      const box=e=>{const b=e&&e.getBoundingClientRect(); return b?`${Math.round(b.width)}x${Math.round(b.height)}`:'нет';};
      const nav=document.querySelector('div.hidden.md\\:flex'), burger=document.getElementById('menuBtn'), en=document.getElementById('btnEn');
      return {nav: nav?getComputedStyle(nav).display+' '+box(nav):'нет', burger: burger?getComputedStyle(burger).display+' '+box(burger):'нет', en: en?box(en):'нет'};
    });
    console.log(`${file.padEnd(11)} ${String(w).padStart(4)}px  меню=${r.nav.padEnd(16)} бургер=${r.burger.padEnd(12)} кнопка_EN=${r.en}`);
    await p.close();
  }
  await b.close();})();
EOF
cd /home/user/phishguard && NODE_PATH=/opt/node22/lib/node_modules node /tmp/hdr.js
```

- **Ожидали:** на 1280px в шапке видно меню и переключатель RU/EN, как в `api.html`.
- **Получили:**

```
index.html   640px  меню=none 0x0      бургер=flex 0x0     кнопка_EN=0x0
index.html   767px  меню=none 0x0      бургер=flex 40x34   кнопка_EN=0x0
index.html   768px  меню=none 0x0      бургер=none 0x0     кнопка_EN=0x0
index.html  1280px  меню=none 0x0      бургер=none 0x0     кнопка_EN=0x0
api.html     768px  меню=flex 259x25   бургер=none 0x0     кнопка_EN=30x23
api.html    1280px  меню=flex 259x25   бургер=none 0x0     кнопка_EN=30x23
```

В шапке `index.html` на компьютере остаётся только логотип. У `api.html` та же разметка шапки, но своего `.hidden` там нет — и всё работает. Это контрольный опыт: причина именно в правиле, а не в разметке.

- **Где в коде:** `index.html:87` (`.hidden { display:none !important; }`), блок шапки `index.html:228` (`class="hidden md:flex ..."`), бургер `index.html:241` (`md:hidden`).
- **Заметка:** это прямое опровержение записи в CLAUDE.md «мобильный слой и настольная вёрстка не пересекаются: правка одного не трогает другое». Пересеклись — через глобальное правило `.hidden`, добавленное вместе с мобильным слоем. Заметку в CLAUDE.md после починки стоит переписать.

---

## Находка F-30. Смена языка не перерисовывает уже показанный результат

- **Зона:** интерфейс
- **Серьёзность:** высокая
- **Проверил сам запуском:** да, в браузере
- **Что не так:** `applyLang()` перерисовывает результат только внутри ветки для мобильного слоя. Настольная панель результата собирается императивно при проверке и после смены языка остаётся на прежнем — вердикт, названия признаков, объяснения, слово «достоверность».
- **Как воспроизвести:** проверить адрес при языке EN, затем переключить на RU и сравнить текст панели результата. Готовый скрипт — в `/tmp/claude-0/.../scratchpad/mine/lang2.js`; суть:

```bash
# 1. localStorage.pg_lang = 'en', перезагрузить страницу
# 2. проверить https://paypa1-secure-login.tk/verify
# 3. переключить язык на RU (на десктопе кнопки нет — см. F-29, сужать окно до 600px)
# 4. сравнить innerText блока #resultPanel до и после
```

- **Ожидали:** результат перерисовывается вместе с интерфейсом.
- **Получили:**

```
EN-проверка:
  интерфейс: Protection from threats
  результат: 97 DANGER ... Server unavailable Local analysis confidence 25% BRAND IN FOREIGN DOMAIN +45 ...

После переключения на RU:
  интерфейс: Сервис для защиты от угроз      <- переключился
  результат: 97 DANGER ... Server unavailable Local analysis confidence 25% BRAND IN FOREIGN DOMAIN +45 ...   <- нет
```

- **Где в коде:** `index.html:1954` — `applyLang()`, перерисовка результата внутри `if ($('mobileApp'))`.
- **Заметка:** в шапке файла этот дефект помечен исправленным («в режиме EN интерфейс переводился, а результаты — нет»). Починили только телефон.

---

## Находка F-31. Гомоглиф считается дважды в копии движка на странице

- **Зона:** интерфейс
- **Серьёзность:** высокая
- **Проверил сам запуском:** да, сверкой страницы с питоном
- **Что не так:** ветка `MIXED_SCRIPTS` / `NON_ASCII_HOST` в `engineLocal` не спрашивает, зажёгся ли уже `BRAND_HOMOGRAPH` — в отличие от соседней ветки `PUNYCODE`, где такая оговорка есть. Сервер это уже не делает: фикс 18 сентября доехал до питона и не доехал до страницы.
- **Как воспроизвести:**

```bash
cat > /tmp/cmp.js <<'EOF'
const {chromium}=require('playwright');
(async()=>{
  const b=await chromium.launch({executablePath:'/opt/pw-browsers/chromium-1194/chrome-linux/chrome'});
  const p=await b.newPage({viewport:{width:1280,height:800}});
  await p.route('**://cdn.tailwindcss.com/**', r=>r.abort());
  await p.goto('file:///home/user/phishguard/index.html');
  const out=await p.evaluate(us=>us.map(u=>{const r=engineLocal(u);
    return {u, score:r&&r.score, sig:r?r.signals.filter(s=>s.weight).map(s=>s.code+':'+s.weight):null};}),
    ['https://аpple.com','https://xn--80ak6aa92e.com','http://185.23.44.9:8080/login','https://пример.рф/вход']);
  console.log(JSON.stringify(out,null,1)); await b.close();})();
EOF
cd /home/user/phishguard && NODE_PATH=/opt/node22/lib/node_modules node /tmp/cmp.js
echo "--- а теперь питон ---"
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import *
for u in ['https://аpple.com','https://xn--80ak6aa92e.com','http://185.23.44.9:8080/login','https://пример.рф/вход']:
    r = sc(u); print(f'{r.risk_score:3d} {u:32s} {[(s.code,s.weight) for s in r.signals if s.weight]}')
"
```

- **Ожидали:** страница и сервер считают одинаково.
- **Получили:**

| адрес | страница | сервер |
|-------|----------|--------|
| `https://аpple.com` | **100** — `BRAND_HOMOGRAPH:60` + `MIXED_SCRIPTS:45` | **65** — `BRAND_HOMOGRAPH:60` |
| `https://xn--80ak6aa92e.com` | **95** — `BRAND_HOMOGRAPH:60` + `NON_ASCII_HOST:35` | **65** — `BRAND_HOMOGRAPH:60` |

- **Где в коде:** `index.html:1371-1382` — в ветке `PUNYCODE` оговорка `!(brand && brand.kind === 'homograph')` есть, в соседней ветке `MIXED_SCRIPTS`/`NON_ASCII_HOST` её нет.
- **Заметка:** `test_frontend_sync.py` этого не ловит принципиально: он сверяет таблицу весов и словарь объяснений, а не поведение. Сюда же F-32 и F-33 — все три из одной пачки фиксов 18 сентября, доехавших только до питона.

---

## Находка F-32. `DIGITS_IN_DOMAIN` горит на IP-адресе (только на странице)

- **Зона:** интерфейс
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** в `engineLocal` признак «цифры в домене» выставляется без оговорки «это не IP», хотя в питоне такая оговорка появилась 18 сентября. IP-адрес состоит из цифр целиком, поэтому получает лишние 10 баллов.
- **Как воспроизвести:** тот же скрипт, что в F-31, адрес `http://185.23.44.9:8080/login`.
- **Ожидали:** одинаковый набор признаков.
- **Получили:** страница — `IP_IN_URL:40, NON_STANDARD_PORT:25, INSECURE_SCHEME:15, TRIGGER_KEYWORDS:12, DIGITS_IN_DOMAIN:10`; сервер — то же самое **без** `DIGITS_IN_DOMAIN`.
- **Где в коде:** `index.html:1443` — `if (/\d/.test(displaySld)) add('DIGITS_IN_DOMAIN', ...)` без `&& !isIp`.

---

## Находка F-33. В копии движка нет кириллических тревожных слов

- **Зона:** интерфейс
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** словарь тревожных слов на странице содержит только латиницу. Кириллический путь вроде `/вход` для неё пустое место.
- **Как воспроизвести:** тот же скрипт, что в F-31, адрес `https://пример.рф/вход`.
- **Ожидали:** одинаковый балл.
- **Получили:** страница — `0` баллов, «БЕЗОПАСНО», ни одного признака; сервер — `17` с `TRIGGER_KEYWORDS:12`.
- **Где в коде:** `index.html:1231` — `KEYWORD_RE`, только латиница.
- **Заметка:** для русскоязычного сервиса, где половина фишинга пишет путь кириллицей, дыра заметная. На живом сайте разрыв больше: там добавляются внешние уровни.

---

## Находка F-34. В списке главных причин два несуществующих кода

- **Зона:** интерфейс
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** мобильный экран результата выбирает «главную причину» по списку приоритетов, и первые два кода в нём — `GSB_THREAT` и `URLHAUS_LISTED`. Скорер таких не выдаёт: у него `GSB_MATCH` и `URLHAUS_URL`. Поэтому совпадение в базе угроз Google — самый весомый признак из всех, 90 баллов — никогда не становится главной причиной; человек видит вместо него что-то следующее по списку.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard && python3 -c "
import re, pathlib
scorer = pathlib.Path('backend/pipeline/scorer.py').read_text(encoding='utf-8')
codes = set(re.findall(r'c\.(?:add|ok)\(\s*\"([A-Z_0-9]+)\"', scorer))
order = ['GSB_THREAT','URLHAUS_LISTED','URLHAUS_HOST','PAGE_BRAND_MISMATCH','BRAND_HOMOGRAPH']
print('нет в скорере:', [c for c in order if c not in codes])
print('как на самом деле:', sorted(c for c in codes if 'GSB' in c or 'URLHAUS' in c))
"
```

- **Ожидали:** пустой список.
- **Получили:** `нет в скорере: ['GSB_THREAT', 'URLHAUS_LISTED']`, реальные имена — `GSB_MATCH`, `URLHAUS_URL`.
- **Где в коде:** `index.html:2071-2077` (`M_REASON_ORDER`), используется в `mMainReason` на `:2079`.

---

## Находка F-35. Без Tailwind настольная вёрстка разваливается

- **Зона:** интерфейс
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** Tailwind грузится с CDN и может не загрузиться (в этом контейнере он и не грузится — прокси отдаёт ошибку сертификата). Мобильный слой это переживает, потому что объявляет нужное сам; настольная вёрстка — нет.
- **Как воспроизвести:** тот же скрипт, что в F-29, но без подстановки `/tmp/tw.js` (заблокировать запрос к CDN через `page.route(..., r => r.abort())`).
- **Ожидали:** страница остаётся пользуемой.
- **Получили:** без Tailwind на `index.html` меню не показывается ни на одной ширине, а бургер схлопывается в `16x6` пикселей — попасть в него нельзя. На `api.html` без Tailwind меню, наоборот, показывается на всех ширинах, включая мобильные, потому что класс `hidden` там ничего не значит.
- **Заметка:** в CLAUDE.md это уже записано как известная ловушка («не опираться на Tailwind с CDN»), но вывод сделан только для мобильного слоя. Настольная вёрстка от CDN зависит полностью.

---

## Находка F-27. На двух мобильных экранах из пяти нет переключателя языка

- **Зона:** интерфейс
- **Серьёзность:** низкая
- **Проверил сам запуском:** да
- **Что не так:** переключатель RU/EN есть на трёх экранах из пяти; на экранах результата и подробностей его нет, а `applyLang` подробности не перерисовывает.
- **Как воспроизвести:** открыть страницу в 390×844, пройти до экрана результата и подробностей, поискать кнопки RU/EN.
- **Ожидали:** язык переключается с любого экрана.
- **Получили:** на экранах результата и подробностей кнопок нет; сменив язык раньше и вернувшись, подробности остаются на старом языке.
- **Где в коде:** `index.html`, мобильный слой `#mobileApp`, функция `applyLang` около `:1954`.

---

## Находка F-28. Метка схемы обмана застревает в языке первой проверки

- **Зона:** интерфейс
- **Серьёзность:** низкая
- **Проверил сам запуском:** да
- **Что не так:** название схемы (`SCAM_LABELS`) подставляется в текст признака в момент проверки и кладётся в кеш вместе с результатом. Повторный показ того же адреса на другом языке достаёт из кеша старую метку.
- **Как воспроизвести:** проверить `https://golosovanie-deti.ru/` на русском, переключить язык, проверить тот же адрес ещё раз (результат придёт из `pg_cache_v2`).
- **Ожидали:** метка на текущем языке.
- **Получили:** метка на языке первой проверки.
- **Где в коде:** `index.html:1449-1452` — `add('SCAM_PATTERN', ..., (SCAM_LABELS[lang] || SCAM_LABELS.ru)[scam])`, то есть язык вмораживается в данные, а не подставляется при отрисовке.

---

## Находка F-36. История пишется с компьютера, но показать её негде

- **Зона:** интерфейс
- **Серьёзность:** низкая
- **Проверил сам запуском:** да
- **Что не так:** история проверок пишется в `localStorage` независимо от ширины экрана, но экран истории есть только в мобильном слое. С компьютера человек накапливает историю, которую не может увидеть.
- **Как воспроизвести:**

```bash
# в браузере на 1280px: сделать проверку, затем
#   JSON.parse(localStorage.getItem('pg_history')).length   -> 1
#   document.querySelectorAll('[id*=istor]:not(#mobileApp *)').length -> 0
```

- **Ожидали:** либо история показывается и на компьютере, либо с компьютера не пишется.
- **Получили:** запись есть (`pg_history`, 1 запись после одной проверки), блока для показа вне `#mobileApp` нет.
- **Заметка:** заявка автора из раздела «Мелочи, замеченные при вёрстке» — **подтверждена**.

---

## Находка F-37. Обратный слеш в адресе: браузер идёт на один домен, мы проверяем другой

- **Зона:** кривой ввод
- **Серьёзность:** высокая
- **Проверил сам запуском:** да, сверкой с настоящим браузером
- **Что не так:** в адресе `https://evil.top\@sberbank.ru/` браузер считает `\` разделителем пути (так велит стандарт WHATWG) и идёт на **evil.top**, а `urlsplit` считает `\` обычным символом логина и отдаёт хост **sberbank.ru**. Мы разбираем доверенный домен, срезаем балл потолком и показываем «БЕЗОПАСНО».
- **Как воспроизвести:**

```bash
# что делает настоящий браузер
cd /tmp && NODE_PATH=/opt/node22/lib/node_modules node -e "
const {chromium}=require('playwright');(async()=>{
 const b=await chromium.launch({executablePath:'/opt/pw-browsers/chromium-1194/chrome-linux/chrome'});
 const p=await b.newPage();
 console.log(await p.evaluate(()=>new URL('https://evil-phish-zzz.top\\\\@sberbank.ru/').host));
 await b.close();})()"

# что делаем мы
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import *
from urllib.parse import urlsplit
for u in ['https://evil-phish-zzz.top\\\\@sberbank.ru/','https://evil-phish-zzz.top/']:
    f = L.analyze(u); r = sc(u)
    print(f'{r.risk_score:3d} {r.verdict.value:12s} наш хост={urlsplit(u).hostname:22s} trusted={f.is_trusted_domain}  {u!r}')
"
```

- **Ожидали:** оба разборщика видят один и тот же домен.
- **Получили:**

```
браузер идёт на: evil-phish-zzz.top

 15 SAFE         наш хост=sberbank.ru           trusted=True    'https://evil-phish-zzz.top\\@sberbank.ru/'
 25 SAFE         наш хост=evil-phish-zzz.top    trusted=False   'https://evil-phish-zzz.top/'
```

Приписка `\@sberbank.ru/` не просто не ухудшает — она **улучшает** вердикт подозрительного домена, добавляя ему значок «известный домен с проверенной репутацией».

- **Где в коде:** `backend/models.py`, функция `normalise_url()` — `\` не запрещён и не превращается в `/`; `backend/pipeline/lexical_analyzer.py:239-241` — `urlsplit` как единственный разборщик хоста.
- **Заметка:** это **не дубль F-01**. Там подмена делалась процент-кодированием и лечится разбором хоста ДО `unquote`; здесь никакого кодирования нет, расходятся сами разборщики. Чинить надо отдельно, иначе одна из двух дыр останется. `httpx` разбирает так же, как `urlsplit`, значит наружу (RDAP, сертификат, страница) мы тоже ходим на `sberbank.ru`, а жертва пойдёт на `evil.top`.

---

## Находка F-38. Лимит запросов обходится одним заголовком

- **Зона:** кривой ввод
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** клиент определяется по заголовку `X-Real-IP` без проверки, что его поставил наш прокси. Меняя значение, любой получает свежий счётчик.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -m uvicorn main:app --port 8091 > /tmp/srv.log 2>&1 &
sleep 4
echo "без заголовка:"; for i in $(seq 1 35); do curl -s -o /dev/null -w "%{http_code} " -X POST \
  http://127.0.0.1:8091/scan -H 'Content-Type: application/json' -d '{"url":"https://a.com:abc/"}'; done; echo
echo "с X-Real-IP:";  for i in $(seq 100 130); do curl -s -o /dev/null -w "%{http_code} " -X POST \
  http://127.0.0.1:8091/scan -H 'Content-Type: application/json' -H "X-Real-IP: 9.9.9.$i" -d '{"url":"https://a.com:abc/"}'; done; echo
```

- **Ожидали:** лимит срабатывает в обоих случаях.
- **Получили:**

```
без заголовка: 422 ×27, дальше 429 ×8
с X-Real-IP:   422 ×31, ни одного 429
```

- **Где в коде:** `backend/rate_limit.py`, `client_identifier()` — ветка `x-real-ip` берётся без всякой проверки цепочки; `TRUST_PROXY_HEADERS=True` в `backend/config.py`.
- **Заметка:** в бою перед сервисом стоит прокси Render, который дописывает `X-Forwarded-For` справа, и до ветки `X-Real-IP` дело не доходит. Дыра открыта, только если сервис окажется доступен напрямую. Поэтому средняя, а не высокая. Сюда же F-17 — тот же файл, соседняя ловушка.

---

## Находка F-39. Забракованный сервером адрес показывается как обычный вердикт

- **Зона:** кривой ввод / интерфейс
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** две беды в одном месте. Сервер отвечает на кривой адрес 422 с английским текстом и питоновскими потрохами, а фронтенд эту 422 проглатывает: в `catch` особо разбирается только случай `RATE_LIMIT:`, всё остальное уходит в ветку «сервер недоступен, считаем локально». Человек видит обычный вердикт локального движка и подпись «Сервер недоступен» — хотя сервер ответил и сказал «такой адрес я проверять не буду».
- **Как воспроизвести:**

```bash
for u in 'https://a.com:abc/' 'https://[::1]/' 'https://a.com:99999/'; do
  curl -s -X POST http://127.0.0.1:8091/scan -H 'Content-Type: application/json' -d "{\"url\":\"$u\"}"; echo; done
```

- **Ожидали:** понятный русский текст, и на странице — честная пометка, что серверная проверка не состоялась.
- **Получили:**

```
{"detail":"url: Value error, Malformed URL: Port could not be cast to integer value as 'abc'","code":"validation_error"}
{"detail":"url: Value error, Hostname '::1' has no TLD","code":"validation_error"}
{"detail":"url: Value error, Malformed URL: Port out of range 0-65535","code":"validation_error"}
```

Остальные ошибки сервиса (SSRF, таймаут, лимит) при этом по-русски — язык рвётся посреди одного API.

- **Где в коде:** `backend/models.py`, `normalise_url()` — тексты ошибок; `index.html:1553` (`if (!resp.ok) throw new Error('HTTP ' + resp.status)`) и ветка `catch` около `:1895`, где особым образом разбирается только `RATE_LIMIT:`.
- **Заметка:** вторая половина — это прямое нарушение принципа «не смогли проверить ≠ безопасно», просто зашедшее с неожиданной стороны: не «источник молчит», а «сервер отказался», и всё равно показан зелёный вердикт.

---

## Находка F-40. Заявленный дедлайн 30 секунд под нагрузкой не действует

- **Зона:** кривой ввод
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** `asyncio.wait_for(..., SCAN_TOTAL_TIMEOUT)` стоит ВНУТРИ `async with _scan_semaphore`, поэтому дедлайном накрыта только сама работа, а ожидание очереди к семафору (20 мест) не ограничено ничем.
- **Как воспроизвести:**

```bash
cat > /tmp/flood.py <<'PY'
import asyncio, httpx, time
B="http://127.0.0.1:8091/scan"
async def one(c,i):
    t=time.time()
    r=await c.post(B, json={"url":f"https://198.51.100.{i%250}/p{i}"}, timeout=400,
                   headers={"X-Real-IP":f"3.3.{i//250}.{i%250}"})
    return r.status_code, time.time()-t
async def main():
    t0=time.time()
    async with httpx.AsyncClient() as c:
        res=await asyncio.gather(*(one(c,i) for i in range(120)))
    lat=sorted(x[1] for x in res)
    print("коды:", {c:[x[0] for x in res].count(c) for c in {x[0] for x in res}})
    print(f"всего {time.time()-t0:.1f}s | min {lat[0]:.1f}s med {lat[len(lat)//2]:.1f}s max {lat[-1]:.1f}s | дольше 30 с: {sum(1 for x in lat if x>30)}")
asyncio.run(main())
PY
python3 /tmp/flood.py
```

- **Ожидали:** либо всё укладывается в 30 с, либо приходит 504.
- **Получили:**

```
коды: {200: 120}
всего 39.6s | min 3.2s med 20.5s max 39.5s | дольше 30 с: 23
```

23 запроса из 120 пробили заявленный дедлайн, ни одного 504.

- **Где в коде:** `backend/main.py`, функция `_scan()` — `async with _scan_semaphore:` строкой выше `wait_for`; `_scan_semaphore = asyncio.Semaphore(20)` на `main.py:68`.
- **Заметка:** фронтенд ждёт 70 с и на своём таймауте так же молча уходит в локальный движок (см. F-39). У ручки `/batch` собственного дедлайна нет вообще: 20 ссылок при `BATCH_CONCURRENCY=5` — это до четырёх волн по 30 с.

---

## Находка F-41. Все адреса с IPv6 отбиваются, кроме одного — ведущего на localhost

- **Зона:** кривой ввод
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** проверка «у хоста должен быть домен верхнего уровня» смотрит на `host.startswith("[")`, но скобки к этому моменту уже сняты — условие мёртвое. Поэтому любой IPv6-литерал получает 422, и проскакивает ровно один: `[::ffff:127.0.0.1]`, в котором есть точки. То есть единственный пропущенный IPv6 — это localhost.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'.')
from models import ScanRequest
for u in ['https://[2606:4700:4700::1111]/','https://[::1]/','https://[2001:db8::1]/','https://[::ffff:127.0.0.1]/']:
    try: print('ПРОШЁЛ ', u, '->', ScanRequest(url=u).url)
    except Exception as e: print('ОТБИТ  ', u, '|', str(e).split('Value error, ')[-1].split('[')[0].strip()[:60])
"
```

- **Ожидали:** публичный IPv6 проверяется, loopback отбивается.
- **Получили:** ровно наоборот:

```
ОТБИТ   https://[2606:4700:4700::1111]/ | Hostname '2606:4700:4700::1111' has no TLD
ОТБИТ   https://[::1]/                  | Hostname '::1' has no TLD
ОТБИТ   https://[2001:db8::1]/          | Hostname '2001:db8::1' has no TLD
ПРОШЁЛ  https://[::ffff:127.0.0.1]/ -> https://[::ffff:127.0.0.1]/
```

- **Где в коде:** `backend/models.py:85`.
- **Заметка:** до реального похода наружу дело не доходит — там `net_guard` честно отбивает loopback (проверено, обхода нет). Но проверять публичные IPv6-адреса сервис не умеет вообще, а сообщение «has no TLD» для IPv6 бессмысленно.

---

## Находка F-42. Адрес, который браузер открывает, сервис отказывается проверять

- **Зона:** кривой ввод
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** проверка NFKC бракует адрес с полноширинным слешем `／`, хотя браузер такой адрес открывает — и ведёт на `evil-phish-zzz.top`. То есть ровно тот случай, ради которого сервис и нужен, остаётся непроверенным.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'.')
from models import ScanRequest
u = 'https://sberbank.ru／@evil-phish-zzz.top/'
try: print('ПРОШЁЛ ->', ScanRequest(url=u).url)
except Exception as e: print('ОТБИТ:', str(e).split('Value error, ')[-1].split('[')[0].strip()[:110])
"
```

- **Ожидали:** адрес проверяется, хост определяется как `evil-phish-zzz.top`.
- **Получили:** `ОТБИТ: Malformed URL: netloc 'sberbank.ru／@evil-phish-zzz.top' contains invalid characters under NFKC normalization`. Плюс на странице эта 422 проглатывается (F-39), и человек видит вердикт локального движка.
- **Где в коде:** `backend/models.py`, `normalise_url()`.
- **Заметка:** отказ сам по себе безопаснее пропуска, так что серьёзность средняя. Но в связке с F-39 получается плохо: сервис отказался, а пользователю показали зелёное.

---

## Находка F-43. Слот пула WHOIS освобождается раньше потока

- **Зона:** кривой ввод / ревью кода
- **Серьёзность:** низкая
- **Проверил сам запуском:** да, частично
- **Что не так:** семафор отпускается в `finally` сразу после таймаута, хотя поток пула ещё висит на мёртвом сокете. Счётчик показывает свободные слоты, которых нет; задача остаётся в очереди пула, её исключение никто не забирает, и в лог сыплется `Future exception was never retrieved`.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys, asyncio, time, logging; sys.path.insert(0,'.')
logging.basicConfig(level=logging.WARNING)
import pipeline.domain_age as DA
async def m():
    await asyncio.gather(*(DA._lookup_whois(f'zzz-nonexistent-{i}.nip.io', 9.0) for i in range(30)))
    t = time.time(); r = await DA._lookup_whois('example.com', 9.0)
    print('следом обычный домен:', 'ОК' if r else 'НЕ УДАЛСЯ', f'{time.time()-t:.1f}s',
          '| осталось в очереди:', DA._whois_executor._work_queue.qsize())
asyncio.run(m())
"
```

- **Ожидали:** слот освобождается вместе с потоком, очередь пуста.
- **Получили:** задача остаётся в очереди, в логе `ERROR | asyncio | Future exception was never retrieved`.
- **Где в коде:** `backend/pipeline/domain_age.py`, `_lookup_whois()`.
- **Заметка, важная:** в этой песочнице порт 43 закрыт вообще, поэтому контрольный одиночный WHOIS по `example.com` тоже не проходит. Значит **«WHOIS перестаёт работать под нагрузкой» подтвердить нельзя** — подтверждено только то, что слот освобождается раньше потока, задача копится в очереди и лог засоряется. Комментарий в коде («поток освободит слот сам») описывает не то, что происходит. Перепроверить там, где WHOIS доступен.

---

## Что агенты заявили, но НЕ подтвердилось

Тоже важно: чтобы рабочая сессия не полезла это перепроверять заново.

| Заявка агента | Почему отбросили |
|---------------|------------------|
| «Punycode-форма и юникодная дают разный балл» (`xn--…` → 20 против 52) | Агент сам собрал недействительный punycode руками. С настоящим ACE через `idna.encode` обе формы совпадают до балла: `52/52`, `5/5`, `62/62`. Фикс с `decoded_host` работает как задумано — **не трогать**. |
| «Потолок сокращателя (45) глушит улики со страницы» | Не воспроизводится. Защита `page_saw_something` отрабатывает, а до потолка балл вообще не доходит (F-06). Проблема ровно обратная: нужен пол. |
| «Потолок доверия можно получить, заведя поддомен на чужой площадке» (`sber-vhod.github.io`) | Не воспроизводится: `_extract_trust` с приватным PSL честно отдаёт `sber-vhod.github.io` как отдельную единицу, `is_trusted_domain = False`. Механика доверия сделана правильно; дыра в другом месте — F-05. |
| «Схемы `data:`, `javascript:`, `file:` дают пропуск» | Не доходят до скорера: отбиваются валидатором на входе, это 422, а не зелёный вердикт. |
| «Двойное кодирование `%25` ломает разбор хоста» | Не воспроизводится: `https://evil.top/%2525/login` разбирается нормально, хост `evil.top`, балл 37. Опасны `%2F`/`%3F`/`%23` в части ДО `@` — это F-01. |
| «Уровень Claude выключен в бою — это пропуск» | Не баг: ключ не задан, автор в курсе и решает сам. |
| «`bücher.de` на живом сайте даёт 75» | Живьём вышло 35: домен переадресует на другой хост, и картина меняется. Класс подтверждён на `société.fr` (75 живьём) и локально на всех пяти (70). Цифру 75 для `bücher.de` не подтверждаю. |
| «`id.rbc.ru` на живом сайте даёт 57» | Живьём вышло 42, локально 47. Находка верна, цифра завышена. В отчёте стоят мои измерения. |
| «`пример.рф/вход`: страница 0, сервер 87» | Локально расхождение 0 против 17, а не 87. Суть (нет кириллических слов в копии движка) подтверждена, цифра нет. |
| «XSS через адрес» | Проверено четырьмя payload'ами на телефоне и десктопе: ни одного диалога, в DOM ничего не создалось. `textContent` держит. Не находка. |
| «Блоки под панелью вкладок на телефоне» | Перекрытие на первом экране есть, но контейнер прокручивается, после скролла перекрытий нет. Фикс 18 сентября держится. |
| «Горизонтальная прокрутка» | `scrollWidth - innerWidth = 0` на 320/390/640/1280/1920, включая адрес в 1917 символов и кириллический в 187. Нет. |
| «Сырые коды сигналов на экране» | Ни одного вхождения `[A-Z]{3,}_[A-Z_]{2,}` в тексте страницы. Словари синхронны: 63 кода скорера есть и в `ru`, и в `en`. Дыра только в тесте — F-16. |
| «HTTP 500 при кривом вводе» | **Не получен ни разу.** ~150 адресов и ~30 кривых тел: пустое, не-JSON, `null`, массив, число, битый JSON, `NaN`, дубли ключей, UTF-16, тело 10 МБ, URL в 1 МБ, заголовок 7 КБ, GET/PUT вместо POST, батч из 10000 элементов. Всё 422/405 за 0.1 с, трейсбеков в логе нет. |
| «Обход защиты от SSRF» | **Не найден.** Проверены `127.0.0.1`, `10.0.0.1`, `192.168.1.1`, `100.64.0.1`, `169.254.169.254`, `0.0.0.0`, `localhost`, `[::ffff:127.0.0.1]`, `127.1`, `0x7f.1`, `2130706433`, домены `localtest.me` и `127.0.0.1.nip.io`, и редирект с публичного хоста на адрес метаданных. Везде `Blocked SSRF attempt`, наружу ни одного запроса. Сам классификатор проверен отдельно на 21 случае (CGNAT, метаданные облаков, IPv4-mapped IPv6, 6to4, NAT64, восьмеричные) — промахов нет. |
| «Символы, нормализующиеся в точку, подменяют домен» | Не воспроизводится: `https://google.com。evil.top/` у нас `evil.top`, как в httpx и в браузере, вердикт PHISHING 80. |
| «Битый punycode роняет разбор» | Не роняет: `xn--`, `xn--a`, `xn--0000`, `xn--xn--`, `xn--`×40, `xn--бред` — все обработаны. |
| «Кеш путает записи» | Не путает: `https://example.com/`, `https://Example.com/`, `https://example.com`, `https://example.com/#a` — четыре разных ключа, четыре скана. Трата времени и памяти, но улики не перемешиваются. |
| (моё) «DNS rebinding в защите от SSRF» | Уже описано в `ARCHITECTURE.md:55-56` как известное ограничение с указанным лечением. Не находка. |

## Чего проверить НЕ удалось

- **Уровень Claude** — ключ `ANTHROPIC_API_KEY` не задан ни локально, ни на Render, уровень выключен целиком.
- **WHOIS под нагрузкой** — в этой песочнице порт 43 закрыт, одиночный контрольный запрос тоже не проходит. F-43 подтверждена только в части «слот освобождается раньше потока»; утверждение «WHOIS перестаёт работать» не проверено, см. заметку к находке.
- **`TLS_BROKEN` на `.рф`** — в разборе `мвд.рф` и `культура.рф` живой сайт добавляет `TLS_BROKEN` 20. Отличить наш дефект от того, что эти сайты просто не пускают к себе из зарубежного контейнера Render, отсюда нельзя. В баллы F-19 и F-21 эта двадцатка входит, но и без неё оба остаются выше порога.
- **Долгая стабильность** — утечки памяти, поведение кеша за сутки, вытеснение по LRU на реальном потоке не проверялись.
