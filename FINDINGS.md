# Находки агентов — 19–20 сентября 2026

**Сеть:** открыта. Живой сайт отвечает, `crt.sh` и RDAP доступны напрямую.
**Агентов запущено:** 4 по новым зонам + пятую зону (пороги) вёл я сам.
**Уровней реально работало:** 7 из 8, выключен только Claude (ключ не задан) — уровень помечен `skipped` и в достоверность не идёт, это правильно.
**Тестов на старте и на финише:** 385 passed.
**Ничего не чинилось:** да. Ни одной правки в файлах проекта.

## Что покрыто

| Зона | Статус |
|------|--------|
| 1. Регрессии на правках 19 сентября | **покрыто**, 9 находок |
| 3. Настольная вёрстка без Tailwind | **покрыто**, поэлементная опись |
| 4. Страница против сервера на кривом вводе | **покрыто**, 166 адресов, 34 расхождения |
| 5. Пороги и пары признаков | **покрыто** мной, 4 находки |
| 2. Живой сайт | **частично** — агента убил лимит сессии, точечные проверки я добил сам |

**18 находок**, каждая перепроверена мной запуском. Где цифры агента расходились с моими — в файле стоят мои.

## Самое срочное, если времени мало

1. **F-01** — сервер выносит разные вердикты одному домену в зависимости от написания. Сломан декодер punycode, и распознавание бренда отваливается от одного подменённого символа.
2. **F-02** — `お名前.com`, крупнейший регистратор доменов Японии, получает 75 и красное «Не переходите». Любой японский домен тоже.
3. **F-03** — `госуслуги.рф` помечен как подделка под самого себя, 45 «ПОДОЗРИТЕЛЬНО».
4. **F-05** — схема из истории проекта перестала ловиться кириллицей: `детский-конкурс.рф/голосование` → 27 «БЕЗОПАСНО».
5. **F-06** — тревожные слова в поддомене и в пути весят ноль.

Первые три — ложные тревоги, а по философии проекта они хуже пропусков. Четвёртая и пятая — пропуски ровно того, ради чего сервис делался.

## Сводка

| № | Зона | Коротко | Серьёзность | Проверил сам |
|---|------|---------|-------------|--------------|
| F-01 | два движка | сервер сам себе противоречит: один домен в двух написаниях даёт 45 и 10 | **критическая** | да |
| F-02 | два движка | `お名前.com` и любой японский домен → 75 «ОПАСНО» | высокая | да |
| F-03 | регрессии | `госуслуги.рф`, `сбербанк.рф`, `vk.company` → 45 «ПОДОЗРИТЕЛЬНО» | высокая | да |
| F-04 | регрессии | честные фирмы под короткие синонимы: `alfa-remont.ru`, `wb-group.ru` → 45 | высокая | да |
| F-05 | регрессии | схема голосования кириллицей больше не ловится → 27 SAFE | высокая | да |
| F-06 | регрессии | тревожные слова в поддомене и в пути весят ноль | высокая | да |
| F-07 | пороги | «поле пароля + вход через Telegram» вместе весят ноль | высокая | да |
| F-08 | регрессии | `bit.ly`: сервер 35 «подозрительно», страница 10 «безопасно» | высокая | да |
| F-09 | вёрстка | без Tailwind десктоп нечитаем: чёрное на чёрном, кольцо балла на весь экран | высокая | да |
| F-10 | два движка | подделку под Microsoft видит страница (100), а сервер нет (30) | высокая | да |
| F-11 | регрессии | поле пароля снимает потолок доверия: `login.microsoftonline.com` 15 → 35 | средняя | да |
| F-12 | регрессии | официальный канал бренда на площадке: `t.me/sberbank` → 35 | средняя | да |
| F-13 | пороги | `MIXED_SCRIPTS` + `PUNYCODE` — двойной счёт одного факта | средняя | да |
| F-14 | пороги | бренд в чужом домене сам по себе никогда не даёт «ОПАСНО» (потолок 57) | средняя | да |
| F-15 | два движка | IPv6: страница 40, сервер отказывает с бессмысленным текстом | средняя | да |
| F-16 | регрессии | `https:\evil.top/` — отказ с враньём в тексте, браузер адрес открывает | средняя | да |
| F-17 | пороги | структурный шум складывается в приговор без единой улики обмана | низкая | да |
| F-18 | живой сайт | `t.me` и `telegra.ph` в бою помечены из-за **трёх** ссылок в базе вредоносов | высокая | да, на живом сайте |

Серьёзность: **высокая** — врёт пользователю; **средняя** — портит объяснение или балл; **низкая** — косметика.

## Общий харнесс

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
def show(u, **kw):
    r = sc(u, **kw)
    print(f'{r.risk_score:3d} {r.verdict.value:10s} {u}')
    print('     ', [(s.code, s.weight) for s in r.signals if s.weight])
    return r
EOF
```

Для браузера: Chromium `/opt/pw-browsers/chromium-1194/chrome-linux/chrome`, Playwright в `/opt/node22/lib/node_modules` (запускать с `NODE_PATH=/opt/node22/lib/node_modules`). Tailwind с CDN в контейнере сам не грузится, копия качается так: `curl -s -o /tmp/tw.js https://cdn.tailwindcss.com/3.4.16` (~451 КБ), подставляется через `page.route`, файл проекта не меняется.

---

## Находка F-01. Сервер выносит разные вердикты одному домену в зависимости от написания

- **Зона:** два движка
- **Серьёзность:** критическая
- **Проверил сам запуском:** да
- **Что не так:** `decode_punycode` разворачивает имя через `idna.decode`, а тот отказывается декодировать метку, не проходящую правила IDNA2008 — например, с неразрывным дефисом U+2011 вместо обычного. Браузер такое разворачивает молча. У нас «человеческий вид» домена остаётся ACE-мусором: бренда в нём нет, зато есть цифры, которых в настоящем имени не было.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import sc
from models import DomainAgeResult, ScanRequest
M = DomainAgeResult(checked=True, age_days=4000, source='rdap')
for label, u in [('обычный дефис', 'https://xn----7sbbbax6afkrcdiwm.xn--p1ai/vhod'),
                 ('U+2011       ', 'https://xn--80aabat1afiqbdhvl6097h.xn--p1ai/vhod')]:
    r = sc(ScanRequest(url=u).url, age=M)
    print(f'{label} -> {r.risk_score:3d} {r.verdict.value:12s} {[(s.code,s.weight) for s in r.signals if s.weight]}')

from normalize import decode_punycode
for h in ['xn----7sbbbax6afkrcdiwm.xn--p1ai','xn--80aabat1afiqbdhvl6097h.xn--p1ai','xn--micrsoft-zwg.com']:
    print(f'{h:36s} -> {decode_punycode(h)}')
"
```

- **Ожидали:** одно и то же имя в двух написаниях — один и тот же балл.
- **Получили:**

```
обычный дефис ->  45 SUSPICIOUS   [('BRAND_IMPERSONATION', 45)]
U+2011        ->  10 SAFE         [('DIGITS_IN_DOMAIN', 10)]

xn----7sbbbax6afkrcdiwm.xn--p1ai     -> сбербанк-онлайн.рф
xn--80aabat1afiqbdhvl6097h.xn--p1ai  -> xn--80aabat1afiqbdhvl6097h.рф    <- провал декодера
xn--micrsoft-zwg.com                 -> xn--micrsoft-zwg.com             <- провал декодера
```

Сервер противоречит сам себе: `https://сбербанк‑онлайн.рф/vhod` юникодом → **45 SUSPICIOUS**, тот же домен в виде `https://xn--80aabat1afiqbdhvl6097h.xn--p1ai/vhod` → **10 SAFE**. Страница (`engineLocal`) на punycode-форме даёт 45 — то есть расходятся ещё и движки.

- **Где в коде:** `backend/normalize.py:43-65` (`decode_punycode`), потребители — `backend/pipeline/lexical_analyzer.py:343` и `:346`. В зоне `.рф` эффект полный: вторая метка (`xn--p1ai` → `рф`) декодируется нормально, поэтому `_idn_is_native` (`lexical_analyzer.py:416`) считает домен «родным IDN» и глушит ещё и `PUNYCODE`. Остаётся 10 баллов за выдуманные цифры.
- **Заметка:** это возврат того самого бага, который чинили 18 сентября для `.рф` (комментарий `lexical_analyzer.py:337-342` про «вход-сбербанк.рф») — только теперь он срабатывает не на зоне, а на одном подменённом символе. Побочно сервер пишет пользователю неправду: «Домен закодирован как xn--… и **отображается как** `xn--80aabat1afiqbdhvl6097h.com`», хотя браузер показывает `сбербанк‑онлайн.com`.
  Агент прогнал 166 адресов: 125 совпали полностью, 34 разошлись, **15 из 74 нелатинских — самопротиворечие сервера на двух написаниях**.
  Смягчающее: при недоступных внешних источниках достоверность падает до 17 %, и `applyConfidence` (`index.html:1616`) подменяет зелёное «БЕЗОПАСНО» на «НЕ ПРОВЕРЕНО» — защита от зелёной галочки пока держит. Но улика потеряна, а на `.com`-варианте достоверность уже 0.33.

---

## Находка F-02. Любой японский домен помечается как «ОПАСНО»

- **Зона:** два движка
- **Серьёзность:** высокая
- **Проверил сам запуском:** да
- **Что не так:** `mixed_scripts` берёт первое слово из Unicode-имени символа как название письменности. У 例 это `CJK UNIFIED IDEOGRAPH-4F8B` → «CJK», у え — `HIRAGANA LETTER E` → «HIRAGANA». Два «алфавита» в одной метке → `MIXED_SCRIPTS` 45. По-японски так пишется почти всё.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import sc
from normalize import mixed_scripts
from models import DomainAgeResult, ScanRequest
for s in ['例え','お名前','日本語','みんな','テスト','аpple','сбербанк']:
    print(f'{s:10s} mixed_scripts={mixed_scripts(s)}')
M = DomainAgeResult(checked=True, age_days=4000, source='rdap')
for u in ['https://お名前.com','https://日本語ドメイン.jp','https://例え.テスト']:
    r = sc(ScanRequest(url=u).url, age=M)
    print(f'{r.risk_score:3d} {r.verdict.value:12s} {[(s.code,s.weight) for s in r.signals if s.weight]}  {u}')
"
```

- **Ожидали:** SAFE. `お名前.com` — крупнейший регистратор доменов Японии, `例え.テスト` — официальный тестовый домен IANA.
- **Получили:**

```
例え         mixed_scripts=True
お名前        mixed_scripts=True
日本語        mixed_scripts=False
みんな        mixed_scripts=False
テスト        mixed_scripts=False

 75 PHISHING     [('MIXED_SCRIPTS', 45), ('PUNYCODE', 30)]  https://お名前.com
 75 PHISHING     [('MIXED_SCRIPTS', 45), ('PUNYCODE', 30)]  https://日本語ドメイン.jp
 75 PHISHING     [('MIXED_SCRIPTS', 45), ('PUNYCODE', 30)]  https://例え.テスト
```

Движок страницы на тех же адресах даёт 0 SAFE — расхождение вдобавок.

- **Где в коде:** `backend/normalize.py:290-312` (`mixed_scripts`). Попутно ломается `_idn_is_native`, и домен добирает `PUNYCODE` 30 — это же F-13.
- **Заметка:** кандзи, хирагана и катакана — три письменности одного языка, и соседство их в одном слове нормально. Проверять надо не «разные письменности», а «письменности, которых не бывает вместе в живом языке» — латиница с кириллицей, латиница с греческим.

---

## Находка F-03. `госуслуги.рф` помечен как подделка под самого себя

- **Зона:** регрессии
- **Серьёзность:** высокая
- **Проверил сам запуском:** да
- **Что не так:** оговорка «свой бренд в своей приличной зоне — не подделка» сверяет канонический ключ словаря и пуникодный `sld`, а новые синонимы (добавлены 19 сентября) ищутся по декодированному человеческому имени. Кириллица и новые зоны проходят мимо оговорки.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import show
from models import DomainAgeResult, CtResult
M = DomainAgeResult(checked=True, age_days=4000, source='rdap')
C = CtResult(checked=True, first_seen_days=3500, total_certs=500)
for u in ['https://госуслуги.рф','https://газпром.рф','https://сбербанк.рф','https://яндекс.рф',
          'https://vk.company','https://vk.team','https://сбер.рф','https://alfa.travel']:
    show(u, age=M, ct=C)
"
```

- **Ожидали:** SAFE. `госуслуги.рф` — настоящий портал госуслуг.
- **Получили:** все восемь → `45 SUSPICIOUS` с `BRAND_IMPERSONATION` 45 и текстом «имя бренда использовано в домене, который бренду не принадлежит».
- **Где в коде:** `backend/pipeline/lexical_analyzer.py:659` (оговорка `if sld == brand and not zone_is_cheap: continue`), синонимы — `:688` и `:692-700`. Коммит `2b68d3b`.
- **Заметка:** объяснение врёт прямым текстом — домен как раз бренду и принадлежит.

---

## Находка F-04. Честные фирмы попали под короткие синонимы брендов

- **Зона:** регрессии
- **Серьёзность:** высокая
- **Проверил сам запуском:** да
- **Что не так:** словарь синонимов от 19 сентября содержит короткие формы (`alfa`, `vk`, `wb`, `tg`, `icloud`, `raif`, `esia`, `msft`), и они бьют по любой фирме с таким словом в имени.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import sc
from models import DomainAgeResult, CtResult
M = DomainAgeResult(checked=True, age_days=4000, source='rdap')
C = CtResult(checked=True, first_seen_days=3500, total_certs=500)
for u in ['https://alfa-remont.ru','https://alfa-stroy.ru','https://vk-service.ru','https://wb-group.ru',
          'https://tg-stroy.ru','https://icloud-repair.ru','https://альфа-ремонт.рф']:
    r = sc(u, age=M, ct=C)
    print(f'{r.risk_score:3d} {r.verdict.value:12s} {[(s.code,s.weight) for s in r.signals if s.weight]}  {u}')
"
```

- **Ожидали:** SAFE. Это ремонтная контора «Альфа», строительная фирма и мастерская по ремонту техники.
- **Получили:** все семь → `45 SUSPICIOUS` с `BRAND_IMPERSONATION` 45.
- **Где в коде:** `backend/data/brands.py` (`BRAND_ALIASES`), сопоставление — `backend/pipeline/lexical_analyzer.py:688`, `:692-700`. Коммит `2b68d3b`.
- **Заметка:** в заметках по проекту записано, что короткие синонимы срабатывают только как отдельное слово, чтобы «озонотерапия» не стала фишингом. Оговорка работает — `ozonoterapia.ru` чист. Но дефис считается границей слова, и `alfa-remont` разбирается как отдельное `alfa`. Правка нужна не в границах слова, а в том, что делать со вторым куском: `alfa-remont` — это не «Альфа-банк с довеском», а другое слово.

---

## Находка F-05. Схема из истории проекта перестала ловиться кириллицей

- **Зона:** регрессии
- **Серьёзность:** высокая
- **Проверил сам запуском:** да
- **Что не так:** 19 сентября из схемы `fake_vote` убрали пересечение групп слов — правильно, оно давало ложные тревоги на `культура.рф/конкурс`. Но в группе Б остались только латинские написания (`detsk`, `detsad`, `shkola`, `risunok`, `talant`, `grant`), кириллических двойников не добавили.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import sc
from pipeline.lexical_analyzer import lexical_analyzer as L
for u in ['https://детский-конкурс.рф/голосование','https://golosovanie-za-rebenka.ru',
          'https://vote-for-kids.ru/konkurs','https://konkurs-detskiy.ru/golos']:
    f = L.analyze(u); r = sc(u)
    print(f'{r.risk_score:3d} {r.verdict.value:12s} scam={f.scam_pattern} {u}')
"
```

- **Ожидали:** `SCAM_PATTERN` — это дословно та ссылка, из-за которой проект появился, в самом естественном русском написании.
- **Получили:**

```
 27 SAFE         scam=None      https://детский-конкурс.рф/голосование
 52 SUSPICIOUS   scam=fake_vote https://golosovanie-za-rebenka.ru
 62 PHISHING     scam=fake_vote https://vote-for-kids.ru/konkurs
 62 PHISHING     scam=fake_vote https://konkurs-detskiy.ru/golos
```

Транслит ловится, кириллица нет.

- **Где в коде:** `backend/pipeline/lexical_analyzer.py:174-185`, группа Б схемы `fake_vote`. Коммит `fb1c273`.

---

## Находка F-06. Тревожные слова в поддомене и в пути весят ноль

- **Зона:** регрессии
- **Серьёзность:** высокая
- **Проверил сам запуском:** да
- **Что не так:** 19 сентября слова входа стали весить по месту: в имени домена — улика, в пути — нет. Разумно, но поддомены попали в «путь». Жертва читает `update-billing.suspended-account.mydomain.ru` как имя сайта, а мы считаем это хвостом и ставим вес 0.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import sc
from pipeline.lexical_analyzer import lexical_analyzer as L
for u in ['https://update-billing.suspended-account.mydomain.ru/',
          'https://login.verify.confirm-account.example-cdn.com/signin',
          'https://mydomain.ru/secure/login/verify/account/update/confirm/password',
          'https://mydomain-secure-login.ru/']:
    f = L.analyze(u); r = sc(u)
    print(f'{r.risk_score:3d} {r.verdict.value:12s} слова={f.trigger_keywords}')
    print(f'     {[(s.code,s.weight) for s in r.signals if s.weight]}  {u}')
"
```

- **Ожидали:** слова в поддомене весят как слова в имени домена — их видно в адресной строке.
- **Получили:**

```
  5 SAFE   слова=['account','billing','suspended','update']            -> вес 0
  5 SAFE   слова=['account','confirm','login','signin','verify']       -> вес 0
  5 SAFE   слова=['account','confirm','login','password','secure',...] -> вес 0   (7 слов в пути)
 27 SAFE   слова=['login','secure']                                    -> вес 22  (в имени домена)
```

- **Где в коде:** `backend/pipeline/lexical_analyzer.py:578-583` (`_keywords_in_host` смотрит только на регистрируемое имя). Коммит `2f020f7`.
- **Заметка:** поддомен и путь — это разные вещи для жертвы. `update-billing.suspended-account.mydomain.ru` в адресной строке телефона выглядит как сайт «update-billing», потому что хвост не влезает. Путь — другое дело, там правка 19 сентября верна.

---

## Находка F-07. «Поле пароля + вход через Telegram» вместе весят ноль

- **Зона:** пороги
- **Серьёзность:** высокая
- **Проверил сам запуском:** да
- **Что не так:** веса признаков страницы включаются только при `hard_evidence` — чужой бренд в тексте, форма на чужой домен, площадка с пользовательским контентом или домен моложе 7 дней. На самостоятельно зарегистрированном домене старше недели связка «просит пароль» + «войти через Telegram» весит ноль. Это дословно сценарий из истории проекта.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import sc
from models import DomainAgeResult, CtResult, PageResult
A = DomainAgeResult(checked=True, age_days=40, source='rdap')
C = CtResult(checked=True, first_seen_days=40, total_certs=2)
u = 'https://my-prize-club.ru/p/9'
cases = [('ничего',                 PageResult(checked=True,status_code=200)),
         ('только вход через ТГ',   PageResult(checked=True,status_code=200,messenger_login=['telegram'])),
         ('только поле пароля',     PageResult(checked=True,status_code=200,has_password_field=True)),
         ('ПАРОЛЬ + ВХОД ЧЕРЕЗ ТГ', PageResult(checked=True,status_code=200,has_password_field=True,
                                               messenger_login=['telegram'],form_count=1))]
for name, p in cases:
    r = sc(u, page=p, age=A, ct=C)
    print(f'{name:24s} -> {r.risk_score:3d} {r.verdict.value:10s} {[(s.code,s.weight) for s in r.signals if s.code.startswith(\"PAGE\")]}')
print('--- обрыв на возрасте домена, та же страница ---')
P = PageResult(checked=True,status_code=200,has_password_field=True,messenger_login=['telegram'],form_count=1)
for d in [6,7,8]:
    r = sc(u, age=DomainAgeResult(checked=True, age_days=d, source='rdap'), ct=C, page=P)
    print(f'{d} дн -> {r.risk_score:3d} {r.verdict.value}')
"
```

- **Ожидали:** связка весит больше, чем каждый признак по отдельности.
- **Получили:**

```
ничего                   ->  27 SAFE  [('PAGE_CLEAN', 0)]
только вход через ТГ     ->  27 SAFE  [('PAGE_MESSENGER_LOGIN_OK', 0)]
только поле пароля       ->  27 SAFE  [('PAGE_PASSWORD_FORM_OK', 0)]
ПАРОЛЬ + ВХОД ЧЕРЕЗ ТГ   ->  27 SAFE  [('PAGE_MESSENGER_LOGIN_OK', 0), ('PAGE_PASSWORD_FORM_OK', 0)]

6 дн -> 100 PHISHING
7 дн ->  47 SUSPICIOUS
8 дн ->  47 SUSPICIOUS
```

Один день разницы в возрасте домена — 53 балла разницы в результате.

- **Где в коде:** `backend/pipeline/scorer.py:390-441` (`hard_evidence` и обе ветки `*_OK`).
- **Почему это не ловится тестами:** `tests/test_no_conflicts.py:101-109` проверяет каждый признак **по отдельности** и ждёт пустой набор — это намеренная защита от ложных тревог, и она верна. `tests/test_new_levels.py:208` («вход через мессенджер сам по себе ничего не стоит») — тоже про одиночный признак. Связку «пароль + мессенджер» саму по себе, без чужого бренда рядом, не проверяет ни один тест.
- **Заметка:** мошеннические домены часто выдерживают: покупают б/у или регистрируют за месяц до рассылки. Возраст 40 дней для фишинга совершенно обычен. Стоит либо дать связке вес самой по себе, либо растянуть обрыв (сейчас он на 7 днях и отвесный).

---

## Находка F-08. `bit.ly` даёт разные вердикты на странице и на сервере

- **Зона:** регрессии
- **Серьёзность:** высокая
- **Проверил сам запуском:** да
- **Что не так:** 19 сентября для нераскрытых сокращателей добавили пол 35 баллов — правильная правка, «не смогли проверить ≠ безопасно». Во фронтенд её не перенесли: там есть только `TRUSTED_SCORE_CAP`.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import sc
from models import RedirectInfo
ri = RedirectInfo(resolved=False, final_url='https://bit.ly/xyz', chain=['https://bit.ly/xyz'],
                  hops=0, was_shortener=True, error='нет ответа')
r = sc('https://bit.ly/xyz', ri=ri)
print('сервер:', r.risk_score, r.verdict.value, [(s.code,s.weight) for s in r.signals if s.weight])
"

cd /home/user/phishguard && NODE_PATH=/opt/node22/lib/node_modules node -e "
const {chromium}=require('playwright');
(async()=>{
 const b=await chromium.launch({executablePath:'/opt/pw-browsers/chromium-1194/chrome-linux/chrome'});
 const p=await b.newPage(); await p.route('**cdn.tailwindcss.com**', r=>r.abort());
 await p.goto('file:///home/user/phishguard/index.html');
 console.log('страница:', await p.evaluate(()=>{const e=engineLocal('https://bit.ly/xyz');
   return e.score+' '+e.verdict+' '+JSON.stringify(e.signals.filter(s=>s.weight).map(s=>s.code+':'+s.weight));}));
 await b.close();})()"

grep -n "SHORTENER_FLOOR\|TRUSTED_SCORE_CAP" backend/pipeline/scorer.py index.html
```

- **Ожидали:** одинаковый вердикт.
- **Получили:**

```
сервер:   35 SUSPICIOUS [('SHORTENER_UNRESOLVED', 10), ('DOMAIN_AGE_UNKNOWN', 5)]
страница: 10 БЕЗОПАСНО  ["SHORTENER:10"]

backend/pipeline/scorer.py:42:UNRESOLVED_SHORTENER_FLOOR = 35
backend/pipeline/scorer.py:43:UNRESOLVED_SHORTENER_CAP = 45
index.html:585:const TRUSTED_SCORE_CAP = 15;
```

- **Где в коде:** `backend/pipeline/scorer.py:42` и `:666`; во фронтенде константы нет вовсе.
- **Заметка, отдельная:** у сервера видимые признаки дают 15 баллов, а показывается 35. Двадцать баллов взялись из пола, и нигде это не объяснено — для сервиса, у которого объяснимость заявлена главной функцией, это само по себе дефект.
  **Почему проскочило мимо 385 тестов:** `tests/test_frontend_sync.py:73-77` сверяет с фронтендом только `TRUSTED_SCORE_CAP`. Чиня это, имеет смысл расширить тест на все константы скоринга, а не только на таблицу весов.

---

## Находка F-09. Без Tailwind настольная страница нечитаема

- **Зона:** вёрстка
- **Серьёзность:** высокая
- **Проверил сам запуском:** да, замеры совпали с агентскими до пикселя
- **Что не так:** аварийный CSS (`index.html:87-218`) целиком лежит внутри `@media (max-width: 640px)` и привязан к селекторам мобильного слоя. Телефону он достаётся, компьютеру — нет вообще.
- **Как воспроизвести:**

```bash
curl -s --max-time 45 -o /tmp/tw.js https://cdn.tailwindcss.com/3.4.16
cd /home/user/phishguard && NODE_PATH=/opt/node22/lib/node_modules node -e "
const {chromium}=require('playwright'); const fs=require('fs');
(async()=>{
 const b=await chromium.launch({executablePath:'/opt/pw-browsers/chromium-1194/chrome-linux/chrome'});
 const tw=fs.readFileSync('/tmp/tw.js','utf8');
 for(const withTw of [true,false]){
  const ctx=await b.newContext({viewport:{width:1280,height:900}}); const p=await ctx.newPage();
  await p.route('**cdn.tailwindcss.com**', r=> withTw ? r.fulfill({contentType:'application/javascript',body:tw}) : r.abort());
  await p.route('**onrender.com**', r=>r.abort());
  await p.goto('file:///home/user/phishguard/index.html'); await p.waitForTimeout(900);
  console.log(withTw?'С TAILWIND':'БЕЗ TAILWIND', await p.evaluate(()=>{
    const d=s=>{const e=document.querySelector(s); const r=e.getBoundingClientRect();
      return getComputedStyle(e).display+' '+Math.round(r.width)+'x'+Math.round(r.height);};
    return {текст:getComputedStyle(document.body).color, меню:d('div.hidden.md\\\\:flex'),
            бургер:d('#menuBtn'), loadingBar:d('#loadingBar'), deskHistory:d('#deskHistory')};}));
  await p.fill('#urlInput','http://paypal.com.account-verify.ru/secure/login');
  await p.click('#scanBtn'); await p.waitForTimeout(2500);
  console.log(await p.evaluate(()=>{const g=s=>{const e=document.querySelector(s); const r=e.getBoundingClientRect();
    return Math.round(r.width)+'x'+Math.round(r.height)+' @y='+Math.round(r.y);};
   return {кольцо:g('#verdictCard svg'), балл:g('#scoreNum'), вердикт:g('#verdictLabel'),
     цвет:getComputedStyle(document.querySelector('#verdictLabel')).color};}));
  await ctx.close();}
 await b.close();})()"
```

- **Ожидали:** без Tailwind страница деградирует, но остаётся пользуемой.
- **Получили:**

```
С TAILWIND   текст: rgb(203,213,225) | меню: flex 259x25 | бургер: none 0x0 | loadingBar: none | deskHistory: none
             кольцо 80x80 @y=7 | балл 29x32 @y=31 | вердикт 694x32 @y=5 цвет rgb(248,113,113)

БЕЗ TAILWIND текст: rgb(0,0,0) | меню: block 1264x39 | бургер: inline-block 16x6 | loadingBar: block 1264x19 | deskHistory: block 1264x113
             кольцо 1262x1262 @y=-19 | балл 19x19 @y=1247 | вердикт 1262x18 @y=1282 цвет rgb(0,0,0)
```

- **Что именно ломается, по порядку починки:**
  1. **`body` теряет цвет текста** — фон `#05070a` задан своим CSS и остаётся, текст становится чёрным. Одна строка аварийного CSS чинит почти весь визуал.
  2. **`<svg>` кольца балла** (`index.html:300`) имеет только `viewBox`, без `width`/`height` — растягивается на всю ширину родителя, 1262×1262. Слово «ОПАСНО» уезжает на 1282 пикселя вниз. Цвет вердикта тоже ставится классом Tailwind — `renderResult()`, `index.html:1913-1917`.
  3. **Пять блоков с голым `.hidden` протекают**: `#loadingBar` (288), `#errorMsg` (294), `#redirectCard` (316), `#rawDetails` (323), `#deskHistory` (353).
  4. **`#menuBtn`** (242) с `md:hidden` — единственный элемент, который *появляется* там, где не должен.
  5. Раскладка: `nav` теряет flex (85 → 317px высотой), логотип 44×44 → 256×256, `main` теряет ограничение ширины, поле ввода схлопывается до 178×21 с белым фоном, кнопка становится серой системной, блоки 01/02/03 выстраиваются в столбик, `box-sizing` остаётся `content-box`.
  6. То же нужно `api.html`, минус пункт 3 — у неё нет протекающих блоков.
- **Что НЕ ломается (не трогать):** фон, `.glass`/`.glass-card`, `#resultPanel{display:none}` (47) — панель корректно скрыта до проверки, `#mobileApp{display:none}` (84) — мобильный слой на десктоп не протекает, переключатель языка, `#mobileMenu`, `.url-tag`. **Весь JavaScript цел**: вердикты считаются до цифры так же, ни одной ошибки в консоли, все кнопки достижимы кликом. Горизонтальной прокрутки нет ни на одной ширине — держит `overflow-x:hidden` (40). На 1280, 1440 и 1920 поломка одинаковая.

---

## Находка F-10. Подделку под Microsoft видит страница, а сервер нет

- **Зона:** два движка
- **Серьёзность:** высокая
- **Проверил сам запуском:** да
- **Что не так:** следствие F-01. `xn--micrsoft-zwg.com` не разворачивается нашим декодером, поэтому сервер не видит в нём имени Microsoft. Страница декодирует по-браузерному и видит.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import sc
from models import DomainAgeResult, ScanRequest
M = DomainAgeResult(checked=True, age_days=4000, source='rdap')
r = sc(ScanRequest(url='https://xn--micrsoft-zwg.com/').url, age=M)
print('сервер:', r.risk_score, r.verdict.value, [(s.code,s.weight) for s in r.signals if s.weight])
"
cd /home/user/phishguard && NODE_PATH=/opt/node22/lib/node_modules node -e "
const {chromium}=require('playwright');
(async()=>{const b=await chromium.launch({executablePath:'/opt/pw-browsers/chromium-1194/chrome-linux/chrome'});
 const p=await b.newPage(); await p.route('**cdn.tailwindcss.com**', r=>r.abort());
 await p.goto('file:///home/user/phishguard/index.html');
 console.log('страница:', await p.evaluate(()=>{const e=engineLocal('https://xn--micrsoft-zwg.com/');
   return e.score+' '+e.verdict+' '+JSON.stringify(e.signals.filter(s=>s.weight).map(s=>s.code+':'+s.weight));}));
 await b.close();})()"
```

- **Ожидали:** оба движка видят подделку.
- **Получили:**

```
сервер:   30 SUSPICIOUS [('PUNYCODE', 30)]
страница: 100 ОПАСНО ["BRAND_TYPOSQUAT:50","MIXED_SCRIPTS:45","PUNYCODE:30"]
```

- **Заметка:** агент заявлял у сервера 45 — у меня вышло 30, в отчёте моя цифра. Заодно видно, что тройной счёт одного факта (F-13) живёт и на странице: `BRAND_TYPOSQUAT` + `MIXED_SCRIPTS` + `PUNYCODE` за одно и то же.

---

## Находка F-11. Поле пароля снимает потолок доверия с честных страниц входа

- **Зона:** регрессии
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** правка 19 сентября «площадка не ручается за чужое» снимает потолок доверия, когда уровень страницы что-то нашёл. Но поле пароля есть на **каждой** честной странице входа, и потолок падает там, где он был нужен. Наружу вылезает `REDIRECT_PARAMS` за `redirect_uri`, без которого OAuth не бывает.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import sc
from models import DomainAgeResult, CtResult, PageResult
A = DomainAgeResult(checked=True, age_days=4000, source='rdap')
C = CtResult(checked=True, first_seen_days=3500, total_certs=500)
NOPAGE = PageResult(checked=True, status_code=200, form_count=0, bytes_read=9000)
LOGIN  = PageResult(checked=True, status_code=200, has_password_field=True, form_count=1, bytes_read=9000)
u = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code'
a = sc(u, age=A, ct=C, page=NOPAGE); b = sc(u, age=A, ct=C, page=LOGIN)
print(f'без поля пароля {a.risk_score:3d} {a.verdict.value:12s} | с полем пароля {b.risk_score:3d} {b.verdict.value:12s}')
print('  признаки:', [(s.code,s.weight) for s in b.signals if s.weight])
"
```

- **Ожидали:** SAFE. Это настоящая страница входа Microsoft.
- **Получили:** `без поля пароля 15 SAFE | с полем пароля 35 SUSPICIOUS`, признаки `[('REDIRECT_PARAMS', 20), ('LONG_URL', 15)]`.
- **Где в коде:** `backend/pipeline/scorer.py:645-651` и `:668-671` (`page_saw_something`), список параметров переадресации — `backend/pipeline/lexical_analyzer.py`, коммит `fbe2bc7` добавил туда `return_url`/`return_to`.
- **Заметка:** агент заявлял, что так же ломаются `accounts.google.com`, `esia.gosuslugi.ru`, `passport.yandex.ru` и `github.com/login` — **у меня они дают 20 SAFE**, а не 30. Механизм тот же, но порога они пока не пробивают. В отчёте мои цифры.

---

## Находка F-12. Официальный канал бренда на площадке помечен как подделка

- **Зона:** регрессии
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** правка «площадка не ручается за чужое» сделала `t.me` не-доверенным для содержимого, и упоминание бренда в тексте страницы стало `PAGE_BRAND_MISMATCH`. Официальный канал Сбербанка в Telegram — это как раз страница, где написано «Сбербанк» и домен `t.me`.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import sc
from models import DomainAgeResult, PageResult
A = DomainAgeResult(checked=True, age_days=4000, source='rdap')
P = PageResult(checked=True, status_code=200, brands_in_text=['sberbank'], form_count=0, bytes_read=9000)
r = sc('https://t.me/sberbank', age=A, page=P)
print(r.risk_score, r.verdict.value, [(s.code,s.weight) for s in r.signals if s.weight])
print([s.detail for s in r.signals if s.code=='PAGE_BRAND_MISMATCH'])
"
```

- **Ожидали:** SAFE или хотя бы без обвинения.
- **Получили:** `35 SUSPICIOUS [('PAGE_BRAND_MISMATCH', 35)]` с текстом «страница выдаёт себя за sberbank, но домен t.me этой компании не принадлежит».
- **Заметка:** правка сама по себе верная — фишинг на площадках она закрыла (проверено: 12 фишинговых адресов на `pages.dev`, `web.app`, `github.io`, `docs.google.com`, `telegra.ph` и других дают 90-100 PHISHING). Но у площадок есть и официальные представительства брендов, и их сервис теперь обвиняет.

---

## Находка F-13. `MIXED_SCRIPTS` и `PUNYCODE` считают один факт дважды

- **Зона:** пороги
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** подавление `PUNYCODE` стоит только для случая `brand.kind == "homograph"`. Если письменности смешаны, но бренд не опознан, оба признака горят за один и тот же факт.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import sc
from models import ScanRequest
import idna
for h in ['сбeрбанк.com','аpple.com']:
    ace = '.'.join(idna.encode(l, uts46=True).decode() for l in h.split('.'))
    for form in (h, ace):
        r = sc(ScanRequest(url='https://'+form+'/').url)
        heavy = [(s.code,s.weight) for s in r.signals if s.weight>=20]
        print(f'{r.risk_score:3d} {r.verdict.value:12s} весомых={len(heavy)} {heavy}  {form}')
"
grep -n 'brand.kind == \"homograph\"' backend/pipeline/scorer.py
```

- **Ожидали:** один факт — один весомый признак, как требует `tests/test_no_conflicts.py`.
- **Получили:** `сбeрбанк.com` (латинская `e` внутри кириллицы) → `80 PHISHING`, два весомых признака `[('MIXED_SCRIPTS', 45), ('PUNYCODE', 30)]`. Для сравнения `аpple.com` → один признак `BRAND_HOMOGRAPH` 60.
- **Где в коде:** `backend/pipeline/scorer.py:496`.
- **Почему не ловится тестами:** `MIXED_SCRIPTS` не встречается в тестах **ни разу**, а в списке `ONE_FACT_URL` (`tests/test_no_conflicts.py:126-131`) случая со смешением письменностей нет.
- **Заметка:** побочно — бренд в таком домене не опознаётся вообще (`brand=None`), то есть `сбeрбанк.com` не считается подделкой под Сбербанк. Это же даёт лишние 30 баллов японским доменам из F-02.

---

## Находка F-14. Бренд в чужом домене сам по себе никогда не даёт «ОПАСНО»

- **Зона:** пороги
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** `brand_impersonation` весит 45, `trigger_keywords` — 12, вместе 57 при пороге 60. Классические фишинговые домены на выдержанном домене в обычной зоне упираются в «ПОДОЗРИТЕЛЬНО» и не доходят до «ОПАСНО».
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import show
from models import DomainAgeResult, CtResult
A = DomainAgeResult(checked=True, age_days=400, source='rdap')
C = CtResult(checked=True, first_seen_days=400, total_certs=5)
for u in ['https://sberbank-login.ru/','https://gosuslugi-vhod.ru/auth','https://vk-restore.ru/',
          'https://wildberries-kabinet.ru/','https://tinkoff-support.ru/help']:
    show(u, age=A, ct=C)
"
```

- **Ожидали:** «ОПАСНО». Чужой бренд в домене — самая сильная улика, какая у сервиса есть.
- **Получили:** `sberbank-login.ru`, `gosuslugi-vhod.ru`, `tinkoff-support.ru` → 57 SUSPICIOUS; `vk-restore.ru`, `wildberries-kabinet.ru` → 45 SUSPICIOUS. Порог пробивают только за счёт дешёвой зоны или свежей регистрации — а и то и другое мошенник легко обходит.
- **Заметка:** это не «поднять вес до 60», а разговор о том, должен ли один признак решать вердикт. Но сейчас получается, что самая сильная улика сервиса по определению не может дать красный вердикт, и это стоит проговорить вслух.

---

## Находка F-15. IPv6: страница считает, сервер отказывается

- **Зона:** два движка
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** проверка «у хоста должен быть домен верхнего уровня» смотрит на `host.startswith("[")`, но `urlsplit(...).hostname` скобки уже снял — условие мёртвое, и все IPv6-адреса уходят в 422. Текст отказа для IPv6 бессмысленный.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'.')
from models import ScanRequest
for u in ['https://[2001:db8::1]/','https://[::1]/','https://[2606:4700:4700::1111]/']:
    try: print('ПРОШЁЛ', u, '->', ScanRequest(url=u).url)
    except Exception as e: print('ОТКАЗ ', u, '|', str(e).split('Value error, ')[-1].split('[')[0].strip()[:80])
"
```

- **Ожидали:** IPv6 проверяется как IP-адрес.
- **Получили:** все три → `ОТКАЗ | В адресе нет доменной зоны — после точки должно быть окончание вроде .ru или .com`. Движок страницы на том же адресе даёт `40 ПОДОЗРИТЕЛЬНО` с `IP_IN_URL`.
- **Где в коде:** `backend/models.py:95`.
- **Заметка:** эта находка была и в прошлой охоте (F-41 от 18 сентября) и осталась незакрытой.

---

## Находка F-16. Отказ с враньём в тексте на адресе, который браузер открывает

- **Зона:** регрессии
- **Серьёзность:** средняя
- **Проверил сам запуском:** да
- **Что не так:** `https:\\evil.top/` браузер открывает как `evil.top` (обратный слеш по стандарту WHATWG равен обычному). Мы отказываемся проверять, и текст отказа говорит про отсутствующую доменную зону, хотя `.top` на месте.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'.')
from models import ScanRequest
u = 'https:\\\\\\\\evil.top/'
try: print('ПРОШЁЛ ->', ScanRequest(url=u).url)
except Exception as e: print('ОТКАЗ:', str(e).split('Value error, ')[-1].split('[')[0].strip()[:90])
"
cd /home/user/phishguard && NODE_PATH=/opt/node22/lib/node_modules node -e "
const {chromium}=require('playwright');
(async()=>{const b=await chromium.launch({executablePath:'/opt/pw-browsers/chromium-1194/chrome-linux/chrome'});
 const p=await b.newPage();
 console.log('браузер идёт на:', await p.evaluate(()=>new URL('https:\\\\\\\\evil.top/').host));
 await b.close();})()"
```

- **Ожидали:** либо проверяем `evil.top`, либо отказываем с честным объяснением.
- **Получили:** браузер идёт на `evil.top`, мы отвечаем «В адресе нет доменной зоны».
- **Где в коде:** `backend/models.py`, `normalise_url()`.

---

## Находка F-17. Структурный шум складывается в приговор без единой улики обмана

- **Зона:** пороги
- **Серьёзность:** низкая
- **Проверил сам запуском:** да
- **Что не так:** нестандартный порт (25), `http` вместо `https` (15) и длинный адрес (15) вместе дают 55 — «ПОДОЗРИТЕЛЬНО», хотя ни один из них не говорит об обмане. С IP вместо домена выходит 80 «ОПАСНО».
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import sys; sys.path.insert(0,'/tmp/pg')
from verify import show
from models import DomainAgeResult, CtResult
A = DomainAgeResult(checked=True, age_days=4000, source='rdap')
C = CtResult(checked=True, first_seen_days=3500, total_certs=200)
for u in ['http://jira-prod-01.corp.example.com:8443/browse/PROJ-1234?filter=my-open-issues&sort=updated',
          'http://build-agent-07.ci.internal.example.com:9090/job/nightly-build-2026/lastSuccessfulBuild/artifact/',
          'http://192.0.2.10:8080/dashboard']:
    show(u, age=A, ct=C)
"
```

- **Ожидали:** внутренние адреса компании — это не фишинг.
- **Получили:** 40 SUSPICIOUS, 55 SUSPICIOUS, 80 PHISHING.
- **Заметка:** спорно, считать ли корпоративные адреса целевой аудиторией сервиса. Записываю как наблюдение: три признака, каждый из которых сам по себе не про обман, складываются в красный вердикт.

---

## Находка F-18. `t.me` и `telegra.ph` в бою помечены из-за трёх ссылок

- **Зона:** живой сайт
- **Серьёзность:** высокая
- **Проверил сам запуском:** да, на живом сайте
- **Что не так:** признак «с этого хоста уже раздавали вредонос» считает ссылки по хосту целиком. Для больших площадок правку 19 сентября сделали — `github.com`, `docs.google.com` и `dropbox.com` теперь чисты. Но `t.me` и `telegra.ph` под неё не попали, и трёх ссылок на весь Telegram хватает, чтобы пометить любую страницу площадки.
- **Как воспроизвести:**

```bash
cd /home/user/phishguard/backend && python3 -c "
import httpx, time
for u in ['https://github.com','https://docs.google.com/document/d/abc/edit','https://dropbox.com',
          'https://t.me/durov','https://t.me/sberbank','https://telegra.ph/test']:
    d = httpx.post('https://phishguard-ayrt.onrender.com/scan', json={'url':u}, timeout=150).json()
    rep = d['details'].get('reputation', {})
    sig = [(s['code'], s['weight']) for s in d['signals'] if s['weight']]
    print(f\"{d['risk_score']:3d} {d['verdict']:10s} {u[:40]:40s} host_listed={rep.get('host_listed')} ссылок={rep.get('host_url_count')} {sig}\")
    time.sleep(2.6)
"
```

- **Ожидали:** SAFE. `t.me/durov` — канал основателя Telegram.
- **Получили:**

```
  0 SAFE       https://github.com                       []                      <- починено 19 сентября
  0 SAFE       https://docs.google.com/document/d/abc   []                      <- починено
  0 SAFE       https://dropbox.com                      []                      <- починено
 45 SUSPICIOUS https://t.me/durov       host_listed=True ссылок=3  [('URLHAUS_HOST', 45)]
 80 PHISHING   https://t.me/sberbank    host_listed=True ссылок=3
 50 SUSPICIOUS https://telegra.ph/test  host_listed=True ссылок=3
```

- **Заметка:** `t.me/sberbank` набирает 80 «ОПАСНО», потому что к этому признаку прибавляется F-12 (`PAGE_BRAND_MISMATCH` за упоминание Сбербанка на его же официальном канале). Две ошибки складываются в красный вердикт на официальном канале банка.
  Хорошая новость внутри плохой: признак больше не поднимает балл до пола 90 и не отменяет потолок доверия — самая тяжёлая часть старой находки закрыта. Осталась доля хоста: **три ссылки на весь Telegram** не должны ничего значить. Смотреть надо на долю вредоносного к общему объёму, а не на сам факт.

---

## Наблюдения по живому сайту (не находки, но важные факты)

- **Код на Render совпадает с репозиторием.** `/health` отдаёт версию `1.1.0`, но поведение — от 19 сентября: `госуслуги.рф` в бою даёт 50 с `BRAND_IMPERSONATION`, а это регрессия свежих правок (F-03). Значит развёрнут текущий код, и расхождения бой/локально можно трактовать как настоящие.
- **Находки подтверждаются в бою:** F-01 (`xn--80aabat1afiqbdhvl6097h.xn--p1ai/vhod` → 15 SAFE), F-02 (`xn--t8jx82hdc.com` → 80 PHISHING), F-03 (`госуслуги.рф` → 50), F-04 (`alfa-remont.ru` → 45).
- **Холодный старт — 50 секунд.** Первый запрос после простоя: 50.4 с. Дальше 3–9 с. Дедлайн при этом работает: `login.microsoftonline.com/common/oauth2/v2.0/authorize?...` отдал честный **HTTP 504** с русским текстом «Проверка заняла слишком много времени». То есть таймаут не врёт — но настоящую страницу входа Microsoft сервис проверить не может вовсе.
- **Достоверность считается честно:** 1.00 там, где ответили все уровни, 0.43–0.57 на доменах, где часть источников молчит.

---

## Что агенты заявили, но НЕ подтвердилось

| Заявка агента | Почему отбросили |
|---------------|------------------|
| «Достоверность 1.0 при трёх выключенных уровнях» | На живом сайте выключен **один** уровень (`ai`, `skipped=True`), остальные семь `checked=True`. Исключение намеренное и как раз почищено 19 сентября. Не находка. |
| «`accounts.google.com`, `esia.gosuslugi.ru`, `passport.yandex.ru`, `github.com/login` → 30 SUSPICIOUS» | У меня 20 SAFE. Механизм верен (F-11), но порога эти адреса не пробивают. Цифры агента завышены. |
| «Сервер даёт `xn--micrsoft-zwg.com` 45» | У меня 30. Класс подтверждён (F-10), цифра нет. |
| «Японские домены дают 80» | У меня 75 (агент считал вместе с `DOMAIN_AGE_UNKNOWN`). Класс подтверждён (F-02). |
| «`t.me/sberbank` → 35 без содержимого страницы» | Голый `t.me/sberbank` даёт **0 SAFE**. 35 появляется только когда уровень страницы принёс бренд в тексте. В F-12 это оговорено. |
| «`.hidden` перебивает `md:flex`, на десктопе нет меню и переключателя языка» (старая F-29) | **Больше не воспроизводится.** Правило загнали в `@media (max-width:640px)` 19 сентября. Замер с Tailwind на 1280: меню `flex 259x25`, кнопка EN `30x23`, достижима кликом. Починено, не трогать. |
| «`SHORTENER` только на странице, сервер его не ставит» | Артефакт харнесса: он передаёт `redirects=None`, а сервер добавляет признак только когда уровень переадресаций отработал. На живом сервере `bit.ly/abc` → 30 SUSPICIOUS с `SHORTENER` + `CROSS_DOMAIN_REDIRECT`. Не баг. |
| «IP в десятичной и шестнадцатеричной записи: питон видит не тот хост» | Страница шлёт серверу уже нормализованный браузером `href`, сервер получает `https://127.0.0.1/`. Оба движка дают 40 `IP_IN_URL`. Не расхождение. |
| «Нормализация уводит на домен, отличный от браузерного» | Кроме F-16 не нашлось. Сверено с настоящим Chromium на 13 хитрых адресах (`evil.top\@bank.ru`, `sberbank.ru／@evil.top`, `google.com。evil.ru`, `a@b@evil.top`, `bank.ru%2Flogin@evil.top` и других) и 11 с невидимыми и полноширинными символами — совпадение полное. Правки 19 сентября работают. |
| «Падения на кривом вводе в новом коде» | 30 000 случайных адресов через `normalize_authority` → `encode_unparseable_userinfo` → `analyze`: **ноль исключений**. |
| «Потолки глушат фишинг на площадках» | Не подтвердилось, правка работает: 12 фишинговых адресов на `pages.dev`, `web.app`, `workers.dev`, `github.io`, `netlify.app`, `vercel.app`, `docs.google.com`, `sites.google.com`, `telegra.ph`, `t.me`, `s3.amazonaws.com`, `storage.googleapis.com` дают 90-100 PHISHING. |
| «Синонимы брендов сломали старый детект» | Наоборот, стало лучше: `сбербанк-онлайн.рф` 5→50, `sber-vhod.ru` 17→62, `vk-login.ru` 17→62, `vk-golosovanie.ru/konkurs-detey` 27→100. |
| «Обход лимита запросов в новом `rate_limit.py`» | Не нашли. Правка `max(1, TRUSTED_PROXY_HOPS)` и отказ от `X-Real-IP` закрыли обе прошлые дыры. |

## Что правки 19 сентября починили (проверено, не откатывать)

`société.fr` 70→5 · `bücher.de`, `мвд.рф`, `www.мвд.рф` чисто · `культура.рф/конкурс` 52→5 · `нацпроекты.рф/голосование` 52→5 · `%2F` в логине адреса 5→100 · обратный слеш в хосте разбирается по-браузерному · `posylka-dostavka.ru/oplatit` 5→40 · `shtraf-gibdd.ru/oplatit-so-skidkoy` 5→40 · `golosovanie-za-rebenka.ru` 17→52 · `vote-for-kids.ru/konkurs` 27→62 · IP в десятичной записи 42→60 · IP в шестнадцатеричной 30→60 · старая F-29 (шапка десктопа) закрыта.

Сплошной прогон 97 настоящих сайтов (банки, госорганы, магазины, СМИ, операторы, международные) дал **ровно одно** расхождение со старым кодом и ровно один балл ≥ 30 — `госуслуги.рф`, это F-03.

## Чего проверить НЕ удалось

- **Живой сайт (зона 2)** — агента убил лимит сессии (HTTP 429) до того, как он что-либо записал. Точечные проверки я добил сам (F-18 и раздел наблюдений выше), но **систематического сравнения «бой против локального» на 30–40 адресах нет**, как и проверки ручки `/batch` и таймаутов под нагрузкой. Это первое, что стоит доделать следующей охотой.
- **Уровень Claude** — ключ `ANTHROPIC_API_KEY` не задан ни локально, ни на Render.
- **Поведение под нагрузкой** — утечки памяти, вытеснение кеша, лимит запросов на реальном потоке не проверялись.
