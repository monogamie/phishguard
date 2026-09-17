"""Бренды и их легитимные домены, плюс список доверенных доменов.

Применяется только к регистрируемому домену (eTLD+1), поэтому
google.com.evil.ru под доверие не попадает."""

from __future__ import annotations

# ── Бренды → их легитимные регистрируемые домены (eTLD+1) ────────
# Ключ — каноническое имя бренда (то, что ищем в чужих доменах).
# Значение — множество доменов, которым это имя принадлежит по праву.
BRAND_DOMAINS: dict[str, frozenset[str]] = {
    "paypal":      frozenset({"paypal.com", "paypal.me", "paypalobjects.com"}),
    "google":      frozenset({
        "google.com", "google.ru", "google.co.uk", "google.de", "google.fr",
        "googleusercontent.com", "gstatic.com", "googleapis.com",
        "youtube.com", "youtu.be", "goo.gl", "withgoogle.com",
    }),
    "apple":       frozenset({"apple.com", "icloud.com", "apple.news", "cdn-apple.com"}),
    "amazon":      frozenset({
        "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.co.jp",
        "amazon.in", "primevideo.com", "amazonaws.com",
    }),
    "facebook":    frozenset({"facebook.com", "fb.com", "fbcdn.net", "messenger.com", "meta.com"}),
    "microsoft":   frozenset({
        "microsoft.com", "microsoftonline.com", "live.com", "outlook.com",
        "hotmail.com", "office.com", "office365.com", "azure.com",
        "windows.com", "msn.com", "xbox.com", "sharepoint.com",
    }),
    "netflix":     frozenset({"netflix.com", "nflxvideo.net"}),
    "tinkoff":     frozenset({"tinkoff.ru", "tbank.ru", "tinkoff.com"}),
    "sberbank":    frozenset({"sberbank.ru", "sber.ru", "sberbusiness.ru", "sberbank.com"}),
    "vtb":         frozenset({"vtb.ru", "vtb24.ru", "vtb.com"}),
    "alfabank":    frozenset({"alfabank.ru", "alfa-bank.ru", "alfabank.com"}),
    "gosuslugi":   frozenset({"gosuslugi.ru", "esia.gosuslugi.ru"}),
    "telegram":    frozenset({"telegram.org", "telegram.me", "t.me", "telegra.ph"}),
    "yandex":      frozenset({"yandex.ru", "yandex.com", "ya.ru", "yandex.net", "yandex.kz"}),
    "instagram":   frozenset({"instagram.com", "cdninstagram.com"}),
    "vkontakte":   frozenset({"vk.com", "vkontakte.ru", "vk.cc", "userapi.com"}),
    "mailru":      frozenset({"mail.ru", "bk.ru", "list.ru", "inbox.ru", "imgsmail.ru"}),
    "visa":        frozenset({"visa.com", "visa.ru", "visa.co.uk"}),
    "mastercard":  frozenset({"mastercard.com", "mastercard.ru"}),
    "gazprom":     frozenset({"gazprom.ru", "gazprombank.ru", "gazprom.com"}),
    "raiffeisen":  frozenset({"raiffeisen.ru", "raiffeisen.com", "rbinternational.com"}),
    "ozon":        frozenset({"ozon.ru", "ozon.com", "ozonru.net"}),
    "wildberries": frozenset({"wildberries.ru", "wb.ru", "wildberries.by"}),
    "steam":       frozenset({"steampowered.com", "steamcommunity.com", "valvesoftware.com"}),
    "binance":     frozenset({"binance.com", "binance.us", "bnbchain.org"}),
    "whatsapp":    frozenset({"whatsapp.com", "whatsapp.net", "wa.me"}),
    "linkedin":    frozenset({"linkedin.com", "licdn.com", "lnkd.in"}),
    "github":      frozenset({"github.com", "github.io", "githubusercontent.com"}),
    "dropbox":     frozenset({"dropbox.com", "dropboxusercontent.com"}),
    "avito":       frozenset({"avito.ru", "avito.st"}),
}

# Бренды короче этого порога не ищутся подстрокой: слишком много
# ложных срабатываний («vtb» встретится в случайном наборе букв).
# Для них работает только точное совпадение метки и опечаточный поиск.
MIN_SUBSTRING_BRAND_LEN = 5

# Плоское множество всех легитимных доменов всех брендов.
BRAND_OWNED_DOMAINS: frozenset[str] = frozenset(
    d for domains in BRAND_DOMAINS.values() for d in domains
)

# ── Площадки, где страницу может выложить кто угодно ─────────────
# Домены настоящих компаний, поэтому имперсонацией они НЕ считаются.
# Но потолок доверия им не даём: файл в чужом бакете S3 или сайт на
# поддомене арендатора — обычный способ разместить фишинг так, чтобы
# он лежал на «приличном» домене. С потолком такая страница получала
# бы «БЕЗОПАСНО» навсегда, сколько улик на ней ни найди.
# Поддомены остальных изолирует приватная часть PSL — см.
# _extract_trust в pipeline/lexical_analyzer.py.
MULTI_TENANT_DOMAINS: frozenset[str] = frozenset({
    "amazonaws.com", "googleapis.com", "sharepoint.com", "wordpress.com",
})

# ── Доверенные регистрируемые домены (eTLD+1) ────────────────────
# Сюда попадают сайты, для которых мы ограничиваем итоговый балл.
TRUSTED_DOMAINS: frozenset[str] = (BRAND_OWNED_DOMAINS | frozenset({
    # поиск / соцсети / медиа
    "wikipedia.org", "wikimedia.org", "twitter.com", "x.com", "reddit.com",
    "twitch.tv", "discord.com", "discord.gg", "ok.ru", "rutube.ru",
    "pinterest.com", "tiktok.com", "spotify.com", "soundcloud.com",
    # разработка
    "stackoverflow.com", "stackexchange.com", "gitlab.com", "bitbucket.org",
    "npmjs.com", "pypi.org", "docker.com", "python.org", "mozilla.org",
    "cloudflare.com", "akamai.com", "fastly.com", "digitalocean.com",
    # финансы / гос
    "stripe.com", "cbr.ru", "nalog.ru", "nalog.gov.ru", "mos.ru",
    "government.ru", "kremlin.ru", "pfr.gov.ru", "sfr.gov.ru",
    "iana.org", "icann.org", "ietf.org",
    # сервисы
    "zoom.us", "slack.com", "figma.com", "notion.so", "trello.com",
    "atlassian.com", "salesforce.com", "adobe.com",
    "medium.com", "openai.com", "anthropic.com", "claude.ai",
    "epicgames.com", "roblox.com", "minecraft.net", "ea.com",
    "aliexpress.com", "ebay.com", "booking.com", "airbnb.com",
    "skype.com", "viber.com", "signal.org",
})) - MULTI_TENANT_DOMAINS

__all__ = [
    "BRAND_DOMAINS",
    "BRAND_OWNED_DOMAINS",
    "TRUSTED_DOMAINS",
    "MULTI_TENANT_DOMAINS",
    "MIN_SUBSTRING_BRAND_LEN",
]
