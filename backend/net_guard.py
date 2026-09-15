"""
net_guard.py — защита исходящих запросов от SSRF.

ПОЧЕМУ ЭТО КРИТИЧНО
───────────────────
PhishGuard принимает произвольный URL от анонимного пользователя и
САМ идёт по нему сетевым запросом (разворачивает редиректы).
Это классический Server-Side Request Forgery: злоумышленник
заставляет наш сервер обращаться туда, куда сам он не достучится.

Что можно украсть без этой защиты:
  • http://169.254.169.254/latest/meta-data/iam/security-credentials/
    — IMDS облака (AWS/GCP/Azure).  Это временные ключи от всего
    аккаунта.  Самая известная реализация такой атаки — утечка
    Capital One 2019 года (106 млн записей).
  • http://127.0.0.1:6379/ — Redis/Postgres/админки, слушающие
    только localhost и потому «без пароля».
  • http://10.0.0.5/ — сканирование внутренней сети по таймингам
    ответа (открытый порт отвечает быстро, закрытый — сразу RST).

ЧТО ДЕЛАЕМ
──────────
1. Разрешаем только схемы http/https (никаких file://, gopher://,
   ftp://, dict:// — через них SSRF превращается в чтение файлов).
2. Резолвим имя в IP и проверяем КАЖДЫЙ полученный адрес против
   списка непубличных диапазонов.  Проверяем все адреса, а не
   первый: домен может резолвиться и в публичный, и в приватный IP.
3. Повторяем проверку на КАЖДОМ хопе редиректа — иначе публичный
   сайт просто редиректит нас на 169.254.169.254.

ОСТАТОЧНЫЙ РИСК (честно, для доклада)
─────────────────────────────────────
Между нашей проверкой и реальным коннектом httpx проходит второй,
независимый DNS-резолв.  Атакующий с собственным DNS-сервером может
отдать публичный IP на первый запрос и приватный на второй —
это DNS rebinding (TOCTOU).  Полностью это лечится пиннингом
соединения к уже проверенному IP на уровне транспорта.  Мы
сознательно оставляем окно, но резко сужаем его: TTL-кеш резолвера
ОС + короткий дедлайн.  Для продакшена правильный ответ —
выносить резолвер в отдельный egress-proxy с allowlist.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from typing import Iterable
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

# Carrier-Grade NAT — не «приватный» по RFC 1918, но и не публичный:
# `ipaddress` его не помечает, приходится добавлять руками.
_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")
# Облачные метаданные. Формально это link-local (169.254.0.0/16),
# который ловится флагом is_link_local, но выносим отдельно,
# чтобы в логе была понятная причина отказа.
_METADATA_IPS = frozenset({
    ipaddress.ip_address("169.254.169.254"),   # AWS / Azure / DigitalOcean
    ipaddress.ip_address("100.100.100.200"),   # Alibaba Cloud
    ipaddress.ip_address("192.0.0.192"),       # Oracle Cloud
    ipaddress.ip_address("fd00:ec2::254"),     # AWS IMDS по IPv6
})


class BlockedTargetError(ValueError):
    """Цель запроса не прошла проверку безопасности."""


def _normalise_ip(ip: ipaddress._BaseAddress) -> ipaddress._BaseAddress:
    """
    Разворачивает IPv4-mapped IPv6 в обычный IPv4.

    `::ffff:127.0.0.1` — это тот же localhost, но флаг is_loopback
    у IPv6-объекта вернёт False.  Классический обход фильтра.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return ip.ipv4_mapped
        if ip.sixtofour:          # 2002::/16 туннели
            return ip.sixtofour
    return ip


def ip_is_public(raw_ip: str | ipaddress._BaseAddress) -> bool:
    """True, если по этому адресу безопасно ходить наружу."""
    try:
        ip = ipaddress.ip_address(raw_ip) if isinstance(raw_ip, str) else raw_ip
    except ValueError:
        return False

    ip = _normalise_ip(ip)

    if ip in _METADATA_IPS:
        return False
    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
        return False
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT_V4:
        return False
    return True


async def resolve_host(host: str, port: int = 443,
                       timeout: float = 3.0) -> list[str]:
    """
    Асинхронный DNS-резолв без блокировки event loop.

    `socket.getaddrinfo` — синхронный вызов, который может висеть
    секундами.  Гоним его через `loop.getaddrinfo`, который под
    капотом уводит работу в тред-пул.
    """
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, proto=socket.IPPROTO_TCP),
            timeout=timeout,
        )
    except (asyncio.TimeoutError, socket.gaierror, OSError, UnicodeError) as exc:
        raise BlockedTargetError(f"DNS resolution failed for {host!r}: {exc}") from exc

    # sockaddr — это (ip, port) для v4 и (ip, port, flow, scope) для v6.
    return [info[4][0] for info in infos]


async def assert_url_is_safe(url: str, *, enabled: bool = True,
                             dns_timeout: float = 3.0) -> None:
    """
    Бросает BlockedTargetError, если по URL ходить нельзя.

    `enabled=False` отключает только проверку адресов (для локальной
    разработки, где надо дёргать 127.0.0.1).  Проверка схемы
    остаётся всегда — она защищает от file:// и прочей экзотики.
    """
    parts = urlsplit(url)

    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise BlockedTargetError(f"Scheme {parts.scheme!r} is not allowed")

    try:
        host = parts.hostname
    except ValueError as exc:                      # битый IPv6-литерал
        raise BlockedTargetError(f"Malformed host in URL: {exc}") from exc

    if not host:
        raise BlockedTargetError("URL has no host")

    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:                      # порт не число
        raise BlockedTargetError(f"Malformed port in URL: {exc}") from exc

    if not enabled:
        return

    # Хост уже задан IP-литералом — резолвить нечего.
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None

    addresses: Iterable[str]
    if literal is not None:
        addresses = [str(literal)]
    else:
        addresses = await resolve_host(host, port, timeout=dns_timeout)

    if not addresses:
        raise BlockedTargetError(f"Host {host!r} did not resolve")

    for addr in addresses:
        if not ip_is_public(addr):
            logger.warning("Blocked SSRF attempt: %s -> %s", host, addr)
            raise BlockedTargetError(
                f"Host {host!r} resolves to non-public address {addr}"
            )


__all__ = [
    "ALLOWED_SCHEMES",
    "BlockedTargetError",
    "assert_url_is_safe",
    "ip_is_public",
    "resolve_host",
]
