"""Уровень 2b: инспекция TLS-сертификата.

Свежий сертификат на домене, который выдаёт себя за банк, — сильный
признак: сертификаты выпускают вместе с доменом, а мошеннический домен
живёт дни. Заодно видно подмену и самоподпись.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlsplit

from cache import TTLCache
from config import settings
from models import TlsResult
from net_guard import BlockedTargetError, assert_url_is_safe

logger = logging.getLogger(__name__)

_cache: TTLCache[TlsResult] = TTLCache(
    ttl_seconds=settings.CACHE_TTL_TLS,
    max_size=settings.CACHE_MAX_SIZE,
)


def _permissive_context() -> ssl.SSLContext:
    """
    Контекст, который берёт сертификат даже если он невалиден.

    Проверку намеренно отключаем: цель не «установить доверенное
    соединение», а ПОСМОТРЕТЬ сертификат — в том числе просроченный,
    самоподписанный или выданный на чужое имя. Именно такие нам и
    интересны. Дальше ничего секретного по этому соединению не
    передаётся, оно закрывается сразу после рукопожатия.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _parse_cert_date(raw: Optional[str]) -> Optional[datetime]:
    """Даты в сертификате приходят как 'Jun  1 12:00:00 2026 GMT'."""
    if not raw:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _names_from_cert(cert: dict[str, Any]) -> list[str]:
    """Собирает все имена, на которые выдан сертификат (CN + SAN)."""
    names: list[str] = []
    for entry in cert.get("subjectAltName") or ():
        if len(entry) == 2 and entry[0].lower() == "dns":
            names.append(entry[1].lower())
    for rdn in cert.get("subject") or ():
        for key, value in rdn:
            if key == "commonName":
                names.append(str(value).lower())
    return names


def _host_matches(host: str, names: list[str]) -> bool:
    """Сверяет хост с именами сертификата, учитывая маску *.example.com."""
    host = host.lower().rstrip(".")
    for name in names:
        name = name.rstrip(".")
        if name == host:
            return True
        if name.startswith("*."):
            # Маска покрывает ровно один уровень: *.example.com подходит
            # для a.example.com, но не для a.b.example.com.
            suffix = name[1:]
            if host.endswith(suffix) and host.count(".") == name.count("."):
                return True
    return False


def _issuer_name(cert: dict[str, Any]) -> Optional[str]:
    for rdn in cert.get("issuer") or ():
        for key, value in rdn:
            if key == "organizationName":
                return str(value)[:120]
    for rdn in cert.get("issuer") or ():
        for key, value in rdn:
            if key == "commonName":
                return str(value)[:120]
    return None


def _is_self_signed(cert: dict[str, Any]) -> bool:
    def flatten(field: str) -> tuple:
        return tuple(sorted(
            (k, str(v)) for rdn in (cert.get(field) or ()) for k, v in rdn
        ))
    subject, issuer = flatten("subject"), flatten("issuer")
    return bool(subject) and subject == issuer


async def check_tls(url: str) -> TlsResult:
    """Забирает сертификат и описывает его. Ошибки не выбрасываются."""
    if not settings.TLS_ENABLED:
        return TlsResult(checked=False, error="Уровень TLS выключен")

    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        return TlsResult(checked=False, error="Адрес не использует https")

    try:
        host = parts.hostname
        port = parts.port or 443
    except ValueError:
        return TlsResult(checked=False, error="Некорректный адрес")
    if not host:
        return TlsResult(checked=False, error="В адресе нет хоста")

    async def _fetch() -> TlsResult:
        try:
            await assert_url_is_safe(
                url, enabled=settings.BLOCK_PRIVATE_ADDRESSES,
                dns_timeout=settings.DNS_TIMEOUT,
            )
        except BlockedTargetError as exc:
            return TlsResult(checked=False, error=str(exc))

        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host, port,
                    ssl=_permissive_context(),
                    server_hostname=host,
                ),
                timeout=settings.TLS_TIMEOUT,
            )
            sslobj = writer.get_extra_info("ssl_object")
            if sslobj is None:
                return TlsResult(checked=False, handshake_failed=True,
                                 error="Соединение без TLS")
            # binary_form=False отдаёт разобранный словарь, но только
            # когда verify_mode != CERT_NONE. Поэтому берём DER и
            # раскладываем его штатным декодером ssl.
            der = sslobj.getpeercert(binary_form=True)
            if not der:
                return TlsResult(checked=False, handshake_failed=True,
                                 error="Сертификат не получен")
            cert_dict = _decode_der(der)
        except asyncio.TimeoutError:
            return TlsResult(checked=False, handshake_failed=True,
                             error="Сервер не ответил на рукопожатие TLS")
        except (ssl.SSLError, OSError) as exc:
            return TlsResult(checked=False, handshake_failed=True,
                             error=f"Рукопожатие TLS не удалось: {type(exc).__name__}")
        except Exception:                              # noqa: BLE001
            logger.exception("TLS unexpected error for %s", host)
            return TlsResult(checked=False, error="Ошибка проверки сертификата")
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:                      # noqa: BLE001
                    pass

        if cert_dict is None:
            return TlsResult(checked=False, error="Сертификат не разобран")

        issued = _parse_cert_date(cert_dict.get("notBefore"))
        expires = _parse_cert_date(cert_dict.get("notAfter"))
        now = datetime.now(timezone.utc)

        age_days = (now - issued).days if issued else None
        if age_days is not None and age_days < 0:
            age_days = 0

        names = _names_from_cert(cert_dict)
        return TlsResult(
            checked=True,
            age_days=age_days,
            issued_at=issued.isoformat() if issued else None,
            expires_at=expires.isoformat() if expires else None,
            issuer=_issuer_name(cert_dict),
            covers_domain=_host_matches(host, names) if names else None,
            self_signed=_is_self_signed(cert_dict),
            expired=bool(expires and expires < now),
        )

    try:
        return await _cache.single_flight(f"{host}:{port}", _fetch)
    except Exception:                                  # noqa: BLE001
        logger.exception("TLS stage failed")
        return TlsResult(checked=False, error="Сбой уровня TLS")


def _decode_der(der: bytes) -> Optional[dict[str, Any]]:
    """
    Разбирает DER-сертификат в словарь.

    Штатный getpeercert() возвращает словарь только при включённой
    проверке, а она у нас снята намеренно. Записываем сертификат во
    временный PEM-файл и просим ssl его разобрать — это единственный
    способ без внешних зависимостей.
    """
    import os
    import tempfile

    pem = ssl.DER_cert_to_PEM_cert(der)
    path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(pem)
            path = fh.name
        return ssl._ssl._test_decode_cert(path)        # noqa: SLF001
    except Exception:                                  # noqa: BLE001
        logger.info("Не удалось разобрать сертификат")
        return None
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def cache_stats() -> dict:
    return _cache.stats()


__all__ = ["cache_stats", "check_tls"]
