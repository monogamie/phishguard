"""Тесты защиты от SSRF."""
import pytest

from net_guard import BlockedTargetError, assert_url_is_safe, ip_is_public


@pytest.mark.parametrize("ip", [
    "127.0.0.1",            # loopback
    "10.0.0.1",             # RFC1918
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",      # метаданные облака
    "100.64.0.1",           # CGNAT
    "0.0.0.0",
    "::1",
    "fe80::1",
    "::ffff:127.0.0.1",     # IPv4-mapped обход
    "not-an-ip",
])
def test_private_addresses_blocked(ip):
    assert ip_is_public(ip) is False


@pytest.mark.parametrize("ip", ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700::1111"])
def test_public_addresses_allowed(ip):
    assert ip_is_public(ip) is True


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "gopher://evil.com/",
    "ftp://files.example.com/",
    "javascript:alert(1)",
])
async def test_non_http_schemes_rejected(url):
    with pytest.raises(BlockedTargetError):
        await assert_url_is_safe(url)


@pytest.mark.asyncio
async def test_metadata_endpoint_blocked():
    """Самый опасный SSRF-таргет: сервис метаданных облака."""
    with pytest.raises(BlockedTargetError):
        await assert_url_is_safe(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/")


@pytest.mark.asyncio
async def test_localhost_ports_blocked():
    with pytest.raises(BlockedTargetError):
        await assert_url_is_safe("http://127.0.0.1:6379/")


@pytest.mark.asyncio
async def test_check_can_be_disabled_for_dev():
    """enabled=False снимает проверку адреса, но НЕ проверку схемы."""
    await assert_url_is_safe("http://127.0.0.1:8000/", enabled=False)
    with pytest.raises(BlockedTargetError):
        await assert_url_is_safe("file:///etc/passwd", enabled=False)
