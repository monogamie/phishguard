"""Регрессии по ревью 15 ноября (FINDINGS-4.md)."""
import time
from collections import OrderedDict

import pytest

import pipeline.page_analyzer as pa
import url_resolver as ur
from url_resolver import resolve_final_url as real_resolve_final_url


async def _allow(url, **kw):
    return None


@pytest.mark.parametrize("location", ["//[", "http://[/x"])
async def test_broken_ipv6_in_location_is_not_a_crash(monkeypatch, location):
    """S-02: `Location: //[` ронял /scan в 500 — urljoin бросал
    ValueError до try. Сайт, узнавший сканер по User-Agent, так оставлял
    нас без вердикта навсегда."""
    class Hop:
        status_code = 302
        headers = {"location": location}

    async def one_hop(client, url):
        return Hop()

    monkeypatch.setattr(ur, "assert_url_is_safe", _allow)
    monkeypatch.setattr(ur, "_one_hop", one_hop)

    info = await real_resolve_final_url("https://phish.top/start")

    assert info.error
    assert info.final_url == "https://phish.top/start"


async def test_site_chosen_punycode_charset_does_not_freeze_the_server(monkeypatch):
    """S-01: кодировку называет сам сайт. `punycode` на 256 КБ работал
    ~10 с синхронно, и сервер не отвечал никому, даже /health."""
    # Медленно именно на сплошных цифрах: на разметке кодек спотыкается
    # сразу. Страница от этого не HTML, но заплатили бы мы 10 секунд.
    body = b"9" * (256 * 1024)

    class Page:
        status_code = 200
        headers = {"content-type": "text/html; charset=punycode"}
        encoding = "punycode"

        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def aiter_bytes(self):
            yield body

    class Client:
        def stream(self, method, url, **kw):
            return Page()

    monkeypatch.setattr(pa, "assert_url_is_safe", _allow)
    monkeypatch.setattr(pa, "get_client", lambda: Client())
    monkeypatch.setattr(pa._cache, "_data", OrderedDict())

    started = time.monotonic()
    page = await pa.analyze_page("https://phish.top/")

    assert time.monotonic() - started < 2
    assert page.bytes_read == len(body)
