"""Общая настройка тестов: путь импорта и отключение сети."""
import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """
    Все тесты идут без сети.

    Внешние уровни заглушаются на уровне функций пайплайна: так тесты
    проверяют НАШУ логику, а не доступность Google и abuse.ch, и
    проходят одинаково в CI без интернета.
    """
    import pipeline.threat_intel as ti
    import pipeline.reputation as rep
    import pipeline.domain_age as da
    import url_resolver as ur
    from models import (AiVerdictResult, CtResult, DomainAgeResult, PageResult,
                        RedirectInfo, ReputationResult, ThreatIntelResult,
                        TlsResult)

    async def no_gsb(url):
        return ThreatIntelResult(checked=False, error="offline")

    async def no_urlhaus(url, host):
        return ReputationResult(checked=False, error="offline")

    async def no_age(domain):
        return DomainAgeResult(checked=False, error="offline")

    async def no_resolve(url):
        return RedirectInfo(final_url=url, chain=[url], hops=0)

    async def no_ai(url, lexical):
        return AiVerdictResult(checked=False, error="offline")

    async def no_tls(url):
        return TlsResult(checked=False, error="offline")

    async def no_ct(domain):
        return CtResult(checked=False, error="offline")

    async def no_page(url):
        return PageResult(checked=False, error="offline")

    monkeypatch.setattr(ti, "check_google_safe_browsing", no_gsb)
    monkeypatch.setattr(rep, "check_urlhaus", no_urlhaus)
    monkeypatch.setattr(da, "check_domain_age", no_age)
    monkeypatch.setattr(ur, "resolve_final_url", no_resolve)

    import main
    monkeypatch.setattr(main, "check_google_safe_browsing", no_gsb)
    monkeypatch.setattr(main, "check_urlhaus", no_urlhaus)
    monkeypatch.setattr(main, "check_domain_age", no_age)
    monkeypatch.setattr(main, "resolve_final_url", no_resolve)
    monkeypatch.setattr(main, "analyze_with_ai", no_ai)
    monkeypatch.setattr(main, "check_tls", no_tls)
    monkeypatch.setattr(main, "check_ct_logs", no_ct)
    monkeypatch.setattr(main, "analyze_page", no_page)
