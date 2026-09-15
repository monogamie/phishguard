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
    from models import (DomainAgeResult, RedirectInfo, ReputationResult,
                        ThreatIntelResult)

    async def no_gsb(url):
        return ThreatIntelResult(checked=False, error="offline")

    async def no_urlhaus(url, host):
        return ReputationResult(checked=False, error="offline")

    async def no_age(domain):
        return DomainAgeResult(checked=False, error="offline")

    async def no_resolve(url):
        return RedirectInfo(final_url=url, chain=[url], hops=0)

    monkeypatch.setattr(ti, "check_google_safe_browsing", no_gsb)
    monkeypatch.setattr(rep, "check_urlhaus", no_urlhaus)
    monkeypatch.setattr(da, "check_domain_age", no_age)
    monkeypatch.setattr(ur, "resolve_final_url", no_resolve)

    import main
    monkeypatch.setattr(main, "check_google_safe_browsing", no_gsb)
    monkeypatch.setattr(main, "check_urlhaus", no_urlhaus)
    monkeypatch.setattr(main, "check_domain_age", no_age)
    monkeypatch.setattr(main, "resolve_final_url", no_resolve)
