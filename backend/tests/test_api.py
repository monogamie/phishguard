"""Интеграционные тесты HTTP-слоя (сеть заглушена в conftest)."""
import pytest
from fastapi.testclient import TestClient

import main
from main import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _clear_caches():
    """Кеш живёт между тестами и делает их зависимыми друг от друга."""
    import asyncio
    asyncio.get_event_loop_policy().new_event_loop()
    main._scan_cache._data.clear()
    yield
    main._scan_cache._data.clear()


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["ssrf_protection"] is True


def test_root_lists_endpoints(client):
    assert "/scan" in str(client.get("/").json())


def test_scan_returns_full_schema(client):
    r = client.post("/scan", json={"url": "https://example.com"})
    assert r.status_code == 200
    body = r.json()
    for field in ("url", "scanned_url", "is_phishing", "risk_score",
                  "verdict", "confidence", "signals", "reasons", "details"):
        assert field in body, f"нет поля {field}"
    assert 0 <= body["risk_score"] <= 100
    assert body["verdict"] in ("SAFE", "SUSPICIOUS", "PHISHING")


def test_scan_signals_have_machine_codes(client):
    """Фронтенд должен опираться на code/severity, а не на эмодзи."""
    r = client.post("/scan", json={"url": "https://paypa1.com/secure-login"})
    signals = r.json()["signals"]
    assert signals
    assert all(s["code"] and s["severity"] in ("ok", "info", "warn", "danger")
               for s in signals)
    assert any(s["code"] == "BRAND_TYPOSQUAT" for s in signals)


def test_phishing_url_flagged(client):
    r = client.post("/scan", json={"url": "https://paypal.com.account-verify.ru/login"})
    assert r.json()["verdict"] in ("SUSPICIOUS", "PHISHING")


def test_trusted_url_is_safe(client):
    r = client.post("/scan", json={"url": "https://google.com"})
    assert r.json()["verdict"] == "SAFE"


@pytest.mark.parametrize("bad", [
    {"url": "javascript:alert(1)"},
    {"url": "file:///etc/passwd"},
    {"url": 123},
    {"url": ""},
    {"url": "http://a.com:bad/"},
    {"nourl": "x"},
])
def test_invalid_input_returns_422_not_500(client, bad):
    """Ключевая регрессия: все эти входы раньше давали HTTP 500."""
    assert client.post("/scan", json=bad).status_code == 422


def test_error_response_shape(client):
    body = client.post("/scan", json={"url": 123}).json()
    assert "detail" in body and body["code"] == "validation_error"


def test_scan_is_cached(client):
    """Повторный скан не выполняет пайплайн заново."""
    client.post("/scan", json={"url": "https://cached-example.com"})
    second = client.post("/scan", json={"url": "https://cached-example.com"})
    assert second.json()["cached"] is True


def test_batch_ok(client):
    r = client.post("/batch", json={"urls": ["https://a.com", "https://b.org"]})
    assert r.status_code == 200
    assert len(r.json()) == 2


def test_batch_limit_enforced(client):
    r = client.post("/batch", json={"urls": [f"https://s{i}.com" for i in range(25)]})
    assert r.status_code == 422


def test_batch_rejects_invalid_member(client):
    r = client.post("/batch", json={"urls": ["https://ok.com", "javascript:alert(1)"]})
    assert r.status_code == 422


def test_batch_empty_rejected(client):
    assert client.post("/batch", json={"urls": []}).status_code == 422


def test_security_headers_present(client):
    h = client.get("/health").headers
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"
    assert h["Referrer-Policy"] == "no-referrer"


def test_rate_limit_triggers(client, monkeypatch):
    from rate_limit import SlidingWindowRateLimiter
    import rate_limit
    monkeypatch.setattr(rate_limit, "limiter",
                        SlidingWindowRateLimiter(limit=3, window_seconds=60))
    codes = [client.post("/scan", json={"url": f"https://rl{i}.com"}).status_code
             for i in range(6)]
    assert 429 in codes
    assert codes.count(200) <= 3


def test_rate_limit_not_bypassed_by_forged_header(client, monkeypatch):
    """
    X-Forwarded-For прокси дописывают в КОНЕЦ, поэтому левые значения
    подставляет сам клиент. Пока лимитер брал первое значение, лимит
    снимался одной строкой: `curl -H "X-Forwarded-For: 1.2.3.$RANDOM"`.
    А каждый /scan — это до семи исходящих запросов наружу.
    """
    from rate_limit import SlidingWindowRateLimiter
    import rate_limit
    monkeypatch.setattr(rate_limit, "limiter",
                        SlidingWindowRateLimiter(limit=3, window_seconds=60))
    # Так выглядит цепочка на Render: слева подстановка клиента,
    # справа — настоящий адрес, дописанный прокси.
    codes = [
        client.post("/scan", json={"url": f"https://rlx{i}.com"},
                    headers={"X-Forwarded-For":
                             f"1.2.3.{i}, 198.51.100.7"}).status_code
        for i in range(8)
    ]
    assert 429 in codes
    assert codes.count(200) <= 3


def test_client_taken_from_the_proxy_end_of_the_chain():
    from rate_limit import client_identifier

    class _Headers(dict):
        def get(self, key, default=None):
            return dict.get(self, key, default)

    class _Request:
        def __init__(self, xff):
            self.headers = _Headers({"x-forwarded-for": xff})
            self.client = type("C", (), {"host": "203.0.113.9"})()

    # Слева — то, что подставил клиент, справа — то, что дописал прокси.
    assert client_identifier(_Request("1.2.3.4, 198.51.100.7")) == "198.51.100.7"


def test_health_not_rate_limited(client, monkeypatch):
    from rate_limit import SlidingWindowRateLimiter
    import rate_limit
    monkeypatch.setattr(rate_limit, "limiter",
                        SlidingWindowRateLimiter(limit=1, window_seconds=60))
    assert all(client.get("/health").status_code == 200 for _ in range(5))


def test_openapi_generates(client):
    """Схема должна собираться: это и есть публичная документация API."""
    assert client.get("/openapi.json").status_code == 200
