"""
Поток прогресса (`POST /scan/stream`).

Главное, что проверяется здесь, — не красота событий, а то, что
**результат собирает тот же пайплайн**. Отдельный путь подсчёта для
потока означал бы третий движок в проекте, где два уже однажды
разъехались и выносили разные вердикты по одной ссылке.
"""
import asyncio
import json

import pytest
from fastapi.testclient import TestClient

import main
from main import PIPELINE_STAGES, app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _clean_state():
    """Кеш и счётчик лимита живут между тестами и делают их зависимыми
    друг от друга: с полным прогоном поток упирался в 429."""
    from rate_limit import limiter

    main._scan_cache._data.clear()
    limiter._hits.clear()
    yield
    main._scan_cache._data.clear()
    limiter._hits.clear()


def events(client, url="https://example.com"):
    """Читает поток целиком и возвращает список событий."""
    out = []
    with client.stream("POST", "/scan/stream", json={"url": url}) as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        for line in r.iter_lines():
            if line.strip():
                out.append(json.loads(line.removeprefix("data: ")))
    return out


def test_stream_starts_before_any_work(client):
    """Первое событие уходит сразу: после холодного старта Render это
    единственный признак, что сервер вообще проснулся."""
    first = events(client)[0]
    assert first["event"] == "start"
    assert first["stages"] == list(PIPELINE_STAGES)


def test_every_stage_is_reported(client):
    reported = [e["name"] for e in events(client) if e["event"] == "stage"]
    assert sorted(reported) == sorted(PIPELINE_STAGES), (
        "о каком-то уровне не доложили — полоска на экране замрёт"
    )


def test_progress_only_moves_forward(client):
    counters = [e["done"] for e in events(client) if e["event"] == "stage"]
    assert counters == sorted(counters)
    assert counters[-1] == len(PIPELINE_STAGES)


def test_stream_ends_with_a_result(client):
    last = events(client)[-1]
    assert last["event"] == "done"
    for field in ("url", "scanned_url", "risk_score", "verdict",
                  "confidence", "signals", "details"):
        assert field in last["result"], f"нет поля {field}"


@pytest.mark.parametrize("url", [
    "https://example.com",
    "http://paypal.com.account-verify.ru/secure/login",
    "https://xn--80ak6aa92e.com/",
])
def test_stream_and_plain_scan_agree(client, url):
    """
    Тот же адрес, два эндпоинта — один вердикт. Если это разойдётся,
    значит у потока завёлся свой путь подсчёта.
    """
    streamed = events(client, url)[-1]
    assert streamed["event"] == "done"

    main._scan_cache._data.clear()
    plain = client.post("/scan", json={"url": url}).json()

    skip = {"elapsed_ms", "cached", "scanned_at"}
    a = {k: v for k, v in streamed["result"].items() if k not in skip}
    b = {k: v for k, v in plain.items() if k not in skip}
    assert a == b, "поток и обычный скан разошлись в ответе"


def test_bad_url_is_refused_before_the_stream_opens(client):
    """Кривой адрес должен получить честный 422, а не поток с ошибкой
    внутри: разбирать статус проще, чем тело."""
    r = client.post("/scan/stream", json={"url": "не ссылка"})
    assert r.status_code == 422


def test_timeout_is_reported_inside_the_stream(client, monkeypatch):
    """
    Поток уже отдан с кодом 200, поэтому о таймауте сообщать статусом
    поздно — только событием. Иначе страница молча дождётся конца
    потока и покажет пустой результат.
    """
    async def _too_slow(*_a, **_kw):
        raise asyncio.TimeoutError

    monkeypatch.setattr(main, "_run_pipeline", _too_slow)
    last = events(client, "https://example.org")[-1]
    assert last["event"] == "error"
    assert last["status"] == 504
    assert "времени" in last["detail"]


def test_cached_answer_still_closes_the_stream(client):
    """Второй запрос того же адреса берётся из кеша и этапов не даёт.
    Событие `done` всё равно обязано прийти, иначе экран зависнет."""
    events(client)
    second = events(client)
    assert second[0]["event"] == "start"
    assert second[-1]["event"] == "done"
    assert second[-1]["result"]["cached"] is True


def test_reporter_failure_does_not_break_the_scan(client, monkeypatch):
    """Читатель может отвалиться на полпути. Проверка от этого падать
    не должна — результат ещё пригодится кешу."""
    async def _broken(_stage):
        raise RuntimeError("читатель ушёл")

    async def run():
        return await main._run_pipeline("https://example.com", _broken)

    result = asyncio.run(run())
    assert result.verdict is not None
