"""Behavioral regressions for security, atomic updates and background work."""
import asyncio
import importlib
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.auth import AuthManager, SESSION_COOKIE
from app.db import Database
from app.policy import PolicyEngine, QueryLogger
from app.safe_fetch import validate_source_url, _connect, _allowed, _RedirectHandler
from app.statistics import StatisticsCache


@pytest.fixture(scope="module")
def web(tmp_path_factory):
    directory = tmp_path_factory.mktemp("review-web")
    with patch.dict(os.environ, DATA_DIR=str(directory), DATABASE_BACKEND="sqlite",
                    ADMIN_PASSWORD="review-test-password", POLICY_API_KEY="review-policy-key-long-enough"):
        main = importlib.import_module("app.main")
    yield main
    main.engine.close()
    main.auth.close()
    main.rdns.close()


@pytest.fixture
def browser(web):
    user = web.auth.authenticate("admin", "review-test-password")
    session = web.auth.create_session(*user)
    with web.db.connect() as con:
        for row in con.execute("SELECT id FROM blocklists").fetchall():
            web.db.delete_blocklist(con, row["id"])
    web.engine.reload()
    client = TestClient(web.app, base_url="https://testserver", follow_redirects=False)
    client.cookies.set(SESSION_COOKIE, session.token)
    yield client, session
    client.close()


def payload():
    return {"client": {"ip": "192.0.2.5"}, "dns": {"questions": [{"name": "example.org", "type": "A"}]}}


@pytest.mark.parametrize("change", [
    lambda p: p["client"].update(ip="not-an-ip"),
    lambda p: p["client"].update(port=65536),
    lambda p: p["dns"].update(questions=[]),
    lambda p: p["dns"].update(questions=p["dns"]["questions"] * 17),
    lambda p: p["dns"]["questions"][0].update(name="x" * 64 + ".org"),
    lambda p: p["dns"].update(wire_base64="A" * 87381),
])
def test_invalid_decisions_rejected(web, change):
    p = payload()
    change(p)
    response = TestClient(web.app).post("/api/v1/decision", json=p, headers={"X-API-Key": "review-policy-key-long-enough"})
    assert response.status_code == 422


@pytest.mark.parametrize("name", [".", "_sip._tcp.example.org.", "5.2.0.192.in-addr.arpa.", "bücher.example"])
def test_valid_dns_names(web, name):
    p = payload()
    p["dns"]["questions"][0]["name"] = name
    assert TestClient(web.app).post("/api/v1/decision", json=p, headers={"X-API-Key": "review-policy-key-long-enough"}).status_code == 200


def test_cookie_remains_secure_after_credentials_change(web, browser):
    client, session = browser
    response = client.post("/admin/credentials", data={"csrf_token": session.csrf_token, "username": "admin", "current_password": "review-test-password", "new_password": "", "confirm_password": ""})
    assert response.status_code == 303
    assert "Secure" in response.headers["set-cookie"]
    assert "HttpOnly" in response.headers["set-cookie"]
    assert web.auth.get_session(session.token) is None


def test_api_key_is_revealed_only_in_noncacheable_post(web, browser):
    client, session = browser
    response = client.post("/admin/api-keys", data={"csrf_token": session.csrf_token, "name": "Review key"})
    assert response.status_code == 200
    assert "Copy this API key now" in response.text
    assert "location" not in response.headers
    assert response.headers["cache-control"] == "no-store"
    assert "Copy this API key now" not in client.get("/security?reveal=attacker-value").text


def create_list(web, browser, **extra):
    client, session = browser
    data = {"csrf_token": session.csrf_token, "name": "Original", "format": "domains", "text": "ads.example.org", "global_list": "1"}
    data.update(extra)
    response = client.post("/admin/lists", data=data)
    assert response.status_code == 303
    assert "error=" not in response.headers["location"]
    with web.db.connect() as con:
        return con.execute("SELECT MAX(id) AS id FROM blocklists").fetchone()["id"]


def test_empty_replacement_does_not_commit_metadata(web, browser):
    list_id = create_list(web, browser)
    client, session = browser
    response = client.post(f"/admin/lists/{list_id}/edit", data={"csrf_token": session.csrf_token, "name": "Changed", "format": "domains"}, files={"replacement_file": ("empty.txt", b"")})
    assert "error=" in response.headers["location"]
    with web.db.connect() as con:
        row = con.execute("SELECT name,enabled FROM blocklists WHERE id=?", (list_id,)).fetchone()
        assert (row["name"], row["enabled"]) == ("Original", 1)
    assert web.engine.snapshot.blocklists[list_id].name == "Original"


def test_list_write_failure_rolls_back_metadata_and_membership(web, browser, monkeypatch):
    list_id = create_list(web, browser)
    original = web.db.replace_list_domains
    def fail(con, list_id, domains):
        original(con, list_id, domains)
        raise RuntimeError("injected write failure")
    monkeypatch.setattr(web.db, "replace_list_domains", fail)
    client, session = browser
    response = client.post(f"/admin/lists/{list_id}/edit", data={"csrf_token": session.csrf_token, "name": "Changed", "format": "domains", "replacement_text": "other.example.org"})
    assert "error=" in response.headers["location"]
    with web.db.connect() as con:
        assert con.execute("SELECT name FROM blocklists WHERE id=?", (list_id,)).fetchone()["name"] == "Original"
        assert con.execute("SELECT domain FROM block_entries WHERE blocklist_id=?", (list_id,)).fetchone()["domain"] == "ads.example.org"
    response = client.post("/admin/lists", data={"csrf_token": session.csrf_token, "name": "Must roll back", "format": "domains", "text": "other.example.org"})
    assert "error=" in response.headers["location"]
    with web.db.connect() as con:
        assert con.execute("SELECT COUNT(*) c FROM blocklists WHERE name='Must roll back'").fetchone()["c"] == 0


def test_format_change_invalidates_source_and_reparses(web, browser, monkeypatch):
    from app.refresher import BlocklistRefresher
    source = "0.0.0.0 ads.example.org\ntracking.example.org\n"
    monkeypatch.setattr(web, "fetch_url", lambda url: source)
    list_id = create_list(web, browser, source_url="https://example.org/list", format="hosts")
    refresher = BlocklistRefresher(web.db, web.engine, fetcher=lambda url: source)
    assert refresher.refresh_list(list_id).error is None
    client, session = browser
    response = client.post(f"/admin/lists/{list_id}/edit", data={"csrf_token": session.csrf_token, "name": "Changed format", "format": "auto", "source_url": "https://example.org/list", "enabled": "1"})
    assert "error=" not in response.headers["location"]
    with web.db.connect() as con:
        assert con.execute("SELECT source_hash FROM blocklists WHERE id=?", (list_id,)).fetchone()["source_hash"] is None
    assert refresher.refresh_list(list_id).entry_count == 2


def test_query_refresh_skips_filter_scans(web, browser, monkeypatch):
    client, _ = browser
    original = web.db.connect
    statements = []
    @contextmanager
    def traced():
        with original() as con:
            con.set_trace_callback(statements.append)
            yield con
    monkeypatch.setattr(web.db, "connect", traced)
    response = client.get("/queries/rows?decision=blocked&limit=25")
    assert response.status_code == 200
    assert "<tbody>" in response.text
    assert "<html" not in response.text
    assert not any("SELECT DISTINCT" in sql for sql in statements)
    assert TestClient(web.app, follow_redirects=False).get("/queries/rows").status_code == 303


def test_health_details_require_session(web, browser):
    assert TestClient(web.app, follow_redirects=False).get("/api/v1/runtime").status_code == 303
    response = browser[0].get("/api/v1/runtime")
    assert response.status_code == 200
    assert response.json()["policy_generation"] > 0
    assert "dropped_rows" in response.json()["logger"]


def test_bootstrap_rejects_defaults_without_partial_user(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "change-this-admin-password")
    monkeypatch.setenv("POLICY_API_KEY", "change-this-long-random-api-key")
    db = Database(str(tmp_path / "bootstrap.db"))
    with pytest.raises(ValueError, match="unique ADMIN_PASSWORD"):
        AuthManager(db)
    with db.connect() as con:
        assert con.execute("SELECT COUNT(*) c FROM admin_users").fetchone()["c"] == 0


def test_statistics_cache_coalesces_parallel_requests(tmp_path, monkeypatch):
    import app.statistics as statistics
    calls = []
    def build(*args, **kwargs):
        calls.append(kwargs)
        time.sleep(0.02)
        return {"count": len(calls)}
    monkeypatch.setattr(statistics, "build_statistics_snapshot", build)
    cache = StatisticsCache(Database(str(tmp_path / "stats.db")))
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: cache.snapshot(), range(16)))
    assert len(calls) == 1
    assert all(r == {"count": 1} for r in results)
    cache.snapshot(minutes=15)
    assert len(calls) == 2


def test_reload_writers_cannot_publish_out_of_order(tmp_path, monkeypatch):
    db = Database(str(tmp_path / "reload.db"))
    engine = PolicyEngine(db)
    captured, release = threading.Event(), threading.Event()
    original = engine._policy_settings_from_rows
    def delayed(rows):
        settings = original(rows)
        if threading.current_thread().name == "old-rebuild":
            captured.set()
            assert release.wait(3)
        return settings
    monkeypatch.setattr(engine, "_policy_settings_from_rows", delayed)
    old = threading.Thread(target=engine.reload_settings, name="old-rebuild")
    newer = threading.Thread(target=engine.reload_settings, name="new-rebuild")
    try:
        old.start()
        assert captured.wait(3)
        db.set_setting("global_blocking", "0")
        newer.start()
        # Reads still run while the older rebuild holds the writer lock.
        assert engine.decide("192.0.2.1", "example.org") is not None
        release.set()
        old.join(3)
        newer.join(3)
        assert not old.is_alive() and not newer.is_alive()
        assert engine.snapshot.global_blocking is False
    finally:
        release.set()
        old.join(3)
        if newer.ident:
            newer.join(3)
        engine.close()


@pytest.mark.parametrize("mode", ["write", "commit"])
def test_logger_recovery_and_shutdown_drain(tmp_path, mode):
    db = Database(str(tmp_path / "logger.db"))
    real_connect = db.connect
    failed = []
    class Connection:
        def __init__(self, con): self.con = con
        def __getattr__(self, key): return getattr(self.con, key)
        def executemany(self, sql, rows):
            if mode == "write" and not failed:
                failed.append(True)
                raise RuntimeError("transient write failure")
            return self.con.executemany(sql, rows)
        def execute(self, sql, *args):
            result = self.con.execute(sql, *args)
            if mode == "commit" and sql == "COMMIT" and not failed:
                failed.append(True)
                raise RuntimeError("lost commit acknowledgement")
            return result
    @contextmanager
    def connect():
        with real_connect() as con:
            yield Connection(con)
    db.connect = connect
    logger = QueryLogger(db)
    logger.submit({"ts": "2026-09-26T00:00:00+00:00", "client_ip": "192.0.2.1", "blocked": False})
    logger.close()
    with real_connect() as con:
        assert con.execute("SELECT COUNT(*) c FROM query_log").fetchone()["c"] == 1
    assert logger.write_failures == 1
    assert logger.dropped_rows == 0
    assert logger.uncertain_rows == (1 if mode == "commit" else 0)
    assert not logger.thread.is_alive()


def test_streamed_body_limit_without_content_length():
    from app.admin import BodyLimitMiddleware
    from fastapi import FastAPI, Request
    app = FastAPI()
    @app.post("/api/v1/decision")
    async def route(request: Request):
        await request.body()
        return {}
    app.add_middleware(BodyLimitMiddleware, upload_limit=1000)
    response = TestClient(app).post("/api/v1/decision", content=iter([b"a" * 150000, b"b" * 150000]))
    assert response.status_code == 413


def test_admin_workers_do_not_block_event_loop():
    from app.admin import run_admin
    entered, release = threading.Event(), threading.Event()
    def work():
        entered.set()
        assert release.wait(3)
        return threading.current_thread().name
    async def check():
        task = asyncio.create_task(run_admin(work))
        while not entered.is_set():
            await asyncio.sleep(0.001)
        release.set()
        assert (await task).startswith("admin")
    asyncio.run(check())


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.org/list", "https://user:pass@example.org/list"])
def test_unsafe_source_schemes_and_credentials(url):
    with pytest.raises(ValueError):
        validate_source_url(url)


def test_private_destination_and_redirect_checks(monkeypatch):
    import socket
    import urllib.request
    monkeypatch.delenv("BLOCKLIST_PRIVATE_HOSTS", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))])
    with pytest.raises(ValueError, match="allowlisting"):
        _connect(("evil.example", 80), timeout=1)
    assert not _allowed("evil.example", "::ffff:127.0.0.1")
    monkeypatch.setenv("BLOCKLIST_PRIVATE_HOSTS", "feeds.internal,10.20.0.0/16")
    assert _allowed("feeds.internal", "10.0.0.5")
    assert _allowed("other.internal", "10.20.2.5")
    assert not _allowed("other.internal", "10.21.2.5")
    with pytest.raises(ValueError):
        _RedirectHandler().redirect_request(urllib.request.Request("https://example.org"), None, 302, "", {}, "file:///etc/passwd")


def test_login_rate_limit_is_bounded():
    from app.admin import LoginLimiter
    from fastapi import HTTPException
    limiter = LoginLimiter()
    for _ in range(10): limiter.check("peer")
    with pytest.raises(HTTPException) as error: limiter.check("peer")
    assert error.value.status_code == 429
