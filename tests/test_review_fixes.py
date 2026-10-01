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


def test_query_paging_filters_and_snapshot(web, browser):
    import html
    import re
    from urllib.parse import parse_qs, urlsplit

    client, _ = browser
    with web.db.connect() as con:
        con.execute("DELETE FROM query_log")
        for i in range(63):
            con.execute("INSERT INTO query_log(ts,client_ip,qname,qtype,blocked,server_id,matched_scope) VALUES(?,?,?,?,?,?,?)",
                        ("2026-09-27T18:00:00+00:00", "192.0.2.1", f"page-{i}.example", "A", 1, "paging-server", "Paging scope"))
    response = client.get("/queries", params={"q": "page-", "server": "paging-server", "target": "Paging scope", "decision": "blocked", "limit": 25, "refresh": 5})
    assert response.status_code == 200
    assert "Showing 1–25 of 63" in response.text
    assert 'data-query-snapshot="0"' in response.text
    first_ids = re.findall(r'data-query-row="(\d+)"', response.text)
    next_url = html.unescape(re.search(r'href="([^"]+)">Next</a>', response.text)[1])
    query = parse_qs(urlsplit(next_url).query)
    assert query["target"] == ["Paging scope"]
    assert query["refresh"] == ["5"]
    with web.db.connect() as con:
        con.execute("INSERT INTO query_log(ts,client_ip,qname,qtype,blocked,server_id,matched_scope) VALUES(?,?,?,?,?,?,?)",
                    ("2026-09-27T18:00:01+00:00", "192.0.2.1", "page-new.example", "A", 1, "paging-server", "Paging scope"))
    second = client.get(next_url)
    assert 'data-query-snapshot="1"' in second.text
    assert "Showing 26–50 of 63" in second.text
    assert not set(first_ids) & set(re.findall(r'data-query-row="(\d+)"', second.text))
    assert "page-new.example" not in second.text
    last = client.get("/queries", params={"q": "page-", "limit": 30, "page": 999})
    assert "Showing 61–64 of 64" in last.text
    assert "Page 3 of 3" in last.text
    assert 'name="limit" min="25" max="500" step="1" value="30"' in last.text
    fragment = client.get(next_url.replace("/queries?", "/queries/rows?"))
    assert "Showing 26–50 of 63" in fragment.text
    assert 'class="query-pagination"' in fragment.text
    empty = client.get("/queries?q=definitely-no-matches")
    assert "Showing 0–0 of 0" in empty.text
    assert '>Next</a>' not in empty.text
    assert '>Previous</a>' not in empty.text


def test_query_date_range(web, browser, monkeypatch):
    client, _ = browser
    monkeypatch.setattr(web, "system_default_timezone", lambda: "America/New_York")
    with web.db.connect() as con:
        con.execute("DELETE FROM query_log")
        for stamp, name in (("2026-09-27T17:59:59.999999+00:00", "before.example"),
                            ("2026-09-27T18:00:00+00:00", "start.example"),
                            ("2026-09-27T18:00:00.999999+00:00", "end.example"),
                            ("2026-09-27T18:00:01+00:00", "after.example")):
            con.execute("INSERT INTO query_log(ts,client_ip,qname,qtype,blocked) VALUES(?,?,?,?,?)",
                        (stamp, "192.0.2.1", name, "A", 1))
    bounds = {"start": "2026-09-27T14:00:00", "end": "2026-09-27T14:00:00"}
    for path in ("/queries", "/queries/rows"):
        response = client.get(path, params=bounds)
        assert response.status_code == 200
        assert "start.example" in response.text and "end.example" in response.text
        assert "before.example" not in response.text and "after.example" not in response.text
        assert "Showing 1–2 of 2" in response.text
    assert "Showing 1–3 of 3" in client.get("/queries", params={"start": bounds["start"]}).text
    assert "Showing 1–3 of 3" in client.get("/queries", params={"end": bounds["end"]}).text
    for params in ({"start": "nonsense"}, {"start": "2026-03-08T02:30"},
                   {"start": "2026-09-27T14:01", "end": bounds["end"]}):
        assert client.get("/queries", params=params).status_code == 400
    for params in ({"page": 0}, {"page": "bad"}, {"snapshot": -1}):
        assert client.get("/queries", params=params).status_code == 422


def test_endpoint_whitelist_create_edit_and_type_change(web, browser):
    client, session = browser
    form = {'csrf_token': session.csrf_token, 'name': 'Trusted endpoint',
            'kind': 'client', 'target': '198.51.100.42', 'state': 'active', 'whitelisted': '1'}
    response = client.post('/admin/scopes', data=form)
    assert response.status_code == 303 and 'error=' not in response.headers['location']
    with web.db.connect() as con:
        row = con.execute("SELECT * FROM scopes WHERE name='Trusted endpoint'").fetchone()
    sid = row['id']
    assert row['whitelisted'] == 1
    assert web.engine.decide(form['target'], 'example.org').reason == 'endpoint_whitelisted'
    page = client.get('/scopes')
    assert page.status_code == 200
    assert 'Whitelisted</span>' in page.text
    assert 'name="whitelisted" value="1" checked' in page.text
    form.pop('whitelisted')
    assert client.post(f'/admin/scopes/{sid}/edit', data=form).status_code == 303
    assert web.engine.decide(form['target'], 'example.org').reason != 'endpoint_whitelisted'
    form.update(whitelisted='1')
    client.post(f'/admin/scopes/{sid}/edit', data=form)
    assert web.engine.decide(form['target'], 'example.org').reason == 'endpoint_whitelisted'
    form.update(kind='network', target_v4='198.51.100.0/24')
    client.post(f'/admin/scopes/{sid}/edit', data=form)
    with web.db.connect() as con:
        assert con.execute('SELECT whitelisted FROM scopes WHERE id=?', (sid,)).fetchone()['whitelisted'] == 1
    assert web.engine.decide('198.51.100.43', 'example.org').reason == 'scope_whitelisted'
    client.post(f'/admin/scopes/{sid}/delete', data={'csrf_token': session.csrf_token})
    assert web.engine.decide('198.51.100.42', 'example.org').reason != 'endpoint_whitelisted'


@pytest.mark.parametrize('kind,target', [('network', '192.0.2.0/24'), ('hostname', '*.trusted.home.arpa')])
def test_whitelist_target_forms_preserve_assignments_and_log_filter(web, browser, kind, target):
    client, session = browser
    with web.db.connect() as con:
        lid = con.execute("INSERT INTO blocklists(name,use_globally) VALUES('Preserved assignment',0)").lastrowid
    form = dict(csrf_token=session.csrf_token, name='Exempt ' + kind, kind=kind,
                target=target, target_v4=target if kind == 'network' else '',
                whitelisted='1', blocklist_id=str(lid))
    result = client.post('/admin/scopes', data=form)
    assert 'error=' not in result.headers['location']
    with web.db.connect() as con:
        sid = con.execute('SELECT id FROM scopes WHERE name=?', (form['name'],)).fetchone()['id']
    page = client.get('/scopes').text
    assert 'data-scope-list-assignments hidden' in page
    client.post(f'/admin/scopes/{sid}/edit', data=form)
    form.pop('whitelisted')
    client.post(f'/admin/scopes/{sid}/edit', data=form)
    with web.db.connect() as con:
        assert con.execute('SELECT blocklist_id FROM scope_blocklists WHERE scope_id=?', (sid,)).fetchone()['blocklist_id'] == lid
        con.execute("INSERT INTO query_log(ts,client_ip,qname,blocked,reason,matched_scope) VALUES(?,?,?,?,?,?)",
                    ('2026-10-01T18:00:00+00:00', '192.0.2.10', 'target-whitelist-test.example', 0, 'scope_whitelisted', form['name']))
    assert 'target-whitelist-test.example' in client.get('/queries?decision=whitelisted').text
    assert 'target-whitelist-test.example' not in client.get('/queries?decision=allowed').text
    client.post(f'/admin/scopes/{sid}/delete', data={'csrf_token': session.csrf_token})
