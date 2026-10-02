"""Regression coverage for 1.20 reliability and console changes."""
import asyncio
import importlib
import os
import re
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from app.auth import AuthManager, SESSION_COOKIE
from app.db import Database
from app.inspector import inspect_policy, next_transition
from app.policy import PolicyEngine, QueryLogger, _compile_schedule, _prune_query_logs
from app.query_cache import query_counts, query_choices
from app.rdns import ReverseDnsResult
from app.refresher import BlocklistRefresher
from app.rollups import retained_totals
from app.statistics import StatisticsCache, build_statistics_snapshot


@pytest.fixture
def web(tmp_path, monkeypatch):
    # Keep the import-time app separate; restore it after each isolated test so
    # the existing web suite can continue using its own bootstrap fixture.
    with patch.dict(os.environ, DATA_DIR=str(tmp_path / 'bootstrap'), DATABASE_BACKEND='sqlite',
                    ADMIN_PASSWORD='review-test-password', POLICY_API_KEY='review-policy-key-long-enough'):
        main = importlib.import_module('app.main')
        db = Database(str(tmp_path / 'test.db'))
        auth = AuthManager(db)
    engine = PolicyEngine(db)
    monkeypatch.setattr(main, 'db', db)
    monkeypatch.setattr(main, 'auth', auth)
    monkeypatch.setattr(main, 'engine', engine)
    monkeypatch.setattr(main, 'statistics_cache', StatisticsCache(db))
    monkeypatch.setattr(main, 'refresher', BlocklistRefresher(db, engine))
    # The installed timing middleware refers to the import-time engine; these
    # tests exercise decisions without relying on its logger.
    query_counts.entries.clear()
    query_choices.entries.clear()
    session = auth.create_session(*auth.authenticate('admin', 'review-test-password'))
    client = TestClient(main.app, follow_redirects=False)
    client.cookies.set(SESSION_COOKIE, session.token)
    yield main, client, session
    client.close()
    engine.close()
    auth.close()


def wait_for(predicate):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.02)
    assert predicate()


def test_failed_rebuild_recovers_without_another_source_change(tmp_path, monkeypatch):
    db = Database(str(tmp_path / 'policy.db'))
    with db.connect() as con:
        lid = con.execute("INSERT INTO blocklists(name,source_type,source_url,format) VALUES('remote','url','https://example.org/list','domains')").lastrowid
        db.replace_list_domains(con, lid, {'old.example'})
    engine = PolicyEngine(db)
    refresher = BlocklistRefresher(db, engine, fetcher=lambda _: 'new.example\n')
    original = db.connect
    failures = [0]
    @contextmanager
    def flaky_connect():
        # Fail the snapshot load, after source membership has committed.
        if threading.current_thread().name == 'MainThread' and failures[0] == 0:
            failures[0] += 1
            raise RuntimeError('temporary database failure')
        with original() as con:
            yield con
    real_reload = engine.reload_lists
    def fail_snapshot_once():
        with patch.object(db, 'connect', flaky_connect):
            return real_reload()
    monkeypatch.setattr(engine, 'reload_lists', fail_snapshot_once)
    try:
        result = refresher.refresh_list(lid)
        assert result.error
        wait_for(lambda: engine.decide('192.0.2.1', 'new.example').block)
        assert not engine.decide('192.0.2.1', 'old.example').block
        assert engine.last_reload_error is None
        assert refresher.refresh_list(lid).changed is False
    finally:
        engine.close()


@pytest.mark.parametrize('start', ['09:00:30', '09:00:00', '09:00+00:00', '24:00'])
def test_schedule_offsets_and_seconds_rejected(web, start):
    main, client, session = web
    result = client.post('/admin/scopes', data={'csrf_token': session.csrf_token,
        'name': 'invalid', 'kind': 'client', 'target': '192.0.2.1',
        'schedule_enabled': '1', 'schedule_day': '4', 'schedule_start': start, 'schedule_end': '17:00'})
    assert result.status_code == 303 and 'error=' in result.headers['location']
    with main.db.connect() as con:
        assert con.execute('SELECT COUNT(*) AS c FROM scopes').fetchone()['c'] == 0
    malformed = _compile_schedule(True, frozenset(range(7)), start, '17:00', 'UTC')
    assert not malformed.is_active(datetime(2026, 10, 2, 12, tzinfo=timezone.utc))


def test_large_paste_and_many_assignments(web):
    main, client, session = web
    with main.db.connect() as con:
        con.executemany("INSERT INTO scopes(name,kind,target) VALUES(?,'client',?)",
                        [(f'Target {i}', f'192.0.2.{i}') for i in range(1, 151)])
        ids = [row['id'] for row in con.execute('SELECT id FROM scopes')]
    fields = [('csrf_token', (None, session.csrf_token)), ('name', (None, 'large-paste')),
              ('format', (None, 'domains')), ('text', (None, 'example.org\n' * 96000))]
    fields.extend(('scope_id', (None, str(i))) for i in ids)
    response = client.post('/admin/lists', files=fields)
    assert response.status_code == 303 and 'error=' not in response.headers['location']
    with main.db.connect() as con:
        assert con.execute('SELECT COUNT(*) AS c FROM scope_blocklists').fetchone()['c'] == 150


def test_retention_runs_idle_in_bounded_batches(tmp_path):
    db = Database(str(tmp_path / 'idle.db'))
    db.set_setting('max_query_log_age_days', '1')
    with db.connect() as con:
        con.executemany("INSERT INTO query_log(ts,client_ip,blocked) VALUES('2000-01-01T00:00:00+00:00','192.0.2.1',0)", [()] * 2101)
        assert _prune_query_logs(con, 0, 1) == (1000, 0)
    logger = QueryLogger(db)
    try:
        logger._last_prune = time.monotonic() - 61
        def remaining():
            with db.connect() as con:
                return con.execute('SELECT COUNT(*) AS c FROM query_log').fetchone()['c']
        wait_for(lambda: remaining() == 0)
    finally:
        logger.close()


def test_rollups_match_retained_rows_after_updates_rollback_and_pruning(tmp_path):
    db = Database(str(tmp_path / 'rollup.db'))
    with db.connect() as con:
        for i in range(20):
            con.execute('INSERT INTO query_log(ts,client_ip,blocked,response_time_ms) VALUES(?,?,?,?)',
                        (f'2026-10-02T12:{i:02}:00+00:00', '192.0.2.1', i % 2, float(i) if i % 3 else None))
        con.execute("UPDATE query_log SET ts='2026-10-02T13:00:00+00:00',blocked=1,response_time_ms=3.5 WHERE id=1")
        con.execute('BEGIN')
        con.execute('DELETE FROM query_log WHERE id>3')
        con.execute('ROLLBACK')
        _prune_query_logs(con, 12, 0)
        direct = dict(con.execute('SELECT COUNT(*) AS queries,SUM(blocked) AS blocks,AVG(response_time_ms) AS average_response_time_ms FROM query_log').fetchone())
        assert retained_totals(con) == direct
        assert con.execute("SELECT COUNT(*) AS c FROM query_statistics WHERE queries=0 AND bucket<>'__total__'").fetchone()['c'] == 0
    # Reopening must not double the rollups.
    reopened = Database(db.path)
    with reopened.connect() as con:
        assert retained_totals(con) == direct
    snapshot = build_statistics_snapshot(reopened, now_utc=datetime(2026, 10, 2, 13, tzinfo=timezone.utc))
    assert snapshot['totals'] == direct


def test_console_saturation_does_not_block_policy(web, monkeypatch):
    main, _, session = web
    gate = threading.Event()
    entered = [0]
    lock = threading.Lock()
    def slow(*args, **kwargs):
        with lock:
            entered[0] += 1
        gate.wait(5)
        return {'ok': True}
    monkeypatch.setattr(main.statistics_cache, 'snapshot', slow)
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url='http://testserver',
                                     cookies={SESSION_COOKIE: session.token}) as client:
            tasks = [asyncio.create_task(client.get('/api/v1/statistics')) for _ in range(40)]
            try:
                for _ in range(200):
                    if entered[0] >= 4:
                        break
                    await asyncio.sleep(.01)
                response = await asyncio.wait_for(client.post('/api/v1/decision',
                    headers={'X-API-Key': 'review-policy-key-long-enough'},
                    json={'client': {'ip': '192.0.2.1'}, 'dns': {'questions': [{'name': 'example.org'}]}}), timeout=1)
                assert response.status_code == 200
            finally:
                gate.set()
                results = await asyncio.gather(*tasks)
            assert any(r.status_code == 503 for r in results)
            assert all(r.status_code in (200, 503) for r in results)
    asyncio.run(exercise())


def test_target_pagination_dedicated_editor_and_inspector_do_not_log(web):
    main, client, session = web
    with main.db.connect() as con:
        con.executemany("INSERT INTO scopes(name,kind,target,whitelisted) VALUES(?,'client',?,1)",
                        [(f'Target {i:03}', f'192.0.2.{i}') for i in range(1, 31)])
    main.engine.reload_scopes()
    page = client.get('/scopes').text
    assert page.count('class="scope-card editable-scope-card"') == 25
    assert 'class="scope-editor"' not in page
    assert 'Whitelisted now' in page
    page2 = client.get('/scopes?page=2').text
    assert page2.count('class="scope-card editable-scope-card"') == 5
    filtered = client.get('/scopes?q=Target+030').text
    assert filtered.count('class="scope-card editable-scope-card"') == 1
    editor = client.get('/scopes/30/edit').text
    assert editor.count('class="scope-editor"') == 1
    assert 'name="whitelisted" value="1" checked' in editor
    preview = client.get('/policy-test?client=192.0.2.30&domain=ads.example&record_type=A').text
    assert 'endpoint_whitelisted' in preview
    with main.db.connect() as con:
        assert con.execute('SELECT COUNT(*) AS c FROM query_log').fetchone()['c'] == 0
    assert main.engine.ptr_resolver.status_snapshot()['queued'] == 0


def test_cursor_pagination_and_literal_search(web, monkeypatch):
    import html
    main, client, _ = web
    with main.db.connect() as con:
        con.executemany("INSERT INTO query_log(client_ip,qname,blocked) VALUES('192.0.2.1',?,0)",
                        [(f'page-{i}.example',) for i in range(60)])
        con.execute("INSERT INTO query_log(client_ip,qname,blocked) VALUES('192.0.2.1','_sip.example',0)")
    first = client.get('/queries?q=page-&match=prefix&limit=25').text
    link = html.unescape(re.search(r'href="([^"]+)">Next</a>', first)[1])
    assert 'before=' in link
    statements = []
    original = main.db.connect
    @contextmanager
    def traced():
        with original() as con:
            con.set_trace_callback(statements.append)
            yield con
    monkeypatch.setattr(main.db, 'connect', traced)
    second = client.get(link).text
    assert not set(re.findall(r'data-query-row="(\d+)"', first)) & set(re.findall(r'data-query-row="(\d+)"', second))
    assert not any('SELECT * FROM query_log' in sql and 'OFFSET' in sql for sql in statements)
    previous = html.unescape(re.search(r'href="([^"]+)">Previous</a>', second)[1])
    assert 'after=' in previous
    assert re.findall(r'data-query-row="(\d+)"', client.get(previous).text) == re.findall(r'data-query-row="(\d+)"', first)
    literal = client.get('/queries?q=_&match=prefix').text
    assert '_sip.example' in literal and 'page-1.example' not in literal
    exact = client.get('/queries?q=page-1.example&match=exact').text
    assert len(re.findall(r'data-query-row="(\d+)"', exact)) == 1


def test_query_actions_and_health_alerts(web):
    main, client, session = web
    with main.db.connect() as con:
        lid = con.execute("INSERT INTO blocklists(name,list_type,use_globally) VALUES('allow','whitelist',1)").lastrowid
        sid = con.execute("INSERT INTO scopes(name,kind,target) VALUES('Office','client','192.0.2.1')").lastrowid
        qid = con.execute("INSERT INTO query_log(client_ip,qname,blocked,matched_scope,matched_list) VALUES('192.0.2.1','ads.example',1,'Office','allow')").lastrowid
    assert client.get(f'/queries/{qid}/target').headers['location'] == f'/scopes/{sid}/edit'
    assert client.get(f'/queries/{qid}/list').headers['location'] == f'/whitelists/{lid}/edit'
    assert 'Whitelist · allow' in client.get(f'/queries/{qid}/actions').text
    result = client.post('/admin/query-domain', data={'csrf_token': session.csrf_token, 'domain': 'ads.example', 'list_id': str(lid)})
    assert 'error=' not in result.headers['location']
    assert main.engine.decide('192.0.2.1', 'ads.example').reason == 'whitelist_match'
    main.engine.logger.dropped_rows = 12
    assert '12 log rows have been dropped' in client.get('/').text


def test_next_schedule_transition_handles_dst_and_overnight():
    schedule = _compile_schedule(True, frozenset({0}), '22:00', '06:00', 'UTC')
    assert next_transition(schedule, datetime(2026, 9, 29, 2, tzinfo=timezone.utc)) == datetime(2026, 9, 29, 6, tzinfo=timezone.utc)
    spring = _compile_schedule(True, frozenset({6}), '02:30', '04:00', 'America/New_York')
    assert next_transition(spring, datetime(2026, 3, 8, 6, tzinfo=timezone.utc)) == datetime(2026, 3, 8, 7, tzinfo=timezone.utc)


def test_ptr_history_cursor_is_durable_and_name_backfills_are_bounded(tmp_path):
    from app.ptr_resolver import PtrResolutionManager
    db = Database(str(tmp_path / 'ptr.db'))
    class Resolver:
        nameservers = []
        def lookup(self, address):
            return ReverseDnsResult('resolved', hostname='pc.home.arpa')
    manager = PtrResolutionManager(db, Resolver())
    with db.connect() as con:
        con.executemany("INSERT INTO query_log(client_ip,qname,blocked) VALUES('192.0.2.1','example.org',0)", [()] * 1100)
    manager._run_backfill_if_due()
    assert db.get_setting('ptr_log_cursor') == '512'
    manager._persist_result('192.0.2.1', ReverseDnsResult('resolved', hostname='pc.home.arpa'))
    with db.connect() as con:
        assert con.execute('SELECT COUNT(*) AS c FROM query_log WHERE client_name IS NOT NULL').fetchone()['c'] == 128
    assert db.get_setting('ptr_backfill:192.0.2.1')
    manager.close()
    restarted = PtrResolutionManager(db, Resolver())
    try:
        restarted._run_backfill_if_due()
        assert db.get_setting('ptr_log_cursor') == '1024'
        for _ in range(10):
            restarted._backfill_known_names()
        assert not db.get_setting('ptr_backfill:192.0.2.1')
        with db.connect() as con:
            assert con.execute('SELECT COUNT(*) AS c FROM query_log WHERE client_name IS NULL').fetchone()['c'] == 0
    finally:
        restarted.close()


def test_rollups_backfill_existing_install_once(tmp_path):
    import sqlite3
    path = str(tmp_path / 'upgrade.db')
    db = Database(path)
    with db.connect() as con:
        for event in ('insert', 'update', 'delete'):
            con.execute('DROP TRIGGER query_statistics_' + event)
        con.execute('DROP TABLE query_statistics')
        con.execute("DELETE FROM settings WHERE `key`='statistics_rollups_v1'")
        con.executemany("INSERT INTO query_log(ts,client_ip,blocked,response_time_ms) VALUES('2026-10-02T12:00:00+00:00','192.0.2.1',1,2.5)", [()] * 37)
    upgraded = Database(path)
    with upgraded.connect() as con:
        assert retained_totals(con) == {'queries': 37, 'blocks': 37, 'average_response_time_ms': 2.5}
        con.execute('DELETE FROM query_log')
        assert retained_totals(con)['queries'] == 0
