from concurrent.futures import Future
import threading

from app.db import Database
from app.ptr_resolver import PtrResolutionManager
from app.rdns import ReverseDnsResolver, ReverseDnsResult
from test_dev_review import web


def test_flush_requeues_all_states_and_discards_old_results(tmp_path):
    db = Database(str(tmp_path / 'ptr.db'))
    rdns = ReverseDnsResolver()
    updates = []
    manager = PtrResolutionManager(db, rdns, updates.append)
    try:
        with db.connect() as con:
            for n, state in enumerate(('resolved', 'no_ptr', 'retry'), 1):
                con.execute('INSERT INTO client_ptr_status(client_ip,status,next_attempt_at,first_seen_at,last_seen_at) VALUES(?,?,?,0,0)',
                            (f'192.0.2.{n}', state, 9999999999))
            con.execute("INSERT INTO client_identities(client_ip,client_name) VALUES('192.0.2.1','old.home')")
            con.execute("INSERT INTO query_log(client_ip,client_name,blocked,qname) VALUES('192.0.2.1','old.home',0,'example.org')")
            con.execute("INSERT INTO settings(`key`,value) VALUES('ptr_backfill:192.0.2.1','[\"old.home\",0,1]')")
        rdns._cache_put('192.0.2.1', 'old.home')
        rdns._cache_put('192.0.2.2', None)
        future = Future()
        future.set_running_or_notify_cancel()
        manager._futures[future] = '192.0.2.1'
        manager._inflight.add('192.0.2.1')
        assert manager.flush_cache() == 3
        future.set_result(ReverseDnsResult('resolved', hostname='stale.home'))
        manager._collect_done()
        assert updates == [{'192.0.2.1': None}]
        assert not rdns._cache and not manager._inflight
        with db.connect() as con:
            assert con.execute('SELECT COUNT(*) AS c FROM client_identities').fetchone()['c'] == 0
            rows = con.execute('SELECT status,next_attempt_at FROM client_ptr_status').fetchall()
            assert all(row['status'] == 'pending' and row['next_attempt_at'] == 0 for row in rows)
            assert con.execute('SELECT client_name FROM query_log').fetchone()['client_name'] == 'old.home'
            assert con.execute("SELECT COUNT(*) AS c FROM settings WHERE `key` LIKE 'ptr_backfill:%'").fetchone()['c'] == 0
        manager._persist_result('192.0.2.1', ReverseDnsResult('resolved', hostname='fresh.home'))
        assert updates[-1] == {'192.0.2.1': 'fresh.home'}
    finally:
        manager.close()
        rdns.close()


def test_display_lookup_cannot_repopulate_flushed_cache(monkeypatch):
    rdns = ReverseDnsResolver()
    entered, release = threading.Event(), threading.Event()
    def lookup(address):
        entered.set()
        assert release.wait(3)
        return ReverseDnsResult('resolved', hostname='old.home')
    monkeypatch.setattr(rdns, 'lookup', lookup)
    future = rdns._executor.submit(rdns.resolve, '192.0.2.1')
    try:
        assert entered.wait(3)
        rdns.clear_cache()
        release.set()
        assert future.result(timeout=3) is None
        assert not rdns._cache
    finally:
        release.set()
        rdns.close()


def test_flush_route_requires_csrf_and_clears_active_identity(web):
    main, client, session = web
    main.engine.ptr_resolver.close()
    with main.db.connect() as con:
        con.execute("INSERT INTO client_identities(client_ip,client_name) VALUES('192.0.2.5','old.home')")
    main.engine.reload()
    assert main.engine.snapshot.client_identities['192.0.2.5'] == 'old.home'
    response = client.post('/admin/settings/ptr-cache/flush', data={})
    assert response.status_code == 403
    assert '192.0.2.5' in main.engine.snapshot.client_identities
    response = client.post('/admin/settings/ptr-cache/flush', data={'csrf_token': session.csrf_token})
    assert response.status_code == 303
    assert '#runtime' in response.headers['location']
    assert not main.engine.snapshot.client_identities
    client.cookies.clear()
    response = client.post('/admin/settings/ptr-cache/flush', data={'csrf_token': session.csrf_token})
    assert response.status_code == 303 and response.headers['location'] == '/login'
    assert client.get('/admin/settings/ptr-cache/flush').status_code == 405
