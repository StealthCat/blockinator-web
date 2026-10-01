from datetime import datetime, timezone

import pytest

from app.db import Database
from app.policy import PolicyEngine


@pytest.mark.parametrize('address,network,other', [
    ('192.0.2.10', '192.0.2.0/24', '192.0.2.11'),
    ('2001:db8::10', '2001:db8::/64', '2001:db8::11'),
])
def test_endpoint_whitelist_bypasses_lists_and_reloads(tmp_path, address, network, other):
    db = Database(str(tmp_path / 'policy.db'))
    with db.connect() as con:
        for name, globally in [('global', 1), ('network', 0), ('endpoint', 0)]:
            lid = con.execute('INSERT INTO blocklists(name,use_globally) VALUES(?,?)', (name, globally)).lastrowid
            con.execute('INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)', (lid, name + '.example'))
        nid = con.execute("INSERT INTO scopes(name,kind,target) VALUES('LAN','network',?)", (network,)).lastrowid
        eid = con.execute("INSERT INTO scopes(name,kind,target,whitelisted) VALUES('Trusted','client',?,1)", (address,)).lastrowid
        con.execute("INSERT INTO scope_blocklists SELECT ?,id FROM blocklists WHERE name='network'", (nid,))
        con.execute("INSERT INTO scope_blocklists SELECT ?,id FROM blocklists WHERE name='endpoint'", (eid,))
    db.set_setting('unmatched_scope_action', 'deny')
    engine = PolicyEngine(db)
    try:
        for domain in ['global.example', 'network.example', 'endpoint.example', 'unlisted.example']:
            decision = engine.decide(address, domain)
            assert not decision.block
            assert decision.reason == 'endpoint_whitelisted'
            assert decision.matched_scope == 'Trusted'
        assert engine.decide(other, 'global.example').block
        assert engine.decide(other, 'network.example').block
        decision, row = engine.decide_with_log_row({'client': {'ip': address}, 'dns': {'questions': [{'name': 'global.example', 'type': 'A'}]}})
        assert row['reason'] == 'endpoint_whitelisted'
        assert row['matched_scope'] == 'Trusted'
        assert row['blocked'] is False
        with db.connect() as con:
            con.execute('UPDATE scopes SET whitelisted=0 WHERE id=?', (eid,))
        engine.reload_scopes()
        assert engine.decide(address, 'endpoint.example').block
        with db.connect() as con:
            con.execute('UPDATE scopes SET whitelisted=1 WHERE id=?', (eid,))
        engine.reload_scopes()
        assert engine.decide(address, 'endpoint.example').reason == 'endpoint_whitelisted'
    finally:
        engine.close()


def test_endpoint_whitelist_schedule_and_pause(tmp_path):
    db = Database(str(tmp_path / 'policy.db'))
    db.set_setting('unmatched_scope_action', 'deny')
    with db.connect() as con:
        con.execute("""INSERT INTO scopes(name,kind,target,whitelisted,schedule_enabled,
            schedule_days,schedule_start,schedule_end) VALUES('Scheduled','client','192.0.2.10',1,1,'0','09:00','17:00')""")
    engine = PolicyEngine(db)
    inside = datetime(2026, 9, 28, 12, tzinfo=timezone.utc)
    outside = datetime(2026, 9, 28, 18, tzinfo=timezone.utc)
    try:
        assert engine.decide('192.0.2.10', 'example.org', inside).reason == 'endpoint_whitelisted'
        assert engine.decide('192.0.2.10', 'example.org', outside).reason == 'no_scope_default_deny'
        with db.connect() as con:
            con.execute("UPDATE scopes SET state='paused'")
        engine.reload_scopes()
        assert not engine.decide('192.0.2.10', 'example.org', inside).block
        db.set_setting('global_blocking', '0')
        engine.reload()
        assert engine.decide('192.0.2.10', 'example.org', inside).reason == 'global_paused'
    finally:
        engine.close()


def test_whitelist_upgrade_preserves_existing_scopes(tmp_path):
    path = str(tmp_path / 'upgrade.db')
    db = Database(path)
    with db.connect() as con:
        con.execute('ALTER TABLE scopes DROP COLUMN whitelisted')
        con.execute("INSERT INTO scopes(name,kind,target) VALUES('Existing','client','192.0.2.10')")
    db.initialize()
    with db.connect() as con:
        assert con.execute('SELECT whitelisted FROM scopes').fetchone()['whitelisted'] == 0
        con.execute('UPDATE scopes SET whitelisted=1')
    db.initialize()
    with db.connect() as con:
        assert con.execute('SELECT whitelisted FROM scopes').fetchone()['whitelisted'] == 1
