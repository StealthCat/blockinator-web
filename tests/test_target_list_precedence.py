from datetime import datetime, timezone

import pytest

from app.db import Database
from app.policy import PolicyEngine
from app.inspector import inspect_policy


@pytest.mark.parametrize('address,network', [('192.0.2.5','192.0.2.0/24'), ('2001:db8::5','2001:db8::/64')])
@pytest.mark.parametrize('host_target', ['pc.home.arpa','*.home.arpa'])
def test_scoped_lists_follow_winning_target(tmp_path, address, network, host_target):
    db = Database(str(tmp_path / 'policy.db'))
    with db.connect() as con:
        network_id = con.execute("INSERT INTO scopes(name,kind,target) VALUES('network','network',?)",(network,)).lastrowid
        host_id = con.execute("INSERT INTO scopes(name,kind,target) VALUES('host','hostname',?)",(host_target,)).lastrowid
        con.execute('INSERT INTO client_identities(client_ip,client_name) VALUES(?,?)',(address,'pc.home.arpa'))
        ids = {}
        for name, global_flag, kind, domain in [('network-block',0,'block','network.example'),('network-allow',0,'whitelist','host.example'),('host-block',0,'block','host.example'),('global-block',1,'block','global.example')]:
            ids[name] = con.execute('INSERT INTO blocklists(name,use_globally,list_type) VALUES(?,?,?)',(name,global_flag,kind)).lastrowid
            con.execute('INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)',(ids[name],domain))
        con.executemany('INSERT INTO scope_blocklists(scope_id,blocklist_id) VALUES(?,?)',[(network_id,ids['network-block']),(network_id,ids['network-allow'])])
    engine = PolicyEngine(db)
    now = datetime(2026,9,28,12,tzinfo=timezone.utc)
    try:
        # A deliberately empty hostname target overrides the network's lists.
        result = engine.decide(address,'network.example',now)
        assert not result.block and result.matched_scope == 'host'
        assert engine.decide(address,'global.example',now).block
        assert [item['name'] for item in inspect_policy(engine,address,'network.example','A',now)['lists']] == ['global-block']
        with db.connect() as con:
            con.execute('INSERT INTO scope_blocklists(scope_id,blocklist_id) VALUES(?,?)',(host_id,ids['host-block']))
        engine.reload_scopes()
        # A less-specific domain whitelist must not leak into the winning policy.
        assert engine.decide(address,'host.example',now).block
        with db.connect() as con:
            con.execute("UPDATE scopes SET schedule_enabled=1,schedule_days='0',schedule_start='13:00',schedule_end='14:00',schedule_timezone='UTC' WHERE id=?",(host_id,))
        engine.reload_scopes()
        assert engine.decide(address,'network.example',now).block
        with db.connect() as con:
            con.execute('UPDATE scopes SET schedule_enabled=0 WHERE id=?',(host_id,))
            endpoint = con.execute("INSERT INTO scopes(name,kind,target) VALUES('endpoint','client',?)",(address,)).lastrowid
        engine.reload_scopes()
        result = engine.decide(address,'host.example',now)
        assert not result.block and result.matched_scope == 'endpoint'
        # Explicit global lists still apply until a whitelist target bypasses them.
        assert engine.decide(address,'global.example',now).block
        with db.connect() as con:
            con.execute('UPDATE scopes SET whitelisted=1 WHERE id=?',(network_id,))
        engine.reload_scopes()
        assert not engine.decide(address,'global.example',now).block
    finally:
        engine.close()
