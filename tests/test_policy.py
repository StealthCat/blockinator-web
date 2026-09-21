from pathlib import Path
import tempfile

from app.db import Database
from app.policy import PolicyEngine


def setup_engine():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    with db.connect() as con:
        cur = con.execute("INSERT INTO blocklists(name,use_globally) VALUES('global',1)")
        lid = cur.lastrowid
        con.execute("INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)", (lid, "ads.example.com"))
        con.execute("UPDATE blocklists SET entry_count=1 WHERE id=?", (lid,))
    return td, db, PolicyEngine(db)


def test_subdomain_is_blocked():
    td, db, e = setup_engine()
    assert e.decide("192.168.1.2", "x.ads.example.com").block is True
    e.close()
    td.cleanup()


def test_network_pause_and_client_resume():
    td, db, e = setup_engine()
    with db.connect() as con:
        con.execute("INSERT INTO scopes(name,kind,target,state) VALUES('lan','network','192.168.1.0/24','paused')")
        con.execute("INSERT INTO scopes(name,kind,target,state) VALUES('pc','client','192.168.1.20','active')")
    e.reload()
    assert e.decide("192.168.1.10", "ads.example.com").block is False
    assert e.decide("192.168.1.20", "ads.example.com").block is True
    e.close()
    td.cleanup()


def test_client_pause_overrides_active_network():
    td, db, e = setup_engine()
    with db.connect() as con:
        con.execute("INSERT INTO scopes(name,kind,target,state) VALUES('lan','network','10.0.0.0/8','active')")
        con.execute("INSERT INTO scopes(name,kind,target,state) VALUES('pc','client','10.1.2.3','paused')")
    e.reload()
    assert e.decide("10.1.2.3", "ads.example.com").block is False
    e.close()
    td.cleanup()


def test_decide_and_log_checks_every_question():
    td, db, e = setup_engine()
    request = {
        "client": {"ip": "192.168.1.2", "port": 53000},
        "protocol": "Udp",
        "dns": {
            "questions": [
                {"name": "ok.example.com", "type": "A", "class": "IN"},
                {"name": "ads.example.com", "type": "AAAA", "class": "IN"},
            ]
        },
    }
    d = e.decide_and_log(request)
    assert d.block is True
    assert d.matched_domain == "ads.example.com"
    e.close()
    td.cleanup()


def test_scoped_list_assignment_can_move_between_network_and_client():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    with db.connect() as con:
        list_id = con.execute(
            "INSERT INTO blocklists(name,use_globally) VALUES('scoped',0)"
        ).lastrowid
        con.execute(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            (list_id, "scoped.example.com"),
        )
        con.execute(
            "UPDATE blocklists SET entry_count=1 WHERE id=?",
            (list_id,),
        )
        network_id = con.execute(
            "INSERT INTO scopes(name,kind,target,state) VALUES('lan','network','10.0.0.0/8','active')"
        ).lastrowid
        client_id = con.execute(
            "INSERT INTO scopes(name,kind,target,state) VALUES('pc','client','192.168.1.20','active')"
        ).lastrowid
        con.execute(
            "INSERT INTO scope_blocklists(scope_id,blocklist_id) VALUES(?,?)",
            (network_id, list_id),
        )

    e = PolicyEngine(db)
    assert e.decide("10.1.2.3", "scoped.example.com").block is True
    assert e.decide("192.168.1.20", "scoped.example.com").block is False

    with db.connect() as con:
        con.execute("DELETE FROM scope_blocklists WHERE blocklist_id=?", (list_id,))
        con.execute(
            "INSERT INTO scope_blocklists(scope_id,blocklist_id) VALUES(?,?)",
            (client_id, list_id),
        )
    e.reload()

    assert e.decide("10.1.2.3", "scoped.example.com").block is False
    assert e.decide("192.168.1.20", "scoped.example.com").block is True
    e.close()
    td.cleanup()


def test_scope_edit_changes_target_and_blocklist_assignment():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    with db.connect() as con:
        list_a = con.execute(
            "INSERT INTO blocklists(name,use_globally) VALUES('a',0)"
        ).lastrowid
        list_b = con.execute(
            "INSERT INTO blocklists(name,use_globally) VALUES('b',0)"
        ).lastrowid
        con.execute(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            (list_a, "a.example.com"),
        )
        con.execute(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            (list_b, "b.example.com"),
        )
        con.execute("UPDATE blocklists SET entry_count=1 WHERE id IN (?,?)", (list_a, list_b))
        scope_id = con.execute(
            "INSERT INTO scopes(name,kind,target,state) VALUES('lan','network','10.0.0.0/8','active')"
        ).lastrowid
        con.execute(
            "INSERT INTO scope_blocklists(scope_id,blocklist_id) VALUES(?,?)",
            (scope_id, list_a),
        )

    e = PolicyEngine(db)
    assert e.decide("10.1.2.3", "a.example.com").block is True
    assert e.decide("10.1.2.3", "b.example.com").block is False

    with db.connect() as con:
        con.execute(
            "UPDATE scopes SET name='host',kind='client',target='192.168.50.20' WHERE id=?",
            (scope_id,),
        )
        con.execute("DELETE FROM scope_blocklists WHERE scope_id=?", (scope_id,))
        con.execute(
            "INSERT INTO scope_blocklists(scope_id,blocklist_id) VALUES(?,?)",
            (scope_id, list_b),
        )
    e.reload()

    assert e.decide("10.1.2.3", "a.example.com").block is False
    assert e.decide("192.168.50.20", "a.example.com").block is False
    assert e.decide("192.168.50.20", "b.example.com").block is True
    e.close()
    td.cleanup()


def test_manual_list_single_domain_add_and_remove():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    with db.connect() as con:
        list_id = con.execute(
            "INSERT INTO blocklists(name,source_type,use_globally) VALUES('manual','manual',1)"
        ).lastrowid
        con.execute(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            (list_id, "keep.example.com"),
        )
        con.execute(
            "UPDATE blocklists SET entry_count=1 WHERE id=?",
            (list_id,),
        )

    e = PolicyEngine(db)
    assert e.decide("192.168.1.10", "keep.example.com").block is True
    assert e.decide("192.168.1.10", "new.example.com").block is False

    with db.connect() as con:
        con.execute(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            (list_id, "new.example.com"),
        )
        con.execute(
            "UPDATE blocklists SET entry_count=2 WHERE id=?",
            (list_id,),
        )
    e.reload()

    assert e.decide("192.168.1.10", "new.example.com").block is True
    assert e.decide("192.168.1.10", "x.new.example.com").block is True

    with db.connect() as con:
        con.execute(
            "DELETE FROM block_entries WHERE blocklist_id=? AND domain=?",
            (list_id, "new.example.com"),
        )
        con.execute(
            "UPDATE blocklists SET entry_count=1 WHERE id=?",
            (list_id,),
        )
    e.reload()

    assert e.decide("192.168.1.10", "new.example.com").block is False
    assert e.decide("192.168.1.10", "keep.example.com").block is True
    e.close()
    td.cleanup()
