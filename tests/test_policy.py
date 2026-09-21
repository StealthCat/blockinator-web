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
