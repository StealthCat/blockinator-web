from datetime import datetime, timezone
from pathlib import Path
import tempfile

from app.db import Database
from app.policy import PolicyEngine, _prune_query_logs


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


def test_scheduled_list_enforces_only_inside_window():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    with db.connect() as con:
        list_id = con.execute(
            """
            INSERT INTO blocklists(
                name,use_globally,schedule_enabled,schedule_days,
                schedule_start,schedule_end,schedule_timezone
            ) VALUES('scheduled',1,1,'0','12:00','14:00','UTC')
            """
        ).lastrowid
        con.execute(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            (list_id, "scheduled.example.com"),
        )
        con.execute(
            "UPDATE blocklists SET entry_count=1 WHERE id=?",
            (list_id,),
        )

    e = PolicyEngine(db)
    monday_inside = datetime(2026, 9, 21, 13, 0, tzinfo=timezone.utc)
    monday_after = datetime(2026, 9, 21, 15, 0, tzinfo=timezone.utc)
    tuesday_same_time = datetime(2026, 9, 22, 13, 0, tzinfo=timezone.utc)

    assert e.decide("192.168.1.10", "scheduled.example.com", monday_inside).block is True
    assert e.decide("192.168.1.10", "scheduled.example.com", monday_after).block is False
    assert e.decide("192.168.1.10", "scheduled.example.com", tuesday_same_time).block is False
    e.close()
    td.cleanup()


def test_overnight_schedule_continues_into_following_morning():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    with db.connect() as con:
        list_id = con.execute(
            """
            INSERT INTO blocklists(
                name,use_globally,schedule_enabled,schedule_days,
                schedule_start,schedule_end,schedule_timezone
            ) VALUES('overnight',1,1,'0','22:00','06:00','UTC')
            """
        ).lastrowid
        con.execute(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            (list_id, "bedtime.example.com"),
        )
        con.execute(
            "UPDATE blocklists SET entry_count=1 WHERE id=?",
            (list_id,),
        )

    e = PolicyEngine(db)
    monday_late = datetime(2026, 9, 21, 23, 0, tzinfo=timezone.utc)
    tuesday_early = datetime(2026, 9, 22, 5, 30, tzinfo=timezone.utc)
    tuesday_after = datetime(2026, 9, 22, 6, 30, tzinfo=timezone.utc)

    assert e.decide("192.168.1.10", "bedtime.example.com", monday_late).block is True
    assert e.decide("192.168.1.10", "bedtime.example.com", tuesday_early).block is True
    assert e.decide("192.168.1.10", "bedtime.example.com", tuesday_after).block is False
    e.close()
    td.cleanup()


def test_schedule_honors_iana_timezone():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    with db.connect() as con:
        list_id = con.execute(
            """
            INSERT INTO blocklists(
                name,use_globally,schedule_enabled,schedule_days,
                schedule_start,schedule_end,schedule_timezone
            ) VALUES('eastern',1,1,'0','22:00','06:00','America/New_York')
            """
        ).lastrowid
        con.execute(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            (list_id, "eastern.example.com"),
        )
        con.execute(
            "UPDATE blocklists SET entry_count=1 WHERE id=?",
            (list_id,),
        )

    e = PolicyEngine(db)
    # 01:00 Tuesday EDT belongs to Monday's 22:00-06:00 window.
    inside = datetime(2026, 9, 22, 5, 0, tzinfo=timezone.utc)
    # 07:00 Tuesday EDT is outside that window.
    outside = datetime(2026, 9, 22, 11, 0, tzinfo=timezone.utc)

    assert e.decide("192.168.1.10", "eastern.example.com", inside).block is True
    assert e.decide("192.168.1.10", "eastern.example.com", outside).block is False
    e.close()
    td.cleanup()


def test_scheduled_network_scope_only_applies_inside_window():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    with db.connect() as con:
        list_id = con.execute(
            "INSERT INTO blocklists(name,use_globally) VALUES('network-only',0)"
        ).lastrowid
        con.execute(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            (list_id, "network.example.com"),
        )
        con.execute(
            "UPDATE blocklists SET entry_count=1 WHERE id=?",
            (list_id,),
        )
        scope_id = con.execute(
            """
            INSERT INTO scopes(
                name,kind,target,state,schedule_enabled,schedule_days,
                schedule_start,schedule_end,schedule_timezone
            ) VALUES('scheduled-lan','network','10.20.0.0/16','active',1,'0','12:00','14:00','UTC')
            """
        ).lastrowid
        con.execute(
            "INSERT INTO scope_blocklists(scope_id,blocklist_id) VALUES(?,?)",
            (scope_id, list_id),
        )

    e = PolicyEngine(db)
    inside = datetime(2026, 9, 21, 13, 0, tzinfo=timezone.utc)
    outside = datetime(2026, 9, 21, 15, 0, tzinfo=timezone.utc)

    assert e.decide("10.20.1.50", "network.example.com", inside).block is True
    assert e.decide("10.20.1.50", "network.example.com", outside).block is False
    e.close()
    td.cleanup()


def test_endpoint_schedule_falls_back_to_network_outside_window():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    with db.connect() as con:
        network_list = con.execute(
            "INSERT INTO blocklists(name,use_globally) VALUES('network-list',0)"
        ).lastrowid
        endpoint_list = con.execute(
            "INSERT INTO blocklists(name,use_globally) VALUES('endpoint-list',0)"
        ).lastrowid
        con.execute(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            (network_list, "network.example.com"),
        )
        con.execute(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            (endpoint_list, "endpoint.example.com"),
        )
        network_scope = con.execute(
            "INSERT INTO scopes(name,kind,target,state) VALUES('lan','network','192.168.40.0/24','active')"
        ).lastrowid
        endpoint_scope = con.execute(
            """
            INSERT INTO scopes(
                name,kind,target,state,schedule_enabled,schedule_days,
                schedule_start,schedule_end,schedule_timezone
            ) VALUES('pc','client','192.168.40.25','active',1,'0','18:00','20:00','UTC')
            """
        ).lastrowid
        con.execute(
            "INSERT INTO scope_blocklists(scope_id,blocklist_id) VALUES(?,?)",
            (network_scope, network_list),
        )
        con.execute(
            "INSERT INTO scope_blocklists(scope_id,blocklist_id) VALUES(?,?)",
            (endpoint_scope, endpoint_list),
        )

    e = PolicyEngine(db)
    inside = datetime(2026, 9, 21, 19, 0, tzinfo=timezone.utc)
    outside = datetime(2026, 9, 21, 21, 0, tzinfo=timezone.utc)

    assert e.decide("192.168.40.25", "endpoint.example.com", inside).block is True
    assert e.decide("192.168.40.25", "endpoint.example.com", outside).block is False
    assert e.decide("192.168.40.25", "network.example.com", outside).block is True
    e.close()
    td.cleanup()


def test_scheduled_paused_endpoint_only_pauses_during_window():
    td, db, e = setup_engine()
    with db.connect() as con:
        con.execute(
            """
            INSERT INTO scopes(
                name,kind,target,state,schedule_enabled,schedule_days,
                schedule_start,schedule_end,schedule_timezone
            ) VALUES('bedtime-pause','client','192.168.1.55','paused',1,'0','20:00','22:00','UTC')
            """
        )
    e.reload()

    inside = datetime(2026, 9, 21, 21, 0, tzinfo=timezone.utc)
    outside = datetime(2026, 9, 21, 23, 0, tzinfo=timezone.utc)

    assert e.decide("192.168.1.55", "ads.example.com", inside).block is False
    assert e.decide("192.168.1.55", "ads.example.com", outside).block is True
    e.close()
    td.cleanup()


def test_query_log_time_retention_prunes_old_rows():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)

    with db.connect() as con:
        con.executemany(
            "INSERT INTO query_log(ts,client_ip,qname,blocked) VALUES(?,?,?,?)",
            [
                ("2026-08-01T12:00:00+00:00", "192.168.1.10", "old.example.com", 0),
                ("2026-09-20T12:00:00+00:00", "192.168.1.10", "recent.example.com", 0),
            ],
        )
        age_deleted, row_deleted = _prune_query_logs(
            con,
            max_rows=1000,
            max_age_days=30,
            now_utc=now,
        )
        rows = con.execute(
            "SELECT qname FROM query_log ORDER BY id"
        ).fetchall()

    assert age_deleted == 1
    assert row_deleted == 0
    assert [row["qname"] for row in rows] == ["recent.example.com"]
    td.cleanup()


def test_query_log_retention_combines_age_and_row_caps():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)

    with db.connect() as con:
        con.executemany(
            "INSERT INTO query_log(ts,client_ip,qname,blocked) VALUES(?,?,?,?)",
            [
                ("2026-01-01T00:00:00+00:00", "192.168.1.10", "expired.example.com", 0),
                ("2026-09-21T08:00:00+00:00", "192.168.1.10", "one.example.com", 0),
                ("2026-09-21T09:00:00+00:00", "192.168.1.10", "two.example.com", 0),
                ("2026-09-21T10:00:00+00:00", "192.168.1.10", "three.example.com", 0),
                ("2026-09-21T11:00:00+00:00", "192.168.1.10", "four.example.com", 0),
            ],
        )
        age_deleted, row_deleted = _prune_query_logs(
            con,
            max_rows=3,
            max_age_days=30,
            now_utc=now,
        )
        rows = con.execute(
            "SELECT qname FROM query_log ORDER BY id"
        ).fetchall()

    assert age_deleted == 1
    assert row_deleted == 1
    assert [row["qname"] for row in rows] == [
        "two.example.com",
        "three.example.com",
        "four.example.com",
    ]
    td.cleanup()


def test_exact_reverse_dns_hostname_scope_blocks_assigned_list():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    with db.connect() as con:
        list_id = con.execute(
            "INSERT INTO blocklists(name,use_globally) VALUES('hostname-only',0)"
        ).lastrowid
        con.execute(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            (list_id, "hostname.example.com"),
        )
        con.execute(
            "UPDATE blocklists SET entry_count=1 WHERE id=?",
            (list_id,),
        )
        scope_id = con.execute(
            """
            INSERT INTO scopes(name,kind,target,state)
            VALUES('desktop-host','hostname','desktop-01.home.arpa','active')
            """
        ).lastrowid
        con.execute(
            "INSERT INTO scope_blocklists(scope_id,blocklist_id) VALUES(?,?)",
            (scope_id, list_id),
        )
        con.execute(
            """
            INSERT INTO client_identities(client_ip,client_name)
            VALUES('192.168.1.42','desktop-01.home.arpa')
            """
        )

    e = PolicyEngine(db)
    assert e.decide("192.168.1.42", "hostname.example.com").block is True
    assert e.decide("192.168.1.43", "hostname.example.com").block is False
    e.close()
    td.cleanup()


def test_wildcard_reverse_dns_hostname_scope_matches_suffix():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    with db.connect() as con:
        list_id = con.execute(
            "INSERT INTO blocklists(name,use_globally) VALUES('kids-list',0)"
        ).lastrowid
        con.execute(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            (list_id, "games.example.com"),
        )
        con.execute(
            "UPDATE blocklists SET entry_count=1 WHERE id=?",
            (list_id,),
        )
        scope_id = con.execute(
            """
            INSERT INTO scopes(name,kind,target,state)
            VALUES('kids-hosts','hostname','*.kids.home.arpa','active')
            """
        ).lastrowid
        con.execute(
            "INSERT INTO scope_blocklists(scope_id,blocklist_id) VALUES(?,?)",
            (scope_id, list_id),
        )
        con.executemany(
            """
            INSERT INTO client_identities(client_ip,client_name)
            VALUES(?,?)
            """,
            [
                ("192.168.1.50", "tablet.kids.home.arpa"),
                ("192.168.1.51", "kids.home.arpa"),
            ],
        )

    e = PolicyEngine(db)
    assert e.decide("192.168.1.50", "games.example.com").block is True
    assert e.decide("192.168.1.51", "games.example.com").block is False
    e.close()
    td.cleanup()


def test_exact_endpoint_precedes_paused_hostname_scope():
    td, db, e = setup_engine()
    with db.connect() as con:
        con.execute(
            """
            INSERT INTO scopes(name,kind,target,state)
            VALUES('paused-host','hostname','desktop-01.home.arpa','paused')
            """
        )
        con.execute(
            """
            INSERT INTO scopes(name,kind,target,state)
            VALUES('exact-client','client','192.168.1.42','active')
            """
        )
        con.execute(
            """
            INSERT INTO client_identities(client_ip,client_name)
            VALUES('192.168.1.42','desktop-01.home.arpa')
            """
        )
    e.reload()

    assert e.decide("192.168.1.42", "ads.example.com").block is True
    e.close()
    td.cleanup()


def test_active_hostname_scope_precedes_paused_network():
    td, db, e = setup_engine()
    with db.connect() as con:
        con.execute(
            """
            INSERT INTO scopes(name,kind,target,state)
            VALUES('paused-lan','network','192.168.1.0/24','paused')
            """
        )
        con.execute(
            """
            INSERT INTO scopes(name,kind,target,state)
            VALUES('active-host','hostname','desktop-01.home.arpa','active')
            """
        )
        con.execute(
            """
            INSERT INTO client_identities(client_ip,client_name)
            VALUES('192.168.1.42','desktop-01.home.arpa')
            """
        )
    e.reload()

    assert e.decide("192.168.1.42", "ads.example.com").block is True
    e.close()
    td.cleanup()


def test_scheduled_hostname_scope_only_applies_inside_window():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    with db.connect() as con:
        list_id = con.execute(
            "INSERT INTO blocklists(name,use_globally) VALUES('host-scheduled-list',0)"
        ).lastrowid
        con.execute(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            (list_id, "school.example.com"),
        )
        con.execute(
            "UPDATE blocklists SET entry_count=1 WHERE id=?",
            (list_id,),
        )
        scope_id = con.execute(
            """
            INSERT INTO scopes(
                name,kind,target,state,schedule_enabled,schedule_days,
                schedule_start,schedule_end,schedule_timezone
            ) VALUES(
                'scheduled-host','hostname','student.home.arpa','active',
                1,'0','15:00','20:00','UTC'
            )
            """
        ).lastrowid
        con.execute(
            "INSERT INTO scope_blocklists(scope_id,blocklist_id) VALUES(?,?)",
            (scope_id, list_id),
        )
        con.execute(
            """
            INSERT INTO client_identities(client_ip,client_name)
            VALUES('192.168.1.60','student.home.arpa')
            """
        )

    e = PolicyEngine(db)
    inside = datetime(2026, 9, 21, 17, 0, tzinfo=timezone.utc)
    outside = datetime(2026, 9, 21, 21, 0, tzinfo=timezone.utc)

    assert e.decide("192.168.1.60", "school.example.com", inside).block is True
    assert e.decide("192.168.1.60", "school.example.com", outside).block is False
    e.close()
    td.cleanup()
