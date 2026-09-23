from datetime import datetime, timezone
from pathlib import Path
import tempfile
import time

from app.blocklists import parse_blocklist
from app.db import Database
from app.policy import PolicyEngine
from app.refresher import BlocklistRefresher


class FakeEngine:
    def __init__(self) -> None:
        self.reloads = 0

    def reload(self) -> None:
        self.reloads += 1


def _add_list(
    con,
    name: str,
    list_type: str,
    domain: str,
    *,
    global_list: bool = True,
    enabled: bool = True,
    schedule_enabled: bool = False,
    schedule_days: str = "0,1,2,3,4,5,6",
    schedule_start: str = "00:00",
    schedule_end: str = "00:00",
    schedule_timezone: str = "UTC",
) -> int:
    list_id = int(
        con.execute(
            """
            INSERT INTO blocklists(
                name,list_type,use_globally,enabled,
                schedule_enabled,schedule_days,schedule_start,schedule_end,schedule_timezone
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                name,
                list_type,
                1 if global_list else 0,
                1 if enabled else 0,
                1 if schedule_enabled else 0,
                schedule_days,
                schedule_start,
                schedule_end,
                schedule_timezone,
            ),
        ).lastrowid
    )
    con.execute(
        "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
        (list_id, domain),
    )
    con.execute(
        "UPDATE blocklists SET entry_count=1 WHERE id=?",
        (list_id,),
    )
    return list_id


def test_global_whitelist_overrides_global_blocklist():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    with db.connect() as con:
        _add_list(con, "blocked", "block", "shared.example.com")
        _add_list(con, "allowed", "whitelist", "shared.example.com")

    engine = PolicyEngine(db)
    decision = engine.decide("192.168.1.20", "shared.example.com")

    assert decision.block is False
    assert decision.reason == "whitelist_match"
    assert decision.matched_list == "allowed"
    assert decision.matched_list_type == "whitelist"
    assert decision.matched_domain == "shared.example.com"

    engine.close()
    td.cleanup()


def test_disabled_whitelist_does_not_override_blocklist():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    with db.connect() as con:
        _add_list(con, "blocked", "block", "shared.example.com")
        _add_list(
            con,
            "disabled-allow",
            "whitelist",
            "shared.example.com",
            enabled=False,
        )

    engine = PolicyEngine(db)
    decision = engine.decide("192.168.1.20", "shared.example.com")

    assert decision.block is True
    assert decision.reason == "blocklist_match"
    assert decision.matched_list == "blocked"
    assert decision.matched_list_type == "block"

    engine.close()
    td.cleanup()


def test_scoped_whitelist_only_overrides_inside_assigned_scope():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    with db.connect() as con:
        _add_list(con, "blocked", "block", "shared.example.com")
        whitelist_id = _add_list(
            con,
            "lan-allow",
            "whitelist",
            "shared.example.com",
            global_list=False,
        )
        scope_id = int(
            con.execute(
                """
                INSERT INTO scopes(name,kind,target,state)
                VALUES('lan','network','10.20.0.0/16','active')
                """
            ).lastrowid
        )
        con.execute(
            "INSERT INTO scope_blocklists(scope_id,blocklist_id) VALUES(?,?)",
            (scope_id, whitelist_id),
        )

    engine = PolicyEngine(db)
    inside = engine.decide("10.20.1.50", "shared.example.com")
    outside = engine.decide("10.21.1.50", "shared.example.com")

    assert inside.block is False
    assert inside.reason == "whitelist_match"
    assert inside.matched_scope == "lan"
    assert inside.matched_list == "lan-allow"

    assert outside.block is True
    assert outside.reason == "blocklist_match"
    assert outside.matched_list == "blocked"

    engine.close()
    td.cleanup()


def test_whitelist_schedule_only_overrides_while_active():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    with db.connect() as con:
        _add_list(con, "blocked", "block", "scheduled.example.com")
        _add_list(
            con,
            "scheduled-allow",
            "whitelist",
            "scheduled.example.com",
            schedule_enabled=True,
            schedule_days="0",
            schedule_start="12:00",
            schedule_end="14:00",
            schedule_timezone="UTC",
        )

    engine = PolicyEngine(db)
    inside = datetime(2026, 9, 21, 13, 0, tzinfo=timezone.utc)
    outside = datetime(2026, 9, 21, 15, 0, tzinfo=timezone.utc)

    allowed = engine.decide("192.168.1.20", "scheduled.example.com", inside)
    blocked = engine.decide("192.168.1.20", "scheduled.example.com", outside)

    assert allowed.block is False
    assert allowed.reason == "whitelist_match"
    assert blocked.block is True
    assert blocked.reason == "blocklist_match"

    engine.close()
    td.cleanup()


def test_global_whitelist_respects_matched_targets_only_mode():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    db.set_settings(
        {
            "global_blocklist_scope_mode": "matched_scopes",
            "unmatched_scope_action": "deny",
        }
    )
    with db.connect() as con:
        _add_list(con, "allow", "whitelist", "safe.example.com")
        con.execute(
            """
            INSERT INTO scopes(name,kind,target,state)
            VALUES('lan','network','192.168.50.0/24','active')
            """
        )

    engine = PolicyEngine(db)

    unmatched = engine.decide("192.168.60.20", "safe.example.com")
    matched = engine.decide("192.168.50.20", "safe.example.com")

    assert unmatched.block is True
    assert unmatched.reason == "no_scope_default_deny"

    assert matched.block is False
    assert matched.reason == "whitelist_match"
    assert matched.matched_scope == "lan"
    assert matched.matched_list == "allow"

    engine.close()
    td.cleanup()


def test_whitelist_match_is_persisted_in_query_log():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    with db.connect() as con:
        _add_list(con, "allow", "whitelist", "safe.example.com")

    engine = PolicyEngine(db)
    engine.logger.rdns.resolve_many = lambda addresses: {}
    request = {
        "server_id": "dns-1",
        "client": {"ip": "192.168.1.20", "port": 53000},
        "protocol": "Udp",
        "dns": {
            "questions": [
                {"name": "safe.example.com", "type": "A", "class": "IN"},
            ]
        },
    }

    decision = engine.decide_and_log(request, policy_scheme="https")
    assert decision.block is False
    assert decision.reason == "whitelist_match"

    deadline = time.monotonic() + 2.0
    row = None
    while time.monotonic() < deadline:
        with db.connect() as con:
            row = con.execute(
                """
                SELECT blocked,reason,matched_list,matched_list_type
                FROM query_log
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()
        if row is not None:
            break
        time.sleep(0.02)

    assert row is not None
    assert row["blocked"] == 0
    assert row["reason"] == "whitelist_match"
    assert row["matched_list"] == "allow"
    assert row["matched_list_type"] == "whitelist"

    engine.close()
    td.cleanup()


def test_whitelist_adblock_parser_accepts_exception_rules():
    parsed = parse_blocklist(
        "@@||allowed.example.com^\n||also-allowed.example.net^\n",
        "adblock",
        "whitelist",
    )
    assert parsed.domains == {
        "allowed.example.com",
        "also-allowed.example.net",
    }


def test_whitelist_url_refresh_uses_whitelist_parser():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    with db.connect() as con:
        list_id = int(
            con.execute(
                """
                INSERT INTO blocklists(
                    name,list_type,source_type,source_url,format,refresh_minutes
                ) VALUES('remote-allow','whitelist','url','https://example.test/allow.txt','adblock',60)
                """
            ).lastrowid
        )
        con.execute(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            (list_id, "old.example.com"),
        )
        con.execute(
            "UPDATE blocklists SET entry_count=1 WHERE id=?",
            (list_id,),
        )

    fake_engine = FakeEngine()
    refresher = BlocklistRefresher(
        db,
        fake_engine,
        fetcher=lambda url: "@@||safe.example.com^\n",
        poll_seconds=5,
    )
    result = refresher.refresh_list(list_id)

    assert result.refreshed is True
    assert fake_engine.reloads == 1

    with db.connect() as con:
        domains = {
            row["domain"]
            for row in con.execute(
                "SELECT domain FROM block_entries WHERE blocklist_id=?",
                (list_id,),
            )
        }

    assert domains == {"safe.example.com"}
    td.cleanup()


def test_block_and_whitelist_share_one_canonical_domain_row():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    with db.connect() as con:
        block_id = _add_list(con, "blocked", "block", "shared.example.com")
        whitelist_id = _add_list(
            con,
            "allowed",
            "whitelist",
            "shared.example.com",
        )
        domain_rows = con.execute(
            "SELECT id FROM domains WHERE domain='shared.example.com'"
        ).fetchall()
        memberships = con.execute(
            """
            SELECT blocklist_id,domain_id
            FROM blocklist_domain_memberships
            WHERE blocklist_id IN (?,?)
            ORDER BY blocklist_id
            """,
            (block_id, whitelist_id),
        ).fetchall()

    assert len(domain_rows) == 1
    assert len(memberships) == 2
    assert memberships[0]["domain_id"] == memberships[1]["domain_id"]

    td.cleanup()


def test_whitelist_ui_and_navigation_are_present():
    source = Path("app/main.py").read_text(encoding="utf-8")

    assert '("/whitelists", "whitelists", "Whitelists", "✓")' in source
    assert '@app.get("/whitelists", response_class=HTMLResponse)' in source
    assert 'value="{list_type}"' in source
    assert '"Whitelist: {matched_list}"' in source
