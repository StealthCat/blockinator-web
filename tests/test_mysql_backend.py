from __future__ import annotations

import os
import time

import pytest

from app.auth import AuthManager, hash_password
from app.db import Database
from app.mysql_backend import MySQLConnection
from app.policy import PolicyEngine
from app.refresher import BlocklistRefresher


pytestmark = pytest.mark.skipif(
    os.getenv("MYSQL_TEST") != "1",
    reason="requires the MySQL integration-test service",
)


class FakeEngine:
    def __init__(self) -> None:
        self.reloads = 0

    def reload(self) -> None:
        self.reloads += 1


def _clear_database(db: Database) -> None:
    with db.connect() as con:
        con.execute("SET FOREIGN_KEY_CHECKS=0")
        for table in (
            "admin_sessions",
            "api_keys",
            "client_identities",
            "query_log",
            "scope_blocklists",
            "scope_network_targets",
            "scopes",
            "blocklist_domain_memberships",
            "domains",
            "blocklists",
            "admin_users",
        ):
            con.execute(f"DELETE FROM {table}")
        con.execute("SET FOREIGN_KEY_CHECKS=1")


def test_mysql_backend_schema_settings_policy_and_storage():
    db = Database()
    assert db.backend == "mysql"
    _clear_database(db)

    db.set_settings(
        {
            "global_blocking": "1",
            "unmatched_scope_action": "allow",
            "global_blocklist_scope_mode": "all_clients",
        }
    )
    assert db.get_setting("global_blocking") == "1"

    with db.connect() as con:
        block_id = int(
            con.execute(
                """
                INSERT INTO blocklists(name,list_type,use_globally)
                VALUES('blocked','block',1)
                """
            ).lastrowid
        )
        whitelist_id = int(
            con.execute(
                """
                INSERT INTO blocklists(name,list_type,use_globally)
                VALUES('allowed','whitelist',1)
                """
            ).lastrowid
        )
        assert db.add_list_domain(con, block_id, "shared.example.com") is True
        assert db.add_list_domain(con, whitelist_id, "shared.example.com") is True

        canonical = con.execute(
            "SELECT COUNT(*) AS c FROM domains WHERE domain=?",
            ("shared.example.com",),
        ).fetchone()
        memberships = con.execute(
            """
            SELECT COUNT(*) AS c
            FROM blocklist_domain_memberships
            WHERE blocklist_id IN (?,?)
            """,
            (block_id, whitelist_id),
        ).fetchone()

    assert int(canonical["c"]) == 1
    assert int(memberships["c"]) == 2

    engine = PolicyEngine(db)
    decision = engine.decide("192.168.1.50", "shared.example.com")
    assert decision.block is False
    assert decision.reason == "whitelist_match"
    assert decision.matched_list == "allowed"
    assert decision.matched_list_type == "whitelist"
    engine.close()


def test_mysql_query_logger_upsert_and_retention():
    db = Database()
    _clear_database(db)
    db.set_settings(
        {
            "max_query_logs": "1",
            "max_query_log_age_days": "0",
        }
    )

    engine = PolicyEngine(db)
    engine.logger.rdns.resolve_many = lambda addresses: {
        str(address): "client.home.arpa" for address in addresses
    }

    for qname in ("one.example.com", "two.example.com"):
        engine.decide_and_log(
            {
                "server_id": "mysql-test",
                "protocol": "Udp",
                "client": {"ip": "192.168.1.77", "port": 53000},
                "dns": {
                    "questions": [
                        {"name": qname, "type": "A", "class": "IN"},
                    ]
                },
            },
            policy_scheme="https",
        )

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        with db.connect() as con:
            row = con.execute(
                "SELECT COUNT(*) AS c FROM query_log"
            ).fetchone()
        if row and int(row["c"]) >= 1:
            break
        time.sleep(0.05)

    engine.logger.prune_now()

    with db.connect() as con:
        count = con.execute("SELECT COUNT(*) AS c FROM query_log").fetchone()
        identity = con.execute(
            "SELECT client_name FROM client_identities WHERE client_ip=?",
            ("192.168.1.77",),
        ).fetchone()

    assert int(count["c"]) == 1
    assert identity["client_name"] == "client.home.arpa"
    engine.close()


def test_mysql_url_refresh_and_due_schedule():
    db = Database()
    _clear_database(db)

    with db.connect() as con:
        list_id = int(
            con.execute(
                """
                INSERT INTO blocklists(
                    name,list_type,source_type,source_url,format,refresh_minutes,
                    last_refresh_attempt
                )
                VALUES(
                    'remote-allow','whitelist','url',
                    'https://example.test/allow.txt','adblock',60,
                    UTC_TIMESTAMP() - INTERVAL 120 MINUTE
                )
                """
            ).lastrowid
        )
        db.add_list_domain(con, list_id, "old.example.com")

    assert list_id in db.due_url_list_ids()

    fake_engine = FakeEngine()
    refresher = BlocklistRefresher(
        db,
        fake_engine,
        fetcher=lambda url: "@@||safe.example.com^\n",
        poll_seconds=5,
    )
    result = refresher.refresh_list(list_id)

    assert result.refreshed is True
    assert result.error is None
    assert fake_engine.reloads == 1

    with db.connect() as con:
        domains = {
            row["domain"]
            for row in con.execute(
                "SELECT domain FROM block_entries WHERE blocklist_id=?",
                (list_id,),
            ).fetchall()
        }
        row = con.execute(
            "SELECT last_error FROM blocklists WHERE id=?",
            (list_id,),
        ).fetchone()

    assert domains == {"safe.example.com"}
    assert row["last_error"] is None


def test_mysql_auth_and_case_insensitive_username():
    db = Database()
    _clear_database(db)

    with db.connect() as con:
        con.execute(
            """
            INSERT INTO admin_users(username,password_hash)
            VALUES(?,?)
            """,
            ("AdminUser", hash_password("correct horse battery staple")),
        )

    auth = AuthManager(db, bootstrap=False)
    authenticated = auth.authenticate(
        "adminuser",
        "correct horse battery staple",
    )
    assert authenticated is not None
    assert authenticated[1] == "AdminUser"


def test_mysql_translation_covers_runtime_sql():
    translated = MySQLConnection._translate(
        """
        INSERT INTO settings(`key`,value)
        VALUES(?,?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value
        """
    )
    assert "%s" in translated
    assert "ON DUPLICATE KEY UPDATE" in translated
    assert "VALUES(value)" in translated

    translated = MySQLConnection._translate(
        "SELECT username FROM admin_users WHERE username=? COLLATE NOCASE"
    )
    assert "COLLATE NOCASE" not in translated
    assert "%s" in translated

    translated = MySQLConnection._translate(
        "DELETE FROM query_log WHERE datetime(ts) < datetime(?)"
    )
    assert "datetime(" not in translated.lower()
    assert "ts < %s" in translated
