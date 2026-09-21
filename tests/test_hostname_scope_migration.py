import sqlite3
import tempfile
from pathlib import Path

from app.db import Database


def test_legacy_scope_table_migrates_to_hostname_kind():
    td = tempfile.TemporaryDirectory()
    path = Path(td.name) / "legacy-scopes.db"

    con = sqlite3.connect(path)
    try:
        con.execute(
            """
            CREATE TABLE scopes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL CHECK(kind IN ('network','client')),
                target TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','paused')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        con.execute(
            """
            CREATE TABLE scope_blocklists (
                scope_id INTEGER NOT NULL,
                blocklist_id INTEGER NOT NULL,
                PRIMARY KEY (scope_id, blocklist_id)
            ) WITHOUT ROWID
            """
        )
        con.execute(
            """
            INSERT INTO scopes(name,kind,target,state)
            VALUES('legacy-lan','network','192.168.10.0/24','active')
            """
        )
        con.commit()
    finally:
        con.close()

    db = Database(str(path))

    with db.connect() as con:
        legacy = con.execute(
            "SELECT name,kind,target FROM scopes WHERE name='legacy-lan'"
        ).fetchone()
        assert legacy is not None
        assert legacy["kind"] == "network"
        assert legacy["target"] == "192.168.10.0/24"

        con.execute(
            """
            INSERT INTO scopes(name,kind,target,state)
            VALUES('host-scope','hostname','*.kids.home.arpa','active')
            """
        )
        hostname = con.execute(
            "SELECT kind,target FROM scopes WHERE name='host-scope'"
        ).fetchone()

    assert hostname["kind"] == "hostname"
    assert hostname["target"] == "*.kids.home.arpa"
    td.cleanup()


def test_existing_network_scope_backfills_address_family_target():
    td = tempfile.TemporaryDirectory()
    path = Path(td.name) / "single-stack.db"

    con = sqlite3.connect(path)
    try:
        con.execute(
            """
            CREATE TABLE scopes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL CHECK(kind IN ('network','client','hostname')),
                target TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','paused')),
                schedule_enabled INTEGER NOT NULL DEFAULT 0,
                schedule_days TEXT NOT NULL DEFAULT '0,1,2,3,4,5,6',
                schedule_start TEXT NOT NULL DEFAULT '00:00',
                schedule_end TEXT NOT NULL DEFAULT '00:00',
                schedule_timezone TEXT NOT NULL DEFAULT 'UTC',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        con.execute(
            """
            CREATE TABLE scope_blocklists (
                scope_id INTEGER NOT NULL,
                blocklist_id INTEGER NOT NULL,
                PRIMARY KEY (scope_id, blocklist_id)
            ) WITHOUT ROWID
            """
        )
        con.execute(
            """
            INSERT INTO scopes(name,kind,target,state)
            VALUES('existing-v6','network','2001:db8:abcd::/64','active')
            """
        )
        con.commit()
    finally:
        con.close()

    db = Database(str(path))

    with db.connect() as con:
        rows = con.execute(
            """
            SELECT family,target
            FROM scope_network_targets
            WHERE scope_id=(SELECT id FROM scopes WHERE name='existing-v6')
            """
        ).fetchall()

    assert [(row["family"], row["target"]) for row in rows] == [
        (6, "2001:db8:abcd::/64")
    ]
    td.cleanup()
