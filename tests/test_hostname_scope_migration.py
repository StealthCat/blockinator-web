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
