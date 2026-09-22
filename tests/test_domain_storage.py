import sqlite3
import tempfile
from pathlib import Path

from app.db import Database
from app.policy import PolicyEngine


def test_domains_shared_across_lists_are_stored_once():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))

    with db.connect() as con:
        list_a = int(
            con.execute(
                "INSERT INTO blocklists(name,use_globally) VALUES('a',1)"
            ).lastrowid
        )
        list_b = int(
            con.execute(
                "INSERT INTO blocklists(name,use_globally) VALUES('b',1)"
            ).lastrowid
        )

        con.execute(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            (list_a, "shared.example.com"),
        )
        con.execute(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            (list_b, "shared.example.com"),
        )

        stored_domains = con.execute(
            "SELECT id,domain FROM domains WHERE domain='shared.example.com'"
        ).fetchall()
        memberships = con.execute(
            """
            SELECT blocklist_id,domain_id
            FROM blocklist_domain_memberships
            ORDER BY blocklist_id
            """
        ).fetchall()
        compatibility_rows = con.execute(
            """
            SELECT blocklist_id,domain
            FROM block_entries
            WHERE domain='shared.example.com'
            ORDER BY blocklist_id
            """
        ).fetchall()

    assert len(stored_domains) == 1
    assert len(memberships) == 2
    assert memberships[0]["domain_id"] == memberships[1]["domain_id"]
    assert [row["blocklist_id"] for row in compatibility_rows] == [list_a, list_b]

    td.cleanup()


def test_shared_domain_is_removed_only_after_last_membership_is_deleted():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))

    with db.connect() as con:
        list_a = int(
            con.execute(
                "INSERT INTO blocklists(name,use_globally) VALUES('a',1)"
            ).lastrowid
        )
        list_b = int(
            con.execute(
                "INSERT INTO blocklists(name,use_globally) VALUES('b',1)"
            ).lastrowid
        )
        con.executemany(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            [
                (list_a, "shared.example.com"),
                (list_b, "shared.example.com"),
            ],
        )

        con.execute("DELETE FROM block_entries WHERE blocklist_id=?", (list_a,))
        assert con.execute(
            "SELECT COUNT(*) FROM domains WHERE domain='shared.example.com'"
        ).fetchone()[0] == 1

        con.execute("DELETE FROM blocklists WHERE id=?", (list_b,))
        assert con.execute(
            "SELECT COUNT(*) FROM domains WHERE domain='shared.example.com'"
        ).fetchone()[0] == 0

    td.cleanup()


def test_legacy_block_entries_migrate_and_deduplicate():
    td = tempfile.TemporaryDirectory()
    path = Path(td.name) / "legacy.db"

    con = sqlite3.connect(path)
    try:
        con.executescript(
            """
            PRAGMA foreign_keys=ON;

            CREATE TABLE blocklists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                source_type TEXT NOT NULL DEFAULT 'manual',
                source_url TEXT,
                format TEXT NOT NULL DEFAULT 'auto',
                enabled INTEGER NOT NULL DEFAULT 1,
                use_globally INTEGER NOT NULL DEFAULT 1,
                refresh_minutes INTEGER NOT NULL DEFAULT 1440,
                schedule_enabled INTEGER NOT NULL DEFAULT 0,
                schedule_days TEXT NOT NULL DEFAULT '0,1,2,3,4,5,6',
                schedule_start TEXT NOT NULL DEFAULT '00:00',
                schedule_end TEXT NOT NULL DEFAULT '00:00',
                schedule_timezone TEXT NOT NULL DEFAULT 'UTC',
                last_updated TEXT,
                last_refresh_attempt TEXT,
                last_error TEXT,
                entry_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE block_entries (
                blocklist_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                PRIMARY KEY (blocklist_id,domain),
                FOREIGN KEY (blocklist_id) REFERENCES blocklists(id) ON DELETE CASCADE
            ) WITHOUT ROWID;

            INSERT INTO blocklists(id,name,entry_count) VALUES
                (1,'one',2),
                (2,'two',2);

            INSERT INTO block_entries(blocklist_id,domain) VALUES
                (1,'shared.example.com'),
                (1,'one.example.com'),
                (2,'shared.example.com'),
                (2,'two.example.com');
            """
        )
        con.commit()
    finally:
        con.close()

    db = Database(str(path))

    with db.connect() as con:
        object_type = con.execute(
            "SELECT type FROM sqlite_master WHERE name='block_entries'"
        ).fetchone()["type"]
        domains = {
            row["domain"]
            for row in con.execute("SELECT domain FROM domains")
        }
        shared_count = con.execute(
            "SELECT COUNT(*) FROM domains WHERE domain='shared.example.com'"
        ).fetchone()[0]
        memberships = con.execute(
            "SELECT COUNT(*) FROM blocklist_domain_memberships"
        ).fetchone()[0]
        list_counts = [
            row["entry_count"]
            for row in con.execute(
                "SELECT entry_count FROM blocklists ORDER BY id"
            )
        ]

    assert object_type == "view"
    assert domains == {
        "shared.example.com",
        "one.example.com",
        "two.example.com",
    }
    assert shared_count == 1
    assert memberships == 4
    assert list_counts == [2, 2]

    td.cleanup()

def test_shared_domain_remains_enforced_when_one_list_is_removed():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))

    with db.connect() as con:
        list_a = int(
            con.execute(
                "INSERT INTO blocklists(name,use_globally) VALUES('a',1)"
            ).lastrowid
        )
        list_b = int(
            con.execute(
                "INSERT INTO blocklists(name,use_globally) VALUES('b',1)"
            ).lastrowid
        )
        con.executemany(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            [
                (list_a, "shared.example.com"),
                (list_b, "shared.example.com"),
            ],
        )
        con.execute(
            "UPDATE blocklists SET entry_count=1 WHERE id IN (?,?)",
            (list_a, list_b),
        )

    engine = PolicyEngine(db)
    first = engine.decide("192.168.1.20", "shared.example.com")
    assert first.block is True

    with db.connect() as con:
        con.execute("DELETE FROM blocklists WHERE id=?", (list_a,))
    engine.reload()

    second = engine.decide("192.168.1.20", "shared.example.com")
    assert second.block is True
    assert second.matched_list == "b"

    engine.close()
    td.cleanup()

