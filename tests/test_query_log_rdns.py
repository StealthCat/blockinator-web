import sqlite3
import tempfile
from pathlib import Path

from app.db import Database


def test_query_log_migration_adds_client_name_and_supports_hostname_filter():
    td = tempfile.TemporaryDirectory()
    path = Path(td.name) / "legacy.db"

    con = sqlite3.connect(path)
    try:
        con.execute(
            """
            CREATE TABLE query_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                server_id TEXT,
                client_ip TEXT NOT NULL,
                client_port INTEGER,
                protocol TEXT,
                qname TEXT,
                qtype TEXT,
                qclass TEXT,
                blocked INTEGER NOT NULL,
                reason TEXT,
                matched_scope TEXT,
                matched_list TEXT,
                request_json TEXT
            )
            """
        )
        con.commit()
    finally:
        con.close()

    db = Database(str(path))

    with db.connect() as con:
        columns = {row["name"] for row in con.execute("PRAGMA table_info(query_log)")}
        assert "client_name" in columns
        assert "policy_scheme" in columns
        assert "matched_list_type" in columns

        con.execute(
            """
            INSERT INTO query_log(
                server_id,client_ip,client_name,blocked,qname
            ) VALUES(?,?,?,?,?)
            """,
            ("dns-1", "192.168.1.42", "desktop-01.home.arpa", 0, "example.com"),
        )

        pattern = "%desktop-01%"
        rows = con.execute(
            """
            SELECT client_ip,client_name
            FROM query_log
            WHERE client_ip LIKE ? OR client_name LIKE ?
            """,
            (pattern, pattern),
        ).fetchall()

    assert len(rows) == 1
    assert rows[0]["client_ip"] == "192.168.1.42"
    assert rows[0]["client_name"] == "desktop-01.home.arpa"

    td.cleanup()
