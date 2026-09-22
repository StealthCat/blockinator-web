import tempfile
from pathlib import Path

from app.db import Database
from app.refresher import BlocklistRefresher


class FakeEngine:
    def __init__(self) -> None:
        self.reloads = 0

    def reload(self) -> None:
        self.reloads += 1


def _create_url_list(
    db: Database,
    name: str,
    url: str,
    refresh_minutes: int,
    last_attempt_sql: str | None = None,
) -> int:
    with db.connect() as con:
        cur = con.execute(
            """
            INSERT INTO blocklists(
                name,source_type,source_url,format,refresh_minutes,
                last_updated,last_refresh_attempt
            )
            VALUES(?,?,?,?,?,CURRENT_TIMESTAMP,NULL)
            """,
            (name, "url", url, "domains", refresh_minutes),
        )
        list_id = int(cur.lastrowid)
        con.execute(
            "INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            (list_id, "old.example.com"),
        )
        con.execute(
            "UPDATE blocklists SET entry_count=1 WHERE id=?",
            (list_id,),
        )
        if last_attempt_sql:
            con.execute(
                f"UPDATE blocklists SET last_refresh_attempt={last_attempt_sql} WHERE id=?",
                (list_id,),
            )
    return list_id


def test_url_refresh_replaces_entries_and_reloads_policy():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    engine = FakeEngine()
    list_id = _create_url_list(db, "remote", "https://example.test/list.txt", 60)

    refresher = BlocklistRefresher(
        db,
        engine,
        fetcher=lambda url: "new.example.com\ntracker.example.net\n",
        poll_seconds=5,
    )
    result = refresher.refresh_list(list_id)

    assert result.refreshed is True
    assert result.entry_count == 2
    assert engine.reloads == 1

    with db.connect() as con:
        row = con.execute(
            "SELECT entry_count,last_updated,last_refresh_attempt,last_error FROM blocklists WHERE id=?",
            (list_id,),
        ).fetchone()
        domains = {
            r["domain"]
            for r in con.execute(
                "SELECT domain FROM block_entries WHERE blocklist_id=?",
                (list_id,),
            )
        }

    assert row["entry_count"] == 2
    assert row["last_updated"] is not None
    assert row["last_refresh_attempt"] is not None
    assert row["last_error"] is None
    assert domains == {"new.example.com", "tracker.example.net"}

    td.cleanup()


def test_failed_url_refresh_keeps_last_good_entries():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    engine = FakeEngine()
    list_id = _create_url_list(db, "remote", "https://example.test/list.txt", 60)

    def failing_fetcher(url: str) -> str:
        raise RuntimeError("upstream unavailable")

    refresher = BlocklistRefresher(
        db,
        engine,
        fetcher=failing_fetcher,
        poll_seconds=5,
    )
    result = refresher.refresh_list(list_id)

    assert result.refreshed is False
    assert "upstream unavailable" in (result.error or "")
    assert engine.reloads == 0

    with db.connect() as con:
        row = con.execute(
            "SELECT entry_count,last_refresh_attempt,last_error FROM blocklists WHERE id=?",
            (list_id,),
        ).fetchone()
        domains = {
            r["domain"]
            for r in con.execute(
                "SELECT domain FROM block_entries WHERE blocklist_id=?",
                (list_id,),
            )
        }

    assert row["entry_count"] == 1
    assert row["last_refresh_attempt"] is not None
    assert "upstream unavailable" in row["last_error"]
    assert domains == {"old.example.com"}

    td.cleanup()


def test_url_lists_become_due_on_their_own_intervals():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    engine = FakeEngine()

    due_id = _create_url_list(
        db,
        "hourly-old",
        "https://example.test/hourly.txt",
        60,
        "datetime('now','-61 minutes')",
    )
    recent_id = _create_url_list(
        db,
        "hourly-recent",
        "https://example.test/recent.txt",
        60,
        "datetime('now','-10 minutes')",
    )
    long_interval_id = _create_url_list(
        db,
        "daily",
        "https://example.test/daily.txt",
        1440,
        "datetime('now','-2 hours')",
    )

    with db.connect() as con:
        upload_id = int(
            con.execute(
                """
                INSERT INTO blocklists(
                    name,source_type,format,refresh_minutes,last_refresh_attempt
                ) VALUES('upload','upload','domains',1,datetime('now','-1 day'))
                """
            ).lastrowid
        )

    refresher = BlocklistRefresher(
        db,
        engine,
        fetcher=lambda url: "ignored.example.com\n",
        poll_seconds=5,
    )
    due = set(refresher.due_list_ids())

    assert due_id in due
    assert recent_id not in due
    assert long_interval_id not in due
    assert upload_id not in due

    td.cleanup()


def test_empty_refresh_does_not_wipe_last_good_list():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    engine = FakeEngine()
    list_id = _create_url_list(db, "remote", "https://example.test/list.txt", 60)

    refresher = BlocklistRefresher(
        db,
        engine,
        fetcher=lambda url: "# comments only\n",
        poll_seconds=5,
    )
    result = refresher.refresh_list(list_id)

    assert result.refreshed is False
    assert engine.reloads == 0

    with db.connect() as con:
        domains = {
            r["domain"]
            for r in con.execute(
                "SELECT domain FROM block_entries WHERE blocklist_id=?",
                (list_id,),
            )
        }
    assert domains == {"old.example.com"}

    td.cleanup()
