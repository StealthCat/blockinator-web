import tempfile
import threading
import time
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

def test_refresh_waits_for_concurrent_writer_without_recording_lock_error():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    engine = FakeEngine()
    list_id = _create_url_list(db, "remote", "https://example.test/list.txt", 60)

    refresher = BlocklistRefresher(
        db,
        engine,
        fetcher=lambda url: "new.example.com\n",
        poll_seconds=5,
    )
    result_holder: dict[str, object] = {}

    with db.connect() as blocker:
        blocker.execute("BEGIN IMMEDIATE")
        blocker.execute(
            "UPDATE settings SET value=value WHERE key='global_blocking'"
        )

        thread = threading.Thread(
            target=lambda: result_holder.setdefault(
                "result", refresher.refresh_list(list_id)
            )
        )
        thread.start()
        time.sleep(0.1)
        assert thread.is_alive()

        blocker.execute("COMMIT")
        thread.join(timeout=5)

    assert not thread.is_alive()
    result = result_holder["result"]
    assert result.refreshed is True
    assert result.error is None
    assert engine.reloads == 1

    with db.connect() as con:
        row = con.execute(
            "SELECT last_error FROM blocklists WHERE id=?",
            (list_id,),
        ).fetchone()
        domains = {
            r["domain"]
            for r in con.execute(
                "SELECT domain FROM block_entries WHERE blocklist_id=?",
                (list_id,),
            )
        }

    assert row["last_error"] is None
    assert domains == {"new.example.com"}
    td.cleanup()




def test_unchanged_refresh_skips_policy_reload_and_membership_rewrite():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    engine = FakeEngine()
    list_id = _create_url_list(
        db,
        "remote",
        "https://example.test/list.txt",
        60,
    )

    refresher = BlocklistRefresher(
        db,
        engine,
        fetcher=lambda url: "old.example.com\n",
        poll_seconds=5,
    )
    try:
        first = refresher.refresh_list(list_id)
        second = refresher.refresh_list(list_id)

        assert first.refreshed is True
        assert first.changed is False
        assert second.refreshed is True
        assert second.changed is False
        assert engine.reloads == 0

        with db.connect() as con:
            row = con.execute(
                "SELECT source_hash,entry_count FROM blocklists WHERE id=?",
                (list_id,),
            ).fetchone()
            count = con.execute(
                """
                SELECT COUNT(*) AS c
                FROM blocklist_domain_memberships
                WHERE blocklist_id=?
                """,
                (list_id,),
            ).fetchone()["c"]

        assert row["source_hash"]
        assert row["entry_count"] == 1
        assert count == 1
    finally:
        refresher.stop()
        td.cleanup()


def test_due_refreshes_download_in_parallel_and_reload_once():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    engine = FakeEngine()
    _create_url_list(
        db,
        "first",
        "https://example.test/first.txt",
        1,
        "datetime('now','-2 minutes')",
    )
    _create_url_list(
        db,
        "second",
        "https://example.test/second.txt",
        1,
        "datetime('now','-2 minutes')",
    )

    barrier = threading.Barrier(2, timeout=2)

    def fetcher(url: str) -> str:
        barrier.wait()
        return (
            "first.example.com\n"
            if "first" in url
            else "second.example.com\n"
        )

    refresher = BlocklistRefresher(
        db,
        engine,
        fetcher=fetcher,
        poll_seconds=5,
    )
    try:
        results = refresher.refresh_due_once()
        assert len(results) == 2
        assert all(result.refreshed for result in results)
        assert all(result.changed for result in results)
        assert engine.reloads == 1
    finally:
        refresher.stop()
        td.cleanup()
