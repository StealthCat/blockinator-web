import tempfile
import time
from pathlib import Path

from app.db import Database
from app.ptr_resolver import PtrResolutionManager
from app.rdns import ReverseDnsResult


class FakeResolver:
    def __init__(self, results):
        self.nameservers = ["192.0.2.53"]
        self.results = list(results)
        self.calls = []

    def lookup(self, address: str) -> ReverseDnsResult:
        self.calls.append(address)
        if len(self.results) > 1:
            return self.results.pop(0)
        return self.results[0]


def _wait_for(predicate, timeout: float = 3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    return None


def _database():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "test.db"))
    return td, db


def test_ptr_status_schema_is_created():
    td, db = _database()
    with db.connect() as con:
        columns = {
            row["name"]
            for row in con.execute("PRAGMA table_info(client_ptr_status)")
        }
        indexes = {
            row["name"]
            for row in con.execute("PRAGMA index_list(client_ptr_status)")
        }

    assert {
        "client_ip",
        "status",
        "client_name",
        "first_seen_at",
        "last_seen_at",
        "last_attempt_at",
        "last_success_at",
        "next_attempt_at",
        "attempt_count",
        "last_error",
    }.issubset(columns)
    assert "idx_client_ptr_status_due" in indexes
    assert "idx_client_ptr_status_state" in indexes
    td.cleanup()


def test_observed_client_resolves_and_backfills_query_log():
    td, db = _database()
    with db.connect() as con:
        con.execute(
            """
            INSERT INTO query_log(client_ip,blocked,qname)
            VALUES('192.168.1.77',0,'example.com')
            """
        )

    resolver = FakeResolver(
        [ReverseDnsResult("resolved", hostname="Desktop.Home.Arpa.")]
    )
    callback_updates = []
    manager = PtrResolutionManager(
        db,
        resolver,
        lambda updates: callback_updates.append(dict(updates)),
        workers=1,
        reconcile_seconds=0.05,
    )
    manager.start()
    manager.observe("192.168.1.77")

    def resolved_row():
        with db.connect() as con:
            return con.execute(
                """
                SELECT status,client_name,attempt_count
                FROM client_ptr_status
                WHERE client_ip='192.168.1.77'
                """
            ).fetchone()

    row = _wait_for(
        lambda: (
            candidate
            if (candidate := resolved_row())
            and candidate["status"] == "resolved"
            else None
        )
    )
    assert row is not None
    assert row["client_name"] == "desktop.home.arpa"
    assert int(row["attempt_count"]) == 0

    with db.connect() as con:
        identity = con.execute(
            """
            SELECT client_name FROM client_identities
            WHERE client_ip='192.168.1.77'
            """
        ).fetchone()
        log_row = con.execute(
            """
            SELECT client_name FROM query_log
            WHERE client_ip='192.168.1.77'
            """
        ).fetchone()

    assert identity["client_name"] == "desktop.home.arpa"
    assert log_row["client_name"] == "desktop.home.arpa"
    assert callback_updates[-1] == {
        "192.168.1.77": "desktop.home.arpa"
    }
    manager.close()
    td.cleanup()


def test_transient_ptr_failure_retries_until_resolved():
    td, db = _database()
    resolver = FakeResolver(
        [
            ReverseDnsResult("retry", error="temporary timeout"),
            ReverseDnsResult("resolved", hostname="client.home.arpa"),
        ]
    )
    manager = PtrResolutionManager(
        db,
        resolver,
        workers=1,
        reconcile_seconds=0.05,
        retry_delays=(0,),
    )
    manager.start()
    manager.observe("192.168.1.88")

    def status():
        with db.connect() as con:
            row = con.execute(
                """
                SELECT status,attempt_count,last_error
                FROM client_ptr_status
                WHERE client_ip='192.168.1.88'
                """
            ).fetchone()
        return row

    row = _wait_for(
        lambda: (
            candidate
            if (candidate := status())
            and candidate["status"] == "resolved"
            else None
        )
    )
    assert row is not None
    assert int(row["attempt_count"]) == 0
    assert row["last_error"] is None
    assert len(resolver.calls) >= 2
    manager.close()
    td.cleanup()


def test_authoritative_no_ptr_removes_stale_identity():
    td, db = _database()
    now = int(time.time())
    with db.connect() as con:
        con.execute(
            """
            INSERT INTO client_identities(client_ip,client_name)
            VALUES('192.168.1.99','old.home.arpa')
            """
        )
        con.execute(
            """
            INSERT INTO client_ptr_status(
                client_ip,status,client_name,first_seen_at,last_seen_at,
                last_success_at,next_attempt_at,attempt_count
            ) VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                "192.168.1.99",
                "resolved",
                "old.home.arpa",
                now,
                now,
                now,
                0,
                0,
            ),
        )

    callback_updates = []
    resolver = FakeResolver([ReverseDnsResult("no_ptr")])
    manager = PtrResolutionManager(
        db,
        resolver,
        lambda updates: callback_updates.append(dict(updates)),
        workers=1,
        reconcile_seconds=0.05,
    )
    manager.start()

    def no_ptr():
        with db.connect() as con:
            return con.execute(
                """
                SELECT status,client_name
                FROM client_ptr_status
                WHERE client_ip='192.168.1.99'
                """
            ).fetchone()

    row = _wait_for(
        lambda: (
            candidate
            if (candidate := no_ptr())
            and candidate["status"] == "no_ptr"
            else None
        )
    )
    assert row is not None
    assert row["client_name"] is None
    with db.connect() as con:
        identity = con.execute(
            """
            SELECT client_name FROM client_identities
            WHERE client_ip='192.168.1.99'
            """
        ).fetchone()
    assert identity is None
    assert callback_updates[-1] == {"192.168.1.99": None}
    manager.close()
    td.cleanup()


def test_observe_does_not_wait_for_slow_dns_lookup():
    td, db = _database()

    class SlowResolver(FakeResolver):
        def lookup(self, address: str) -> ReverseDnsResult:
            time.sleep(0.2)
            return ReverseDnsResult("resolved", hostname="slow.home.arpa")

    manager = PtrResolutionManager(
        db,
        SlowResolver([]),
        workers=1,
        reconcile_seconds=0.05,
    )
    manager.start()

    started = time.perf_counter()
    manager.observe("192.168.1.111")
    elapsed = time.perf_counter() - started

    assert elapsed < 0.05
    manager.close()
    td.cleanup()
