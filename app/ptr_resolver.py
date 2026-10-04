from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Callable

from .db import Database
from .rdns import ReverseDnsResolver, ReverseDnsResult


def _normalize_ptr_hostname(value: str | None) -> str | None:
    raw = str(value or "").strip().rstrip(".").lower()
    if not raw or any(ch.isspace() for ch in raw):
        return None
    labels = raw.split(".")
    if any(not label for label in labels):
        return None
    normalized: list[str] = []
    try:
        for label in labels:
            ascii_label = label.encode("idna").decode("ascii").lower()
            if not ascii_label or len(ascii_label) > 63:
                return None
            normalized.append(ascii_label)
    except UnicodeError:
        return None
    hostname = ".".join(normalized)
    return hostname if len(hostname) <= 253 else None


class PtrResolutionManager:
    """Durable, nonblocking PTR resolver running beside the decision pipeline."""

    RETRY_DELAYS_SECONDS = (5, 30, 120, 600, 3600)

    def __init__(
        self,
        db: Database,
        rdns: ReverseDnsResolver,
        identity_callback: Callable[[dict[str, str | None]], None] | None = None,
        *,
        workers: int | None = None,
        resolved_refresh_seconds: int | None = None,
        no_ptr_refresh_seconds: int | None = None,
        reconcile_seconds: float | None = None,
        retry_delays: tuple[int, ...] | None = None,
    ) -> None:
        self.db = db
        self.rdns = rdns
        self.identity_callback = identity_callback
        self.workers = max(
            1,
            min(
                int(
                    workers
                    if workers is not None
                    else os.getenv("RDNS_RESOLVER_WORKERS", "8")
                ),
                32,
            ),
        )
        self.resolved_refresh_seconds = max(
            60,
            int(
                resolved_refresh_seconds
                if resolved_refresh_seconds is not None
                else os.getenv("RDNS_RESOLVED_REFRESH_SECONDS", "86400")
            ),
        )
        self.no_ptr_refresh_seconds = max(
            60,
            int(
                no_ptr_refresh_seconds
                if no_ptr_refresh_seconds is not None
                else os.getenv("RDNS_NO_PTR_REFRESH_SECONDS", "21600")
            ),
        )
        self.reconcile_seconds = max(
            0.05,
            float(
                reconcile_seconds
                if reconcile_seconds is not None
                else os.getenv("RDNS_RECONCILE_SECONDS", "1")
            ),
        )
        configured_delays = retry_delays or self.RETRY_DELAYS_SECONDS
        self.retry_delays = tuple(max(0, int(value)) for value in configured_delays)
        if not self.retry_delays:
            self.retry_delays = self.RETRY_DELAYS_SECONDS

        self._state_lock = threading.RLock()
        self._stale_futures: set[Future] = set()
        self._observed: set[str] = set()
        self._recent_observed: dict[str, float] = {}
        self._observe_lock = threading.Lock()
        self._inflight: set[str] = set()
        self._futures: dict[Future[ReverseDnsResult], str] = {}
        self._executor = ThreadPoolExecutor(
            max_workers=self.workers,
            thread_name_prefix="blockinator-ptr",
        )
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_backfill = 0.0
        self._last_error = ""
        self._backfill_interval = 10.0
        self._observe_dedupe_seconds = 30.0
        self._batch_size = 512

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="ptr-resolution-manager",
            daemon=True,
        )
        self._thread.start()

    def close(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=3.0)
        self._executor.shutdown(wait=False, cancel_futures=True)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def observe(self, address: str) -> None:
        """Record a client IP for PTR work without DNS or database I/O."""
        try:
            canonical = str(ipaddress.ip_address(str(address or "").strip()))
        except ValueError:
            return

        now = time.monotonic()
        with self._observe_lock:
            last_seen = self._recent_observed.get(canonical)
            if (
                last_seen is not None
                and now - last_seen < self._observe_dedupe_seconds
            ):
                return
            self._recent_observed[canonical] = now
            self._observed.add(canonical)
            if len(self._recent_observed) > 16384:
                cutoff = now - max(300.0, self._observe_dedupe_seconds * 4)
                stale = [
                    key
                    for key, timestamp in self._recent_observed.items()
                    if timestamp < cutoff
                ]
                for key in stale[:8192]:
                    self._recent_observed.pop(key, None)

    def observe_many(self, addresses) -> None:
        for address in addresses:
            self.observe(str(address or ""))

    def status_snapshot(self) -> dict[str, object]:
        counts = {
            "resolved": 0,
            "no_ptr": 0,
            "pending": 0,
            "retry": 0,
        }
        try:
            with self.db.connect() as con:
                rows = con.execute(
                    """
                    SELECT status,COUNT(*) AS c
                    FROM client_ptr_status
                    GROUP BY status
                    """
                ).fetchall()
            for row in rows:
                status = str(row["status"])
                if status in counts:
                    counts[status] = int(row["c"] or 0)
        except Exception as exc:
            self._last_error = str(exc)[:500]

        with self._observe_lock:
            queued_observations = len(self._observed)
        return {
            **counts,
            "total": sum(counts.values()),
            "queued": queued_observations,
            "inflight": len(self._inflight),
            "workers": self.workers,
            "running": self.running,
            "resolver": ", ".join(self.rdns.nameservers) if self.rdns.nameservers else "System resolver",
            "last_error": self._last_error,
        }

    def flush_cache(self) -> int:
        """Clear learned answers and retry tracked clients without erasing history."""
        with self._state_lock:
            removed = {}
            count = 0

            def clear(con):
                nonlocal count
                rows = con.execute("SELECT client_ip FROM client_identities").fetchall()
                removed.update({str(row["client_ip"]): None for row in rows})
                now = int(time.time())
                # Preserve clients that have an identity but no tracking row yet.
                con.executemany("""INSERT OR IGNORE INTO client_ptr_status(
                    client_ip,status,first_seen_at,last_seen_at,next_attempt_at,attempt_count)
                    VALUES(?,'pending',?,?,0,0)""", [(ip, now, now) for ip in removed])
                count = int(con.execute("SELECT COUNT(*) AS c FROM client_ptr_status").fetchone()["c"])
                con.execute("DELETE FROM client_identities")
                con.execute("""UPDATE client_ptr_status SET status='pending',client_name=NULL,
                    last_attempt_at=NULL,last_success_at=NULL,next_attempt_at=0,
                    attempt_count=0,last_error=NULL""")
                con.execute("DELETE FROM settings WHERE `key` LIKE ?", ("ptr_backfill:%",))

            self._write_transaction(clear)
            self._stale_futures.update(self._futures)
            for future in self._futures:
                future.cancel()
            self.rdns.clear_cache()
            if removed and self.identity_callback is not None:
                self.identity_callback(removed)
            with self._observe_lock:
                self._recent_observed.clear()
            self._last_error = ""
            return count

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                with self._state_lock:
                    self._flush_observed()
                    self._collect_done()
                    self._run_backfill_if_due()
                    self._schedule_due()
                    self._collect_done()
                    self._backfill_known_names()
                    self._last_error = ""
            except Exception as exc:
                self._last_error = str(exc)[:500]
            self._stop_event.wait(self.reconcile_seconds)

        try:
            with self._state_lock:
                self._collect_done()
        except Exception:
            pass

    def _drain_observed(self) -> list[str]:
        with self._observe_lock:
            if not self._observed:
                return []
            addresses = list(self._observed)
            self._observed.clear()
        return addresses

    def _flush_observed(self) -> None:
        addresses = self._drain_observed()
        if not addresses:
            return
        now = int(time.time())
        rows = [
            (address, "pending", now, now, 0, 0)
            for address in addresses
        ]

        def write(con) -> None:
            con.executemany(
                """
                INSERT INTO client_ptr_status(
                    client_ip,status,first_seen_at,last_seen_at,
                    next_attempt_at,attempt_count
                ) VALUES(?,?,?,?,?,?)
                ON CONFLICT(client_ip) DO UPDATE SET
                    last_seen_at=excluded.last_seen_at
                """,
                rows,
            )

        self._write_transaction(write)

    def _run_backfill_if_due(self) -> None:
        now = time.monotonic()
        if now - self._last_backfill < self._backfill_interval:
            return
        self._last_backfill = now
        epoch_now = int(time.time())

        with self.db.connect() as con:
            identities = con.execute(
                """
                SELECT i.client_ip,i.client_name
                FROM client_identities AS i
                WHERE NOT EXISTS(
                    SELECT 1
                    FROM client_ptr_status AS p
                    WHERE p.client_ip=i.client_ip
                )
                LIMIT ?
                """,
                (self._batch_size,),
            ).fetchall()

        if identities:
            seed_rows = [
                (
                    str(row["client_ip"]),
                    "resolved",
                    str(row["client_name"]),
                    epoch_now,
                    epoch_now,
                    epoch_now,
                    epoch_now + self.resolved_refresh_seconds,
                    0,
                )
                for row in identities
            ]

            def seed(con) -> None:
                con.executemany(
                    """
                    INSERT INTO client_ptr_status(
                        client_ip,status,client_name,first_seen_at,last_seen_at,
                        last_success_at,next_attempt_at,attempt_count
                    ) VALUES(?,?,?,?,?,?,?,?)
                    ON CONFLICT(client_ip) DO UPDATE SET
                        last_seen_at=excluded.last_seen_at
                    """,
                    seed_rows,
                )

            self._write_transaction(seed)

        # Walk each historical row once using the primary key. Persist the
        # checkpoint together with discovered clients and name updates.
        cursor = int(self.db.get_setting("ptr_log_cursor", "0"))
        with self.db.connect() as con:
            candidates = con.execute("""SELECT q.id,q.client_ip,q.client_name,
                i.client_name AS known_name FROM query_log q
                LEFT JOIN client_identities i ON i.client_ip=q.client_ip
                WHERE q.id>? ORDER BY q.id LIMIT ?""", (cursor, self._batch_size)).fetchall()
        if candidates:
            def reconcile(con):
                con.executemany("""INSERT OR IGNORE INTO client_ptr_status(
                    client_ip,status,first_seen_at,last_seen_at,next_attempt_at,attempt_count)
                    VALUES(?,'pending',?,?,0,0)""",
                    [(address, epoch_now, epoch_now) for address in {str(r["client_ip"]) for r in candidates}])
                con.executemany("UPDATE query_log SET client_name=? WHERE id=? AND (client_name IS NULL OR client_name='')",
                    [(r["known_name"], r["id"]) for r in candidates if r["known_name"] and not r["client_name"]])
                con.execute("""INSERT INTO settings(`key`,value) VALUES('ptr_log_cursor',?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value""", (str(candidates[-1]["id"]),))
            self._write_transaction(reconcile)
            if len(candidates) == self._batch_size:
                self._last_backfill = 0.0  # Continue next tick, with bounded work.

    def _backfill_name_chunk(self, con, address, hostname, after_id, through_id):
        rows = con.execute("""SELECT id FROM query_log WHERE client_ip=?
            AND id>? AND id<=? ORDER BY id LIMIT 128""", (address, after_id, through_id)).fetchall()
        con.executemany("UPDATE query_log SET client_name=? WHERE id=? AND (client_name IS NULL OR client_name='')",
                        [(hostname, row["id"]) for row in rows])
        key = "ptr_backfill:" + address
        if len(rows) < 128 or rows[-1]["id"] >= through_id:
            con.execute("DELETE FROM settings WHERE `key`=?", (key,))
        else:
            value = json.dumps([hostname, rows[-1]["id"], through_id])
            con.execute("""INSERT INTO settings(`key`,value) VALUES(?,?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value""", (key, value))

    def _backfill_known_names(self) -> None:
        with self.db.connect() as con:
            jobs = con.execute("""SELECT `key`,value FROM settings
                WHERE `key` LIKE ? ORDER BY `key` LIMIT 4""", ("ptr_backfill:%",)).fetchall()
        for job in jobs:
            hostname, after_id, through_id = json.loads(job["value"])
            self._write_transaction(lambda con: self._backfill_name_chunk(
                con, job["key"].split(":", 1)[1], hostname, after_id, through_id))

    def _schedule_due(self) -> None:
        capacity = max(0, self.workers * 2 - len(self._inflight))
        if capacity <= 0:
            return
        now = int(time.time())
        with self.db.connect() as con:
            rows = con.execute(
                """
                SELECT client_ip
                FROM client_ptr_status
                WHERE next_attempt_at<=?
                ORDER BY
                    CASE status
                        WHEN 'pending' THEN 0
                        WHEN 'retry' THEN 1
                        WHEN 'no_ptr' THEN 2
                        ELSE 3
                    END,
                    next_attempt_at,
                    last_seen_at DESC
                LIMIT ?
                """,
                (now, min(self._batch_size, capacity)),
            ).fetchall()

        for row in rows:
            address = str(row["client_ip"])
            if address in self._inflight:
                continue
            future = self._executor.submit(self.rdns.lookup, address)
            self._futures[future] = address
            self._inflight.add(address)

    def _collect_done(self) -> None:
        done = [future for future in self._futures if future.done()]
        for future in done:
            address = self._futures.pop(future)
            self._inflight.discard(address)
            if future in self._stale_futures:
                self._stale_futures.discard(future)
                continue
            try:
                result = future.result()
            except Exception as exc:
                result = ReverseDnsResult(
                    "retry",
                    error=f"{exc.__class__.__name__}: {exc}"[:500],
                )
            self._persist_result(address, result)

    def _persist_result(self, address: str, result: ReverseDnsResult) -> None:
        now = int(time.time())
        hostname = _normalize_ptr_hostname(result.hostname)
        status = result.status
        if status == "resolved" and hostname is None:
            status = "retry"
            result = ReverseDnsResult(
                "retry",
                error="PTR response contained an invalid hostname",
            )

        with self.db.connect() as con:
            row = con.execute(
                """
                SELECT attempt_count,client_name
                FROM client_ptr_status
                WHERE client_ip=?
                """,
                (address,),
            ).fetchone()
        if row is None:
            self.observe(address)
            return

        previous_name = str(row["client_name"]) if row["client_name"] else None
        updates: dict[str, str | None] = {}

        if status == "resolved":
            next_attempt = now + self.resolved_refresh_seconds

            def write_resolved(con) -> None:
                con.execute(
                    """
                    UPDATE client_ptr_status
                    SET status='resolved',client_name=?,last_attempt_at=?,
                        last_success_at=?,next_attempt_at=?,attempt_count=0,
                        last_error=NULL
                    WHERE client_ip=?
                    """,
                    (hostname, now, now, next_attempt, address),
                )
                con.execute(
                    """
                    INSERT INTO client_identities(client_ip,client_name,updated_at)
                    VALUES(?,?,CURRENT_TIMESTAMP)
                    ON CONFLICT(client_ip) DO UPDATE SET
                        client_name=excluded.client_name,
                        updated_at=CURRENT_TIMESTAMP
                    """,
                    (address, hostname),
                )
                through_id = con.execute("SELECT COALESCE(MAX(id),0) AS id FROM query_log").fetchone()["id"]
                self._backfill_name_chunk(con, address, hostname, 0, through_id)

            self._write_transaction(write_resolved)
            if hostname != previous_name:
                updates[address] = hostname

        elif status == "no_ptr":
            next_attempt = now + self.no_ptr_refresh_seconds

            def write_no_ptr(con) -> None:
                con.execute(
                    """
                    UPDATE client_ptr_status
                    SET status='no_ptr',client_name=NULL,last_attempt_at=?,
                        last_success_at=?,next_attempt_at=?,attempt_count=0,
                        last_error=NULL
                    WHERE client_ip=?
                    """,
                    (now, now, next_attempt, address),
                )
                con.execute(
                    "DELETE FROM client_identities WHERE client_ip=?",
                    (address,),
                )

            self._write_transaction(write_no_ptr)
            if previous_name is not None:
                updates[address] = None

        else:
            attempt_count = int(row["attempt_count"] or 0) + 1
            delay = self.retry_delays[
                min(attempt_count - 1, len(self.retry_delays) - 1)
            ]
            next_attempt = now + delay
            error = str(result.error or "temporary PTR lookup failure")[:500]

            def write_retry(con) -> None:
                con.execute(
                    """
                    UPDATE client_ptr_status
                    SET status='retry',last_attempt_at=?,next_attempt_at=?,
                        attempt_count=?,last_error=?
                    WHERE client_ip=?
                    """,
                    (now, next_attempt, attempt_count, error, address),
                )

            self._write_transaction(write_retry)

        if updates and self.identity_callback is not None:
            self.identity_callback(updates)

    def _write_transaction(self, operation: Callable[[object], None]) -> None:
        delays = (0.0, 0.05, 0.2, 0.5)
        last_error: Exception | None = None
        for delay in delays:
            if delay:
                self._stop_event.wait(delay)
            try:
                with self.db.connect() as con:
                    con.execute("BEGIN")
                    try:
                        operation(con)
                        con.execute("COMMIT")
                    except Exception:
                        if getattr(con, "in_transaction", False):
                            con.execute("ROLLBACK")
                        raise
                return
            except Exception as exc:
                last_error = exc
                if not self.db.is_retryable_write_error(exc):
                    raise
        assert last_error is not None
        raise last_error
