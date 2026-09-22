from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from typing import Callable, Protocol

from .blocklists import fetch_url, parse_blocklist
from .db import Database


class ReloadablePolicy(Protocol):
    def reload(self) -> None: ...


@dataclass(frozen=True, slots=True)
class RefreshResult:
    list_id: int
    refreshed: bool
    entry_count: int = 0
    ignored: int = 0
    error: str | None = None


class BlocklistRefresher:
    """Refresh URL-backed block lists independently on their configured intervals."""

    def __init__(
        self,
        db: Database,
        engine: ReloadablePolicy,
        fetcher: Callable[[str], str] = fetch_url,
        poll_seconds: float | None = None,
    ) -> None:
        self.db = db
        self.engine = engine
        self.fetcher = fetcher
        configured_poll = (
            float(os.getenv("BLOCKLIST_REFRESH_POLL_SECONDS", "30"))
            if poll_seconds is None
            else float(poll_seconds)
        )
        self.poll_seconds = max(5.0, min(configured_poll, 3600.0))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._run_lock = threading.Lock()

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="blockinator-blocklist-refresher",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
        self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.refresh_due_once()
            except Exception:
                # A refresh worker failure must never affect DNS serving.
                pass
            self._stop.wait(self.poll_seconds)

    def due_list_ids(self) -> list[int]:
        with self.db.connect() as con:
            rows = con.execute(
                """
                SELECT id
                FROM blocklists
                WHERE source_type='url'
                  AND source_url IS NOT NULL
                  AND TRIM(source_url) <> ''
                  AND julianday('now') >= julianday(
                        COALESCE(last_refresh_attempt,last_updated,created_at)
                      ) + (
                        CASE
                          WHEN refresh_minutes < 1 THEN 1
                          ELSE refresh_minutes
                        END / 1440.0
                      )
                ORDER BY id
                """
            ).fetchall()
        return [int(row["id"]) for row in rows]

    def refresh_due_once(self) -> list[RefreshResult]:
        if not self._run_lock.acquire(blocking=False):
            return []
        try:
            return [self.refresh_list(list_id) for list_id in self.due_list_ids()]
        finally:
            self._run_lock.release()

    def refresh_list(self, list_id: int) -> RefreshResult:
        with self.db.connect() as con:
            row = con.execute(
                """
                SELECT id,source_type,source_url,format
                FROM blocklists
                WHERE id=?
                """,
                (list_id,),
            ).fetchone()

        if (
            row is None
            or row["source_type"] != "url"
            or not str(row["source_url"] or "").strip()
        ):
            return RefreshResult(list_id=list_id, refreshed=False)

        source_url = str(row["source_url"]).strip()
        list_format = str(row["format"] or "auto")

        try:
            text = self.fetcher(source_url)
            parsed = parse_blocklist(text, list_format)
            if not parsed.domains:
                raise ValueError("refreshed block list contained no usable domains")

            with self.db.connect() as con:
                con.execute("BEGIN")
                current = con.execute(
                    """
                    SELECT source_type,source_url,format
                    FROM blocklists
                    WHERE id=?
                    """,
                    (list_id,),
                ).fetchone()
                if (
                    current is None
                    or current["source_type"] != "url"
                    or str(current["source_url"] or "").strip() != source_url
                    or str(current["format"] or "auto") != list_format
                ):
                    con.execute("ROLLBACK")
                    return RefreshResult(list_id=list_id, refreshed=False)

                con.execute(
                    "DELETE FROM block_entries WHERE blocklist_id=?",
                    (list_id,),
                )
                con.executemany(
                    """
                    INSERT OR IGNORE INTO block_entries(blocklist_id,domain)
                    VALUES(?,?)
                    """,
                    [(list_id, domain) for domain in parsed.domains],
                )
                con.execute(
                    """
                    UPDATE blocklists
                    SET entry_count=?,
                        last_updated=CURRENT_TIMESTAMP,
                        last_refresh_attempt=CURRENT_TIMESTAMP,
                        last_error=NULL
                    WHERE id=?
                    """,
                    (len(parsed.domains), list_id),
                )
                con.execute("COMMIT")

            self.engine.reload()
            return RefreshResult(
                list_id=list_id,
                refreshed=True,
                entry_count=len(parsed.domains),
                ignored=parsed.ignored,
            )
        except Exception as exc:
            message = str(exc).strip() or exc.__class__.__name__
            with self.db.connect() as con:
                con.execute(
                    """
                    UPDATE blocklists
                    SET last_refresh_attempt=CURRENT_TIMESTAMP,
                        last_error=?
                    WHERE id=?
                      AND source_type='url'
                      AND source_url=?
                      AND format=?
                    """,
                    (message[:2000], list_id, source_url, list_format),
                )
            return RefreshResult(
                list_id=list_id,
                refreshed=False,
                error=message,
            )
