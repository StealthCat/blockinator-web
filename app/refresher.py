from __future__ import annotations

import hashlib
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Protocol

from .blocklists import ParseResult, fetch_parse_url_conditional, fetch_url, parse_blocklist
from .db import Database


class ReloadablePolicy(Protocol):
    def reload(self) -> None: ...
    def reload_lists(self) -> None: ...


@dataclass(frozen=True, slots=True)
class RefreshResult:
    list_id: int
    refreshed: bool
    entry_count: int = 0
    ignored: int = 0
    changed: bool = False
    error: str | None = None


class BlocklistRefresher:
    """Refresh URL-backed lists with parallel fetch/parse and serialized writes."""

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
        self.max_workers = max(
            1,
            min(int(os.getenv("BLOCKLIST_REFRESH_WORKERS", "4")), 8),
        )
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._run_lock = threading.Lock()
        self._write_lock = threading.Lock()

    def _reload_policy_lists(self) -> None:
        reload_lists = getattr(self.engine, "reload_lists", None)
        if callable(reload_lists):
            reload_lists()
        else:
            # Compatibility for tests and external ReloadablePolicy adapters
            # that implement only the original full reload contract.
            self.engine.reload()

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
        return self.db.due_url_list_ids()

    def refresh_due_once(self) -> list[RefreshResult]:
        """Fetch due lists concurrently, then reload policy at most once."""
        if not self._run_lock.acquire(blocking=False):
            return []
        try:
            list_ids = self.due_list_ids()
            if not list_ids:
                return []

            workers = min(self.max_workers, len(list_ids))
            if workers <= 1:
                results = [
                    self._refresh_list(list_id, reload_engine=False)
                    for list_id in list_ids
                ]
            else:
                with ThreadPoolExecutor(
                    max_workers=workers,
                    thread_name_prefix="blockinator-list-refresh",
                ) as executor:
                    results = list(
                        executor.map(
                            lambda list_id: self._refresh_list(
                                list_id,
                                reload_engine=False,
                            ),
                            list_ids,
                        )
                    )

            if any(result.changed for result in results):
                self._reload_policy_lists()
            return results
        finally:
            self._run_lock.release()

    def refresh_list(self, list_id: int) -> RefreshResult:
        return self._refresh_list(list_id, reload_engine=True)

    def _read_source(self, list_id: int):
        with self.db.connect() as con:
            return con.execute(
                """
                SELECT
                    id,source_type,source_url,format,list_type,entry_count,
                    source_etag,source_last_modified,source_hash
                FROM blocklists
                WHERE id=?
                """,
                (list_id,),
            ).fetchone()

    @staticmethod
    def _valid_source(row) -> bool:
        return bool(
            row is not None
            and row["source_type"] == "url"
            and str(row["source_url"] or "").strip()
        )

    def _fetch(
        self,
        source_url: str,
        source_etag: str | None,
        source_last_modified: str | None,
        list_format: str,
        list_type: str,
    ) -> tuple[
        str | None,
        ParseResult | None,
        str | None,
        str | None,
        str | None,
        bool,
    ]:
        # Production refreshes stream directly into the parser and SHA-256
        # digest. Custom/test fetchers keep the original text contract.
        if self.fetcher is fetch_url:
            result = fetch_parse_url_conditional(
                source_url,
                list_format,
                list_type,
                source_etag,
                source_last_modified,
            )
            return (
                None,
                result.parsed,
                result.etag,
                result.last_modified,
                result.content_hash,
                result.not_modified,
            )

        text = self.fetcher(source_url)
        return (
            text,
            None,
            None,
            None,
            hashlib.sha256(text.encode("utf-8")).hexdigest(),
            False,
        )

    def _metadata_update_with_retry(
        self,
        list_id: int,
        source_url: str,
        list_format: str,
        list_type: str,
        *,
        entry_count: int | None = None,
        source_etag: str | None = None,
        source_last_modified: str | None = None,
        source_hash: str | None = None,
        mark_updated: bool = False,
    ) -> bool:
        write_delays = (0.05, 0.15, 0.45)
        for attempt in range(len(write_delays) + 1):
            try:
                with self._write_lock, self.db.connect() as con:
                    assignments = [
                        "last_refresh_attempt=CURRENT_TIMESTAMP",
                        "last_error=NULL",
                    ]
                    params: list[object] = []
                    if mark_updated:
                        assignments.append("last_updated=CURRENT_TIMESTAMP")
                    if entry_count is not None:
                        assignments.append("entry_count=?")
                        params.append(entry_count)
                    if source_etag is not None:
                        assignments.append("source_etag=?")
                        params.append(source_etag)
                    if source_last_modified is not None:
                        assignments.append("source_last_modified=?")
                        params.append(source_last_modified)
                    if source_hash is not None:
                        assignments.append("source_hash=?")
                        params.append(source_hash)
                    params.extend([list_id, source_url, list_format, list_type])
                    cur = con.execute(
                        f"""
                        UPDATE blocklists
                        SET {",".join(assignments)}
                        WHERE id=?
                          AND source_type='url'
                          AND source_url=?
                          AND format=?
                          AND list_type=?
                        """,
                        params,
                    )
                    return cur.rowcount == 1
            except Exception as exc:
                if (
                    not self.db.is_retryable_write_error(exc)
                    or attempt >= len(write_delays)
                ):
                    raise
                if self._stop.wait(write_delays[attempt]):
                    return False
        return False

    def _refresh_list(
        self,
        list_id: int,
        reload_engine: bool,
    ) -> RefreshResult:
        row = self._read_source(list_id)
        if not self._valid_source(row):
            return RefreshResult(list_id=list_id, refreshed=False)

        source_url = str(row["source_url"]).strip()
        list_format = str(row["format"] or "auto")
        list_type = str(row["list_type"] or "block")
        if list_type not in {"block", "whitelist"}:
            list_type = "block"
        old_hash = str(row["source_hash"] or "").strip() or None
        old_etag = str(row["source_etag"] or "").strip() or None
        old_last_modified = (
            str(row["source_last_modified"] or "").strip() or None
        )
        old_count = int(row["entry_count"] or 0)

        try:
            (
                text,
                parsed,
                etag,
                last_modified,
                source_hash,
                not_modified,
            ) = self._fetch(
                source_url,
                old_etag,
                old_last_modified,
                list_format,
                list_type,
            )

            if not_modified:
                self._metadata_update_with_retry(
                    list_id,
                    source_url,
                    list_format,
                    list_type,
                    source_etag=etag or old_etag,
                    source_last_modified=last_modified or old_last_modified,
                )
                return RefreshResult(
                    list_id=list_id,
                    refreshed=True,
                    entry_count=old_count,
                    changed=False,
                )

            if source_hash is None:
                raise ValueError("refreshed list did not produce a source hash")

            # An identical source needs only refresh bookkeeping. Avoid parsing,
            # database membership writes, and a policy snapshot rebuild.
            if old_hash and source_hash == old_hash:
                self._metadata_update_with_retry(
                    list_id,
                    source_url,
                    list_format,
                    list_type,
                    entry_count=old_count,
                    source_etag=etag,
                    source_last_modified=last_modified,
                    source_hash=source_hash,
                )
                return RefreshResult(
                    list_id=list_id,
                    refreshed=True,
                    entry_count=old_count,
                    changed=False,
                )

            if parsed is None:
                if text is None:
                    raise ValueError("refreshed list contained no content")
                parsed = parse_blocklist(text, list_format, list_type)
            if not parsed.domains:
                raise ValueError("refreshed list contained no usable domains")

            write_delays = (0.05, 0.15, 0.45)
            membership_changed = False
            committed = False

            for attempt in range(len(write_delays) + 1):
                try:
                    with self._write_lock, self.db.connect() as con:
                        con.execute("BEGIN IMMEDIATE")
                        try:
                            current = con.execute(
                                """
                                SELECT
                                    source_type,source_url,format,list_type,
                                    source_hash
                                FROM blocklists
                                WHERE id=?
                                """,
                                (list_id,),
                            ).fetchone()
                            if (
                                current is None
                                or current["source_type"] != "url"
                                or str(current["source_url"] or "").strip()
                                != source_url
                                or str(current["format"] or "auto")
                                != list_format
                                or str(current["list_type"] or "block")
                                != list_type
                            ):
                                con.execute("ROLLBACK")
                                return RefreshResult(
                                    list_id=list_id,
                                    refreshed=False,
                                )

                            if (
                                str(current["source_hash"] or "").strip()
                                == source_hash
                            ):
                                con.execute(
                                    """
                                    UPDATE blocklists
                                    SET last_refresh_attempt=CURRENT_TIMESTAMP,
                                        last_error=NULL,
                                        source_etag=?,
                                        source_last_modified=?
                                    WHERE id=?
                                    """,
                                    (etag, last_modified, list_id),
                                )
                                con.execute("COMMIT")
                                return RefreshResult(
                                    list_id=list_id,
                                    refreshed=True,
                                    entry_count=len(parsed.domains),
                                    ignored=parsed.ignored,
                                    changed=False,
                                )

                            membership_changed = self.db.replace_list_domains(
                                con,
                                list_id,
                                parsed.domains,
                            )
                            con.execute(
                                """
                                UPDATE blocklists
                                SET entry_count=?,
                                    last_updated=CURRENT_TIMESTAMP,
                                    last_refresh_attempt=CURRENT_TIMESTAMP,
                                    last_error=NULL,
                                    source_etag=?,
                                    source_last_modified=?,
                                    source_hash=?
                                WHERE id=?
                                """,
                                (
                                    len(parsed.domains),
                                    etag,
                                    last_modified,
                                    source_hash,
                                    list_id,
                                ),
                            )
                            con.execute("COMMIT")
                        except Exception:
                            if con.in_transaction:
                                con.execute("ROLLBACK")
                            raise
                    committed = True
                    break
                except Exception as write_exc:
                    if (
                        not self.db.is_retryable_write_error(write_exc)
                        or attempt >= len(write_delays)
                    ):
                        raise
                    if self._stop.wait(write_delays[attempt]):
                        return RefreshResult(
                            list_id=list_id,
                            refreshed=False,
                        )

            if not committed:
                return RefreshResult(list_id=list_id, refreshed=False)

            if membership_changed and reload_engine:
                self._reload_policy_lists()
            return RefreshResult(
                list_id=list_id,
                refreshed=True,
                entry_count=len(parsed.domains),
                ignored=parsed.ignored,
                changed=membership_changed,
            )
        except Exception as exc:
            message = str(exc).strip() or exc.__class__.__name__
            try:
                with self._write_lock, self.db.connect() as con:
                    con.execute(
                        """
                        UPDATE blocklists
                        SET last_refresh_attempt=CURRENT_TIMESTAMP,
                            last_error=?
                        WHERE id=?
                          AND source_type='url'
                          AND source_url=?
                          AND format=?
                          AND list_type=?
                        """,
                        (
                            message[:2000],
                            list_id,
                            source_url,
                            list_format,
                            list_type,
                        ),
                    )
            except Exception as bookkeeping_exc:
                if not self.db.is_retryable_write_error(bookkeeping_exc):
                    raise
            return RefreshResult(
                list_id=list_id,
                refreshed=False,
                error=message,
            )
