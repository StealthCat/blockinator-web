from __future__ import annotations

import hashlib
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Protocol

from .blocklists import FetchResult, fetch_url, fetch_url_conditional, parse_blocklist
from .db import Database


class ReloadablePolicy(Protocol):
    def reload(self) -> None: ...


@dataclass(frozen=True, slots=True)
class RefreshResult:
    list_id: int
    refreshed: bool
    entry_count: int = 0
    ignored: int = 0
    changed: bool = False
    error: str | None = None


class BlocklistRefresher:
    """Refresh URL-backed lists with parallel I/O and serialized database writes."""

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
        configured_workers = int(os.getenv("BLOCKLIST_REFRESH_WORKERS", "4"))
        self.max_workers = max(1, min(configured_workers, 8))

        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._run_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._executor = ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="blockinator-list-fetch",
        )

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
        self._executor.shutdown(wait=False, cancel_futures=True)

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
        if not self._run_lock.acquire(blocking=False):
            return []
        try:
            list_ids = self.due_list_ids()
            if not list_ids:
                return []

            futures = [
                self._executor.submit(
                    self.refresh_list,
                    list_id,
                    reload_policy=False,
                )
                for list_id in list_ids
            ]
            results = [future.result() for future in futures]
            if any(result.changed for result in results):
                self.engine.reload()
            return results
        finally:
            self._run_lock.release()

    def _fetch(
        self,
        source_url: str,
        etag: str | None,
        last_modified: str | None,
    ) -> FetchResult:
        if self.fetcher is fetch_url:
            return fetch_url_conditional(
                source_url,
                etag=etag,
                last_modified=last_modified,
            )

        text = self.fetcher(source_url)
        if isinstance(text, FetchResult):
            return text
        encoded = str(text).encode("utf-8")
        return FetchResult(
            text=str(text),
            content_hash=hashlib.sha256(encoded).hexdigest(),
        )

    def refresh_list(
        self,
        list_id: int,
        reload_policy: bool = True,
    ) -> RefreshResult:
        with self.db.connect() as con:
            row = con.execute(
                """
                SELECT id,source_type,source_url,format,list_type,entry_count,
                       source_etag,source_last_modified,source_hash
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
        list_type = str(row["list_type"] or "block")
        if list_type not in {"block", "whitelist"}:
            list_type = "block"
        previous_hash = str(row["source_hash"] or "") or None
        previous_etag = str(row["source_etag"] or "") or None
        previous_last_modified = str(row["source_last_modified"] or "") or None
        previous_count = int(row["entry_count"] or 0)
        config_hash = hashlib.sha256(
            f"{source_url}\\0{list_format}\\0{list_type}".encode("utf-8")
        ).hexdigest()[:16]
        metadata_matches_config = bool(
            previous_hash
            and previous_hash.startswith(config_hash + ":")
        )

        try:
            fetched = self._fetch(
                source_url,
                previous_etag if metadata_matches_config else None,
                previous_last_modified if metadata_matches_config else None,
            )
            stored_hash = (
                f"{config_hash}:{fetched.content_hash}"
                if fetched.content_hash
                else previous_hash
            )
            if stored_hash != fetched.content_hash:
                fetched = FetchResult(
                    text=fetched.text,
                    etag=fetched.etag,
                    last_modified=fetched.last_modified,
                    content_hash=stored_hash,
                    not_modified=fetched.not_modified,
                )

            if fetched.not_modified or (
                fetched.content_hash
                and previous_hash
                and fetched.content_hash == previous_hash
            ):
                self._record_unchanged(
                    list_id,
                    source_url,
                    list_format,
                    list_type,
                    fetched,
                )
                return RefreshResult(
                    list_id=list_id,
                    refreshed=True,
                    entry_count=previous_count,
                    changed=False,
                )

            if fetched.text is None:
                raise ValueError("block list refresh returned no content")

            parsed = parse_blocklist(
                fetched.text,
                list_format,
                list_type,
            )
            if not parsed.domains:
                raise ValueError("refreshed list contained no usable domains")

            changed = self._commit_refresh(
                list_id,
                source_url,
                list_format,
                list_type,
                parsed.domains,
                fetched,
            )

            if changed and reload_policy:
                self.engine.reload()
            return RefreshResult(
                list_id=list_id,
                refreshed=True,
                entry_count=len(parsed.domains),
                ignored=parsed.ignored,
                changed=changed,
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

    def _record_unchanged(
        self,
        list_id: int,
        source_url: str,
        list_format: str,
        list_type: str,
        fetched: FetchResult,
    ) -> None:
        with self._write_lock, self.db.connect() as con:
            con.execute(
                """
                UPDATE blocklists
                SET last_refresh_attempt=CURRENT_TIMESTAMP,
                    last_error=NULL,
                    source_etag=COALESCE(?,source_etag),
                    source_last_modified=COALESCE(?,source_last_modified),
                    source_hash=COALESCE(?,source_hash)
                WHERE id=?
                  AND source_type='url'
                  AND source_url=?
                  AND format=?
                  AND list_type=?
                """,
                (
                    fetched.etag,
                    fetched.last_modified,
                    fetched.content_hash,
                    list_id,
                    source_url,
                    list_format,
                    list_type,
                ),
            )

    def _commit_refresh(
        self,
        list_id: int,
        source_url: str,
        list_format: str,
        list_type: str,
        domains: set[str],
        fetched: FetchResult,
    ) -> bool:
        write_delays = (0.05, 0.15, 0.45)
        for attempt in range(len(write_delays) + 1):
            try:
                with self._write_lock, self.db.connect() as con:
                    con.execute("BEGIN IMMEDIATE")
                    try:
                        current = con.execute(
                            """
                            SELECT source_type,source_url,format,list_type
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
                            or str(current["list_type"] or "block") != list_type
                        ):
                            con.execute("ROLLBACK")
                            return False

                        changed = self.db.replace_list_domains(
                            con,
                            list_id,
                            domains,
                        )
                        con.execute(
                            """
                            UPDATE blocklists
                            SET entry_count=?,
                                last_updated=CASE
                                    WHEN ? THEN CURRENT_TIMESTAMP
                                    ELSE last_updated
                                END,
                                last_refresh_attempt=CURRENT_TIMESTAMP,
                                last_error=NULL,
                                source_etag=?,
                                source_last_modified=?,
                                source_hash=?
                            WHERE id=?
                            """,
                            (
                                len(domains),
                                1 if changed else 0,
                                fetched.etag,
                                fetched.last_modified,
                                fetched.content_hash,
                                list_id,
                            ),
                        )
                        con.execute("COMMIT")
                    except Exception:
                        if con.in_transaction:
                            con.execute("ROLLBACK")
                        raise
                return changed
            except Exception as write_exc:
                if (
                    not self.db.is_retryable_write_error(write_exc)
                    or attempt >= len(write_delays)
                ):
                    raise
                if self._stop.wait(write_delays[attempt]):
                    return False
        return False
