from __future__ import annotations

import ipaddress
import json
import queue
import threading
import time as monotonic_time
from dataclasses import dataclass, replace
from datetime import datetime, time, timedelta, timezone
from typing import Any, Callable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .db import Database
from .rdns import ReverseDnsResolver


def normalize_hostname(value: str | None) -> str | None:
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


def normalize_hostname_pattern(value: str | None) -> str | None:
    raw = str(value or "").strip()
    wildcard = raw.startswith("*.")
    if "*" in raw[2 if wildcard else 0:]:
        return None
    hostname = normalize_hostname(raw[2:] if wildcard else raw)
    if hostname is None:
        return None
    return f"*.{hostname}" if wildcard else hostname


@dataclass(frozen=True, slots=True)
class CompiledSchedule:
    enabled: bool
    days: frozenset[int]
    start: time
    end: time
    timezone: ZoneInfo | None
    valid: bool = True

    def is_active(self, now_utc: datetime | None = None) -> bool:
        if not self.enabled:
            return True
        if not self.valid or self.timezone is None or not self.days:
            return False

        current_utc = now_utc or datetime.now(timezone.utc)
        if current_utc.tzinfo is None:
            current_utc = current_utc.replace(tzinfo=timezone.utc)
        current = current_utc.astimezone(self.timezone)
        current_time = current.time().replace(tzinfo=None)
        weekday = current.weekday()

        if self.start == self.end:
            return weekday in self.days
        if self.start < self.end:
            return weekday in self.days and self.start <= current_time < self.end
        if weekday in self.days and current_time >= self.start:
            return True
        previous_weekday = (weekday - 1) % 7
        return previous_weekday in self.days and current_time < self.end


def _parse_schedule_days(value: Any) -> frozenset[int]:
    days: set[int] = set()
    for raw in str(value or "").split(","):
        try:
            day = int(raw)
        except (TypeError, ValueError):
            continue
        if 0 <= day <= 6:
            days.add(day)
    return frozenset(days)


def _compile_schedule(
    enabled: bool,
    days: frozenset[int],
    start_text: str,
    end_text: str,
    timezone_name: str,
) -> CompiledSchedule:
    try:
        start = time.fromisoformat(start_text)
        end = time.fromisoformat(end_text)
        tz = ZoneInfo(timezone_name)
        return CompiledSchedule(bool(enabled), days, start, end, tz, True)
    except (ValueError, ZoneInfoNotFoundError):
        return CompiledSchedule(
            bool(enabled),
            days,
            time(0, 0),
            time(0, 0),
            None,
            False,
        )


def _schedule_window_is_active(
    enabled: bool,
    days: frozenset[int],
    start_text: str,
    end_text: str,
    timezone_name: str,
    now_utc: datetime | None = None,
) -> bool:
    """Compatibility helper used by tests and callers outside the policy cache."""
    return _compile_schedule(
        enabled,
        days,
        start_text,
        end_text,
        timezone_name,
    ).is_active(now_utc)


def _prune_query_logs(
    con,
    max_rows: int,
    max_age_days: int,
    now_utc: datetime | None = None,
) -> tuple[int, int]:
    """Prune query logs by age and row count using index-friendly predicates."""
    age_deleted = 0
    row_deleted = 0

    if max_age_days > 0:
        cutoff = (now_utc or datetime.now(timezone.utc)) - timedelta(days=max_age_days)
        cur = con.execute(
            "DELETE FROM query_log WHERE ts < ?",
            (cutoff.isoformat(),),
        )
        age_deleted = max(0, cur.rowcount)

    if max_rows > 0:
        row = con.execute(
            "SELECT COALESCE(MAX(id),0) AS max_id FROM query_log"
        ).fetchone()
        cutoff_id = int(row["max_id"] or 0) - max_rows if row else 0
        if cutoff_id > 0:
            cur = con.execute(
                "DELETE FROM query_log WHERE id <= ?",
                (cutoff_id,),
            )
            row_deleted = max(0, cur.rowcount)

    return age_deleted, row_deleted


@dataclass(frozen=True, slots=True)
class Scope:
    id: int
    name: str
    kind: str
    target: str
    state: str
    networks: tuple[ipaddress._BaseNetwork, ...]
    blocklist_ids: frozenset[int]
    blocklist_mask: int
    schedule: CompiledSchedule

    def schedule_is_active(self, now_utc: datetime | None = None) -> bool:
        return self.schedule.is_active(now_utc)


@dataclass(frozen=True, slots=True)
class BlockListCache:
    id: int
    name: str
    list_type: str
    enabled: bool
    use_globally: bool
    schedule: CompiledSchedule

    def schedule_is_active(self, now_utc: datetime | None = None) -> bool:
        return self.schedule.is_active(now_utc)


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    blocklists: dict[int, BlockListCache]
    list_order: tuple[BlockListCache, ...]
    bit_for_list_id: dict[int, int]
    domain_masks: dict[str, int]
    global_list_mask: int
    whitelist_mask: int
    block_mask: int
    client_scopes: dict[str, tuple[Scope, ...]]
    exact_hostname_scopes: dict[str, tuple[Scope, ...]]
    wildcard_hostname_scopes: dict[str, tuple[Scope, ...]]
    wildcard_suffixes: tuple[str, ...]
    network_scopes_v4: dict[int, dict[int, tuple[Scope, ...]]]
    network_scopes_v6: dict[int, dict[int, tuple[Scope, ...]]]
    network_prefixes_v4: tuple[int, ...]
    network_prefixes_v6: tuple[int, ...]
    client_identities: dict[str, str]
    global_blocking: bool
    response_mode: str
    unmatched_scope_action: str
    global_blocklist_scope_mode: str
    unique_domain_count: int = 0
    block_domain_count: int = 0
    whitelist_domain_count: int = 0
    client_scope_count: int = 0
    hostname_scope_count: int = 0
    network_scope_count: int = 0


@dataclass(slots=True)
class Decision:
    block: bool
    reason: str
    matched_scope: str | None = None
    matched_list: str | None = None
    matched_domain: str | None = None
    response_mode: str = "nxdomain"
    matched_list_type: str | None = None


class QueryLogger:
    """Single-writer asynchronous logger with decoupled reverse-DNS resolution."""

    def __init__(
        self,
        db: Database,
        identity_callback: Callable[[dict[str, str]], None] | None = None,
        rdns: ReverseDnsResolver | None = None,
    ) -> None:
        self.db = db
        self.identity_callback = identity_callback
        self.rdns = rdns or ReverseDnsResolver()
        self._owns_rdns = rdns is None

        settings = self.db.get_settings(
            {
                "max_query_logs": "25000",
                "max_query_log_age_days": "0",
                "log_request_json": "0",
            }
        )
        self.max_rows = int(settings["max_query_logs"])
        self.max_age_days = int(settings["max_query_log_age_days"])
        self.capture_request_json = settings["log_request_json"] == "1"
        self._last_prune = monotonic_time.monotonic()
        self._rows_since_prune = 0
        self._last_legacy_scan = 0.0

        self.q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=10000)
        self.rdns_q: queue.Queue[str] = queue.Queue(maxsize=4096)
        self.identity_q: queue.Queue[dict[str, str]] = queue.Queue()
        self._rdns_pending: set[str] = set()
        self._rdns_pending_lock = threading.Lock()
        self.stop_event = threading.Event()

        self.thread = threading.Thread(
            target=self._run,
            name="query-log-writer",
            daemon=True,
        )
        self.resolver_thread = threading.Thread(
            target=self._resolve_loop,
            name="query-log-rdns",
            daemon=True,
        )
        self.thread.start()
        self.resolver_thread.start()

    @property
    def queue_depth(self) -> int:
        return self.q.qsize()

    def configure_retention(
        self,
        max_rows: int,
        max_age_days: int,
        capture_request_json: bool | None = None,
    ) -> None:
        self.max_rows = max(0, int(max_rows))
        self.max_age_days = max(0, int(max_age_days))
        if capture_request_json is not None:
            self.capture_request_json = bool(capture_request_json)

    def submit(self, row: dict[str, Any]) -> None:
        try:
            self.q.put_nowait(row)
        except queue.Full:
            # DNS decisions must never wait for logging.
            pass

    def close(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=2.0)
        self.resolver_thread.join(timeout=2.0)
        if self._owns_rdns:
            self.rdns.close()

    def prune_now(self, now_utc: datetime | None = None) -> tuple[int, int]:
        with self.db.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                result = _prune_query_logs(
                    con,
                    self.max_rows,
                    self.max_age_days,
                    now_utc,
                )
                con.execute("COMMIT")
            except Exception:
                if con.in_transaction:
                    con.execute("ROLLBACK")
                raise
        self._last_prune = monotonic_time.monotonic()
        self._rows_since_prune = 0
        return result

    def queue_rdns(self, addresses) -> None:
        self._queue_rdns({str(address or "").strip() for address in addresses})

    def _queue_rdns(self, addresses: set[str]) -> None:
        for address in addresses:
            if not address:
                continue
            with self._rdns_pending_lock:
                if address in self._rdns_pending:
                    continue
                self._rdns_pending.add(address)
            try:
                self.rdns_q.put_nowait(address)
            except queue.Full:
                with self._rdns_pending_lock:
                    self._rdns_pending.discard(address)

    def _resolve_loop(self) -> None:
        while not self.stop_event.is_set():
            addresses: list[str] = []
            try:
                addresses.append(self.rdns_q.get(timeout=0.5))
            except queue.Empty:
                continue
            while len(addresses) < 128:
                try:
                    addresses.append(self.rdns_q.get_nowait())
                except queue.Empty:
                    break

            unique = list(dict.fromkeys(addresses))
            try:
                resolved = self.rdns.resolve_many(unique)
                identities = {
                    address: normalized
                    for address, hostname in resolved.items()
                    if (normalized := normalize_hostname(hostname)) is not None
                }
                if identities:
                    self.identity_q.put(identities)
            finally:
                with self._rdns_pending_lock:
                    for address in unique:
                        self._rdns_pending.discard(address)

    def _queue_legacy_backfill(self, con) -> None:
        now = monotonic_time.monotonic()
        if now - self._last_legacy_scan < 60.0:
            return
        self._last_legacy_scan = now
        rows = con.execute(
            """
            SELECT client_ip, MAX(id) AS latest_id
            FROM query_log
            WHERE client_name IS NULL OR client_name=''
            GROUP BY client_ip
            ORDER BY latest_id DESC
            LIMIT 256
            """
        ).fetchall()
        if rows:
            self._queue_rdns({str(row["client_ip"]) for row in rows})

    def _should_prune(self, inserted_rows: int) -> bool:
        self._rows_since_prune += inserted_rows
        now = monotonic_time.monotonic()
        return (
            self._rows_since_prune >= 5000
            or now - self._last_prune >= 60.0
        )

    def _run(self) -> None:
        # Keep the logger's database connection on its dedicated writer thread.
        # This avoids a SQLite connection setup (and, for MySQL, a network
        # handshake) for every query batch.
        while not self.stop_event.is_set():
            try:
                with self.db.connect() as con:
                    self._run_connected(con)
            except Exception:
                # Reconnect after transient database failures without affecting
                # the DNS decision path.
                self.stop_event.wait(0.1)

    def _run_connected(self, con) -> None:
        while not self.stop_event.is_set():
            batch: list[dict[str, Any]] = []
            identities: dict[str, str] = {}

            try:
                batch.append(self.q.get(timeout=0.25))
            except queue.Empty:
                pass
            while len(batch) < 250:
                try:
                    batch.append(self.q.get_nowait())
                except queue.Empty:
                    break
            while True:
                try:
                    identities.update(self.identity_q.get_nowait())
                except queue.Empty:
                    break

            self._queue_legacy_backfill(con)

            if not batch and not identities:
                continue

            missing_addresses: set[str] = set()
            inserted_rows = len(batch)
            try:
                con.execute("BEGIN")
                if batch:
                    con.executemany(
                        """
                        INSERT INTO query_log(
                          ts,server_id,client_ip,client_name,client_port,protocol,policy_scheme,
                          qname,qtype,qclass,blocked,reason,matched_scope,matched_list,
                          matched_list_type,response_time_ms,request_json
                        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        [
                            (
                                r["ts"],
                                r.get("server_id"),
                                r["client_ip"],
                                r.get("client_name"),
                                r.get("client_port"),
                                r.get("protocol"),
                                r.get("policy_scheme"),
                                r.get("qname"),
                                r.get("qtype"),
                                r.get("qclass"),
                                1 if r["blocked"] else 0,
                                r.get("reason"),
                                r.get("matched_scope"),
                                r.get("matched_list"),
                                r.get("matched_list_type"),
                                r.get("response_time_ms"),
                                (
                                    json.dumps(
                                        r.get("request_obj"),
                                        separators=(",", ":"),
                                        ensure_ascii=False,
                                    )
                                    if self.capture_request_json
                                    and r.get("request_obj") is not None
                                    else None
                                ),
                            )
                            for r in batch
                        ],
                    )
                    missing_addresses = {
                        str(r.get("client_ip") or "")
                        for r in batch
                        if not r.get("client_name")
                    }

                if identities:
                    for client_ip, client_name in identities.items():
                        con.execute(
                            """
                            UPDATE query_log
                            SET client_name=?
                            WHERE client_ip=? AND (client_name IS NULL OR client_name='')
                            """,
                            (client_name, client_ip),
                        )
                    con.executemany(
                        """
                        INSERT INTO client_identities(client_ip,client_name,updated_at)
                        VALUES(?,?,CURRENT_TIMESTAMP)
                        ON CONFLICT(client_ip) DO UPDATE SET
                            client_name=excluded.client_name,
                            updated_at=CURRENT_TIMESTAMP
                        """,
                        [
                            (client_ip, client_name)
                            for client_ip, client_name in identities.items()
                        ],
                    )

                if self._should_prune(inserted_rows):
                    _prune_query_logs(
                        con,
                        self.max_rows,
                        self.max_age_days,
                    )
                    self._last_prune = monotonic_time.monotonic()
                    self._rows_since_prune = 0

                con.execute("COMMIT")
            except Exception:
                if con.in_transaction:
                    con.execute("ROLLBACK")
                raise

            if identities and self.identity_callback is not None:
                self.identity_callback(identities)
            if missing_addresses:
                self._queue_rdns(missing_addresses)


class PolicyEngine:
    def __init__(
        self,
        db: Database,
        rdns: ReverseDnsResolver | None = None,
    ) -> None:
        self.db = db
        self._write_lock = threading.RLock()
        self._owns_rdns = rdns is None
        self.rdns = rdns or ReverseDnsResolver()
        self._active_list_cache: tuple[PolicySnapshot | None, int, int] = (None, -1, 0)
        self._snapshot = PolicySnapshot(
            blocklists={},
            list_order=(),
            bit_for_list_id={},
            domain_masks={},
            global_list_mask=0,
            whitelist_mask=0,
            block_mask=0,
            client_scopes={},
            exact_hostname_scopes={},
            wildcard_hostname_scopes={},
            wildcard_suffixes=(),
            network_scopes_v4={},
            network_scopes_v6={},
            network_prefixes_v4=(),
            network_prefixes_v6=(),
            client_identities={},
            global_blocking=True,
            response_mode="nxdomain",
            unmatched_scope_action="allow",
            global_blocklist_scope_mode="all_clients",
        )
        self.logger = QueryLogger(db, self._remember_client_identities, self.rdns)
        self.reload()

    def close(self) -> None:
        self.logger.close()
        if self._owns_rdns:
            self.rdns.close()

    @property
    def snapshot(self) -> PolicySnapshot:
        return self._snapshot

    def _remember_client_identities(self, identities: dict[str, str]) -> None:
        if not identities:
            return
        with self._write_lock:
            current = self._snapshot
            merged = dict(current.client_identities)
            merged.update(identities)
            self._snapshot = replace(current, client_identities=merged)

    @staticmethod
    def _scope_tuple_map_add(
        mapping: dict[Any, list[Scope]],
        key: Any,
        scope: Scope,
    ) -> None:
        mapping.setdefault(key, []).append(scope)

    def reload(self) -> None:
        with self.db.connect() as con:
            settings = {
                str(r["key"]): str(r["value"])
                for r in con.execute("SELECT `key` AS `key`,value FROM settings")
            }
            list_rows = con.execute("SELECT * FROM blocklists ORDER BY id").fetchall()

            list_order: list[BlockListCache] = []
            bit_for_list_id: dict[int, int] = {}
            global_list_mask = 0
            whitelist_mask = 0
            block_mask = 0

            for row in list_rows:
                list_id = int(row["id"])
                list_type = str(row["list_type"] or "block")
                if list_type not in {"block", "whitelist"}:
                    list_type = "block"
                cache = BlockListCache(
                    id=list_id,
                    name=str(row["name"]),
                    list_type=list_type,
                    enabled=bool(row["enabled"]),
                    use_globally=bool(row["use_globally"]),
                    schedule=_compile_schedule(
                        bool(row["schedule_enabled"]),
                        _parse_schedule_days(row["schedule_days"]),
                        str(row["schedule_start"] or "00:00"),
                        str(row["schedule_end"] or "00:00"),
                        str(row["schedule_timezone"] or "UTC"),
                    ),
                )
                bit = 1 << len(list_order)
                list_order.append(cache)
                bit_for_list_id[list_id] = bit
                if cache.enabled:
                    if cache.use_globally:
                        global_list_mask |= bit
                    if cache.list_type == "whitelist":
                        whitelist_mask |= bit
                    else:
                        block_mask |= bit

            blocklists = {item.id: item for item in list_order}

            domain_masks: dict[str, int] = {}
            for row in con.execute(
                """
                SELECT memberships.blocklist_id, domains.domain
                FROM blocklist_domain_memberships AS memberships
                JOIN domains ON domains.id=memberships.domain_id
                JOIN blocklists ON blocklists.id=memberships.blocklist_id
                WHERE blocklists.enabled=1
                """
            ):
                bit = bit_for_list_id.get(int(row["blocklist_id"]), 0)
                if bit:
                    domain = str(row["domain"])
                    domain_masks[domain] = domain_masks.get(domain, 0) | bit

            unique_domain_count = len(domain_masks)
            block_domain_count = sum(
                1 for mask in domain_masks.values() if mask & block_mask
            )
            whitelist_domain_count = sum(
                1 for mask in domain_masks.values() if mask & whitelist_mask
            )

            memberships: dict[int, set[int]] = {}
            for row in con.execute(
                "SELECT scope_id,blocklist_id FROM scope_blocklists"
            ):
                memberships.setdefault(int(row["scope_id"]), set()).add(
                    int(row["blocklist_id"])
                )

            network_targets: dict[int, list[str]] = {}
            for row in con.execute(
                "SELECT scope_id,family,target FROM scope_network_targets ORDER BY family"
            ):
                network_targets.setdefault(int(row["scope_id"]), []).append(
                    str(row["target"])
                )

            client_build: dict[str, list[Scope]] = {}
            exact_hostname_build: dict[str, list[Scope]] = {}
            wildcard_hostname_build: dict[str, list[Scope]] = {}
            client_scope_count = 0
            hostname_scope_count = 0
            network_scope_count = 0
            network_build_v4: dict[int, dict[int, list[Scope]]] = {}
            network_build_v6: dict[int, dict[int, list[Scope]]] = {}

            for row in con.execute("SELECT * FROM scopes ORDER BY id"):
                scope_id = int(row["id"])
                target = str(row["target"])
                networks: tuple[ipaddress._BaseNetwork, ...] = ()
                try:
                    if row["kind"] == "client":
                        ip = ipaddress.ip_address(target)
                        target = str(ip)
                        networks = (
                            ipaddress.ip_network(
                                f"{ip}/{ip.max_prefixlen}",
                                strict=False,
                            ),
                        )
                    elif row["kind"] == "network":
                        raw_targets = network_targets.get(scope_id) or [target]
                        parsed: list[ipaddress._BaseNetwork] = []
                        for raw_target in raw_targets:
                            try:
                                parsed.append(
                                    ipaddress.ip_network(raw_target, strict=False)
                                )
                            except ValueError:
                                continue
                        if not parsed:
                            continue
                        networks = tuple(parsed)
                        target = " · ".join(str(network) for network in networks)
                    elif row["kind"] == "hostname":
                        normalized = normalize_hostname_pattern(target)
                        if normalized is None:
                            continue
                        target = normalized
                    else:
                        continue
                except ValueError:
                    continue

                assigned_ids = frozenset(memberships.get(scope_id, set()))
                assigned_mask = 0
                for list_id in assigned_ids:
                    assigned_mask |= bit_for_list_id.get(list_id, 0)

                scope = Scope(
                    id=scope_id,
                    name=str(row["name"]),
                    kind=str(row["kind"]),
                    target=target,
                    state=str(row["state"]),
                    networks=networks,
                    blocklist_ids=assigned_ids,
                    blocklist_mask=assigned_mask,
                    schedule=_compile_schedule(
                        bool(row["schedule_enabled"]),
                        _parse_schedule_days(row["schedule_days"]),
                        str(row["schedule_start"] or "00:00"),
                        str(row["schedule_end"] or "00:00"),
                        str(row["schedule_timezone"] or "UTC"),
                    ),
                )

                if scope.kind == "client":
                    client_scope_count += 1
                    self._scope_tuple_map_add(client_build, scope.target, scope)
                elif scope.kind == "hostname":
                    hostname_scope_count += 1
                    if scope.target.startswith("*."):
                        self._scope_tuple_map_add(
                            wildcard_hostname_build,
                            scope.target[2:],
                            scope,
                        )
                    else:
                        self._scope_tuple_map_add(
                            exact_hostname_build,
                            scope.target,
                            scope,
                        )
                else:
                    network_scope_count += 1
                    for network in scope.networks:
                        family_map = (
                            network_build_v4
                            if network.version == 4
                            else network_build_v6
                        )
                        prefix_map = family_map.setdefault(network.prefixlen, {})
                        key = int(network.network_address)
                        prefix_map.setdefault(key, []).append(scope)

            def freeze_scope_map(
                source: dict[Any, list[Scope]],
            ) -> dict[Any, tuple[Scope, ...]]:
                return {
                    key: tuple(sorted(scopes, key=lambda scope: scope.id))
                    for key, scopes in source.items()
                }

            def freeze_network_map(
                source: dict[int, dict[int, list[Scope]]],
            ) -> dict[int, dict[int, tuple[Scope, ...]]]:
                return {
                    prefix: {
                        address: tuple(sorted(scopes, key=lambda scope: scope.id))
                        for address, scopes in addresses.items()
                    }
                    for prefix, addresses in source.items()
                }

            identities = {
                str(row["client_ip"]): str(row["client_name"])
                for row in con.execute(
                    "SELECT client_ip,client_name FROM client_identities"
                )
            }

        new_snapshot = PolicySnapshot(
            blocklists=blocklists,
            list_order=tuple(list_order),
            bit_for_list_id=bit_for_list_id,
            domain_masks=domain_masks,
            global_list_mask=global_list_mask,
            whitelist_mask=whitelist_mask,
            block_mask=block_mask,
            client_scopes=freeze_scope_map(client_build),
            exact_hostname_scopes=freeze_scope_map(exact_hostname_build),
            wildcard_hostname_scopes=freeze_scope_map(wildcard_hostname_build),
            wildcard_suffixes=tuple(
                sorted(
                    wildcard_hostname_build,
                    key=lambda value: (-len(value), value),
                )
            ),
            network_scopes_v4=freeze_network_map(network_build_v4),
            network_scopes_v6=freeze_network_map(network_build_v6),
            network_prefixes_v4=tuple(sorted(network_build_v4, reverse=True)),
            network_prefixes_v6=tuple(sorted(network_build_v6, reverse=True)),
            client_identities=identities,
            global_blocking=settings.get("global_blocking", "1") == "1",
            response_mode=settings.get("block_response", "nxdomain"),
            unmatched_scope_action=(
                settings.get("unmatched_scope_action", "allow")
                if settings.get("unmatched_scope_action", "allow") in {"allow", "deny"}
                else "allow"
            ),
            global_blocklist_scope_mode=(
                settings.get("global_blocklist_scope_mode", "all_clients")
                if settings.get("global_blocklist_scope_mode", "all_clients")
                in {"all_clients", "matched_scopes"}
                else "all_clients"
            ),
            unique_domain_count=unique_domain_count,
            block_domain_count=block_domain_count,
            whitelist_domain_count=whitelist_domain_count,
            client_scope_count=client_scope_count,
            hostname_scope_count=hostname_scope_count,
            network_scope_count=network_scope_count,
        )

        # The expensive rebuild occurs without blocking DNS decisions. The short
        # critical section only merges identities learned while we were rebuilding
        # and swaps the immutable snapshot reference.
        with self._write_lock:
            current_identities = self._snapshot.client_identities
            if current_identities:
                merged = dict(new_snapshot.client_identities)
                merged.update(current_identities)
                new_snapshot = replace(new_snapshot, client_identities=merged)
            self._snapshot = new_snapshot
            self._active_list_cache = (None, -1, 0)

        self.logger.queue_rdns(new_snapshot.client_scopes.keys())

    @staticmethod
    def suffixes(domain: str) -> tuple[str, ...]:
        d = domain.lower().rstrip(".")
        parts = d.split(".")
        return tuple(
            ".".join(parts[index:])
            for index in range(max(1, len(parts) - 1))
        )

    @staticmethod
    def _first_scheduled_scope(
        scopes: tuple[Scope, ...] | None,
        now_utc: datetime,
    ) -> Scope | None:
        if not scopes:
            return None
        for scope in scopes:
            if scope.schedule_is_active(now_utc):
                return scope
        return None

    def _matching_scopes(
        self,
        snapshot: PolicySnapshot,
        ip: ipaddress._BaseAddress,
        now_utc: datetime,
    ) -> tuple[Scope | None, Scope | None, Scope | None]:
        canonical_ip = str(ip)
        client = self._first_scheduled_scope(
            snapshot.client_scopes.get(canonical_ip),
            now_utc,
        )

        hostname: Scope | None = None
        client_name = snapshot.client_identities.get(canonical_ip)
        if client_name:
            hostname = self._first_scheduled_scope(
                snapshot.exact_hostname_scopes.get(client_name),
                now_utc,
            )
            if hostname is None:
                for suffix in snapshot.wildcard_suffixes:
                    if client_name.endswith("." + suffix):
                        hostname = self._first_scheduled_scope(
                            snapshot.wildcard_hostname_scopes.get(suffix),
                            now_utc,
                        )
                        if hostname is not None:
                            break

        network: Scope | None = None
        family_map = (
            snapshot.network_scopes_v4
            if ip.version == 4
            else snapshot.network_scopes_v6
        )
        prefixes = (
            snapshot.network_prefixes_v4
            if ip.version == 4
            else snapshot.network_prefixes_v6
        )
        width = 32 if ip.version == 4 else 128
        ip_value = int(ip)
        for prefix in prefixes:
            shift = width - prefix
            network_value = (ip_value >> shift) << shift if shift else ip_value
            candidate = self._first_scheduled_scope(
                family_map[prefix].get(network_value),
                now_utc,
            )
            if candidate is not None:
                network = candidate
                break

        return client, hostname, network

    def _active_list_mask(
        self,
        snapshot: PolicySnapshot,
        now_utc: datetime,
    ) -> int:
        minute = int(now_utc.timestamp() // 60)
        cached_snapshot, cached_minute, cached_mask = self._active_list_cache
        if cached_snapshot is snapshot and cached_minute == minute:
            return cached_mask

        mask = 0
        for index, blocklist in enumerate(snapshot.list_order):
            if blocklist.enabled and blocklist.schedule_is_active(now_utc):
                mask |= 1 << index

        # Races only cause a harmless duplicate calculation; readers never depend
        # on this cache for correctness.
        self._active_list_cache = (snapshot, minute, mask)
        return mask

    @staticmethod
    def _lowest_bit(mask: int) -> int:
        return mask & -mask

    def _matched_list(
        self,
        snapshot: PolicySnapshot,
        suffix_masks: tuple[tuple[str, int], ...],
        combined_mask: int,
        active_mask: int,
        type_mask: int,
    ) -> tuple[BlockListCache, str] | None:
        matches = combined_mask & active_mask & type_mask
        if not matches:
            return None

        bit = self._lowest_bit(matches)
        index = bit.bit_length() - 1
        blocklist = snapshot.list_order[index]
        matched_domain = next(
            suffix
            for suffix, mask in suffix_masks
            if mask & bit
        )
        return blocklist, matched_domain

    def known_client_name(self, client_ip: str) -> str | None:
        return self._snapshot.client_identities.get(str(client_ip))

    def decide(
        self,
        client_ip: str,
        qname: str,
        now_utc: datetime | None = None,
    ) -> Decision:
        snapshot = self._snapshot
        try:
            ip = ipaddress.ip_address(client_ip)
        except ValueError:
            return Decision(
                False,
                "invalid_client_ip",
                response_mode=snapshot.response_mode,
            )

        now = now_utc or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        if not snapshot.global_blocking:
            return Decision(
                False,
                "global_paused",
                response_mode=snapshot.response_mode,
            )

        client_scope, hostname_scope, network_scope = self._matching_scopes(
            snapshot,
            ip,
            now,
        )

        if client_scope is not None:
            if client_scope.state == "paused":
                return Decision(
                    False,
                    "client_paused",
                    client_scope.name,
                    response_mode=snapshot.response_mode,
                )
            effective_scope = client_scope.name
        elif hostname_scope is not None:
            if hostname_scope.state == "paused":
                return Decision(
                    False,
                    "hostname_paused",
                    hostname_scope.name,
                    response_mode=snapshot.response_mode,
                )
            effective_scope = hostname_scope.name
        elif network_scope is not None:
            if network_scope.state == "paused":
                return Decision(
                    False,
                    "network_paused",
                    network_scope.name,
                    response_mode=snapshot.response_mode,
                )
            effective_scope = network_scope.name
        else:
            effective_scope = None

        scheduled_mask = self._active_list_mask(snapshot, now)
        candidate_mask = 0
        if (
            snapshot.global_blocklist_scope_mode == "all_clients"
            or effective_scope is not None
        ):
            candidate_mask |= snapshot.global_list_mask
        if network_scope is not None:
            candidate_mask |= network_scope.blocklist_mask
        if hostname_scope is not None:
            candidate_mask |= hostname_scope.blocklist_mask
        if client_scope is not None:
            candidate_mask |= client_scope.blocklist_mask

        active_mask = candidate_mask & scheduled_mask
        if not active_mask:
            if (
                effective_scope is None
                and snapshot.unmatched_scope_action == "deny"
            ):
                return Decision(
                    True,
                    "no_scope_default_deny",
                    response_mode=snapshot.response_mode,
                )
            return Decision(
                False,
                "no_active_lists",
                effective_scope,
                response_mode=snapshot.response_mode,
            )

        suffixes = self.suffixes(qname)
        suffix_masks = tuple(
            (suffix, snapshot.domain_masks.get(suffix, 0))
            for suffix in suffixes
        )
        combined_domain_mask = 0
        for _suffix, mask in suffix_masks:
            combined_domain_mask |= mask

        whitelist_match = self._matched_list(
            snapshot,
            suffix_masks,
            combined_domain_mask,
            active_mask,
            snapshot.whitelist_mask,
        )
        if whitelist_match is not None:
            blocklist, matched_domain = whitelist_match
            return Decision(
                False,
                "whitelist_match",
                effective_scope,
                blocklist.name,
                matched_domain,
                snapshot.response_mode,
                "whitelist",
            )

        block_match = self._matched_list(
            snapshot,
            suffix_masks,
            combined_domain_mask,
            active_mask,
            snapshot.block_mask,
        )
        if block_match is not None:
            blocklist, matched_domain = block_match
            return Decision(
                True,
                "blocklist_match",
                effective_scope,
                blocklist.name,
                matched_domain,
                snapshot.response_mode,
                "block",
            )

        if (
            effective_scope is None
            and snapshot.unmatched_scope_action == "deny"
        ):
            return Decision(
                True,
                "no_scope_default_deny",
                response_mode=snapshot.response_mode,
            )
        return Decision(
            False,
            "not_listed",
            effective_scope,
            response_mode=snapshot.response_mode,
        )

    def decide_with_log_row(
        self,
        request_obj: dict[str, Any],
        policy_scheme: str | None = None,
    ) -> tuple[Decision, dict[str, Any]]:
        """Evaluate a policy request and build its asynchronous log record.

        The API endpoint uses this form so response timing can be attached after
        the final ASGI response body has actually been sent.
        """
        client = request_obj.get("client") or {}
        dns = request_obj.get("dns") or {}
        questions = dns.get("questions") or []
        client_ip = str(client.get("ip", ""))

        decision: Decision | None = None
        matched_question: dict[str, Any] = questions[0] if questions else {}
        if questions:
            now = datetime.now(timezone.utc)
            for question in questions:
                candidate = self.decide(
                    client_ip,
                    str(question.get("name", "")),
                    now_utc=now,
                )
                if decision is None:
                    decision = candidate
                if candidate.block:
                    decision = candidate
                    matched_question = question
                    break
        else:
            decision = Decision(
                False,
                "no_question",
                response_mode=self._snapshot.response_mode,
            )

        assert decision is not None
        log_row = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "server_id": request_obj.get("server_id"),
            "client_ip": client_ip,
            "client_name": self.known_client_name(client_ip),
            "client_port": client.get("port"),
            "protocol": request_obj.get("protocol"),
            "policy_scheme": policy_scheme,
            "qname": matched_question.get("name"),
            "qtype": matched_question.get("type"),
            "qclass": matched_question.get("class"),
            "blocked": decision.block,
            "reason": decision.reason,
            "matched_scope": decision.matched_scope,
            "matched_list": decision.matched_list,
            "matched_list_type": decision.matched_list_type,
            "response_time_ms": None,
            # Serialize the original payload off the request thread.
            "request_obj": request_obj if self.logger.capture_request_json else None,
        }
        return decision, log_row

    def decide_and_log(
        self,
        request_obj: dict[str, Any],
        policy_scheme: str | None = None,
    ) -> Decision:
        decision, log_row = self.decide_with_log_row(
            request_obj,
            policy_scheme=policy_scheme,
        )
        self.logger.submit(log_row)
        return decision
