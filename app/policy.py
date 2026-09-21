from __future__ import annotations

import ipaddress
import json
import queue
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .db import Database
from .rdns import ReverseDnsResolver


def _schedule_window_is_active(
    enabled: bool,
    days: frozenset[int],
    start_text: str,
    end_text: str,
    timezone_name: str,
    now_utc: datetime | None = None,
) -> bool:
    if not enabled:
        return True
    if not days:
        return False

    try:
        tz = ZoneInfo(timezone_name)
        start = time.fromisoformat(start_text)
        end = time.fromisoformat(end_text)
    except (ValueError, ZoneInfoNotFoundError):
        return False

    current = (now_utc or datetime.now(timezone.utc)).astimezone(tz)
    current_time = current.time().replace(tzinfo=None)
    weekday = current.weekday()

    if start == end:
        return weekday in days
    if start < end:
        return weekday in days and start <= current_time < end

    if weekday in days and current_time >= start:
        return True
    previous_weekday = (weekday - 1) % 7
    return previous_weekday in days and current_time < end


def _prune_query_logs(
    con: sqlite3.Connection,
    max_rows: int,
    max_age_days: int,
    now_utc: datetime | None = None,
) -> tuple[int, int]:
    """Prune query logs by age and row count.

    Both limits apply when enabled. A max_age_days value of 0 disables
    time-based retention while preserving the row cap.
    """
    age_deleted = 0
    row_deleted = 0

    if max_age_days > 0:
        cutoff = (now_utc or datetime.now(timezone.utc)) - timedelta(days=max_age_days)
        cur = con.execute(
            "DELETE FROM query_log WHERE datetime(ts) < datetime(?)",
            (cutoff.isoformat(),),
        )
        age_deleted = max(0, cur.rowcount)

    if max_rows > 0:
        cur = con.execute(
            "DELETE FROM query_log "
            "WHERE id <= (SELECT COALESCE(MAX(id),0)-? FROM query_log)",
            (max_rows,),
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
    network: ipaddress._BaseNetwork
    blocklist_ids: frozenset[int]
    schedule_enabled: bool = False
    schedule_days: frozenset[int] = frozenset(range(7))
    schedule_start: str = "00:00"
    schedule_end: str = "00:00"
    schedule_timezone: str = "UTC"

    def schedule_is_active(self, now_utc: datetime | None = None) -> bool:
        return _schedule_window_is_active(
            self.schedule_enabled,
            self.schedule_days,
            self.schedule_start,
            self.schedule_end,
            self.schedule_timezone,
            now_utc,
        )


@dataclass(frozen=True, slots=True)
class BlockListCache:
    id: int
    name: str
    enabled: bool
    use_globally: bool
    domains: frozenset[str]
    schedule_enabled: bool = False
    schedule_days: frozenset[int] = frozenset(range(7))
    schedule_start: str = "00:00"
    schedule_end: str = "00:00"
    schedule_timezone: str = "UTC"

    def schedule_is_active(self, now_utc: datetime | None = None) -> bool:
        return _schedule_window_is_active(
            self.schedule_enabled,
            self.schedule_days,
            self.schedule_start,
            self.schedule_end,
            self.schedule_timezone,
            now_utc,
        )


@dataclass(slots=True)
class Decision:
    block: bool
    reason: str
    matched_scope: str | None = None
    matched_list: str | None = None
    matched_domain: str | None = None
    response_mode: str = "nxdomain"


class QueryLogger:
    def __init__(self, db: Database) -> None:
        self.db = db
        self.rdns = ReverseDnsResolver()
        self.q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=10000)
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="query-log-writer", daemon=True)
        self.thread.start()

    def submit(self, row: dict[str, Any]) -> None:
        try:
            self.q.put_nowait(row)
        except queue.Full:
            pass

    def close(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=2.0)

    def prune_now(self, now_utc: datetime | None = None) -> tuple[int, int]:
        max_rows = int(self.db.get_setting("max_query_logs", "25000"))
        max_age_days = int(self.db.get_setting("max_query_log_age_days", "0"))
        with self.db.connect() as con:
            con.execute("BEGIN")
            result = _prune_query_logs(con, max_rows, max_age_days, now_utc)
            con.execute("COMMIT")
        return result

    def _run(self) -> None:
        while not self.stop_event.is_set():
            batch: list[dict[str, Any]] = []
            try:
                batch.append(self.q.get(timeout=1.0))
            except queue.Empty:
                continue
            while len(batch) < 250:
                try:
                    batch.append(self.q.get_nowait())
                except queue.Empty:
                    break
            try:
                client_names = self.rdns.resolve_many(r["client_ip"] for r in batch)
                with self.db.connect() as con:
                    con.execute("BEGIN")
                    con.executemany(
                        """
                        INSERT INTO query_log(
                          ts,server_id,client_ip,client_name,client_port,protocol,qname,qtype,qclass,
                          blocked,reason,matched_scope,matched_list,request_json
                        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        [
                            (
                                r["ts"], r.get("server_id"), r["client_ip"],
                                client_names.get(str(r["client_ip"])),
                                r.get("client_port"), r.get("protocol"), r.get("qname"),
                                r.get("qtype"), r.get("qclass"), 1 if r["blocked"] else 0,
                                r.get("reason"), r.get("matched_scope"), r.get("matched_list"),
                                r.get("request_json"),
                            ) for r in batch
                        ],
                    )
                    for client_ip, client_name in client_names.items():
                        if client_name:
                            con.execute(
                                """
                                UPDATE query_log
                                SET client_name=?
                                WHERE client_ip=? AND (client_name IS NULL OR client_name='')
                                """,
                                (client_name, client_ip),
                            )
                    max_rows = int(self.db.get_setting("max_query_logs", "25000"))
                    max_age_days = int(self.db.get_setting("max_query_log_age_days", "0"))
                    _prune_query_logs(con, max_rows, max_age_days)
                    con.execute("COMMIT")
            except Exception:
                # Logging must never interfere with DNS decisions.
                pass


class PolicyEngine:
    def __init__(self, db: Database) -> None:
        self.db = db
        self.lock = threading.RLock()
        self.blocklists: dict[int, BlockListCache] = {}
        self.client_scopes: list[Scope] = []
        self.network_scopes: list[Scope] = []
        self.global_blocking = True
        self.response_mode = "nxdomain"
        self.logger = QueryLogger(db)
        self.reload()

    def close(self) -> None:
        self.logger.close()

    def reload(self) -> None:
        with self.db.connect() as con:
            settings = {r["key"]: r["value"] for r in con.execute("SELECT key,value FROM settings")}
            list_rows = con.execute("SELECT * FROM blocklists").fetchall()
            memberships: dict[int, set[int]] = {}
            for r in con.execute("SELECT scope_id,blocklist_id FROM scope_blocklists"):
                memberships.setdefault(r["scope_id"], set()).add(r["blocklist_id"])
            new_lists: dict[int, BlockListCache] = {}
            for r in list_rows:
                domains = frozenset(
                    x["domain"] for x in con.execute(
                        "SELECT domain FROM block_entries WHERE blocklist_id=?", (r["id"],)
                    )
                ) if r["enabled"] else frozenset()
                schedule_days: set[int] = set()
                for value in str(r["schedule_days"] or "").split(","):
                    try:
                        day = int(value)
                    except ValueError:
                        continue
                    if 0 <= day <= 6:
                        schedule_days.add(day)
                new_lists[r["id"]] = BlockListCache(
                    id=r["id"], name=r["name"], enabled=bool(r["enabled"]),
                    use_globally=bool(r["use_globally"]), domains=domains,
                    schedule_enabled=bool(r["schedule_enabled"]),
                    schedule_days=frozenset(schedule_days),
                    schedule_start=str(r["schedule_start"] or "00:00"),
                    schedule_end=str(r["schedule_end"] or "00:00"),
                    schedule_timezone=str(r["schedule_timezone"] or "UTC"),
                )
            clients: list[Scope] = []
            networks: list[Scope] = []
            for r in con.execute("SELECT * FROM scopes"):
                try:
                    if r["kind"] == "client":
                        ip = ipaddress.ip_address(r["target"])
                        net = ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False)
                    else:
                        net = ipaddress.ip_network(r["target"], strict=False)
                except ValueError:
                    continue
                scope_days: set[int] = set()
                for value in str(r["schedule_days"] or "").split(","):
                    try:
                        day = int(value)
                    except ValueError:
                        continue
                    if 0 <= day <= 6:
                        scope_days.add(day)
                s = Scope(
                    id=r["id"], name=r["name"], kind=r["kind"], target=r["target"],
                    state=r["state"], network=net,
                    blocklist_ids=frozenset(memberships.get(r["id"], set())),
                    schedule_enabled=bool(r["schedule_enabled"]),
                    schedule_days=frozenset(scope_days),
                    schedule_start=str(r["schedule_start"] or "00:00"),
                    schedule_end=str(r["schedule_end"] or "00:00"),
                    schedule_timezone=str(r["schedule_timezone"] or "UTC"),
                )
                (clients if s.kind == "client" else networks).append(s)
            networks.sort(key=lambda s: s.network.prefixlen, reverse=True)

        with self.lock:
            self.blocklists = new_lists
            self.client_scopes = clients
            self.network_scopes = networks
            self.global_blocking = settings.get("global_blocking", "1") == "1"
            self.response_mode = settings.get("block_response", "nxdomain")

    @staticmethod
    def suffixes(domain: str) -> list[str]:
        d = domain.lower().rstrip(".")
        parts = d.split(".")
        # Avoid matching a top-level domain as an imported entry.
        return [".".join(parts[i:]) for i in range(max(1, len(parts) - 1))]

    def _matching_scopes(
        self,
        ip: ipaddress._BaseAddress,
        now_utc: datetime | None = None,
    ) -> tuple[Scope | None, Scope | None]:
        client = next(
            (
                s
                for s in self.client_scopes
                if ip in s.network and s.schedule_is_active(now_utc)
            ),
            None,
        )
        network = next(
            (
                s
                for s in self.network_scopes
                if ip.version == s.network.version
                and ip in s.network
                and s.schedule_is_active(now_utc)
            ),
            None,
        )
        return client, network

    def decide(self, client_ip: str, qname: str, now_utc: datetime | None = None) -> Decision:
        try:
            ip = ipaddress.ip_address(client_ip)
        except ValueError:
            return Decision(False, "invalid_client_ip", response_mode=self.response_mode)
        domain = qname.lower().rstrip(".")

        with self.lock:
            if not self.global_blocking:
                return Decision(False, "global_paused", response_mode=self.response_mode)

            client_scope, network_scope = self._matching_scopes(ip, now_utc)
            if client_scope is not None:
                if client_scope.state == "paused":
                    return Decision(False, "client_paused", client_scope.name, response_mode=self.response_mode)
                effective_scope = client_scope.name
            elif network_scope is not None:
                if network_scope.state == "paused":
                    return Decision(False, "network_paused", network_scope.name, response_mode=self.response_mode)
                effective_scope = network_scope.name
            else:
                effective_scope = None

            active_ids = {
                lid
                for lid, bl in self.blocklists.items()
                if bl.enabled and bl.use_globally and bl.schedule_is_active(now_utc)
            }
            if network_scope is not None:
                active_ids.update(network_scope.blocklist_ids)
            if client_scope is not None:
                active_ids.update(client_scope.blocklist_ids)
            active_ids = {
                lid
                for lid in active_ids
                if lid in self.blocklists
                and self.blocklists[lid].enabled
                and self.blocklists[lid].schedule_is_active(now_utc)
            }

            if not active_ids:
                return Decision(False, "no_active_lists", effective_scope, response_mode=self.response_mode)

            suffixes = self.suffixes(domain)
            for lid in sorted(active_ids):
                bl = self.blocklists[lid]
                for suffix in suffixes:
                    if suffix in bl.domains:
                        return Decision(
                            True, "blocklist_match", effective_scope, bl.name, suffix, self.response_mode
                        )
            return Decision(False, "not_listed", effective_scope, response_mode=self.response_mode)

    def decide_and_log(self, request_obj: dict[str, Any]) -> Decision:
        client = request_obj.get("client") or {}
        dns = request_obj.get("dns") or {}
        questions = dns.get("questions") or []
        client_ip = str(client.get("ip", ""))

        # DNS normally carries one question, but evaluate every question supplied.
        # The first blocking match wins; otherwise keep the first allow decision.
        decision: Decision | None = None
        matched_question: dict[str, Any] = questions[0] if questions else {}
        if questions:
            for q in questions:
                candidate = self.decide(client_ip, str(q.get("name", "")))
                if decision is None:
                    decision = candidate
                if candidate.block:
                    decision = candidate
                    matched_question = q
                    break
        else:
            decision = Decision(False, "no_question", response_mode=self.response_mode)

        assert decision is not None
        self.logger.submit({
            "ts": datetime.now(timezone.utc).isoformat(),
            "server_id": request_obj.get("server_id"),
            "client_ip": client_ip,
            "client_port": client.get("port"),
            "protocol": request_obj.get("protocol"),
            "qname": matched_question.get("name"),
            "qtype": matched_question.get("type"),
            "qclass": matched_question.get("class"),
            "blocked": decision.block,
            "reason": decision.reason,
            "matched_scope": decision.matched_scope,
            "matched_list": decision.matched_list,
            "request_json": json.dumps(request_obj, separators=(",", ":"), ensure_ascii=False),
        })
        return decision
