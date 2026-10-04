"""Read-only policy explanations and schedule status for the console."""
import ipaddress
from dataclasses import asdict
from datetime import datetime, time, timedelta, timezone

from .policy import _compile_schedule, _parse_schedule_days


def next_transition(schedule, now):
    if not schedule.enabled or not schedule.valid or not schedule.timezone or not schedule.days:
        return None
    local = now.astimezone(schedule.timezone)
    candidates = set()
    # Include hourly boundaries to handle clocks jumping over a nonexistent
    # local start/end time. Both folds cover repeated times in autumn.
    times = {schedule.start, schedule.end, *(time(hour, 0) for hour in range(24))}
    for offset in range(9):
        day = local.date() + timedelta(days=offset)
        for wall_time in times:
            for fold in (0, 1):
                candidate = datetime.combine(day, wall_time, schedule.timezone).replace(fold=fold).astimezone(timezone.utc)
                if candidate > now:
                    candidates.add(candidate)
    for candidate in sorted(candidates):
        if schedule.is_active(candidate - timedelta(microseconds=1)) != schedule.is_active(candidate):
            return candidate
    return None


def target_status(row, global_blocking=True, now=None):
    now = now or datetime.now(timezone.utc)
    schedule = _compile_schedule(bool(row["schedule_enabled"]), _parse_schedule_days(row["schedule_days"]),
                                 row["schedule_start"], row["schedule_end"], row["schedule_timezone"])
    if not global_blocking:
        label = "Global blocking paused"
    elif schedule.enabled and not schedule.valid:
        label = "Invalid schedule — inactive"
    elif not schedule.is_active(now):
        label = "Outside schedule"
    elif row["whitelisted"]:
        label = "Whitelisted now"
    elif row["state"] == "paused":
        label = "Blocking paused"
    else:
        label = "Filtering active"
    return label, next_transition(schedule, now)


def inspect_policy(engine, client_ip, qname, qtype, now=None):
    """Evaluate the same immutable snapshot as the trace; never log or resolve."""
    now = now or datetime.now(timezone.utc)
    snapshot = engine.snapshot
    ip = ipaddress.ip_address(client_ip)
    hostname = snapshot.client_identities.get(str(ip))
    scopes = {}
    for mapping in (snapshot.client_scopes, snapshot.exact_hostname_scopes, snapshot.wildcard_hostname_scopes):
        for entries in mapping.values():
            for scope in entries:
                scopes[scope.id] = scope
    for family in (snapshot.network_scopes_v4, snapshot.network_scopes_v6):
        for networks in family.values():
            for entries in networks.values():
                for scope in entries:
                    scopes[scope.id] = scope
    matching = []
    for scope in scopes.values():
        matches = (scope.kind == "client" and scope.target == str(ip)) or (
            scope.kind == "network" and any(ip.version == network.version and ip in network for network in scope.networks)) or (
            scope.kind == "hostname" and hostname and (hostname == scope.target or
                (scope.target.startswith("*.") and hostname.endswith(scope.target[1:]))))
        if matches:
            matching.append({"id": scope.id, "name": scope.name, "kind": scope.kind,
                             "target": scope.target, "state": scope.state, "whitelisted": scope.whitelisted,
                             "schedule_active": scope.schedule.is_active(now),
                             "schedule_valid": scope.schedule.valid,
                             "timezone": str(scope.schedule.timezone or "Invalid"),
                             "schedule_start": scope.schedule.start.isoformat(timespec="minutes"),
                             "schedule_end": scope.schedule.end.isoformat(timespec="minutes"),
                             "scheduled": scope.schedule.enabled})
    selected = engine._matching_scopes(snapshot, ip, now)
    candidate_mask = engine._candidate_list_mask(snapshot, selected)
    suffixes = engine.suffixes(qname)
    lists = []
    for index, item in enumerate(snapshot.list_order):
        bit = 1 << index
        matched = next((suffix for suffix in suffixes if snapshot.domain_masks.get(suffix, 0) & bit), None)
        if candidate_mask & bit:
            lists.append({"id": item.id, "name": item.name, "type": item.list_type,
                          "enabled": item.enabled, "schedule_active": item.schedule_is_active(now),
                          "matched_domain": matched, "timezone": str(item.schedule.timezone or "Invalid")})
    ignored = qtype.upper() in snapshot.ignored_record_types
    result = {"block": False, "reason": "ignored_record_type"} if ignored else asdict(
        engine.decide(str(ip), qname, now, snapshot=snapshot))
    return {"decision": result, "hostname": hostname, "time": now.isoformat(),
            "scopes": sorted(matching, key=lambda row: row["id"]), "lists": lists,
            "global_blocking": snapshot.global_blocking, "ignored": ignored,
            "unmatched_scope_action": snapshot.unmatched_scope_action}
