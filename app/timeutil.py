from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def parse_utc_timestamp(value: str | None) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None

    candidate = raw
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None

    # SQLite CURRENT_TIMESTAMP values are UTC but have no explicit offset.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_timestamp_for_timezone(
    value: str | None,
    timezone_name: str,
) -> str:
    parsed = parse_utc_timestamp(value)
    if parsed is None:
        return str(value or "")

    try:
        tz = ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError):
        tz = timezone.utc

    local = parsed.astimezone(tz)
    # Example: 2026-09-21 4:43:34 PM EDT
    return local.strftime("%Y-%m-%d %-I:%M:%S %p %Z")
