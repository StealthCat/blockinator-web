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
    # Keep the display portable across platforms while avoiding a leading zero
    # in the 12-hour clock.
    date_part = local.strftime("%Y-%m-%d")
    hour = str(int(local.strftime("%I")))
    time_part = local.strftime(":%M:%S %p %Z")
    return f"{date_part} {hour}{time_part}"
