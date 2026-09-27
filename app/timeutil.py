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


def query_range_bound(value: str, timezone_name: str, *, end: bool = False) -> str | None:
    """Convert a wall-clock input to an indexed UTC boundary (end is exclusive)."""
    import re
    from datetime import timedelta

    if not value:
        return None
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?", value):
        raise ValueError("Use a date and time in YYYY-MM-DDTHH:MM:SS format")
    try:
        local = datetime.fromisoformat(value)
        tz = ZoneInfo(timezone_name)
        # On fall-back days include both occurrences of an ambiguous wall time.
        aware = local.replace(tzinfo=tz, fold=1 if end else 0)
        utc = aware.astimezone(timezone.utc)
        if utc.astimezone(tz).replace(tzinfo=None) != local:
            raise ValueError("This local time does not exist because of a daylight-saving transition")
        if end:
            utc += timedelta(seconds=1)
        return utc.isoformat(timespec="seconds")
    except (OverflowError, ZoneInfoNotFoundError) as exc:
        raise ValueError("Date/time is outside the supported range") from exc
