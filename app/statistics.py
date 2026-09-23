from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .db import Database


STATISTICS_WINDOWS = {15, 60, 360, 1440}


def normalize_statistics_window(minutes: int) -> int:
    return minutes if minutes in STATISTICS_WINDOWS else 60


def statistics_bucket_minutes(minutes: int) -> int:
    if minutes <= 60:
        return 1
    if minutes <= 360:
        return 5
    return 15


def _parse_utc_minute(value: str) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        if len(raw) == 16:
            parsed = datetime.fromisoformat(raw + ":00+00:00")
        else:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(second=0, microsecond=0)


def build_statistics_snapshot(
    db: Database,
    minutes: int = 60,
    timezone_name: str = "UTC",
    now_utc: datetime | None = None,
) -> dict:
    minutes = normalize_statistics_window(int(minutes))
    bucket_minutes = statistics_bucket_minutes(minutes)
    current = now_utc or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)
    end_minute = current.replace(second=0, microsecond=0)
    start_minute = end_minute - timedelta(minutes=minutes - 1)

    try:
        display_tz = ZoneInfo(timezone_name)
    except (ValueError, ZoneInfoNotFoundError):
        timezone_name = "UTC"
        display_tz = ZoneInfo("UTC")

    cutoff = start_minute.isoformat()

    with db.connect() as con:
        totals = con.execute(
            """
            SELECT
              COUNT(*) AS queries,
              COALESCE(SUM(blocked),0) AS blocks,
              AVG(response_time_ms) AS average_response_time_ms
            FROM query_log
            """
        ).fetchone()
        minute_rows = con.execute(
            """
            SELECT
              SUBSTR(ts,1,16) AS minute_key,
              COUNT(*) AS queries,
              COALESCE(SUM(blocked),0) AS blocks,
              AVG(response_time_ms) AS average_response_time_ms,
              COUNT(response_time_ms) AS response_samples
            FROM query_log
            WHERE ts >= ?
            GROUP BY SUBSTR(ts,1,16)
            ORDER BY minute_key
            """,
            (cutoff,),
        ).fetchall()

    raw_minutes: dict[datetime, tuple[int, int, float | None, int]] = {}
    for row in minute_rows:
        minute = _parse_utc_minute(row["minute_key"])
        if minute is None or minute < start_minute or minute > end_minute:
            continue
        average = row["average_response_time_ms"]
        raw_minutes[minute] = (
            int(row["queries"] or 0),
            int(row["blocks"] or 0),
            float(average) if average is not None else None,
            int(row["response_samples"] or 0),
        )

    points: list[dict] = []
    bucket_start = start_minute
    while bucket_start <= end_minute:
        queries = 0
        blocks = 0
        weighted_response_total = 0.0
        response_samples = 0

        for offset in range(bucket_minutes):
            minute = bucket_start + timedelta(minutes=offset)
            if minute > end_minute:
                break
            sample = raw_minutes.get(minute)
            if sample is None:
                continue
            (
                minute_queries,
                minute_blocks,
                minute_average,
                minute_response_samples,
            ) = sample
            queries += minute_queries
            blocks += minute_blocks
            if minute_average is not None and minute_response_samples > 0:
                weighted_response_total += (
                    minute_average * minute_response_samples
                )
                response_samples += minute_response_samples

        local = bucket_start.astimezone(display_tz)
        points.append(
            {
                "timestamp": bucket_start.isoformat(),
                "label": local.strftime("%H:%M"),
                "queries": queries,
                "blocks": blocks,
                "average_response_time_ms": (
                    weighted_response_total / response_samples
                    if response_samples
                    else None
                ),
            }
        )
        bucket_start += timedelta(minutes=bucket_minutes)

    average_total = totals["average_response_time_ms"] if totals else None
    return {
        "generated_at": current.isoformat(),
        "timezone": timezone_name,
        "window_minutes": minutes,
        "bucket_minutes": bucket_minutes,
        "totals": {
            "queries": int(totals["queries"] or 0) if totals else 0,
            "blocks": int(totals["blocks"] or 0) if totals else 0,
            "average_response_time_ms": (
                float(average_total) if average_total is not None else None
            ),
        },
        "points": points,
    }
