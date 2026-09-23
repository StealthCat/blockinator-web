from datetime import datetime, timezone
from pathlib import Path
import tempfile

from app.db import Database
from app.statistics import build_statistics_snapshot


def test_statistics_snapshot_reports_totals_and_live_series():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "statistics.db"))

    with db.connect() as con:
        con.executemany(
            """
            INSERT INTO query_log(
                ts,client_ip,qname,blocked,response_time_ms
            ) VALUES(?,?,?,?,?)
            """,
            [
                ("2026-09-23T17:59:05+00:00", "192.0.2.1", "a.example", 1, 2.0),
                ("2026-09-23T17:59:35+00:00", "192.0.2.2", "b.example", 0, 4.0),
                ("2026-09-23T17:58:10+00:00", "192.0.2.3", "c.example", 0, None),
                ("2026-09-23T15:00:00+00:00", "192.0.2.4", "old.example", 1, 10.0),
            ],
        )

    snapshot = build_statistics_snapshot(
        db,
        minutes=60,
        timezone_name="UTC",
        now_utc=datetime(2026, 9, 23, 18, 0, tzinfo=timezone.utc),
    )

    assert snapshot["totals"]["queries"] == 4
    assert snapshot["totals"]["blocks"] == 2
    assert abs(snapshot["totals"]["average_response_time_ms"] - (16.0 / 3.0)) < 0.000001
    assert snapshot["window_minutes"] == 60
    assert snapshot["bucket_minutes"] == 1
    assert len(snapshot["points"]) == 60

    point = next(
        row for row in snapshot["points"]
        if row["timestamp"].startswith("2026-09-23T17:59")
    )
    assert point["queries"] == 2
    assert point["blocks"] == 1
    assert point["average_response_time_ms"] == 3.0
    assert point["label"] == "17:59"

    td.cleanup()


def test_statistics_window_uses_larger_buckets_for_long_ranges():
    td = tempfile.TemporaryDirectory()
    db = Database(str(Path(td.name) / "statistics.db"))

    snapshot = build_statistics_snapshot(
        db,
        minutes=360,
        timezone_name="UTC",
        now_utc=datetime(2026, 9, 23, 18, 0, tzinfo=timezone.utc),
    )

    assert snapshot["bucket_minutes"] == 5
    assert len(snapshot["points"]) == 72
    td.cleanup()


def test_statistics_page_is_present_in_navigation_and_has_live_chart_controls():
    source = Path("app/main.py").read_text(encoding="utf-8")
    javascript = Path("app/static/app.js").read_text(encoding="utf-8")

    assert '("/statistics", "statistics", "Statistics", "∿")' in source
    assert '@app.get("/statistics", response_class=HTMLResponse)' in source
    assert '@app.get("/api/v1/statistics")' in source
    assert 'data-statistics-chart' in source
    assert 'data-statistics-total="queries"' in source
    assert 'data-statistics-total="blocks"' in source
    assert 'data-statistics-total="response"' in source
    assert 'data-statistics-window="1440"' in source
    assert 'Average response time</span>' in source
    assert 'statistics-series-response' in javascript
    assert 'average_response_time_ms' in javascript
    assert 'initializeStatisticsDashboard' in javascript
    assert 'setInterval(load, 5000)' in javascript
