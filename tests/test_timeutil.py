from app.timeutil import format_timestamp_for_timezone, parse_utc_timestamp


def test_iso_utc_timestamp_converts_to_configured_timezone():
    rendered = format_timestamp_for_timezone(
        "2026-09-21T20:43:34+00:00",
        "America/New_York",
    )
    assert rendered == "2026-09-21 4:43:34 PM EDT"


def test_legacy_sqlite_timestamp_is_treated_as_utc():
    rendered = format_timestamp_for_timezone(
        "2026-01-15 20:43:34",
        "America/New_York",
    )
    assert rendered == "2026-01-15 3:43:34 PM EST"


def test_timestamp_parser_normalizes_to_utc():
    parsed = parse_utc_timestamp("2026-09-21T16:43:34-04:00")
    assert parsed is not None
    assert parsed.isoformat() == "2026-09-21T20:43:34+00:00"


def test_invalid_display_timezone_falls_back_to_utc():
    rendered = format_timestamp_for_timezone(
        "2026-09-21T20:43:34+00:00",
        "Not/A_Real_Zone",
    )
    assert rendered == "2026-09-21 8:43:34 PM UTC"
