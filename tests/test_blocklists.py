from app.blocklists import parse_blocklist


def test_auto_parser_accepts_domain_hosts_and_adblock():
    result = parse_blocklist(
        """
        # comment
        ads.example.com
        0.0.0.0 tracker.example.net
        ||telemetry.example.org^
        @@||allowed.example.org^
        """,
        "auto",
    )
    assert result.domains == {"ads.example.com", "tracker.example.net", "telemetry.example.org"}
