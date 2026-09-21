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
    assert "ads.example.com" in result.domains
    assert "tracker.example.net" in result.domains
    assert "telemetry.example.org" in result.domains
    assert "allowed.example.org" not in result.domains
