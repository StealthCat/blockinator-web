"""Regression coverage for the data exposed by expandable query records."""
import sqlite3

from app.ui import query_details_html


def test_query_details_escape_stored_values_and_preserve_metadata():
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    row = con.execute(
        "SELECT 19 AS id, ? AS qname, ? AS server_id, ? AS client_ip, "
        "'AAAA' AS qtype, 'https' AS policy_scheme, ? AS matched_scope, "
        "'Udp' AS protocol, 53000 AS client_port",
        ('<script>alert(1)</script>', 'dns-"<test>', '2001:db8::42', 'Office <LAN>'),
    ).fetchone()
    rendered = query_details_html(row, "2026-09-26 12:54:08")
    assert '<script>' not in rendered
    assert '&lt;script&gt;' in rendered
    assert 'dns-&quot;&lt;test&gt;' in rendered
    assert 'Office &lt;LAN&gt;' in rendered
    assert '2001:db8::42' in rendered
    assert 'HTTPS' in rendered
    assert '53000' in rendered
    assert 'data-query-id="19"' in rendered
    con.close()


def test_query_details_handle_missing_optional_metadata():
    row = dict(id=1, qname=None, server_id=None, client_ip="127.0.0.1",
               qtype=None, policy_scheme=None, matched_scope=None,
               protocol=None, client_port=None)
    rendered = query_details_html(row, "2026-09-26")
    assert 'None' not in rendered
    assert '<dd>—</dd>' in rendered
