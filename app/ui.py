"""Small, dependency-free presentation helpers. All icon paths are local artwork."""
from html import escape

# A consistent 24px grid; no font glyphs or third-party runtime requests.
ICON_PATHS = {
    "dashboard": '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
    "statistics": '<path d="M3 3v18h18M6 15l4-5 4 3 6-8"/>',
    "lists": '<path d="M9 6h12M9 12h12M9 18h12M3 6h1M3 12h1M3 18h1"/>',
    "whitelists": '<path d="m3 6 2 2 3-4m2 3h11M3 13h3m4 0h11M3 19h3m4 0h11"/>',
    "scopes": '<rect x="8" y="3" width="8" height="5" rx="1"/><rect x="2" y="16" width="7" height="5" rx="1"/><rect x="15" y="16" width="7" height="5" rx="1"/><path d="M12 8v4H5v4m7-4h7v4"/>',
    "queries": '<path d="M9 5h12M9 12h12M9 19h12M3 5h1M3 12h1M3 19h1"/>',
    "security": '<circle cx="8" cy="8" r="5"/><path d="m12 12 9 9m-5-5 3-3m0 6 3-3"/>',
    "settings": '<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="8" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="10" cy="18" r="2"/>',
    "shield": '<path d="m12 2 9 4v6c0 5-9 10-9 10S3 17 3 12V6z"/><path d="m8 12 3 3 5-6"/>',
    "menu": '<path d="M3 6h18M3 12h18M3 18h18"/>',
    "logout": '<path d="M9 3H3v18h6m6-14 5 5-5 5M8 12h12"/>',
    "plus": '<path d="M12 4v16M4 12h16"/>',
    "arrow": '<path d="M4 12h16m-6-6 6 6-6 6"/>',
    "refresh": '<path d="M20 8a8 8 0 1 0 0 8M20 3v5h-5"/>',
    "server": '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M12 6.5h5M12 17.5h5"/>',
    "appearance": '<circle cx="12" cy="12" r="9"/><path d="M12 3v18"/>',
}


def icon(name: str) -> str:
    paths = ICON_PATHS.get(name, ICON_PATHS["settings"])
    return ('<svg class="ui-icon" viewBox="0 0 24 24" width="20" height="20" '
            'fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" '
            'stroke-linejoin="round" aria-hidden="true" focusable="false">' + paths + '</svg>')


def query_details_html(row, display_time: str) -> str:
    """Escape every stored value; details are available without JavaScript."""
    fields = (("Time", display_time), ("DNS server", row["server_id"]),
              ("Client IP", row["client_ip"]), ("Record type", row["qtype"]),
              ("Policy API", (row["policy_scheme"] or "").upper()),
              ("Policy target", row["matched_scope"]),
              ("DNS transport", row["protocol"]), ("Client port", row["client_port"]))
    items = ''.join('<div><dt>' + label + '</dt><dd>' +
                    escape(str(value or "—"), quote=True) + '</dd></div>'
                    for label, value in fields)
    return ('<details class="query-details" data-query-id="' + str(int(row["id"])) + '">'
            '<summary>Details<span class="sr-only"> for ' + escape(str(row["qname"] or "")) +
            '</span></summary><dl>' + items + '</dl></details>')
