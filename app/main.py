from __future__ import annotations

import html
import ipaddress
import json
import os
import secrets
from datetime import datetime, time as dt_time, timezone
from pathlib import Path
from urllib.parse import quote
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .auth import AuthManager, SESSION_COOKIE, SESSION_TTL_SECONDS
from .blocklists import fetch_url, normalize_domain, parse_blocklist
from .db import Database
from .policy import PolicyEngine, normalize_hostname_pattern
from .rdns import ReverseDnsResolver

BASE_DIR = Path(__file__).resolve().parent
APP_VERSION = "1.13.1"

app = FastAPI(title="Blockinator", version=APP_VERSION)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

db = Database()
auth = AuthManager(db)
engine = PolicyEngine(db)
rdns = ReverseDnsResolver()

class Question(BaseModel):
    name: str
    type: str = "A"
    class_: str = Field(default="IN", alias="class")
    model_config = {"populate_by_name": True}

class DnsInfo(BaseModel):
    questions: list[Question] = Field(default_factory=list)
    identifier: int | None = None
    is_response: bool | None = None
    opcode: str | None = None
    recursion_desired: bool | None = None
    rcode: str | None = None
    has_edns: bool | None = None
    wire_base64: str | None = None

class ClientInfo(BaseModel):
    ip: str
    port: int | None = None

class DecisionRequest(BaseModel):
    server_id: str | None = None
    protocol: str | None = None
    client: ClientInfo
    dns: DnsInfo

def esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)

def client_identity_html(address: str, names: dict[str, str | None]) -> str:
    """Render a client hostname together with its IP address."""
    raw = str(address or "").strip()
    try:
        canonical = str(ipaddress.ip_address(raw))
    except ValueError:
        return f'<span class="client-identity"><b class="client-name">{esc(raw)}</b></span>'

    hostname = names.get(canonical)
    if hostname:
        return (
            f'<span class="client-identity" title="{esc(hostname)} · {esc(canonical)}">'
            f'<b class="client-name">{esc(hostname)}</b>'
            f'<span class="client-address mono">{esc(canonical)}</span>'
            f'</span>'
        )
    return (
        f'<span class="client-identity" title="No reverse DNS record found">'
        f'<b class="client-name mono">{esc(canonical)}</b>'
        f'<span class="client-address client-no-ptr">No PTR record</span>'
        f'</span>'
    )


def querying_server_html(server_id: str | None) -> str:
    """Render the DNS server that submitted a logged query."""
    label = str(server_id or "").strip()
    if not label:
        return (
            '<span class="query-server unknown" title="The querying server did not provide a server_id">'
            '<span class="query-server-icon">◌</span>'
            '<span><b>Unknown server</b><small>No server ID</small></span>'
            '</span>'
        )
    return (
        f'<span class="query-server" title="Querying DNS server: {esc(label)}">'
        f'<span class="query-server-icon">◆</span>'
        f'<span><b>{esc(label)}</b><small>DNS server</small></span>'
        f'</span>'
    )


DAY_LABELS = [
    (0, "Mon"),
    (1, "Tue"),
    (2, "Wed"),
    (3, "Thu"),
    (4, "Fri"),
    (5, "Sat"),
    (6, "Sun"),
]


def parse_schedule_form(form, label: str = "block list") -> tuple[bool, str, str, str, str]:
    enabled = str(form.get("schedule_enabled", "")) == "1"
    days: list[int] = []
    for raw in form.getlist("schedule_day"):
        try:
            day = int(raw)
        except (TypeError, ValueError):
            continue
        if 0 <= day <= 6 and day not in days:
            days.append(day)

    start = str(form.get("schedule_start", "00:00")).strip() or "00:00"
    end = str(form.get("schedule_end", "00:00")).strip() or "00:00"
    tz_name = str(form.get("schedule_timezone", "UTC")).strip() or "UTC"

    try:
        dt_time.fromisoformat(start)
        dt_time.fromisoformat(end)
    except ValueError as exc:
        raise ValueError("Schedule start and end must be valid times") from exc

    try:
        ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(
            "Schedule timezone must be a valid IANA timezone such as America/New_York"
        ) from exc

    if enabled and not days:
        raise ValueError(f"Select at least one day for the scheduled {label}")

    if not days:
        days = list(range(7))

    return enabled, ",".join(str(day) for day in sorted(days)), start, end, tz_name


def schedule_days_set(value: str | None) -> set[int]:
    days: set[int] = set()
    for raw in str(value or "").split(","):
        try:
            day = int(raw)
        except ValueError:
            continue
        if 0 <= day <= 6:
            days.add(day)
    return days


def schedule_summary(row) -> str:
    if not row["schedule_enabled"]:
        return "Always active"
    selected = schedule_days_set(row["schedule_days"])
    if selected == set(range(7)):
        day_text = "Every day"
    elif selected == {0, 1, 2, 3, 4}:
        day_text = "Mon–Fri"
    elif selected == {5, 6}:
        day_text = "Sat–Sun"
    else:
        labels = dict(DAY_LABELS)
        day_text = ", ".join(labels[d] for d in sorted(selected)) or "No days"
    return (
        f'{day_text} · {row["schedule_start"]}–{row["schedule_end"]} · '
        f'{row["schedule_timezone"]}'
    )


def schedule_fields_html(row=None, default_timezone: str = "UTC") -> str:
    enabled = bool(row["schedule_enabled"]) if row is not None else False
    days = schedule_days_set(row["schedule_days"]) if row is not None else set(range(7))
    start = str(row["schedule_start"] or "00:00") if row is not None else "00:00"
    end = str(row["schedule_end"] or "00:00") if row is not None else "00:00"
    tz_name = (
        str(row["schedule_timezone"] or default_timezone)
        if row is not None
        else default_timezone
    )
    if row is None:
        try:
            ZoneInfo(tz_name)
        except (ZoneInfoNotFoundError, ValueError):
            tz_name = "UTC"
    day_buttons = "".join(
        f'<label class="schedule-day">'
        f'<input type="checkbox" name="schedule_day" value="{day}"'
        f'{" checked" if day in days else ""}>'
        f'<span>{label}</span></label>'
        for day, label in DAY_LABELS
    )
    return f'''<div class="schedule-editor full" data-schedule-editor>
      <label class="check schedule-toggle">
        <input type="checkbox" name="schedule_enabled" value="1" data-schedule-toggle{" checked" if enabled else ""}>
        Enforce only during a schedule
      </label>
      <div class="schedule-controls{" schedule-disabled" if not enabled else ""}" data-schedule-controls>
        <div class="schedule-days">
          <span class="schedule-label">Days</span>
          <div class="schedule-day-grid">{day_buttons}</div>
        </div>
        <label>Start time<input type="time" name="schedule_start" value="{esc(start)}"></label>
        <label>End time<input type="time" name="schedule_end" value="{esc(end)}"></label>
        <label>Timezone<input name="schedule_timezone" value="{esc(tz_name)}" placeholder="America/New_York"></label>
        <p class="schedule-help full">Selected days are the days the window begins. Overnight ranges such as 22:00–06:00 continue into the following morning. Equal start/end times mean the full selected day.</p>
      </div>
    </div>'''


def system_default_timezone() -> str:
    configured = db.get_setting(
        "default_timezone",
        os.getenv("TZ", "UTC").strip() or "UTC",
    ).strip() or "UTC"
    try:
        ZoneInfo(configured)
    except (ZoneInfoNotFoundError, ValueError):
        return "UTC"
    return configured


def log_client_names(rows) -> dict[str, str | None]:
    """Use stored PTR names first, resolve missing names, and backfill old rows."""
    names: dict[str, str | None] = {}
    missing: list[str] = []

    for row in rows:
        address = str(row["client_ip"] or "").strip()
        stored_name = None
        try:
            stored_name = row["client_name"]
        except (IndexError, KeyError):
            stored_name = None
        if stored_name:
            names[address] = str(stored_name)
        else:
            missing.append(address)

    if missing:
        resolved = rdns.resolve_many(missing)
        names.update(resolved)
        updates = [
            (hostname, address)
            for address, hostname in resolved.items()
            if hostname
        ]
        if updates:
            with db.connect() as con:
                con.executemany(
                    """
                    UPDATE query_log
                    SET client_name=?
                    WHERE client_ip=? AND (client_name IS NULL OR client_name='')
                    """,
                    updates,
                )

    return names


def backfill_query_client_names(limit: int = 128) -> None:
    """Resolve a bounded set of legacy log clients before hostname filtering."""
    with db.connect() as con:
        rows = con.execute(
            """
            SELECT DISTINCT client_ip
            FROM query_log
            WHERE client_name IS NULL OR client_name=''
            ORDER BY id DESC
            LIMIT ?
            """,
            (max(1, min(limit, 512)),),
        ).fetchall()

    if not rows:
        return

    resolved = rdns.resolve_many(row["client_ip"] for row in rows)
    updates = [
        (hostname, address)
        for address, hostname in resolved.items()
        if hostname
    ]
    if updates:
        with db.connect() as con:
            con.executemany(
                """
                UPDATE query_log
                SET client_name=?
                WHERE client_ip=? AND (client_name IS NULL OR client_name='')
                """,
                updates,
            )

def redirect(path: str, notice: str | None = None, error: str | None = None):
    parts = []
    if notice:
        parts.append("notice=" + quote(notice))
    if error:
        parts.append("error=" + quote(error))

    base, marker, fragment = path.partition("#")
    if parts:
        base += ("&" if "?" in base else "?") + "&".join(parts)
    if marker:
        base += "#" + fragment
    return RedirectResponse(base, status_code=303)

def session_for(request: Request):
    return auth.get_session(request.cookies.get(SESSION_COOKIE))

def require_session(request: Request):
    session = session_for(request)
    if not session:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return session

async def require_post_session(request: Request):
    session = require_session(request)
    form = await request.form()
    token = str(form.get("csrf_token", ""))
    if not token or not secrets.compare_digest(token, session.csrf_token):
        raise HTTPException(status_code=403, detail="invalid CSRF token")
    return session, form

def page(request: Request, title: str, active: str, body: str, session=None) -> HTMLResponse:
    notice = request.query_params.get("notice")
    error = request.query_params.get("error")
    if session is None:
        session = session_for(request)

    page_descriptions = {
        "dashboard": "Monitor DNS enforcement, request activity, and policy health at a glance.",
        "lists": "Import, organize, and control the domain intelligence that powers your blocking policy.",
        "scopes": "Define filtering by network, exact endpoint, or reverse-DNS hostname and control each target independently.",
        "queries": "Inspect DNS decisions, troubleshoot policy matches, and follow activity across your clients.",
        "security": "Manage administrator access and the API credentials used by connected DNS resolvers.",
        "settings": "Tune Blockinator's response behavior, retention, and core service preferences.",
    }
    page_actions = {
        "dashboard": ('/queries', 'View activity', 'arrow'),
        "lists": ('#add-list', 'Import a list', 'plus'),
        "scopes": ('#add-scope', 'Add endpoint', 'plus'),
        "queries": ('/queries', 'Reset filters', 'refresh'),
        "security": ('#create-key', 'Create API key', 'plus'),
        "settings": (None, None, None),
    }

    nav = [
        ("/", "dashboard", "Dashboard", "⌂"),
        ("/lists", "lists", "Block Lists", "☷"),
        ("/scopes", "scopes", "Policy Targets", "◎"),
        ("/queries", "queries", "Query Log", "≡"),
    ]
    admin_nav = [
        ("/security", "security", "Access & Security", "◈"),
        ("/settings", "settings", "System Settings", "⚙"),
    ]

    def render_nav(items):
        return "".join(
            f'<a class="nav-link {"active" if key == active else ""}" href="{href}"><span class="nav-icon">{icon}</span><span>{label}</span></a>'
            for href, key, label, icon in items
        )

    flash = ""
    if notice:
        flash += f'<div class="flash ok"><span class="flash-icon">✓</span><div><b>Success</b><span>{esc(notice)}</span></div></div>'
    if error:
        flash += f'<div class="flash bad"><span class="flash-icon">!</span><div><b>Something needs attention</b><span>{esc(error)}</span></div></div>'

    global_on = db.get_setting("global_blocking", "1") == "1"
    status_label = "Protection active" if global_on else "Protection paused"
    status_detail = "DNS policy is being enforced" if global_on else "Requests are currently allowed"
    action_href, action_label, action_icon = page_actions.get(active, (None, None, None))
    header_action = (
        f'<a class="primary-button header-primary" href="{action_href}"><span>{"+" if action_icon == "plus" else "↗" if action_icon == "arrow" else "↻"}</span>{esc(action_label)}</a>'
        if action_href and action_label else ""
    )
    user_initial = esc(session.username[:1].upper()) if session else "A"
    username = esc(session.username) if session else "Administrator"
    logout = ""
    if session:
        logout = f"""
        <form method="post" action="/logout" class="logout-form">
          <input type="hidden" name="csrf_token" value="{esc(session.csrf_token)}">
          <button class="icon-button" type="submit" title="Sign out" aria-label="Sign out">↪</button>
        </form>"""

    return HTMLResponse(f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#071018">
<title>{esc(title)} · Blockinator</title>
<link rel="icon" href="/static/blockinator-mark.webp">
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
<div class="app-shell">
  <aside class="sidebar">
    <a class="brand" href="/"><span class="brand-mark"><img src="/static/blockinator-mark.webp" alt=""></span><div><b>Blockinator</b><small>DNS Policy Control</small></div></a>
    <div class="nav-section-label">Policy</div>
    <nav>{render_nav(nav)}</nav>
    <div class="nav-section-label nav-section-spacer">Administration</div>
    <nav>{render_nav(admin_nav)}</nav>
    <div class="sidebar-foot">
      <div class="sidebar-status"><span class="status-dot"></span><div><b>Service online</b><small>Blockinator v{APP_VERSION}</small></div></div>
    </div>
  </aside>
  <main class="main">
    <header class="workspace-header">
      <div class="header-copy">
        <div class="breadcrumb"><span>Blockinator</span><i>›</i><b>{esc(title)}</b></div>
        <h1>{esc(title)}</h1>
        <p>{esc(page_descriptions.get(active, ""))}</p>
      </div>
      <div class="header-tools">
        <a class="protection-chip {"active" if global_on else "paused"}" href="/">
          <span class="protection-icon">◆</span>
          <span><small>{esc(status_label)}</small><b>{esc(status_detail)}</b></span>
        </a>
        {header_action}
        <div class="user-chip"><span class="avatar">{user_initial}</span><span><b>{username}</b><small>Administrator</small></span></div>
        {logout}
      </div>
    </header>
    <div class="content-wrap">
      {flash}
      {body}
    </div>
  </main>
</div>
<script src="/static/app.js"></script>
</body>
</html>""")

def api_key_ok(raw: str | None):
    info = auth.verify_api_key(raw)
    if not info:
        raise HTTPException(status_code=401, detail="invalid API key")
    return info

def import_list(list_id: int, text: str, fmt: str):
    parsed = parse_blocklist(text, fmt)
    with db.connect() as con:
        con.execute("BEGIN")
        con.execute("DELETE FROM block_entries WHERE blocklist_id=?", (list_id,))
        con.executemany(
            "INSERT OR IGNORE INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            [(list_id, d) for d in parsed.domains],
        )
        con.execute(
            "UPDATE blocklists SET entry_count=?,last_updated=CURRENT_TIMESTAMP,last_error=NULL WHERE id=?",
            (len(parsed.domains), list_id),
        )
        con.execute("COMMIT")
    engine.reload()
    return len(parsed.domains), parsed.ignored

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.get("/api/v1/ping")
def ping(x_api_key: str | None = Header(default=None)):
    api_key_ok(x_api_key)
    return {"status": "ok", "service": "blockinator", "version": APP_VERSION}

@app.post("/api/v1/decision")
def decision(payload: DecisionRequest, x_api_key: str | None = Header(default=None)):
    api_key_ok(x_api_key)
    d = engine.decide_and_log(payload.model_dump(by_alias=True))
    return {
        "block": d.block,
        "reason": d.reason,
        "matched_scope": d.matched_scope,
        "matched_list": d.matched_list,
        "matched_domain": d.matched_domain,
        "response_mode": d.response_mode,
    }

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if session_for(request):
        return RedirectResponse("/", status_code=303)
    error = request.query_params.get("error", "")
    return HTMLResponse(f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in · Blockinator</title><link rel="icon" href="/static/blockinator-mark.webp"><link rel="stylesheet" href="/static/style.css"></head>
<body class="login-body"><section class="login-visual"><div class="login-shade"></div><div class="login-copy"><img src="/static/blockinator-mark.webp" alt=""><p>DNS POLICY CONTROL</p><h1>Bad traffic<br>stops here.</h1><span>Block · Filter · Protect</span></div></section>
<section class="login-panel"><form method="post" action="/login" class="login-card"><div class="mini-brand"><img src="/static/blockinator-mark.webp" alt=""><b>Blockinator</b></div><h2>Welcome back</h2><p>Sign in to manage DNS policy, endpoints, block lists and access keys.</p>
{"<div class='flash bad'>" + esc(error) + "</div>" if error else ""}
<label>Username<input name="username" autocomplete="username" required autofocus></label>
<label>Password<input type="password" name="password" autocomplete="current-password" required></label>
<button class="primary-button wide" type="submit">Sign in</button><small>Blockinator v{APP_VERSION}</small></form></section></body></html>""")

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    result = auth.authenticate(username, password)
    if not result:
        return redirect("/login", error="Invalid username or password")
    user_id, canonical = result
    s = auth.create_session(user_id, canonical)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE, s.token, max_age=SESSION_TTL_SECONDS, httponly=True,
        secure=os.getenv("ADMIN_COOKIE_SECURE", "0").lower() in {"1","true","yes","on"},
        samesite="strict", path="/",
    )
    return response

@app.post("/logout")
async def logout(request: Request):
    s, _ = await require_post_session(request)
    auth.delete_session(request.cookies.get(SESSION_COOKIE))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    s = require_session(request)
    with db.connect() as con:
        totals = dict(con.execute("""
            SELECT
              (SELECT COUNT(*) FROM blocklists WHERE enabled=1) active_lists,
              (SELECT COALESCE(SUM(entry_count),0) FROM blocklists WHERE enabled=1) entries,
              (SELECT COUNT(*) FROM scopes WHERE kind='network') networks,
              (SELECT COUNT(*) FROM scopes WHERE kind='client') clients,
              (SELECT COUNT(*) FROM scopes WHERE kind='hostname') hostnames,
              (SELECT COUNT(*) FROM query_log WHERE blocked=1) blocked,
              (SELECT COUNT(*) FROM query_log) queries
        """).fetchone())
        recent = con.execute("SELECT ts,server_id,client_ip,client_name,qname,blocked,reason FROM query_log ORDER BY id DESC LIMIT 8").fetchall()
    global_on = db.get_setting("global_blocking", "1") == "1"
    recent_client_names = log_client_names(recent)
    rows = "".join(
        f'<tr><td>{esc(r["ts"])}</td><td>{querying_server_html(r["server_id"])}</td><td>{client_identity_html(r["client_ip"], recent_client_names)}</td><td>{esc(r["qname"])}</td><td><span class="pill {"red" if r["blocked"] else "green"}">{"Blocked" if r["blocked"] else "Allowed"}</span></td><td>{esc(r["reason"])}</td></tr>'
        for r in recent
    ) or '<tr><td colspan="6" class="empty">No DNS decisions recorded yet.</td></tr>'
    body = f'''
    <section class="hero-card"><img src="/static/blockinator-hero.webp" alt="Blockinator"><div class="hero-overlay"><p>BLOCK · FILTER · PROTECT</p><h2>Your network. Your policy.</h2><span>Centralized DNS policy control with client-aware filtering.</span></div></section>
    <div class="stat-grid">
      <article class="stat"><span>Queries</span><strong>{totals["queries"]:,}</strong><small>Recorded decisions</small></article>
      <article class="stat"><span>Blocked</span><strong>{totals["blocked"]:,}</strong><small>Rejected requests</small></article>
      <article class="stat"><span>Block entries</span><strong>{totals["entries"]:,}</strong><small>Across enabled lists</small></article>
      <article class="stat"><span>Policy targets</span><strong>{totals["clients"] + totals["networks"] + totals["hostnames"]:,}</strong><small>{totals["networks"]} networks · {totals["clients"]} endpoints · {totals["hostnames"]} hostnames</small></article>
    </div>
    <section class="panel status-panel"><div><span class="big-dot {"green" if global_on else "amber"}"></span><div><h3>Global blocking is {"active" if global_on else "paused"}</h3><p>{"Policy decisions are enforced." if global_on else "All requests are currently allowed."}</p></div></div>
      <form method="post" action="/admin/global-toggle"><input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}"><button class="{"danger-button" if global_on else "primary-button"}">{"Pause blocking" if global_on else "Resume blocking"}</button></form>
    </section>
    <section class="panel"><div class="panel-head"><div><h3>Recent DNS activity</h3><p>Latest policy decisions from connected resolvers.</p></div><a class="text-link" href="/queries">View all →</a></div>
      <div class="table-wrap"><table><thead><tr><th>Time</th><th>Server</th><th>Client</th><th>Domain</th><th>Decision</th><th>Reason</th></tr></thead><tbody>{rows}</tbody></table></div>
    </section>'''
    return page(request, "Dashboard", "dashboard", body, s)

@app.post("/admin/global-toggle")
async def global_toggle(request: Request):
    _, _form = await require_post_session(request)
    current = db.get_setting("global_blocking", "1") == "1"
    db.set_setting("global_blocking", "0" if current else "1")
    engine.reload()
    return redirect("/", notice="Global blocking paused" if current else "Global blocking resumed")

@app.get("/lists", response_class=HTMLResponse)
def lists_page(request: Request):
    s = require_session(request)
    with db.connect() as con:
        rows = con.execute("SELECT * FROM blocklists ORDER BY name COLLATE NOCASE").fetchall()
        scopes = con.execute("SELECT * FROM scopes ORDER BY kind,name COLLATE NOCASE").fetchall()
        membership_rows = con.execute(
            "SELECT blocklist_id,scope_id FROM scope_blocklists"
        ).fetchall()
        network_target_rows = con.execute(
            "SELECT scope_id,family,target FROM scope_network_targets"
        ).fetchall()

    memberships: dict[int, set[int]] = {}
    for membership in membership_rows:
        memberships.setdefault(int(membership["blocklist_id"]), set()).add(int(membership["scope_id"]))

    network_targets: dict[int, dict[int, str]] = {}
    for row in network_target_rows:
        network_targets.setdefault(int(row["scope_id"]), {})[int(row["family"])] = str(row["target"])

    client_names = rdns.resolve_many(
        scope["target"] for scope in scopes if scope["kind"] == "client"
    )
    networks = [scope for scope in scopes if scope["kind"] == "network"]
    clients = [scope for scope in scopes if scope["kind"] == "client"]
    hostnames = [scope for scope in scopes if scope["kind"] == "hostname"]

    def scope_option(scope, selected: set[int], disabled: bool = False) -> str:
        checked = " checked" if int(scope["id"]) in selected else ""
        disabled_attr = " disabled" if disabled else ""
        disabled_class = " global-disabled" if disabled else ""
        if scope["kind"] == "client":
            target_html = client_identity_html(scope["target"], client_names)
            kind_label = "Endpoint"
        elif scope["kind"] == "hostname":
            target_html = f'<span class="scope-target mono">{esc(scope["target"])}</span>'
            kind_label = "Hostname"
        else:
            ipv4, ipv6 = _scope_network_values(scope, network_targets)
            target_html = _network_target_html(ipv4, ipv6)
            kind_label = "Network"
        return (
            f'<label class="scope-option{disabled_class}">'
            f'<input type="checkbox" name="scope_id" value="{int(scope["id"])}"{checked}{disabled_attr}>'
            f'<span class="scope-option-copy"><span class="scope-option-title">'
            f'<b>{esc(scope["name"])}</b><small>{kind_label}</small></span>{target_html}</span>'
            f'</label>'
        )

    def scope_editor(selected: set[int], global_disabled: bool = False) -> str:
        if not scopes:
            return (
                '<div class="scope-empty">No policy targets exist yet. '
                '<a href="/scopes#add-scope">Create one first →</a></div>'
            )
        network_html = "".join(
            scope_option(scope, selected, global_disabled) for scope in networks
        )
        client_html = "".join(
            scope_option(scope, selected, global_disabled) for scope in clients
        )
        hostname_html = "".join(
            scope_option(scope, selected, global_disabled) for scope in hostnames
        )
        disabled_class = " is-global-disabled" if global_disabled else ""
        return (
            f'<div class="scope-assignment-grid{disabled_class}" data-scope-assignments>'
            '<section class="scope-group"><div class="scope-group-head"><b>Networks</b>'
            f'<span>{len(networks)}</span></div>'
            f'{network_html or "<p class=\"scope-empty-inline\">No network scopes.</p>"}</section>'
            '<section class="scope-group"><div class="scope-group-head"><b>Endpoints</b>'
            f'<span>{len(clients)}</span></div>'
            f'{client_html or "<p class=\"scope-empty-inline\">No endpoint scopes.</p>"}</section>'
            '<section class="scope-group"><div class="scope-group-head"><b>Hostnames</b>'
            f'<span>{len(hostnames)}</span></div>'
            f'{hostname_html or "<p class=\"scope-empty-inline\">No hostname scopes.</p>"}</section>'
            '</div>'
        )

    cards = ""
    for r in rows:
        selected = memberships.get(int(r["id"]), set())
        assignment_text = (
            f'Global + {len(selected)} scoped assignment{"s" if len(selected) != 1 else ""}'
            if r["use_globally"] and selected
            else "Global"
            if r["use_globally"]
            else f'{len(selected)} scoped assignment{"s" if len(selected) != 1 else ""}'
            if selected
            else "No assignments"
        )
        format_options = "".join(
            f'<option value="{fmt}"{" selected" if r["format"] == fmt else ""}>{fmt}</option>'
            for fmt in ("auto", "hosts", "adblock", "domains")
        )
        error_html = (
            f'<div class="list-warning">Last refresh error: {esc(r["last_error"])}</div>'
            if r["last_error"] else ""
        )
        source_label = r["source_url"] or (
            "Uploaded list" if r["source_type"] == "upload" else "Manual list"
        )
        list_schedule_summary = schedule_summary(r)
        list_schedule_fields = schedule_fields_html(r)
        refresh_button = (
            '<button class="small-button" type="submit" name="action" value="refresh">'
            'Save & refresh URL</button>'
        )
        manual_manage_link = (
            f'<a class="small-button domain-manage-link" href="/lists/{int(r["id"])}/domains">'
            'Manage domains</a>'
            if r["source_type"] == "manual"
            else ""
        )

        cards += f'''<article class="list-card editable-list-card" id="list-{int(r["id"])}">
          <div class="list-card-summary">
            <div class="list-card-top">
              <div class="list-title-block"><h3>{esc(r["name"])}</h3><p>{esc(source_label)}</p></div>
              <span class="pill {"green" if r["enabled"] else "gray"}">{"Enabled" if r["enabled"] else "Disabled"}</span>
            </div>
            <div class="list-meta">
              <span><b>{int(r["entry_count"]):,}</b> entries</span>
              <span>{esc(r["format"])}</span>
              <span>{esc(assignment_text)}</span>
              <span class="schedule-meta {"scheduled" if r["schedule_enabled"] else ""}">{esc(list_schedule_summary)}</span>
              <span>Updated {esc(r["last_updated"] or "Never")}</span>
            </div>
            {error_html}
            <div class="actions list-card-actions">
              <form method="post" action="/admin/lists/{int(r["id"])}/toggle">
                <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">
                <button class="small-button">{"Disable" if r["enabled"] else "Enable"}</button>
              </form>
              <a class="small-button edit-link" href="#edit-list-{int(r["id"])}">Edit & assign</a>
              {manual_manage_link}
              <form method="post" action="/admin/lists/{int(r["id"])}/delete" onsubmit="return confirm('Delete this list and its scope assignments?')">
                <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">
                <button class="small-button danger">Delete</button>
              </form>
            </div>
          </div>
          <details class="list-editor" id="edit-list-{int(r["id"])}">
            <summary><span><b>Edit list</b><small>Settings, contents and policy-target assignments</small></span><span class="editor-chevron">⌄</span></summary>
            <div class="list-edit-body">
              <form method="post" action="/admin/lists/{int(r["id"])}/edit" enctype="multipart/form-data" class="form-grid list-edit-form">
                <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">
                <label>Name<input name="name" value="{esc(r["name"])}" required></label>
                <label>Format<select name="format">{format_options}</select></label>
                <label class="full">Source URL<input name="source_url" value="{esc(r["source_url"] or "")}" placeholder="https://example.com/list.txt"></label>
                <label>Refresh interval (minutes)<input type="number" name="refresh_minutes" min="1" max="10080" value="{int(r["refresh_minutes"])}"></label>
                <label class="check"><input type="checkbox" name="enabled" value="1"{" checked" if r["enabled"] else ""}> List enabled</label>
                <label class="check full"><input type="checkbox" name="global_list" value="1" data-global-toggle{" checked" if r["use_globally"] else ""}> Apply globally to every network, endpoint, and hostname</label>

                <div class="form-section full schedule-section">
                  <div class="form-section-head"><div><b>Enforcement schedule</b><p>Leave scheduling off to enforce this list at all times.</p></div></div>
                  {list_schedule_fields}
                </div>

                <div class="form-section full">
                  <div class="form-section-head"><div><b>Scope assignments</b><p>Select every network, endpoint, and hostname scope that should use this list.</p></div><span>{len(selected)} selected</span></div>
                  {scope_editor(selected, bool(r["use_globally"]))}
                </div>

                <div class="form-section full replacement-section">
                  <div class="form-section-head"><div><b>Replace list contents</b><p>Optional. Leave both fields blank to keep the current {int(r["entry_count"]):,} entries.</p></div></div>
                  <label>Upload replacement file<input type="file" name="replacement_file"></label>
                  <label>Or paste replacement rules<textarea name="replacement_text" rows="5" placeholder="One domain per line, hosts format, or supported Adblock domain rules"></textarea></label>
                </div>

                <div class="editor-actions full">
                  <button class="primary-button" type="submit" name="action" value="save">Save changes</button>
                  {refresh_button}
                  <button class="small-button" type="button" onclick="this.closest('details').open=false">Close editor</button>
                </div>
              </form>
            </div>
          </details>
        </article>'''

    if not cards:
        cards = '<div class="empty-card">No block lists yet. Import one to start building policy.</div>'

    new_schedule_fields = schedule_fields_html(default_timezone=system_default_timezone())
    body = f'''<div class="split-grid blocklist-layout">
      <section class="panel">
        <div class="panel-head"><div><div class="panel-kicker">Policy sources</div><h3>Managed block lists</h3><p>Edit each list and assign it to networks or exact endpoints without leaving this page.</p></div><span class="result-count">{len(rows)} lists</span></div>
        <div class="blocklist-list">{cards}</div>
      </section>
      <section class="panel action-panel" id="add-list">
        <div class="panel-kicker">New source</div><h3>Add block list</h3>
        <p class="panel-help">Import from a URL, upload a file, or paste rules directly. You can make the list global and/or assign it to specific scopes immediately.</p>
        <form method="post" action="/admin/lists" enctype="multipart/form-data" class="form-grid">
          <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">
          <label>Name<input name="name" required></label>
          <label>Format<select name="format"><option>auto</option><option>hosts</option><option>adblock</option><option>domains</option></select></label>
          <label class="full">Source URL (optional)<input name="source_url" placeholder="https://example.com/list.txt"></label>
          <label>Refresh interval (minutes)<input type="number" name="refresh_minutes" min="1" max="10080" value="1440"></label>
          <label class="check"><input type="checkbox" name="global_list" value="1" data-global-toggle checked> Apply globally</label>
          <div class="form-section full schedule-section">
            <div class="form-section-head"><div><b>Enforcement schedule</b><p>Optional. Configure recurring days and times for this list.</p></div></div>
            {new_schedule_fields}
          </div>
          <label class="full">Upload file (optional)<input type="file" name="file"></label>
          <label class="full">Paste domains / hosts / adblock rules<textarea name="text" rows="7"></textarea></label>
          <div class="form-section full">
            <div class="form-section-head"><div><b>Initial scope assignments</b><p>Optional when the list is global; useful for scoped-only lists.</p></div></div>
            {scope_editor(set(), True)}
          </div>
          <button class="primary-button full" type="submit">Import list</button>
        </form>
      </section>
    </div>'''
    return page(request, "Block Lists", "lists", body, s)



def _get_manual_blocklist(list_id: int):
    with db.connect() as con:
        row = con.execute("SELECT * FROM blocklists WHERE id=?", (list_id,)).fetchone()
    if not row:
        return None, "Block list not found"
    if row["source_type"] != "manual":
        return row, "Only manual block lists can be edited one domain at a time"
    return row, None


def _refresh_manual_list_count(con, list_id: int) -> int:
    count = int(
        con.execute(
            "SELECT COUNT(*) AS c FROM block_entries WHERE blocklist_id=?",
            (list_id,),
        ).fetchone()["c"]
    )
    con.execute(
        """
        UPDATE blocklists
        SET entry_count=?, last_updated=CURRENT_TIMESTAMP, last_error=NULL
        WHERE id=?
        """,
        (count, list_id),
    )
    return count


@app.get("/lists/{list_id}/domains", response_class=HTMLResponse)
def manual_list_domains_page(
    list_id: int,
    request: Request,
    q: str = "",
    page_num: int = 1,
):
    s = require_session(request)
    blocklist, error = _get_manual_blocklist(list_id)
    if error:
        return redirect(f"/lists#list-{list_id}", error=error)

    assert blocklist is not None
    q = q.strip()
    page_size = 100
    page_num = max(1, page_num)
    where_sql = "blocklist_id=?"
    args: list[object] = [list_id]
    if q:
        where_sql += " AND domain LIKE ?"
        args.append("%" + q.lower() + "%")

    with db.connect() as con:
        total = int(
            con.execute(
                f"SELECT COUNT(*) AS c FROM block_entries WHERE {where_sql}",
                args,
            ).fetchone()["c"]
        )
        max_page = max(1, (total + page_size - 1) // page_size)
        page_num = min(page_num, max_page)
        offset = (page_num - 1) * page_size
        entries = con.execute(
            f"""
            SELECT domain
            FROM block_entries
            WHERE {where_sql}
            ORDER BY domain COLLATE NOCASE
            LIMIT ? OFFSET ?
            """,
            [*args, page_size, offset],
        ).fetchall()

    domain_rows = []
    for entry in entries:
        domain = str(entry["domain"])
        domain_rows.append(
            f'''<tr>
              <td><span class="manual-domain-name mono">{esc(domain)}</span></td>
              <td class="manual-domain-action">
                <form method="post" action="/admin/lists/{list_id}/domains/remove"
                      onsubmit="return confirm('Remove {esc(domain)} from this block list?')">
                  <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">
                  <input type="hidden" name="domain" value="{esc(domain)}">
                  <input type="hidden" name="return_q" value="{esc(q)}">
                  <input type="hidden" name="return_page" value="{page_num}">
                  <button class="small-button danger" type="submit">Remove</button>
                </form>
              </td>
            </tr>'''
        )
    rows_html = "".join(domain_rows) or (
        '<tr><td colspan="2" class="empty">'
        + ("No domains match this search." if q else "This manual list has no domains yet.")
        + "</td></tr>"
    )

    query_suffix = "&q=" + quote(q) if q else ""
    prev_link = (
        f'<a class="small-button" href="/lists/{list_id}/domains?page_num={page_num - 1}{query_suffix}">← Previous</a>'
        if page_num > 1 else '<span class="small-button disabled">← Previous</span>'
    )
    next_link = (
        f'<a class="small-button" href="/lists/{list_id}/domains?page_num={page_num + 1}{query_suffix}">Next →</a>'
        if page_num < max_page else '<span class="small-button disabled">Next →</span>'
    )

    assignment_label = "Global" if blocklist["use_globally"] else "Scoped only"
    clear_search_link = (
        f'<a class="small-button" href="/lists/{list_id}/domains">Clear</a>'
        if q
        else ""
    )
    body = f'''<div class="manual-domain-page">
      <section class="manual-domain-heading">
        <a class="back-link" href="/lists#list-{list_id}">← Back to Block Lists</a>
        <div class="manual-domain-title-row">
          <div>
            <div class="panel-kicker">Manual block list</div>
            <h2>{esc(blocklist["name"])}</h2>
            <p>Add or remove individual domains without replacing the entire list.</p>
          </div>
          <div class="manual-list-stats">
            <span><b>{int(blocklist["entry_count"]):,}</b><small>Total domains</small></span>
            <span><b>{esc(assignment_label)}</b><small>Policy mode</small></span>
            <span><b>{"Enabled" if blocklist["enabled"] else "Disabled"}</b><small>List state</small></span>
            <span><b>{esc("Scheduled" if blocklist["schedule_enabled"] else "Always")}</b><small>{esc(schedule_summary(blocklist))}</small></span>
          </div>
        </div>
      </section>

      <div class="manual-domain-layout">
        <section class="panel action-panel manual-domain-add">
          <div class="panel-kicker">Add entry</div>
          <h3>Add a domain</h3>
          <p class="panel-help">Enter one hostname. Subdomains are covered automatically by Blockinator's suffix matching.</p>
          <form method="post" action="/admin/lists/{list_id}/domains/add" class="manual-domain-add-form">
            <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">
            <label>Domain
              <input name="domain" placeholder="example.com" autocomplete="off" required autofocus>
            </label>
            <button class="primary-button" type="submit">Add domain</button>
          </form>
          <div class="manual-domain-tip">
            <b>Accepted</b>
            <span>Normal hostnames and IDNs are normalized to lowercase ASCII. Wildcard prefixes such as <code>*.example.com</code> are stored as <code>example.com</code>.</span>
          </div>
        </section>

        <section class="panel manual-domain-list-panel">
          <div class="panel-head">
            <div>
              <div class="panel-kicker">List entries</div>
              <h3>Domains</h3>
              <p>{total:,} matching domain{"s" if total != 1 else ""} · page {page_num} of {max_page}</p>
            </div>
            <span class="result-count">{total:,} results</span>
          </div>

          <form class="manual-domain-search" method="get">
            <input name="q" value="{esc(q)}" placeholder="Search domains…">
            <button class="small-button" type="submit">Search</button>
            {clear_search_link}
          </form>

          <div class="table-wrap manual-domain-table-wrap">
            <table class="manual-domain-table">
              <thead><tr><th>Domain</th><th></th></tr></thead>
              <tbody>{rows_html}</tbody>
            </table>
          </div>

          <div class="manual-domain-pagination">
            {prev_link}
            <span>Page {page_num} of {max_page}</span>
            {next_link}
          </div>
        </section>
      </div>
    </div>'''
    return page(request, f"Manual List · {blocklist['name']}", "lists", body, s)


@app.post("/admin/lists/{list_id}/domains/add")
async def add_manual_list_domain(list_id: int, request: Request):
    _, form = await require_post_session(request)
    blocklist, error = _get_manual_blocklist(list_id)
    if error:
        return redirect(f"/lists#list-{list_id}", error=error)

    raw_domain = str(form.get("domain", ""))
    domain = normalize_domain(raw_domain)
    if not domain:
        return redirect(
            f"/lists/{list_id}/domains",
            error="Enter a valid domain such as example.com",
        )

    with db.connect() as con:
        cur = con.execute(
            "INSERT OR IGNORE INTO block_entries(blocklist_id,domain) VALUES(?,?)",
            (list_id, domain),
        )
        count = _refresh_manual_list_count(con, list_id)

    engine.reload()
    if cur.rowcount == 0:
        return redirect(
            f"/lists/{list_id}/domains?q={quote(domain)}",
            notice=f"{domain} is already in this list",
        )
    return redirect(
        f"/lists/{list_id}/domains?q={quote(domain)}",
        notice=f"Added {domain}; manual list now contains {count:,} domains",
    )


@app.post("/admin/lists/{list_id}/domains/remove")
async def remove_manual_list_domain(list_id: int, request: Request):
    _, form = await require_post_session(request)
    blocklist, error = _get_manual_blocklist(list_id)
    if error:
        return redirect(f"/lists#list-{list_id}", error=error)

    domain = normalize_domain(str(form.get("domain", "")))
    return_q = str(form.get("return_q", "")).strip()
    try:
        return_page = max(1, int(form.get("return_page", "1")))
    except (TypeError, ValueError):
        return_page = 1

    return_path = f"/lists/{list_id}/domains?page_num={return_page}"
    if return_q:
        return_path += "&q=" + quote(return_q)

    if not domain:
        return redirect(return_path, error="Invalid domain")

    with db.connect() as con:
        cur = con.execute(
            "DELETE FROM block_entries WHERE blocklist_id=? AND domain=?",
            (list_id, domain),
        )
        count = _refresh_manual_list_count(con, list_id)

    engine.reload()
    if cur.rowcount == 0:
        return redirect(
            return_path,
            error=f"{domain} was not found in this list",
        )
    return redirect(
        return_path,
        notice=f"Removed {domain}; manual list now contains {count:,} domains",
    )

def _scope_ids_from_form(form) -> list[int]:
    scope_ids: list[int] = []
    for raw in form.getlist("scope_id"):
        try:
            scope_ids.append(int(raw))
        except (TypeError, ValueError):
            continue
    return list(dict.fromkeys(scope_ids))


def _save_list_scope_assignments(con, list_id: int, scope_ids: list[int]) -> int:
    con.execute("DELETE FROM scope_blocklists WHERE blocklist_id=?", (list_id,))
    if not scope_ids:
        return 0
    placeholders = ",".join("?" for _ in scope_ids)
    valid_rows = con.execute(
        f"SELECT id FROM scopes WHERE id IN ({placeholders})",
        scope_ids,
    ).fetchall()
    valid_ids = [int(row["id"]) for row in valid_rows]
    con.executemany(
        "INSERT OR IGNORE INTO scope_blocklists(scope_id,blocklist_id) VALUES(?,?)",
        [(scope_id, list_id) for scope_id in valid_ids],
    )
    return len(valid_ids)


@app.post("/admin/lists")
async def add_list(request: Request):
    _, form = await require_post_session(request)
    name = str(form.get("name", "")).strip()
    format_name = str(form.get("format", "auto")).strip().lower()
    source_url = str(form.get("source_url", "")).strip()
    text = str(form.get("text", ""))
    global_list = str(form.get("global_list", "")) == "1"
    try:
        schedule_enabled, schedule_days, schedule_start, schedule_end, schedule_timezone = parse_schedule_form(form)
    except ValueError as e:
        return redirect("/lists", error=str(e))
    scope_ids = _scope_ids_from_form(form)
    if global_list:
        scope_ids = []

    if not name:
        return redirect("/lists", error="List name is required")
    if format_name not in {"auto", "hosts", "adblock", "domains"}:
        return redirect("/lists", error="Unsupported block-list format")
    try:
        refresh_minutes = max(1, min(int(form.get("refresh_minutes", "1440")), 10080))
    except (TypeError, ValueError):
        refresh_minutes = 1440

    source_type = "manual"
    content = text
    file_obj = form.get("file")
    if getattr(file_obj, "filename", None):
        content = (await file_obj.read()).decode("utf-8", errors="replace")
        source_type = "upload"
    elif source_url:
        try:
            content = fetch_url(source_url)
        except Exception as e:
            return redirect("/lists", error=f"Could not fetch list URL: {e}")
        source_type = "url"

    if not content.strip():
        return redirect("/lists", error="Provide a URL, upload, or pasted list content")

    with db.connect() as con:
        try:
            cur = con.execute(
                """
                INSERT INTO blocklists(
                    name,source_type,source_url,format,use_globally,refresh_minutes,
                    schedule_enabled,schedule_days,schedule_start,schedule_end,schedule_timezone
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    name, source_type, source_url or None, format_name,
                    1 if global_list else 0, refresh_minutes,
                    1 if schedule_enabled else 0, schedule_days,
                    schedule_start, schedule_end, schedule_timezone,
                ),
            )
            list_id = int(cur.lastrowid)
        except Exception as e:
            return redirect("/lists", error=str(e))

    try:
        count, ignored = import_list(list_id, content, format_name)
        with db.connect() as con:
            assigned = _save_list_scope_assignments(con, list_id, scope_ids)
    except Exception as e:
        with db.connect() as con:
            con.execute("DELETE FROM blocklists WHERE id=?", (list_id,))
        return redirect("/lists", error=f"Import failed: {e}")

    engine.reload()
    return redirect(
        f"/lists#list-{list_id}",
        notice=f"Imported {count:,} entries, ignored {ignored:,}, assigned to {assigned} scope{'s' if assigned != 1 else ''}",
    )


@app.post("/admin/lists/{list_id}/edit")
async def edit_list(list_id: int, request: Request):
    _, form = await require_post_session(request)
    name = str(form.get("name", "")).strip()
    format_name = str(form.get("format", "auto")).strip().lower()
    source_url = str(form.get("source_url", "")).strip()
    enabled = str(form.get("enabled", "")) == "1"
    global_list = str(form.get("global_list", "")) == "1"
    try:
        schedule_enabled, schedule_days, schedule_start, schedule_end, schedule_timezone = parse_schedule_form(form)
    except ValueError as e:
        return redirect(f"/lists#edit-list-{list_id}", error=str(e))
    action = str(form.get("action", "save")).strip().lower()
    replacement_text = str(form.get("replacement_text", ""))
    replacement_file = form.get("replacement_file")
    scope_ids = _scope_ids_from_form(form)
    if global_list:
        scope_ids = []

    if not name:
        return redirect(f"/lists#edit-list-{list_id}", error="List name is required")
    if format_name not in {"auto", "hosts", "adblock", "domains"}:
        return redirect(f"/lists#edit-list-{list_id}", error="Unsupported block-list format")
    try:
        refresh_minutes = max(1, min(int(form.get("refresh_minutes", "1440")), 10080))
    except (TypeError, ValueError):
        refresh_minutes = 1440

    with db.connect() as con:
        existing = con.execute("SELECT * FROM blocklists WHERE id=?", (list_id,)).fetchone()
    if not existing:
        return redirect("/lists", error="Block list not found")

    replacement_content: str | None = None
    source_type = str(existing["source_type"])

    try:
        if action == "refresh":
            if not source_url:
                return redirect(
                    f"/lists#edit-list-{list_id}",
                    error="A source URL is required to refresh this list",
                )
            replacement_content = fetch_url(source_url)
            source_type = "url"
        elif getattr(replacement_file, "filename", None):
            replacement_content = (await replacement_file.read()).decode("utf-8", errors="replace")
            source_type = "upload"
        elif replacement_text.strip():
            replacement_content = replacement_text
            source_type = "manual"
        elif source_url:
            source_type = "url"
        elif source_type == "url":
            source_type = "manual"
    except Exception as e:
        return redirect(f"/lists#edit-list-{list_id}", error=f"Could not refresh list: {e}")

    with db.connect() as con:
        try:
            con.execute("BEGIN")
            con.execute(
                """
                UPDATE blocklists
                SET name=?, source_type=?, source_url=?, format=?, enabled=?,
                    use_globally=?, refresh_minutes=?, schedule_enabled=?,
                    schedule_days=?, schedule_start=?, schedule_end=?, schedule_timezone=?
                WHERE id=?
                """,
                (
                    name,
                    source_type,
                    source_url or None,
                    format_name,
                    1 if enabled else 0,
                    1 if global_list else 0,
                    refresh_minutes,
                    1 if schedule_enabled else 0,
                    schedule_days,
                    schedule_start,
                    schedule_end,
                    schedule_timezone,
                    list_id,
                ),
            )
            assigned = _save_list_scope_assignments(con, list_id, scope_ids)
            con.execute("COMMIT")
        except Exception as e:
            con.execute("ROLLBACK")
            return redirect(f"/lists#edit-list-{list_id}", error=f"Could not save list: {e}")

    replaced_notice = ""
    if replacement_content is not None:
        if not replacement_content.strip():
            return redirect(f"/lists#edit-list-{list_id}", error="Replacement list content is empty")
        try:
            count, ignored = import_list(list_id, replacement_content, format_name)
            replaced_notice = f"; replaced contents with {count:,} entries ({ignored:,} ignored)"
        except Exception as e:
            return redirect(
                f"/lists#edit-list-{list_id}",
                error=f"Settings were saved, but replacing list contents failed: {e}",
            )

    engine.reload()
    return redirect(
        f"/lists#list-{list_id}",
        notice=f"Saved {name}; {assigned} scoped assignment{'s' if assigned != 1 else ''}{replaced_notice}",
    )


@app.post("/admin/lists/{list_id}/toggle")
async def toggle_list(list_id: int, request: Request):
    await require_post_session(request)
    with db.connect() as con:
        con.execute("UPDATE blocklists SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?", (list_id,))
    engine.reload()
    return redirect(f"/lists#list-{list_id}", notice="List state updated")


@app.post("/admin/lists/{list_id}/delete")
async def delete_list(list_id: int, request: Request):
    await require_post_session(request)
    with db.connect() as con:
        con.execute("DELETE FROM blocklists WHERE id=?", (list_id,))
    engine.reload()
    return redirect("/lists", notice="Block list deleted")


def _scope_network_values(scope, network_targets: dict[int, dict[int, str]]) -> tuple[str, str]:
    values = network_targets.get(int(scope["id"]), {})
    ipv4 = str(values.get(4, "") or "")
    ipv6 = str(values.get(6, "") or "")
    if scope["kind"] == "network" and not ipv4 and not ipv6:
        try:
            network = ipaddress.ip_network(str(scope["target"]), strict=False)
            if network.version == 4:
                ipv4 = str(network)
            else:
                ipv6 = str(network)
        except ValueError:
            pass
    return ipv4, ipv6


def _network_target_html(ipv4: str, ipv6: str) -> str:
    parts: list[str] = []
    if ipv4:
        parts.append(
            f'<span class="network-family-target"><b>IPv4</b><span class="mono">{esc(ipv4)}</span></span>'
        )
    if ipv6:
        parts.append(
            f'<span class="network-family-target"><b>IPv6</b><span class="mono">{esc(ipv6)}</span></span>'
        )
    return '<span class="network-target-stack">' + "".join(parts) + "</span>"


def _normalize_network_targets(ipv4_raw: str, ipv6_raw: str) -> tuple[str, str]:
    ipv4 = ipv4_raw.strip()
    ipv6 = ipv6_raw.strip()
    if not ipv4 and not ipv6:
        raise ValueError("Enter an IPv4 CIDR, an IPv6 CIDR, or both")

    normalized_v4 = ""
    normalized_v6 = ""
    if ipv4:
        network4 = ipaddress.ip_network(ipv4, strict=False)
        if network4.version != 4:
            raise ValueError("IPv4 CIDR must be an IPv4 network")
        normalized_v4 = str(network4)
    if ipv6:
        network6 = ipaddress.ip_network(ipv6, strict=False)
        if network6.version != 6:
            raise ValueError("IPv6 CIDR must be an IPv6 network")
        normalized_v6 = str(network6)
    return normalized_v4, normalized_v6


def _save_scope_network_targets(
    con,
    scope_id: int,
    kind: str,
    ipv4: str,
    ipv6: str,
) -> None:
    con.execute("DELETE FROM scope_network_targets WHERE scope_id=?", (scope_id,))
    if kind != "network":
        return
    rows = []
    if ipv4:
        rows.append((scope_id, 4, ipv4))
    if ipv6:
        rows.append((scope_id, 6, ipv6))
    con.executemany(
        """
        INSERT INTO scope_network_targets(scope_id,family,target)
        VALUES(?,?,?)
        """,
        rows,
    )

@app.get("/scopes", response_class=HTMLResponse)
def scopes_page(request: Request):
    s = require_session(request)
    with db.connect() as con:
        scopes = con.execute("SELECT * FROM scopes ORDER BY kind,name COLLATE NOCASE").fetchall()
        blocklists = con.execute("SELECT * FROM blocklists ORDER BY name COLLATE NOCASE").fetchall()
        membership_rows = con.execute(
            "SELECT scope_id,blocklist_id FROM scope_blocklists"
        ).fetchall()
        network_target_rows = con.execute(
            "SELECT scope_id,family,target FROM scope_network_targets"
        ).fetchall()

    memberships: dict[int, set[int]] = {}
    for membership in membership_rows:
        memberships.setdefault(int(membership["scope_id"]), set()).add(int(membership["blocklist_id"]))

    network_targets: dict[int, dict[int, str]] = {}
    for row in network_target_rows:
        network_targets.setdefault(int(row["scope_id"]), {})[int(row["family"])] = str(row["target"])

    scope_client_names = rdns.resolve_many(
        scope["target"] for scope in scopes if scope["kind"] == "client"
    )

    def blocklist_option(blocklist, selected: set[int]) -> str:
        is_global = bool(blocklist["use_globally"])
        checked = " checked" if int(blocklist["id"]) in selected else ""
        disabled_attr = " disabled" if is_global else ""
        disabled_class = " global-disabled" if is_global else ""
        status_class = "green" if blocklist["enabled"] else "gray"
        global_badge = '<span class="scope-list-global">Global</span>' if is_global else ""
        schedule_badge = (
            '<span class="scope-list-scheduled">Scheduled</span>'
            if blocklist["schedule_enabled"]
            else ""
        )
        detail = (
            "Applied globally · individual assignment not needed"
            if is_global
            else f'{int(blocklist["entry_count"]):,} entries · {esc(blocklist["format"])}'
        )
        schedule_detail = (
            f'<small class="scope-list-schedule">{esc(schedule_summary(blocklist))}</small>'
            if blocklist["schedule_enabled"]
            else ""
        )
        return (
            f'<label class="scope-list-option{disabled_class}">'
            f'<input type="checkbox" name="blocklist_id" value="{int(blocklist["id"])}"{checked}{disabled_attr}>'
            f'<span class="scope-list-copy"><span class="scope-list-title">'
            f'<b>{esc(blocklist["name"])}</b>'
            f'<span class="pill {status_class}">{"Enabled" if blocklist["enabled"] else "Disabled"}</span>'
            f'{global_badge}{schedule_badge}</span>'
            f'<small>{detail}</small>{schedule_detail}'
            f'</span></label>'
        )

    def blocklist_editor(selected: set[int]) -> str:
        if not blocklists:
            return (
                '<div class="scope-empty">No block lists exist yet. '
                '<a href="/lists#add-list">Import one first →</a></div>'
            )
        return (
            '<div class="scope-list-grid">'
            + "".join(blocklist_option(blocklist, selected) for blocklist in blocklists)
            + '</div>'
        )

    cards = ""
    for scope in scopes:
        selected = memberships.get(int(scope["id"]), set())
        scope_ipv4, scope_ipv6 = _scope_network_values(scope, network_targets)
        if scope["kind"] == "client":
            target_html = client_identity_html(scope["target"], scope_client_names)
        elif scope["kind"] == "network":
            target_html = _network_target_html(scope_ipv4, scope_ipv6)
        else:
            target_html = f'<span class="mono">{esc(scope["target"])}</span>'
        single_target_value = "" if scope["kind"] == "network" else str(scope["target"])
        scope_kind_label = {
            "network": "Network",
            "client": "Endpoint",
            "hostname": "Hostname",
        }.get(scope["kind"], "Target")
        scope_kind_class = {
            "network": "network",
            "client": "client",
            "hostname": "hostname",
        }.get(scope["kind"], "network")
        scope_kind_icon = {
            "network": "◎",
            "client": "◆",
            "hostname": "◈",
        }.get(scope["kind"], "◎")
        assigned_names = [
            str(blocklist["name"])
            for blocklist in blocklists
            if int(blocklist["id"]) in selected
        ]
        assigned_summary = (
            ", ".join(assigned_names[:3])
            + (f" +{len(assigned_names) - 3} more" if len(assigned_names) > 3 else "")
            if assigned_names else "No explicit list assignments"
        )
        kind_network_selected = " selected" if scope["kind"] == "network" else ""
        kind_client_selected = " selected" if scope["kind"] == "client" else ""
        kind_hostname_selected = " selected" if scope["kind"] == "hostname" else ""
        state_active_selected = " selected" if scope["state"] == "active" else ""
        state_paused_selected = " selected" if scope["state"] == "paused" else ""
        scope_schedule_summary = schedule_summary(scope)
        scope_schedule_fields = schedule_fields_html(scope)
        scope_schedule_badge = (
            '<span class="scope-list-scheduled">Scheduled</span>'
            if scope["schedule_enabled"]
            else ""
        )
        scope_target_note = {
            "network": ("Dual-stack CIDR network", "Enter an IPv4 CIDR, an IPv6 CIDR, or both. Both families share the same policy."),
            "client": ("Exact client address", "Matches one exact IPv4/IPv6 client address."),
            "hostname": (
                "Reverse-DNS hostname",
                "Matches a learned PTR name exactly or by wildcard suffix such as *.kids.home.arpa.",
            ),
        }.get(scope["kind"], ("Policy target", "Changing the type changes target validation."))

        cards += f'''<article class="scope-card editable-scope-card" id="scope-{int(scope["id"])}">
          <div class="scope-card-summary">
            <div class="scope-summary-main">
              <div class="scope-icon {scope_kind_class}">{scope_kind_icon}</div>
              <div class="scope-summary-copy">
                <div class="scope-summary-title">
                  <h3>{esc(scope["name"])}</h3>
                  <span class="pill">{esc(scope_kind_label)}</span>
                  <span class="pill {"green" if scope["state"] == "active" else "amber"}">{esc(scope["state"])}</span>
                  {scope_schedule_badge}
                </div>
                <div class="scope-summary-target">{target_html}</div>
                <p class="scope-assignment-summary">{esc(assigned_summary)}</p>
                <p class="scope-schedule-summary {"scheduled" if scope["schedule_enabled"] else ""}">{esc(scope_schedule_summary)}</p>
              </div>
            </div>
            <div class="actions scope-card-actions">
              <form method="post" action="/admin/scopes/{int(scope["id"])}/toggle">
                <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">
                <button class="small-button">{"Pause" if scope["state"] == "active" else "Resume"}</button>
              </form>
              <a class="small-button edit-link" href="#edit-scope-{int(scope["id"])}">Edit & assign</a>
              <form method="post" action="/admin/scopes/{int(scope["id"])}/delete" onsubmit="return confirm('Delete this scope and its block-list assignments?')">
                <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">
                <button class="small-button danger">Delete</button>
              </form>
            </div>
          </div>
          <details class="scope-editor" id="edit-scope-{int(scope["id"])}">
            <summary><span><b>Edit {esc(scope_kind_label.lower())}</b><small>Identity, target, state, schedule and block-list assignments</small></span><span class="editor-chevron">⌄</span></summary>
            <div class="scope-edit-body">
              <form method="post" action="/admin/scopes/{int(scope["id"])}/edit" class="form-grid scope-edit-form">
                <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">
                <label>Name<input name="name" value="{esc(scope["name"])}" required></label>
                <label>Type<select name="kind" data-scope-kind-select><option value="network"{kind_network_selected}>Network</option><option value="client"{kind_client_selected}>Endpoint</option><option value="hostname"{kind_hostname_selected}>Reverse-DNS Hostname</option></select></label>
                <div class="network-target-fields full" data-scope-network-fields>
                  <label>IPv4 CIDR<input name="target_v4" value="{esc(scope_ipv4)}" placeholder="192.168.20.0/24"></label>
                  <label>IPv6 CIDR<input name="target_v6" value="{esc(scope_ipv6)}" placeholder="2001:db8:20::/64"></label>
                </div>
                <label class="full" data-scope-single-target>Endpoint IP / PTR hostname<input name="target" value="{esc(single_target_value)}" placeholder="192.168.20.44 or *.kids.home.arpa"></label>
                <label>Blocking state<select name="state"><option value="active"{state_active_selected}>Active</option><option value="paused"{state_paused_selected}>Paused</option></select></label>
                <div class="scope-edit-note"><b>{esc(scope_target_note[0])}</b><span>{esc(scope_target_note[1])}</span></div>

                <div class="form-section full schedule-section">
                  <div class="form-section-head"><div><b>Enforcement schedule</b><p>Leave scheduling off for this policy target to participate at all times.</p></div></div>
                  {scope_schedule_fields}
                </div>

                <div class="form-section full">
                  <div class="form-section-head">
                    <div><b>Block-list assignments</b><p>Select lists that should explicitly apply to this scope. Lists marked Global already apply everywhere, but can also remain explicitly assigned for future policy changes.</p></div>
                    <span>{len(selected)} selected</span>
                  </div>
                  {blocklist_editor(selected)}
                </div>

                <div class="editor-actions full">
                  <button class="primary-button" type="submit">Save changes</button>
                  <button class="small-button" type="button" onclick="this.closest('details').open=false">Close editor</button>
                </div>
              </form>
            </div>
          </details>
        </article>'''

    if not cards:
        cards = '<div class="empty-card">No managed policy targets yet. Add a network, endpoint, or reverse-DNS hostname to start scoping policy.</div>'

    new_list_editor = blocklist_editor(set())
    new_scope_schedule_fields = schedule_fields_html(default_timezone=system_default_timezone())
    body = f'''<div class="split-grid scopes-layout">
      <section class="panel">
        <div class="panel-head">
          <div><div class="panel-kicker">Policy targets</div><h3>Networks, endpoints & hostnames</h3><p>Edit targets, schedules, pause/resume enforcement, and block-list assignments without leaving this page.</p></div>
          <span class="result-count">{len(scopes)} scopes</span>
        </div>
        <div class="scope-card-list">{cards}</div>
      </section>

      <section class="panel action-panel" id="add-scope">
        <div class="panel-kicker">New policy target</div><h3>Add network, endpoint, or hostname</h3>
        <p class="panel-help">A Network can contain IPv4, IPv6, or both CIDRs under one shared policy. Endpoints use one exact IP; hostname targets use exact or wildcard PTR names.</p>
        <form method="post" action="/admin/scopes" class="form-grid">
          <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">
          <label>Name<input name="name" required></label>
          <label>Type<select name="kind" data-scope-kind-select><option value="network">Network</option><option value="client">Endpoint</option><option value="hostname">Reverse-DNS Hostname</option></select></label>
          <div class="network-target-fields full" data-scope-network-fields>
            <label>IPv4 CIDR<input name="target_v4" placeholder="192.168.20.0/24"></label>
            <label>IPv6 CIDR<input name="target_v6" placeholder="2001:db8:20::/64"></label>
          </div>
          <label class="full" data-scope-single-target>Endpoint IP / PTR hostname<input name="target" placeholder="192.168.20.44 or *.kids.home.arpa"></label>
          <label>Initial state<select name="state"><option value="active">Active</option><option value="paused">Paused</option></select></label>
          <div class="form-section full schedule-section">
            <div class="form-section-head"><div><b>Enforcement schedule</b><p>Optional. Limit when this policy target participates in policy.</p></div></div>
            {new_scope_schedule_fields}
          </div>
          <div class="form-section full">
            <div class="form-section-head"><div><b>Initial block-list assignments</b><p>Optional. Global lists apply automatically even when they are not explicitly selected.</p></div></div>
            {new_list_editor}
          </div>
          <button class="primary-button full" type="submit">Add scope</button>
        </form>
      </section>
    </div>'''
    return page(request, "Policy Targets", "scopes", body, s)


def _blocklist_ids_from_form(form) -> list[int]:
    blocklist_ids: list[int] = []
    for raw in form.getlist("blocklist_id"):
        try:
            blocklist_ids.append(int(raw))
        except (TypeError, ValueError):
            continue
    return list(dict.fromkeys(blocklist_ids))


def _save_scope_blocklist_assignments(con, scope_id: int, blocklist_ids: list[int]) -> int:
    con.execute("DELETE FROM scope_blocklists WHERE scope_id=?", (scope_id,))
    if not blocklist_ids:
        return 0
    placeholders = ",".join("?" for _ in blocklist_ids)
    valid_rows = con.execute(
        f"SELECT id FROM blocklists WHERE id IN ({placeholders}) AND use_globally=0",
        blocklist_ids,
    ).fetchall()
    valid_ids = [int(row["id"]) for row in valid_rows]
    con.executemany(
        "INSERT OR IGNORE INTO scope_blocklists(scope_id,blocklist_id) VALUES(?,?)",
        [(scope_id, blocklist_id) for blocklist_id in valid_ids],
    )
    return len(valid_ids)


def _normalize_scope_target(kind: str, target: str) -> str:
    target = target.strip()
    if kind == "client":
        return str(ipaddress.ip_address(target))
    if kind == "hostname":
        normalized = normalize_hostname_pattern(target)
        if normalized is None:
            raise ValueError(
                "Enter a valid PTR hostname or wildcard suffix such as *.kids.home.arpa"
            )
        return normalized
    raise ValueError("Scope type must be Network, Endpoint, or Reverse-DNS Hostname")


@app.post("/admin/scopes")
async def add_scope(request: Request):
    _, form = await require_post_session(request)
    name = str(form.get("name", "")).strip()
    kind = str(form.get("kind", "")).strip().lower()
    target_raw = str(form.get("target", ""))
    target_v4_raw = str(form.get("target_v4", ""))
    target_v6_raw = str(form.get("target_v6", ""))
    state = str(form.get("state", "active")).strip().lower()
    try:
        schedule_enabled, schedule_days, schedule_start, schedule_end, schedule_timezone = parse_schedule_form(
            form, "policy target"
        )
    except ValueError as e:
        return redirect("/scopes", error=str(e))
    blocklist_ids = _blocklist_ids_from_form(form)

    if not name:
        return redirect("/scopes", error="Scope name is required")
    if kind not in {"network", "client", "hostname"}:
        return redirect("/scopes", error="Scope type must be Network, Endpoint, or Reverse-DNS Hostname")
    if state not in {"active", "paused"}:
        return redirect("/scopes", error="Scope state must be active or paused")
    try:
        if kind == "network":
            target_v4, target_v6 = _normalize_network_targets(target_v4_raw, target_v6_raw)
            target = target_v4 or target_v6
        else:
            target_v4 = ""
            target_v6 = ""
            target = _normalize_scope_target(kind, target_raw)
    except ValueError as e:
        label = {
            "client": "endpoint IP address",
            "network": "network CIDRs",
            "hostname": "PTR hostname pattern",
        }.get(kind, "policy target")
        return redirect("/scopes", error=f"Invalid {label}: {e}")

    try:
        with db.connect() as con:
            con.execute("BEGIN")
            cur = con.execute(
                """
                INSERT INTO scopes(
                    name,kind,target,state,schedule_enabled,schedule_days,
                    schedule_start,schedule_end,schedule_timezone
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    name, kind, target, state,
                    1 if schedule_enabled else 0, schedule_days,
                    schedule_start, schedule_end, schedule_timezone,
                ),
            )
            scope_id = int(cur.lastrowid)
            _save_scope_network_targets(con, scope_id, kind, target_v4, target_v6)
            assigned = _save_scope_blocklist_assignments(con, scope_id, blocklist_ids)
            con.execute("COMMIT")
    except Exception as e:
        return redirect("/scopes", error=str(e))

    engine.reload()
    return redirect(
        f"/scopes#scope-{scope_id}",
        notice=f"Added {name} with {assigned} block-list assignment{'s' if assigned != 1 else ''}",
    )


@app.post("/admin/scopes/{scope_id}/edit")
async def edit_scope(scope_id: int, request: Request):
    _, form = await require_post_session(request)
    name = str(form.get("name", "")).strip()
    kind = str(form.get("kind", "")).strip().lower()
    target_raw = str(form.get("target", ""))
    target_v4_raw = str(form.get("target_v4", ""))
    target_v6_raw = str(form.get("target_v6", ""))
    state = str(form.get("state", "active")).strip().lower()
    try:
        schedule_enabled, schedule_days, schedule_start, schedule_end, schedule_timezone = parse_schedule_form(
            form, "policy target"
        )
    except ValueError as e:
        return redirect(f"/scopes#edit-scope-{scope_id}", error=str(e))
    blocklist_ids = _blocklist_ids_from_form(form)

    if not name:
        return redirect(f"/scopes#edit-scope-{scope_id}", error="Scope name is required")
    if kind not in {"network", "client", "hostname"}:
        return redirect(f"/scopes#edit-scope-{scope_id}", error="Scope type must be Network, Endpoint, or Reverse-DNS Hostname")
    if state not in {"active", "paused"}:
        return redirect(f"/scopes#edit-scope-{scope_id}", error="Scope state must be active or paused")
    try:
        if kind == "network":
            target_v4, target_v6 = _normalize_network_targets(target_v4_raw, target_v6_raw)
            target = target_v4 or target_v6
        else:
            target_v4 = ""
            target_v6 = ""
            target = _normalize_scope_target(kind, target_raw)
    except ValueError as e:
        label = {
            "client": "endpoint IP address",
            "network": "network CIDRs",
            "hostname": "PTR hostname pattern",
        }.get(kind, "policy target")
        return redirect(f"/scopes#edit-scope-{scope_id}", error=f"Invalid {label}: {e}")

    with db.connect() as con:
        existing = con.execute("SELECT id FROM scopes WHERE id=?", (scope_id,)).fetchone()
        if not existing:
            return redirect("/scopes", error="Policy target not found")
        try:
            con.execute("BEGIN")
            con.execute(
                """
                UPDATE scopes
                SET name=?,kind=?,target=?,state=?,schedule_enabled=?,schedule_days=?,
                    schedule_start=?,schedule_end=?,schedule_timezone=?
                WHERE id=?
                """,
                (
                    name, kind, target, state,
                    1 if schedule_enabled else 0, schedule_days,
                    schedule_start, schedule_end, schedule_timezone,
                    scope_id,
                ),
            )
            _save_scope_network_targets(con, scope_id, kind, target_v4, target_v6)
            assigned = _save_scope_blocklist_assignments(con, scope_id, blocklist_ids)
            con.execute("COMMIT")
        except Exception as e:
            con.execute("ROLLBACK")
            return redirect(f"/scopes#edit-scope-{scope_id}", error=f"Could not save scope: {e}")

    engine.reload()
    return redirect(
        f"/scopes#scope-{scope_id}",
        notice=f"Saved {name}; {assigned} block-list assignment{'s' if assigned != 1 else ''}",
    )


@app.post("/admin/scopes/{scope_id}/toggle")
async def toggle_scope(scope_id: int, request: Request):
    await require_post_session(request)
    with db.connect() as con:
        con.execute("UPDATE scopes SET state=CASE state WHEN 'active' THEN 'paused' ELSE 'active' END WHERE id=?", (scope_id,))
    engine.reload()
    return redirect(f"/scopes#scope-{scope_id}", notice="Scope state updated")


@app.post("/admin/scopes/{scope_id}/delete")
async def delete_scope(scope_id: int, request: Request):
    await require_post_session(request)
    with db.connect() as con:
        con.execute("DELETE FROM scopes WHERE id=?", (scope_id,))
    engine.reload()
    return redirect("/scopes", notice="Scope deleted")

@app.get("/queries", response_class=HTMLResponse)
def queries_page(
    request: Request,
    q: str = "",
    client: str = "",
    server: str = "",
    decision: str = "",
    limit: int = 100,
):
    s = require_session(request)
    clauses, args = [], []
    if q:
        clauses.append("qname LIKE ?")
        args.append("%" + q + "%")
    if client:
        backfill_query_client_names()
        clauses.append("(client_ip LIKE ? OR client_name LIKE ?)")
        client_pattern = "%" + client + "%"
        args.extend([client_pattern, client_pattern])
    if server:
        clauses.append("server_id = ?")
        args.append(server)
    if decision in {"blocked", "allowed"}:
        clauses.append("blocked=?")
        args.append(1 if decision == "blocked" else 0)

    limit = max(25, min(limit, 500))
    sql = (
        "SELECT * FROM query_log"
        + (" WHERE " + " AND ".join(clauses) if clauses else "")
        + " ORDER BY id DESC LIMIT ?"
    )
    args.append(limit)

    with db.connect() as con:
        rows = con.execute(sql, args).fetchall()
        server_rows = con.execute(
            """
            SELECT DISTINCT server_id
            FROM query_log
            WHERE server_id IS NOT NULL AND TRIM(server_id) <> ''
            ORDER BY server_id COLLATE NOCASE
            """
        ).fetchall()

    query_client_names = log_client_names(rows)
    trs = "".join(
        f'<tr><td>{esc(r["ts"])}</td>'
        f'<td>{querying_server_html(r["server_id"])}</td>'
        f'<td>{client_identity_html(r["client_ip"], query_client_names)}</td>'
        f'<td>{esc(r["qname"])}</td>'
        f'<td>{esc(r["qtype"])}</td>'
        f'<td><span class="pill {"red" if r["blocked"] else "green"}">'
        f'{"Blocked" if r["blocked"] else "Allowed"}</span></td>'
        f'<td>{esc((r["matched_list"] or r["reason"]) if r["blocked"] else "")}</td></tr>'
        for r in rows
    ) or '<tr><td colspan="7" class="empty">No matching queries.</td></tr>'

    server_options = '<option value="">All servers</option>' + "".join(
        f'<option value="{esc(row["server_id"])}"'
        f'{" selected" if server == row["server_id"] else ""}>'
        f'{esc(row["server_id"])}</option>'
        for row in server_rows
    )

    body = f'''<section class="panel">
      <div class="panel-head query-head">
        <div><div class="panel-kicker">DNS activity</div><h3>Decision history</h3>
        <p>Showing {len(rows)} most recent matching requests, including the DNS server that submitted each query.</p></div>
        <span class="result-count">{len(rows)} results</span>
      </div>
      <form class="filter-bar query-filter-bar" method="get">
        <input name="q" value="{esc(q)}" placeholder="Domain contains…">
        <input name="client" value="{esc(client)}" placeholder="Client IP or hostname…">
        <select name="server">{server_options}</select>
        <select name="decision">
          <option value="">All decisions</option>
          <option value="blocked" {"selected" if decision=="blocked" else ""}>Blocked</option>
          <option value="allowed" {"selected" if decision=="allowed" else ""}>Allowed</option>
        </select>
        <select name="limit">
          <option value="{limit}">{limit}</option>
          <option>50</option><option>100</option><option>250</option><option>500</option>
        </select>
        <button class="primary-button">Filter</button>
      </form>
      <div class="table-wrap"><table>
        <thead><tr><th>Time</th><th>Server</th><th>Client</th><th>Domain</th><th>Type</th><th>Decision</th><th>Match</th></tr></thead>
        <tbody>{trs}</tbody>
      </table></div>
    </section>'''
    return page(request, "Query Log", "queries", body, s)

@app.get("/security", response_class=HTMLResponse)
def security_page(request: Request):
    s = require_session(request)
    keys = auth.list_api_keys()
    cards = ""
    for k in keys:
        cards += f'''<article class="key-card"><div><h3>{esc(k["name"])}</h3><p class="mono">{esc(k["key_prefix"])}</p><small>Last used: {esc(k["last_used_at"] or "Never")}</small></div><span class="pill {"green" if k["enabled"] else "gray"}">{"Enabled" if k["enabled"] else "Disabled"}</span>
        <div class="actions"><form method="post" action="/admin/api-keys/{k["id"]}/toggle"><input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}"><button class="small-button">{"Disable" if k["enabled"] else "Enable"}</button></form><form method="post" action="/admin/api-keys/{k["id"]}/delete"><input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}"><button class="small-button danger">Delete</button></form></div></article>'''
    reveal = request.query_params.get("reveal")
    reveal_box = f'<div class="secret-box"><b>Copy this API key now</b><code>{esc(reveal)}</code><p>It will not be shown again.</p></div>' if reveal else ""
    body = f'''{reveal_box}<div class="split-grid"><section class="panel action-panel"><div class="panel-kicker">Console access</div><h3>Administrator credentials</h3><p class="panel-help">Update the account used to sign in to this Blockinator console.</p><form method="post" action="/admin/credentials" class="form-grid"><input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}"><label>Username<input name="username" value="{esc(s.username)}" required></label><label>Current password<input type="password" name="current_password" required></label><label>New password<input type="password" name="new_password"></label><label>Confirm new password<input type="password" name="confirm_password"></label><button class="primary-button">Update credentials</button></form></section>
    <section class="panel action-panel" id="create-key"><div class="panel-kicker">Resolver access</div><h3>Create API key</h3><p class="panel-help">Give each DNS server its own named credential so keys can be rotated or revoked independently.</p><form method="post" action="/admin/api-keys" class="form-grid"><input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}"><label class="full">Key name<input name="name" placeholder="Primary Technitium" required></label><button class="primary-button">Generate key</button></form></section></div>
    <section class="panel"><div class="panel-head"><div><h3>API keys</h3><p>Multiple resolvers can authenticate independently. Secrets are stored only as hashes.</p></div></div><div class="card-grid">{cards or '<div class="empty-card">No API keys.</div>'}</div></section>'''
    return page(request, "Access & Security", "security", body, s)

@app.post("/admin/credentials")
async def update_credentials(request: Request):
    s, form = await require_post_session(request)
    username = str(form.get("username","")).strip()
    current = str(form.get("current_password",""))
    new = str(form.get("new_password",""))
    confirm = str(form.get("confirm_password",""))
    if new != confirm:
        return redirect("/security", error="New passwords do not match")
    try:
        canonical = auth.update_admin_credentials(s.user_id, current, username, new or None)
    except ValueError as e:
        return redirect("/security", error=str(e))
    ns = auth.create_session(s.user_id, canonical)
    response = redirect("/security", notice="Administrator credentials updated")
    response.set_cookie(SESSION_COOKIE, ns.token, max_age=SESSION_TTL_SECONDS, httponly=True, samesite="strict", path="/")
    return response

@app.post("/admin/api-keys")
async def create_key(request: Request):
    _, form = await require_post_session(request)
    try:
        _id, raw = auth.create_api_key(str(form.get("name","")).strip())
        return redirect("/security", notice="API key created") if not raw else redirect("/security?reveal=" + quote(raw), notice="API key created")
    except ValueError as e:
        return redirect("/security", error=str(e))

@app.post("/admin/api-keys/{key_id}/toggle")
async def toggle_key(key_id: int, request: Request):
    await require_post_session(request)
    with db.connect() as con:
        row = con.execute("SELECT enabled FROM api_keys WHERE id=?", (key_id,)).fetchone()
    if not row:
        return redirect("/security", error="API key not found")
    try:
        auth.set_api_key_enabled(key_id, not bool(row["enabled"]))
    except ValueError as e:
        return redirect("/security", error=str(e))
    return redirect("/security", notice="API key state updated")

@app.post("/admin/api-keys/{key_id}/delete")
async def delete_key(key_id: int, request: Request):
    await require_post_session(request)
    try:
        auth.delete_api_key(key_id)
    except ValueError as e:
        return redirect("/security", error=str(e))
    return redirect("/security", notice="API key deleted")

@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    s = require_session(request)
    mode = db.get_setting("block_response", "nxdomain")
    retention = db.get_setting("max_query_logs", "25000")
    retention_days = db.get_setting("max_query_log_age_days", "0")
    default_timezone = system_default_timezone()
    age_summary = (
        "Disabled"
        if str(retention_days) == "0"
        else f'{esc(retention_days)} day{"s" if str(retention_days) != "1" else ""}'
    )
    body = f'''<div class="split-grid">
      <section class="panel action-panel">
        <div class="panel-kicker">DNS behavior</div>
        <h3>Blocked response & logging</h3>
        <p class="panel-help">Configure blocked DNS responses and how long query history is retained.</p>
        <form method="post" action="/admin/settings" class="form-grid">
          <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">
          <label class="full">Response mode
            <select name="block_response">
              <option value="nxdomain" {"selected" if mode=="nxdomain" else ""}>NXDOMAIN</option>
              <option value="refused" {"selected" if mode=="refused" else ""}>REFUSED</option>
              <option value="nodata" {"selected" if mode=="nodata" else ""}>NODATA</option>
              <option value="zero" {"selected" if mode=="zero" else ""}>0.0.0.0 / ::</option>
            </select>
          </label>

          <div class="form-section full log-retention-section">
            <div class="form-section-head">
              <div><b>Query log retention</b><p>Both limits apply. Blockinator removes a row when it exceeds either the age limit or the row-count limit.</p></div>
              <span>{age_summary}</span>
            </div>
            <div class="retention-grid">
              <label>Maximum age (days)
                <input type="number" min="0" max="3650" name="max_query_log_age_days" value="{esc(retention_days)}">
                <small>0 disables time-based retention.</small>
              </label>
              <label>Maximum rows
                <input type="number" min="1000" max="5000000" name="max_query_logs" value="{esc(retention)}">
                <small>Oldest rows are removed when this cap is exceeded.</small>
              </label>
            </div>
          </div>

          <div class="form-section full">
            <div class="form-section-head">
              <div><b>Default schedule timezone</b><p>Used when creating new block-list and policy-target schedules. Existing schedules keep their saved timezone.</p></div>
              <span>{esc(default_timezone)}</span>
            </div>
            <label class="full">IANA timezone
              <input name="default_timezone" value="{esc(default_timezone)}" list="timezone-options" placeholder="America/New_York" required>
              <small>Examples: UTC, America/New_York, America/Chicago, America/Denver, America/Los_Angeles.</small>
            </label>
            <datalist id="timezone-options">
              <option value="UTC"></option>
              <option value="America/New_York"></option>
              <option value="America/Chicago"></option>
              <option value="America/Denver"></option>
              <option value="America/Los_Angeles"></option>
              <option value="America/Anchorage"></option>
              <option value="Pacific/Honolulu"></option>
            </datalist>
          </div>

          <button class="primary-button full">Save settings & prune logs</button>
        </form>
      </section>

      <section class="panel">
        <div class="panel-kicker">Service details</div><h3>Runtime</h3>
        <p class="panel-help">Current application and storage information for this Blockinator instance.</p>
        <div class="info-grid">
          <div><span>Version</span><b>{APP_VERSION}</b></div>
          <div><span>Database</span><b class="mono">{esc(db.path)}</b></div>
          <div><span>Decision API</span><b class="mono">/api/v1/decision</b></div>
          <div><span>Service</span><b>Blockinator</b></div>
          <div><span>Log age limit</span><b>{age_summary}</b></div>
          <div><span>Log row limit</span><b>{int(retention):,}</b></div>
          <div><span>Default timezone</span><b class="mono">{esc(default_timezone)}</b></div>
        </div>
      </section>
    </div>'''
    return page(request, "System Settings", "settings", body, s)

@app.post("/admin/settings")
async def save_settings(request: Request):
    _, form = await require_post_session(request)
    mode = str(form.get("block_response","nxdomain"))
    if mode not in {"nxdomain","refused","nodata","zero"}:
        mode = "nxdomain"
    try:
        retention = max(1000, min(int(form.get("max_query_logs","25000")), 5_000_000))
    except (TypeError, ValueError):
        retention = 25000
    try:
        retention_days = max(0, min(int(form.get("max_query_log_age_days","0")), 3650))
    except (TypeError, ValueError):
        retention_days = 0

    default_timezone = str(form.get("default_timezone", "")).strip() or "UTC"
    try:
        ZoneInfo(default_timezone)
    except (ZoneInfoNotFoundError, ValueError):
        return redirect(
            "/settings",
            error="Default timezone must be a valid IANA timezone such as America/New_York",
        )

    db.set_setting("block_response", mode)
    db.set_setting("max_query_logs", str(retention))
    db.set_setting("max_query_log_age_days", str(retention_days))
    db.set_setting("default_timezone", default_timezone)
    engine.reload()

    try:
        age_deleted, row_deleted = engine.logger.prune_now()
        removed = age_deleted + row_deleted
        notice = (
            f"Settings saved; pruned {removed:,} query log row{'s' if removed != 1 else ''}"
            if removed
            else "Settings saved; no query log rows needed pruning"
        )
    except Exception:
        notice = "Settings saved; automatic retention will apply on the next logged query"

    return redirect("/settings", notice=notice)
