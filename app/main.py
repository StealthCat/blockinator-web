from __future__ import annotations

import html
import ipaddress
import json
import os
import secrets
from datetime import datetime, time as dt_time, timezone
from time import perf_counter_ns
from pathlib import Path
from urllib.parse import quote
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .auth import AuthManager, SESSION_COOKIE, SESSION_TTL_SECONDS
from .blocklists import fetch_url, normalize_domain, parse_blocklist
from .db import Database
from .policy import PolicyEngine, normalize_hostname_pattern
from .rdns import ReverseDnsResolver
from .refresher import BlocklistRefresher
from .statistics import build_statistics_snapshot
from .timeutil import format_timestamp_for_timezone
from .tls import DEFAULT_ACME_DIRECTORY, TlsManager, TlsSettings, validate_http_redirect_change

BASE_DIR = Path(__file__).resolve().parent
APP_VERSION = "1.18.5"


class PolicyResponseTimingMiddleware:
    """Measure policy API latency through the final ASGI response send."""

    def __init__(self, app, engine: PolicyEngine) -> None:
        self.app = app
        self.engine = engine

    async def __call__(self, scope, receive, send) -> None:
        if (
            scope.get("type") != "http"
            or scope.get("path") != "/api/v1/decision"
        ):
            await self.app(scope, receive, send)
            return

        started_ns = perf_counter_ns()
        state = scope.setdefault("state", {})
        logged = False

        async def send_with_timing(message) -> None:
            nonlocal logged
            await send(message)
            if (
                not logged
                and message.get("type") == "http.response.body"
                and not message.get("more_body", False)
            ):
                log_row = state.pop("policy_log_row", None)
                if log_row is not None:
                    log_row["response_time_ms"] = (
                        perf_counter_ns() - started_ns
                    ) / 1_000_000.0
                    self.engine.logger.submit(log_row)
                    logged = True

        await self.app(scope, receive, send_with_timing)


app = FastAPI(title="Blockinator", version=APP_VERSION)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

db = Database()
_runtime_settings = db.get_settings(
    {
        "default_timezone": os.getenv("TZ", "UTC").strip() or "UTC",
        "ui_theme": "dark",
    }
)
_runtime_default_timezone = (
    _runtime_settings["default_timezone"].strip() or "UTC"
)
_runtime_ui_theme = _runtime_settings["ui_theme"].strip().lower() or "dark"

auth = AuthManager(db)
rdns = ReverseDnsResolver()
engine = PolicyEngine(db, rdns=rdns)
app.add_middleware(PolicyResponseTimingMiddleware, engine=engine)
refresher = BlocklistRefresher(db, engine)
tls_manager = TlsManager(db)


@app.on_event("startup")
def start_background_workers() -> None:
    refresher.start()
    tls_manager.start()


@app.on_event("shutdown")
def stop_background_workers() -> None:
    tls_manager.stop()
    refresher.stop()
    engine.close()
    auth.close()
    rdns.close()


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


def decision_match_text(row) -> str:
    matched_list = str(row["matched_list"] or "").strip()
    if matched_list:
        if str(row["matched_list_type"] or "") == "whitelist":
            return f"Whitelist: {matched_list}"
        return matched_list
    return str(row["reason"] or "") if row["blocked"] else ""


def response_time_text(value) -> str:
    if value is None:
        return "—"
    milliseconds = float(value)
    if milliseconds < 1:
        return f"{milliseconds:.3f} ms"
    if milliseconds < 100:
        return f"{milliseconds:.2f} ms"
    return f"{milliseconds:.1f} ms"


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


def _update_runtime_settings_cache(
    *,
    default_timezone: str | None = None,
    ui_theme: str | None = None,
) -> None:
    global _runtime_default_timezone, _runtime_ui_theme
    if default_timezone is not None:
        _runtime_default_timezone = default_timezone
    if ui_theme is not None:
        _runtime_ui_theme = ui_theme


def system_default_timezone() -> str:
    configured = _runtime_default_timezone
    try:
        ZoneInfo(configured)
    except (ZoneInfoNotFoundError, ValueError):
        return "UTC"
    return configured


def log_client_names(rows) -> dict[str, str | None]:
    """Render stored or already-learned PTR identities without blocking on DNS."""
    names: dict[str, str | None] = {}
    for row in rows:
        address = str(row["client_ip"] or "").strip()
        stored_name = None
        try:
            stored_name = row["client_name"]
        except (IndexError, KeyError):
            stored_name = None
        names[address] = (
            str(stored_name)
            if stored_name
            else engine.known_client_name(address)
        )
    return names


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


def application_theme() -> str:
    theme = _runtime_ui_theme
    return theme if theme in {"dark", "light"} else "dark"


def page(request: Request, title: str, active: str, body: str, session=None) -> HTMLResponse:
    notice = request.query_params.get("notice")
    error = request.query_params.get("error")
    if session is None:
        session = session_for(request)

    page_descriptions = {
        "dashboard": "Monitor DNS enforcement, request activity, and policy health at a glance.",
        "statistics": "Watch live DNS request volume, blocks, and policy response latency over time.",
        "lists": "Import, organize, and control the domain intelligence that powers your blocking policy.",
        "whitelists": "Create explicit allow rules with the same sources, schedules, assignments, and refresh controls as block lists.",
        "scopes": "Define filtering by network, exact endpoint, or reverse-DNS hostname and control each target independently.",
        "queries": "Inspect DNS decisions, troubleshoot policy matches, and follow activity across your clients.",
        "security": "Manage administrator access and the API credentials used by connected DNS resolvers.",
        "settings": "Tune Blockinator's response behavior, retention, and core service preferences.",
    }
    page_actions = {
        "dashboard": ('/queries', 'View activity', 'arrow'),
        "statistics": (None, None, None),
        "lists": ('#add-list', 'Import a list', 'plus'),
        "whitelists": ('#add-list', 'Add whitelist', 'plus'),
        "scopes": ('#add-scope', 'Add endpoint', 'plus'),
        "queries": ('/queries', 'Reset filters', 'refresh'),
        "security": ('#create-key', 'Create API key', 'plus'),
        "settings": (None, None, None),
    }

    nav = [
        ("/", "dashboard", "Dashboard", "⌂"),
        ("/statistics", "statistics", "Statistics", "∿"),
        ("/lists", "lists", "Block Lists", "☷"),
        ("/whitelists", "whitelists", "Whitelists", "✓"),
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
    ui_theme = application_theme()
    theme_color = "#f4f7fb" if ui_theme == "light" else "#071018"
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
<html lang="en" data-theme="{ui_theme}">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="{theme_color}">
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

def import_list(
    list_id: int,
    text: str,
    fmt: str,
    reload_policy: bool = True,
):
    with db.connect() as con:
        row = con.execute(
            "SELECT list_type FROM blocklists WHERE id=?",
            (list_id,),
        ).fetchone()
    list_type = str(row["list_type"] or "block") if row else "block"
    if list_type not in {"block", "whitelist"}:
        list_type = "block"
    parsed = parse_blocklist(text, fmt, list_type)
    with db.connect() as con:
        con.execute("BEGIN IMMEDIATE")
        db.replace_list_domains(con, list_id, parsed.domains)
        con.execute(
            """
            UPDATE blocklists
            SET entry_count=?,
                last_updated=CURRENT_TIMESTAMP,
                last_refresh_attempt=CURRENT_TIMESTAMP,
                last_error=NULL
            WHERE id=?
            """,
            (len(parsed.domains), list_id),
        )
        con.execute("COMMIT")
    if reload_policy:
        engine.reload_lists()
    return len(parsed.domains), parsed.ignored

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.get("/api/v1/ping")
def ping(x_api_key: str | None = Header(default=None)):
    api_key_ok(x_api_key)
    return {"status": "ok", "service": "blockinator", "version": APP_VERSION}

@app.post("/api/v1/decision")
def decision(
    payload: DecisionRequest,
    request: Request,
    x_api_key: str | None = Header(default=None),
):
    api_key_ok(x_api_key)
    policy_scheme = request.url.scheme.lower()
    d, log_row = engine.decide_with_log_row(
        payload.model_dump(by_alias=True),
        policy_scheme=policy_scheme if policy_scheme in {"http", "https"} else None,
    )
    request.state.policy_log_row = log_row
    return {
        "block": d.block,
        "reason": d.reason,
        "matched_scope": d.matched_scope,
        "matched_list": d.matched_list,
        "matched_list_type": d.matched_list_type,
        "matched_domain": d.matched_domain,
        "response_mode": d.response_mode,
    }

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if session_for(request):
        return RedirectResponse("/", status_code=303)
    error = request.query_params.get("error", "")
    ui_theme = application_theme()
    theme_color = "#f4f7fb" if ui_theme == "light" else "#071018"
    return HTMLResponse(f"""<!doctype html><html data-theme="{ui_theme}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="{theme_color}"><title>Sign in · Blockinator</title><link rel="icon" href="/static/blockinator-mark.webp"><link rel="stylesheet" href="/static/style.css"></head>
<body class="login-body"><section class="login-visual"><div class="login-shade"></div><div class="login-copy"><img src="/static/blockinator-mark.webp" alt=""><p>DNS POLICY CONTROL</p><h1>Bad traffic<br>stops here.</h1><span>Block · Filter · Protect</span></div></section>
<section class="login-panel"><form method="post" action="/login" class="login-card"><div class="mini-brand"><img src="/static/blockinator-mark.webp" alt=""><b>Blockinator</b></div><h2>Welcome back</h2><p>Sign in to manage DNS policy, endpoints, block lists and access keys.</p>
{"<div class='flash bad'>" + esc(error) + "</div>" if error else ""}
<label>Username<input name="username" autocomplete="username" required autofocus></label>
<label>Password<input type="password" name="password" autocomplete="current-password" required></label>
<button class="primary-button wide" type="submit">Sign in</button><small>Blockinator v{APP_VERSION}</small></form></section></body></html>""")

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    result = auth.authenticate(username, password)
    if not result:
        return redirect("/login", error="Invalid username or password")
    user_id, canonical = result
    s = auth.create_session(user_id, canonical)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE, s.token, max_age=SESSION_TTL_SECONDS, httponly=True,
        secure=(request.url.scheme == "https" or os.getenv("ADMIN_COOKIE_SECURE", "0").lower() in {"1","true","yes","on"}),
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
    snapshot = engine.snapshot
    with db.connect() as con:
        query_totals = dict(
            con.execute(
                """
                SELECT
                    COUNT(*) AS queries,
                    COALESCE(SUM(blocked),0) AS blocked
                FROM query_log
                """
            ).fetchone()
        )
        recent = con.execute(
            """
            SELECT
              ts,server_id,client_ip,client_name,qname,blocked,reason,
              matched_scope,matched_list,matched_list_type,policy_scheme,
              response_time_ms
            FROM query_log
            ORDER BY id DESC
            LIMIT 8
            """
        ).fetchall()
    totals = {
        "queries": int(query_totals["queries"] or 0),
        "blocked": int(query_totals["blocked"] or 0),
        "entries": snapshot.unique_domain_count,
        "block_entries": snapshot.block_domain_count,
        "whitelist_entries": snapshot.whitelist_domain_count,
        "networks": snapshot.network_scope_count,
        "clients": snapshot.client_scope_count,
        "hostnames": snapshot.hostname_scope_count,
    }
    global_on = snapshot.global_blocking
    recent_client_names = log_client_names(recent)
    display_timezone = system_default_timezone()
    rows = "".join(
        f'<tr><td title="Stored in UTC">{esc(format_timestamp_for_timezone(r["ts"], display_timezone))}</td>'
        f'<td>{querying_server_html(r["server_id"])}</td>'
        f'<td>{client_identity_html(r["client_ip"], recent_client_names)}</td>'
        f'<td>{esc(r["qname"])}</td>'
        f'<td>{esc((r["policy_scheme"] or "").upper() or "—")}</td>'
        f'<td>{esc(response_time_text(r["response_time_ms"]))}</td>'
        f'<td>{esc(r["matched_scope"] or "—")}</td>'
        f'<td><span class="pill {"red" if r["blocked"] else "green"}">'
        f'{"Blocked" if r["blocked"] else "Allowed"}</span></td>'
        f'<td>{esc(decision_match_text(r))}</td></tr>'
        for r in recent
    ) or '<tr><td colspan="9" class="empty">No DNS decisions recorded yet.</td></tr>'
    body = f'''
    <section class="hero-card"><img src="/static/blockinator-hero.webp" alt="Blockinator"><div class="hero-overlay"><p>BLOCK · FILTER · PROTECT</p><h2>Your network. Your policy.</h2><span>Centralized DNS policy control with client-aware filtering.</span></div></section>
    <div class="stat-grid">
      <article class="stat"><span>Queries</span><strong>{totals["queries"]:,}</strong><small>Recorded decisions</small></article>
      <article class="stat"><span>Blocked</span><strong>{totals["blocked"]:,}</strong><small>Rejected requests</small></article>
      <article class="stat"><span>Policy domains</span><strong>{totals["entries"]:,}</strong><small>{totals["block_entries"]:,} block · {totals["whitelist_entries"]:,} whitelist</small></article>
      <article class="stat"><span>Policy targets</span><strong>{totals["clients"] + totals["networks"] + totals["hostnames"]:,}</strong><small>{totals["networks"]} networks · {totals["clients"]} endpoints · {totals["hostnames"]} hostnames</small></article>
    </div>
    <section class="panel status-panel"><div><span class="big-dot {"green" if global_on else "amber"}"></span><div><h3>Global blocking is {"active" if global_on else "paused"}</h3><p>{"Policy decisions are enforced." if global_on else "All requests are currently allowed."}</p></div></div>
      <form method="post" action="/admin/global-toggle"><input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}"><button class="{"danger-button" if global_on else "primary-button"}">{"Pause blocking" if global_on else "Resume blocking"}</button></form>
    </section>
    <section class="panel"><div class="panel-head"><div><h3>Recent DNS activity</h3><p>Latest policy decisions from connected resolvers · times shown in {esc(display_timezone)}.</p></div><a class="text-link" href="/queries">View all →</a></div>
      <div class="table-wrap"><table><thead><tr><th>Time</th><th>Server</th><th>Client</th><th>Domain</th><th>Policy API</th><th>Response time</th><th>Policy target</th><th>Decision</th><th>Reason</th></tr></thead><tbody>{rows}</tbody></table></div>
    </section>'''
    return page(request, "Dashboard", "dashboard", body, s)

@app.get("/statistics", response_class=HTMLResponse)
def statistics_page(request: Request):
    s = require_session(request)
    display_timezone = system_default_timezone()
    snapshot = build_statistics_snapshot(
        db,
        minutes=60,
        timezone_name=display_timezone,
    )
    totals = snapshot["totals"]
    average_response = response_time_text(
        totals["average_response_time_ms"]
    )
    body = f"""
    <section class="statistics-page" data-statistics-dashboard data-window="60">
      <div class="statistics-live-strip">
        <div class="statistics-live-state">
          <span class="statistics-live-dot"></span>
          <span><b>Live statistics</b><small>Refreshes every 5 seconds</small></span>
        </div>
        <div class="statistics-updated" data-statistics-updated>Connecting to live data…</div>
      </div>

      <div class="stat-grid statistics-summary-grid">
        <article class="stat statistics-summary-card">
          <span>Total queries</span>
          <strong data-statistics-total="queries">{int(totals["queries"]):,}</strong>
          <small>Queries retained in the log</small>
        </article>
        <article class="stat statistics-summary-card">
          <span>Total blocks</span>
          <strong data-statistics-total="blocks">{int(totals["blocks"]):,}</strong>
          <small>Blocked queries retained in the log</small>
        </article>
        <article class="stat statistics-summary-card">
          <span>Average response time</span>
          <strong data-statistics-total="response">{esc(average_response)}</strong>
          <small>Measured policy API responses</small>
        </article>
      </div>

      <section class="panel statistics-chart-panel">
        <div class="panel-head statistics-chart-head">
          <div>
            <div class="panel-kicker">Live traffic</div>
            <h3>DNS query activity</h3>
            <p>Queries and blocked requests per interval · times shown in {esc(display_timezone)}.</p>
          </div>
          <div class="statistics-window-picker" role="group" aria-label="Statistics time range">
            <button type="button" data-statistics-window="15">15m</button>
            <button type="button" class="active" data-statistics-window="60">1h</button>
            <button type="button" data-statistics-window="360">6h</button>
            <button type="button" data-statistics-window="1440">24h</button>
          </div>
        </div>

        <div class="statistics-chart-meta">
          <div class="statistics-legend">
            <span><i class="statistics-legend-swatch queries"></i>Queries</span>
            <span><i class="statistics-legend-swatch blocks"></i>Blocks</span>
          </div>
          <span data-statistics-bucket>1 minute intervals</span>
        </div>

        <div class="statistics-chart-shell">
          <svg
            class="statistics-chart"
            data-statistics-chart
            viewBox="0 0 1000 340"
            preserveAspectRatio="none"
            role="img"
            aria-label="Live DNS query and block statistics"
          ></svg>
          <div class="statistics-chart-empty" data-statistics-empty hidden>
            No query activity in this time range.
          </div>
        </div>
      </section>
    </section>
    """
    return page(request, "Statistics", "statistics", body, s)


@app.get("/api/v1/statistics")
def statistics_api(
    request: Request,
    minutes: int = 60,
):
    require_session(request)
    return build_statistics_snapshot(
        db,
        minutes=minutes,
        timezone_name=system_default_timezone(),
    )


@app.post("/admin/global-toggle")
async def global_toggle(request: Request):
    _, _form = await require_post_session(request)
    current = db.get_setting("global_blocking", "1") == "1"
    db.set_setting("global_blocking", "0" if current else "1")
    engine.reload_settings()
    return redirect("/", notice="Global blocking paused" if current else "Global blocking resumed")

@app.get("/lists", response_class=HTMLResponse)
def lists_page(request: Request):
    return _managed_lists_page(request, "block")


@app.get("/whitelists", response_class=HTMLResponse)
def whitelists_page(request: Request):
    return _managed_lists_page(request, "whitelist")


def _managed_lists_page(request: Request, list_type: str):
    s = require_session(request)
    is_whitelist = list_type == "whitelist"
    base_path = "/whitelists" if is_whitelist else "/lists"
    active_key = "whitelists" if is_whitelist else "lists"
    singular_label = "whitelist" if is_whitelist else "block list"
    plural_label = "whitelists" if is_whitelist else "block lists"
    with db.connect() as con:
        rows = con.execute(
            "SELECT * FROM blocklists WHERE list_type=? ORDER BY name COLLATE NOCASE",
            (list_type,),
        ).fetchall()
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

    client_names = {
        str(scope["target"]): engine.known_client_name(str(scope["target"]))
        for scope in scopes
        if scope["kind"] == "client"
    }
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
        error_html = (
            f'<div class="list-warning">Last refresh error: {esc(r["last_error"])}</div>'
            if r["last_error"] else ""
        )
        source_label = r["source_url"] or (
            "Uploaded list" if r["source_type"] == "upload" else "Manual list"
        )
        if r["source_type"] == "url":
            refresh_summary = f'Auto-refresh every {int(r["refresh_minutes"]):,} minute{"s" if int(r["refresh_minutes"]) != 1 else ""}'
            refresh_detail = (
                f'Last attempt {r["last_refresh_attempt"]}'
                if r["last_refresh_attempt"]
                else "Waiting for first scheduled refresh"
            )
        else:
            refresh_summary = "No automatic refresh"
            refresh_detail = "Only URL-backed lists refresh automatically"
        list_schedule_summary = schedule_summary(r)
        manual_manage_link = (
            f'<a class="small-button domain-manage-link" href="{base_path}/{int(r["id"])}/domains">'
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
              <span class="refresh-meta {"scheduled" if r["source_type"] == "url" else ""}" title="{esc(refresh_detail)}">{esc(refresh_summary)}</span>
              <span>Updated {esc(r["last_updated"] or "Never")}</span>
            </div>
            {error_html}
            <div class="actions list-card-actions">
              <form method="post" action="/admin/lists/{int(r["id"])}/toggle">
                <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">
                <button class="small-button">{"Disable" if r["enabled"] else "Enable"}</button>
              </form>
              <a class="small-button edit-link" href="{base_path}/{int(r["id"])}/edit">Edit</a>
              {manual_manage_link}
              <form method="post" action="/admin/lists/{int(r["id"])}/delete" onsubmit="return confirm('Delete this {singular_label} and its scope assignments?')">
                <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">
                <button class="small-button danger">Delete</button>
              </form>
            </div>
          </div>
        </article>'''

    if not cards:
        cards = f'<div class="empty-card">No {plural_label} yet. Import one to start building policy.</div>'

    new_schedule_fields = schedule_fields_html(default_timezone=system_default_timezone())
    body = f'''<div class="split-grid blocklist-layout">
      <section class="panel">
        <div class="panel-head"><div><div class="panel-kicker">Policy sources</div><h3>Managed {plural_label}</h3><p>Open a {singular_label} to edit its settings, contents, schedule, and policy-target assignments on a dedicated page.</p></div><span class="result-count">{len(rows)} lists</span></div>
        <div class="blocklist-list">{cards}</div>
      </section>
      <section class="panel action-panel" id="add-list">
        <div class="panel-kicker">New source</div><h3>Add {singular_label}</h3>
        <p class="panel-help">Import from a URL, upload a file, or paste rules directly. URL sources refresh automatically on their own per-list interval.</p>
        <form method="post" action="/admin/lists" enctype="multipart/form-data" class="form-grid">
          <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">
          <input type="hidden" name="list_type" value="{list_type}">
          <label>Name<input name="name" required></label>
          <label>Format<select name="format"><option>auto</option><option>hosts</option><option>adblock</option><option>domains</option></select></label>
          <label class="full">Source URL (optional)<input name="source_url" placeholder="https://example.com/list.txt"></label>
          <label>Automatic refresh interval (minutes)<input type="number" name="refresh_minutes" min="1" max="10080" value="1440"></label>
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
          <button class="primary-button full" type="submit">{"Import whitelist" if is_whitelist else "Import block list"}</button>
        </form>
      </section>
    </div>'''
    return page(
        request,
        "Whitelists" if is_whitelist else "Block Lists",
        active_key,
        body,
        s,
    )



def _list_base_path(row) -> str:
    return "/whitelists" if str(row["list_type"] or "block") == "whitelist" else "/lists"


def _list_label(row) -> str:
    return "whitelist" if str(row["list_type"] or "block") == "whitelist" else "block list"


@app.get("/lists/{list_id}/edit", response_class=HTMLResponse)
@app.get("/whitelists/{list_id}/edit", response_class=HTMLResponse)
def managed_list_edit_page(list_id: int, request: Request):
    s = require_session(request)

    with db.connect() as con:
        blocklist = con.execute(
            "SELECT * FROM blocklists WHERE id=?",
            (list_id,),
        ).fetchone()
        if not blocklist:
            return redirect("/lists", error="List not found")

        base_path = _list_base_path(blocklist)
        requested_path = request.url.path
        if requested_path.startswith("/whitelists/") and base_path != "/whitelists":
            return redirect(f"{base_path}/{list_id}/edit")
        if requested_path.startswith("/lists/") and base_path != "/lists":
            return redirect(f"{base_path}/{list_id}/edit")

        scopes = con.execute(
            "SELECT * FROM scopes ORDER BY kind,name COLLATE NOCASE"
        ).fetchall()
        membership_rows = con.execute(
            "SELECT scope_id FROM scope_blocklists WHERE blocklist_id=?",
            (list_id,),
        ).fetchall()
        network_target_rows = con.execute(
            "SELECT scope_id,family,target FROM scope_network_targets"
        ).fetchall()
        preview_rows = con.execute(
            """
            SELECT domain
            FROM block_entries
            WHERE blocklist_id=?
            ORDER BY domain
            LIMIT 10
            """,
            (list_id,),
        ).fetchall()

    list_label = _list_label(blocklist)
    page_title = "Whitelist" if list_label == "whitelist" else "Block List"
    active_key = "whitelists" if list_label == "whitelist" else "lists"
    selected = {int(row["scope_id"]) for row in membership_rows}

    network_targets: dict[int, dict[int, str]] = {}
    for row in network_target_rows:
        network_targets.setdefault(int(row["scope_id"]), {})[
            int(row["family"])
        ] = str(row["target"])

    client_names = {
        str(scope["target"]): engine.known_client_name(str(scope["target"]))
        for scope in scopes
        if scope["kind"] == "client"
    }
    networks = [scope for scope in scopes if scope["kind"] == "network"]
    clients = [scope for scope in scopes if scope["kind"] == "client"]
    hostnames = [scope for scope in scopes if scope["kind"] == "hostname"]

    def scope_option(scope, disabled: bool = False) -> str:
        checked = " checked" if int(scope["id"]) in selected else ""
        disabled_attr = " disabled" if disabled else ""
        disabled_class = " global-disabled" if disabled else ""
        if scope["kind"] == "client":
            target_html = client_identity_html(scope["target"], client_names)
            kind_label = "Endpoint"
        elif scope["kind"] == "hostname":
            target_html = (
                f'<span class="scope-target mono">{esc(scope["target"])}</span>'
            )
            kind_label = "Hostname"
        else:
            ipv4, ipv6 = _scope_network_values(scope, network_targets)
            target_html = _network_target_html(ipv4, ipv6)
            kind_label = "Network"
        return (
            f'<label class="scope-option{disabled_class}">'
            f'<input type="checkbox" name="scope_id" value="{int(scope["id"])}"'
            f'{checked}{disabled_attr}>'
            f'<span class="scope-option-copy"><span class="scope-option-title">'
            f'<b>{esc(scope["name"])}</b><small>{kind_label}</small></span>'
            f'{target_html}</span></label>'
        )

    def scope_group(label: str, items, disabled: bool) -> str:
        options = "".join(scope_option(scope, disabled) for scope in items)
        return (
            '<section class="scope-group">'
            f'<div class="scope-group-head"><b>{esc(label)}</b>'
            f'<span>{len(items)}</span></div>'
            f'{options or "<p class=\"scope-empty-inline\">No matching policy targets.</p>"}'
            '</section>'
        )

    global_list = bool(blocklist["use_globally"])
    disabled_class = " is-global-disabled" if global_list else ""
    if scopes:
        scope_editor_html = (
            f'<div class="scope-assignment-grid{disabled_class}" data-scope-assignments>'
            f'{scope_group("Networks", networks, global_list)}'
            f'{scope_group("Endpoints", clients, global_list)}'
            f'{scope_group("Hostnames", hostnames, global_list)}'
            '</div>'
        )
    else:
        scope_editor_html = (
            '<div class="scope-empty">No policy targets exist yet. '
            '<a href="/scopes#add-scope">Create one first →</a></div>'
        )

    format_options = "".join(
        f'<option value="{fmt}"'
        f'{" selected" if blocklist["format"] == fmt else ""}>{fmt}</option>'
        for fmt in ("auto", "hosts", "adblock", "domains")
    )
    list_schedule_fields = schedule_fields_html(blocklist)
    source_label = blocklist["source_url"] or (
        "Uploaded list"
        if blocklist["source_type"] == "upload"
        else "Manual list"
    )
    assignment_text = (
        "Global"
        if global_list
        else f'{len(selected)} scoped assignment{"s" if len(selected) != 1 else ""}'
        if selected
        else "No assignments"
    )
    manual_manage_link = (
        f'<a class="small-button" href="{base_path}/{list_id}/domains">'
        'Manage domains</a>'
        if blocklist["source_type"] == "manual"
        else ""
    )

    refresh_minutes = int(blocklist["refresh_minutes"])
    if refresh_minutes % 1440 == 0:
        refresh_label = (
            f'{refresh_minutes // 1440} day'
            f'{"s" if refresh_minutes // 1440 != 1 else ""}'
        )
    elif refresh_minutes % 60 == 0:
        refresh_label = (
            f'{refresh_minutes // 60} hour'
            f'{"s" if refresh_minutes // 60 != 1 else ""}'
        )
    else:
        refresh_label = (
            f'{refresh_minutes} minute'
            f'{"s" if refresh_minutes != 1 else ""}'
        )

    source_type_label = {
        "url": "Remote URL",
        "upload": "Uploaded file",
        "manual": "Manual list",
    }.get(str(blocklist["source_type"]), str(blocklist["source_type"]).title())

    preview_lines = [str(row["domain"]) for row in preview_rows]
    preview_text = "\n".join(preview_lines) if preview_lines else "No entries to preview."
    last_updated = str(blocklist["last_updated"] or "Never")
    list_state_label = "Enabled" if blocklist["enabled"] else "Disabled"
    scope_state_label = "Global" if global_list else "Scoped"
    schedule_state_label = "Scheduled" if blocklist["schedule_enabled"] else "Always active"
    list_kind_icon = "✓" if list_label == "whitelist" else "⊘"

    body = f"""<div class="managed-list-edit-page">
      <div class="list-edit-breadcrumb">
        <a href="{base_path}">{"Whitelists" if list_label == "whitelist" else "Block Lists"}</a>
        <span>›</span>
        <b>Edit</b>
      </div>

      <section class="list-edit-hero">
        <div class="list-edit-hero-main">
          <span class="list-edit-type-icon {"whitelist" if list_label == "whitelist" else "blocklist"}">{list_kind_icon}</span>
          <div>
            <div class="panel-kicker">Edit {esc(list_label)}</div>
            <h2>{esc(blocklist["name"])}</h2>
            <p>Configure the source, policy targeting, schedule, and update behavior for this {esc(list_label)}.</p>
          </div>
        </div>
        <div class="list-edit-hero-actions">
          <a class="small-button" href="{base_path}#list-{list_id}">← Back to Lists</a>
          <form method="post" action="/admin/lists/{list_id}/delete"
                onsubmit="return confirm('Delete this {list_label}? This cannot be undone.')">
            <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">
            <button class="danger-button" type="submit">Delete List</button>
          </form>
        </div>
      </section>

      <nav class="list-edit-section-nav" aria-label="{esc(page_title)} editor sections">
        <a class="active" href="#general">General</a>
        <a href="#policy-targeting">Policy &amp; Targeting</a>
        <a href="#schedule">Schedule</a>
        <a href="#import-update">Import &amp; Update</a>
        <a href="#preview">Preview</a>
      </nav>

      <section class="list-edit-status-grid" aria-label="List summary">
        <article>
          <span class="list-edit-status-icon">▤</span>
          <div><b>{int(blocklist["entry_count"]):,}</b><small>Entries</small><em>Updated {esc(last_updated)}</em></div>
        </article>
        <article>
          <span class="list-edit-status-icon state">✓</span>
          <div><b>{esc(list_state_label)}</b><small>Status</small><em>{"List is active and enforced" if blocklist["enabled"] else "List is currently disabled"}</em></div>
        </article>
        <article>
          <span class="list-edit-status-icon scope">◎</span>
          <div><b>{esc(scope_state_label)}</b><small>Scope</small><em>{esc(assignment_text)}</em></div>
        </article>
        <article>
          <span class="list-edit-status-icon refresh">↻</span>
          <div><b>{esc(refresh_label)}</b><small>Refresh interval</small><em>{esc(source_type_label)}</em></div>
        </article>
      </section>

      <form method="post" action="/admin/lists/{list_id}/edit"
            enctype="multipart/form-data" class="list-edit-workspace" id="list-edit-form">
        <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">

        <section class="list-edit-card" id="general">
          <div class="list-edit-card-head">
            <span>▤</span>
            <div><h3>List Details</h3><p>Basic information about this {esc(list_label)}.</p></div>
          </div>
          <div class="list-edit-fields">
            <label class="full">Name
              <input name="name" value="{esc(blocklist["name"])}" required>
            </label>
            <label>List Format
              <select name="format">{format_options}</select>
            </label>
            <label>Source Type
              <input value="{esc(source_type_label)}" disabled>
            </label>
          </div>
        </section>

        <section class="list-edit-card" id="source-configuration">
          <div class="list-edit-card-head">
            <span>↗</span>
            <div><h3>Source Configuration</h3><p>Configure where and how this list is obtained.</p></div>
          </div>
          <div class="list-edit-fields">
            <label class="full">Source URL
              <input name="source_url" value="{esc(blocklist["source_url"] or "")}"
                     placeholder="https://example.com/list.txt">
              <small>Leave blank for manual or uploaded lists.</small>
            </label>
            <label>Refresh Interval
              <input type="number" name="refresh_minutes" min="1" max="10080"
                     value="{refresh_minutes}">
              <small>Minutes between automatic URL refreshes.</small>
            </label>
            <label class="list-edit-toggle-field">
              <span>List State</span>
              <span class="list-edit-toggle-row">
                <input type="checkbox" name="enabled" value="1"{" checked" if blocklist["enabled"] else ""}>
                <span><b>Enabled</b><small>Download updates and enforce this list.</small></span>
              </span>
            </label>
            <button class="small-button list-edit-refresh-button" type="submit" name="action" value="refresh">
              Save &amp; refresh URL
            </button>
          </div>
        </section>

        <section class="list-edit-card" id="policy-targeting">
          <div class="list-edit-card-head">
            <span>◎</span>
            <div><h3>Policy &amp; Targeting</h3><p>Control where this list is applied.</p></div>
          </div>
          <div class="list-edit-policy-mode">
            <label class="list-edit-choice">
              <input type="checkbox" name="global_list" value="1" data-global-toggle{" checked" if global_list else ""}>
              <span><b>Apply globally</b><small>Apply to every network, endpoint, and hostname.</small></span>
            </label>
            <div class="list-edit-targeting-summary">
              <span class="list-edit-status-icon scope">◎</span>
              <div><b>{esc(assignment_text)}</b><small>{"Global policy" if global_list else "Selected policy targets"}</small></div>
            </div>
          </div>
          <div class="list-edit-scope-wrap">
            <div class="list-edit-subhead">
              <div><b>Selected policy targets</b><p>Used when global application is disabled.</p></div>
              <span>{len(selected)} selected</span>
            </div>
            {scope_editor_html}
          </div>
        </section>

        <section class="list-edit-card" id="schedule">
          <div class="list-edit-card-head">
            <span>◷</span>
            <div><h3>Schedule</h3><p>Limit when this list is enforced.</p></div>
          </div>
          <div class="list-edit-schedule-summary">
            <span class="list-edit-status-icon schedule">◷</span>
            <div><b>{esc(schedule_state_label)}</b><small>{esc(schedule_summary(blocklist))}</small></div>
          </div>
          <div class="list-edit-schedule-controls">
            {list_schedule_fields}
          </div>
        </section>

        <section class="list-edit-card" id="import-update">
          <div class="list-edit-card-head">
            <span>⇧</span>
            <div><h3>Import &amp; Update</h3><p>Manually replace this list's contents.</p></div>
          </div>
          <div class="list-edit-import-grid">
            <label class="list-edit-file-drop">
              <span class="list-edit-file-icon">⇧</span>
              <b>Choose a replacement file</b>
              <small>Plain text, hosts, domain, or supported Adblock formats.</small>
              <input type="file" name="replacement_file">
            </label>
            <label class="list-edit-paste">Paste replacement rules
              <textarea name="replacement_text" rows="9"
                        placeholder="One domain per line, hosts format, or supported Adblock domain rules"></textarea>
            </label>
          </div>
        </section>

        <section class="list-edit-card" id="preview">
          <div class="list-edit-card-head">
            <span>◉</span>
            <div><h3>List Preview</h3><p>Preview the first entries currently stored for this list.</p></div>
          </div>
          <pre class="list-edit-preview"><code>{esc(preview_text)}</code></pre>
          <div class="list-edit-preview-foot">
            <span>Showing {len(preview_lines)} of {int(blocklist["entry_count"]):,} entr{"y" if int(blocklist["entry_count"]) == 1 else "ies"}</span>
            {manual_manage_link}
          </div>
        </section>

        <div class="list-edit-savebar">
          <div>
            <b>Ready to apply changes?</b>
            <small>Settings and targeting changes take effect after the policy engine reloads.</small>
          </div>
          <div class="actions">
            <a class="small-button" href="{base_path}#list-{list_id}">Cancel</a>
            <button class="primary-button" type="submit" name="action" value="save">Save Changes</button>
          </div>
        </div>
      </form>
    </div>"""
    return page(
        request,
        f"Edit {page_title} · {blocklist['name']}",
        active_key,
        body,
        s,
    )


def _get_manual_blocklist(list_id: int):
    with db.connect() as con:
        row = con.execute("SELECT * FROM blocklists WHERE id=?", (list_id,)).fetchone()
    if not row:
        return None, "List not found"
    if row["source_type"] != "manual":
        return row, "Only manual lists can be edited one domain at a time"
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
@app.get("/whitelists/{list_id}/domains", response_class=HTMLResponse)
def manual_list_domains_page(
    list_id: int,
    request: Request,
    q: str = "",
    page_num: int = 1,
):
    s = require_session(request)
    blocklist, error = _get_manual_blocklist(list_id)
    if error:
        return redirect("/lists", error=error)

    assert blocklist is not None
    base_path = _list_base_path(blocklist)
    list_label = _list_label(blocklist)
    page_title = "Whitelist" if list_label == "whitelist" else "Block List"
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
                      onsubmit="return confirm('Remove {esc(domain)} from this {list_label}?')">
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
        f'<a class="small-button" href="{base_path}/{list_id}/domains?page_num={page_num - 1}{query_suffix}">← Previous</a>'
        if page_num > 1 else '<span class="small-button disabled">← Previous</span>'
    )
    next_link = (
        f'<a class="small-button" href="{base_path}/{list_id}/domains?page_num={page_num + 1}{query_suffix}">Next →</a>'
        if page_num < max_page else '<span class="small-button disabled">Next →</span>'
    )

    assignment_label = "Global" if blocklist["use_globally"] else "Scoped only"
    clear_search_link = (
        f'<a class="small-button" href="{base_path}/{list_id}/domains">Clear</a>'
        if q
        else ""
    )
    body = f'''<div class="manual-domain-page">
      <section class="manual-domain-heading">
        <a class="back-link" href="{base_path}#list-{list_id}">← Back to {"Whitelists" if list_label == "whitelist" else "Block Lists"}</a>
        <div class="manual-domain-title-row">
          <div>
            <div class="panel-kicker">Manual {esc(list_label)}</div>
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
    return page(
        request,
        f"Manual {page_title} · {blocklist['name']}",
        "whitelists" if list_label == "whitelist" else "lists",
        body,
        s,
    )


@app.post("/admin/lists/{list_id}/domains/add")
async def add_manual_list_domain(list_id: int, request: Request):
    _, form = await require_post_session(request)
    blocklist, error = _get_manual_blocklist(list_id)
    if error:
        return redirect("/lists", error=error)

    assert blocklist is not None
    base_path = _list_base_path(blocklist)
    raw_domain = str(form.get("domain", ""))
    domain = normalize_domain(raw_domain)
    if not domain:
        return redirect(
            f"{base_path}/{list_id}/domains",
            error="Enter a valid domain such as example.com",
        )

    with db.connect() as con:
        added = db.add_list_domain(con, list_id, domain)
        count = _refresh_manual_list_count(con, list_id)

    engine.reload_lists()
    if not added:
        return redirect(
            f"{base_path}/{list_id}/domains?q={quote(domain)}",
            notice=f"{domain} is already in this list",
        )
    return redirect(
        f"{base_path}/{list_id}/domains?q={quote(domain)}",
        notice=f"Added {domain}; manual list now contains {count:,} domains",
    )


@app.post("/admin/lists/{list_id}/domains/remove")
async def remove_manual_list_domain(list_id: int, request: Request):
    _, form = await require_post_session(request)
    blocklist, error = _get_manual_blocklist(list_id)
    if error:
        return redirect("/lists", error=error)

    assert blocklist is not None
    base_path = _list_base_path(blocklist)
    domain = normalize_domain(str(form.get("domain", "")))
    return_q = str(form.get("return_q", "")).strip()
    try:
        return_page = max(1, int(form.get("return_page", "1")))
    except (TypeError, ValueError):
        return_page = 1

    return_path = f"{base_path}/{list_id}/domains?page_num={return_page}"
    if return_q:
        return_path += "&q=" + quote(return_q)

    if not domain:
        return redirect(return_path, error="Invalid domain")

    with db.connect() as con:
        removed = db.remove_list_domain(con, list_id, domain)
        count = _refresh_manual_list_count(con, list_id)

    engine.reload_lists()
    if not removed:
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
    list_type = str(form.get("list_type", "block")).strip().lower()
    if list_type not in {"block", "whitelist"}:
        list_type = "block"
    base_path = "/whitelists" if list_type == "whitelist" else "/lists"
    list_label = "whitelist" if list_type == "whitelist" else "block list"

    name = str(form.get("name", "")).strip()
    format_name = str(form.get("format", "auto")).strip().lower()
    source_url = str(form.get("source_url", "")).strip()
    text = str(form.get("text", ""))
    global_list = str(form.get("global_list", "")) == "1"
    try:
        schedule_enabled, schedule_days, schedule_start, schedule_end, schedule_timezone = parse_schedule_form(
            form, list_label
        )
    except ValueError as e:
        return redirect(base_path, error=str(e))
    scope_ids = _scope_ids_from_form(form)
    if global_list:
        scope_ids = []

    if not name:
        return redirect(base_path, error="List name is required")
    if format_name not in {"auto", "hosts", "adblock", "domains"}:
        return redirect(base_path, error="Unsupported list format")
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
            content = await run_in_threadpool(fetch_url, source_url)
        except Exception as e:
            return redirect(base_path, error=f"Could not fetch list URL: {e}")
        source_type = "url"

    if not content.strip():
        return redirect(base_path, error="Provide a URL, upload, or pasted list content")

    with db.connect() as con:
        try:
            cur = con.execute(
                """
                INSERT INTO blocklists(
                    name,source_type,source_url,format,list_type,use_globally,refresh_minutes,
                    schedule_enabled,schedule_days,schedule_start,schedule_end,schedule_timezone
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    name, source_type, source_url or None, format_name, list_type,
                    1 if global_list else 0, refresh_minutes,
                    1 if schedule_enabled else 0, schedule_days,
                    schedule_start, schedule_end, schedule_timezone,
                ),
            )
            list_id = int(cur.lastrowid)
        except Exception as e:
            return redirect(base_path, error=str(e))

    try:
        count, ignored = await run_in_threadpool(
            import_list,
            list_id,
            content,
            format_name,
            False,
        )
        with db.connect() as con:
            assigned = _save_list_scope_assignments(con, list_id, scope_ids)
    except Exception as e:
        with db.connect() as con:
            db.delete_blocklist(con, list_id)
        return redirect(base_path, error=f"Import failed: {e}")

    engine.reload_lists()
    engine.reload_scopes()
    return redirect(
        f"{base_path}#list-{list_id}",
        notice=f"Imported {count:,} entries, ignored {ignored:,}, assigned to {assigned} scope{'s' if assigned != 1 else ''}",
    )


@app.post("/admin/lists/{list_id}/edit")
async def edit_list(list_id: int, request: Request):
    _, form = await require_post_session(request)

    with db.connect() as con:
        existing = con.execute("SELECT * FROM blocklists WHERE id=?", (list_id,)).fetchone()
    if not existing:
        return redirect("/lists", error="List not found")
    base_path = _list_base_path(existing)
    list_label = _list_label(existing)

    name = str(form.get("name", "")).strip()
    format_name = str(form.get("format", "auto")).strip().lower()
    source_url = str(form.get("source_url", "")).strip()
    enabled = str(form.get("enabled", "")) == "1"
    global_list = str(form.get("global_list", "")) == "1"
    try:
        schedule_enabled, schedule_days, schedule_start, schedule_end, schedule_timezone = parse_schedule_form(
            form, list_label
        )
    except ValueError as e:
        return redirect(f"{base_path}/{list_id}/edit", error=str(e))
    action = str(form.get("action", "save")).strip().lower()
    replacement_text = str(form.get("replacement_text", ""))
    replacement_file = form.get("replacement_file")
    scope_ids = _scope_ids_from_form(form)
    if global_list:
        scope_ids = []

    if not name:
        return redirect(f"{base_path}/{list_id}/edit", error="List name is required")
    if format_name not in {"auto", "hosts", "adblock", "domains"}:
        return redirect(f"{base_path}/{list_id}/edit", error="Unsupported list format")
    try:
        refresh_minutes = max(1, min(int(form.get("refresh_minutes", "1440")), 10080))
    except (TypeError, ValueError):
        refresh_minutes = 1440

    replacement_content: str | None = None
    source_type = str(existing["source_type"])

    try:
        if action == "refresh":
            if not source_url:
                return redirect(
                    f"{base_path}/{list_id}/edit",
                    error="A source URL is required to refresh this list",
                )
            replacement_content = await run_in_threadpool(fetch_url, source_url)
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
        return redirect(f"{base_path}/{list_id}/edit", error=f"Could not refresh list: {e}")

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
            return redirect(f"{base_path}/{list_id}/edit", error=f"Could not save list: {e}")

    replaced_notice = ""
    if replacement_content is not None:
        if not replacement_content.strip():
            return redirect(f"{base_path}/{list_id}/edit", error="Replacement list content is empty")
        try:
            count, ignored = await run_in_threadpool(
                import_list,
                list_id,
                replacement_content,
                format_name,
                False,
            )
            replaced_notice = f"; replaced contents with {count:,} entries ({ignored:,} ignored)"
        except Exception as e:
            return redirect(
                f"{base_path}/{list_id}/edit",
                error=f"Settings were saved, but replacing list contents failed: {e}",
            )

    engine.reload_lists()
    engine.reload_scopes()
    return redirect(
        f"{base_path}/{list_id}/edit",
        notice=f"Saved {name}; {assigned} scoped assignment{'s' if assigned != 1 else ''}{replaced_notice}",
    )


@app.post("/admin/lists/{list_id}/toggle")
async def toggle_list(list_id: int, request: Request):
    await require_post_session(request)
    with db.connect() as con:
        row = con.execute("SELECT * FROM blocklists WHERE id=?", (list_id,)).fetchone()
        if not row:
            return redirect("/lists", error="List not found")
        base_path = _list_base_path(row)
        con.execute(
            "UPDATE blocklists SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?",
            (list_id,),
        )
    engine.reload_lists()
    return redirect(f"{base_path}#list-{list_id}", notice="List state updated")


@app.post("/admin/lists/{list_id}/delete")
async def delete_list(list_id: int, request: Request):
    await require_post_session(request)
    with db.connect() as con:
        row = con.execute("SELECT * FROM blocklists WHERE id=?", (list_id,)).fetchone()
        if not row:
            return redirect("/lists", error="List not found")
        base_path = _list_base_path(row)
        label = _list_label(row)
        db.delete_blocklist(con, list_id)
    engine.reload_lists()
    return redirect(base_path, notice=f"{label.title()} deleted")


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

    scope_client_names = {
        str(scope["target"]): engine.known_client_name(str(scope["target"]))
        for scope in scopes
        if scope["kind"] == "client"
    }

    def blocklist_option(blocklist, selected: set[int]) -> str:
        is_global = bool(blocklist["use_globally"])
        is_whitelist = str(blocklist["list_type"] or "block") == "whitelist"
        checked = " checked" if int(blocklist["id"]) in selected else ""
        disabled_attr = " disabled" if is_global else ""
        disabled_class = " global-disabled" if is_global else ""
        status_class = "green" if blocklist["enabled"] else "gray"
        global_badge = '<span class="scope-list-global">Global</span>' if is_global else ""
        type_badge = (
            '<span class="scope-list-global">Whitelist</span>'
            if is_whitelist
            else '<span class="scope-list-scheduled">Block</span>'
        )
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
            f'{type_badge}{global_badge}{schedule_badge}</span>'
            f'<small>{detail}</small>{schedule_detail}'
            f'</span></label>'
        )

    def blocklist_editor(selected: set[int]) -> str:
        block_only = [
            item for item in blocklists
            if str(item["list_type"] or "block") == "block"
        ]
        whitelist_only = [
            item for item in blocklists
            if str(item["list_type"] or "block") == "whitelist"
        ]
        if not blocklists:
            return (
                '<div class="scope-empty">No block lists or whitelists exist yet. '
                '<a href="/lists#add-list">Import a block list →</a> · '
                '<a href="/whitelists#add-list">Add a whitelist →</a></div>'
            )

        sections: list[str] = []
        if block_only:
            sections.append(
                '<section class="scope-group"><div class="scope-group-head"><b>Block Lists</b>'
                f'<span>{len(block_only)}</span></div>'
                + "".join(blocklist_option(item, selected) for item in block_only)
                + '</section>'
            )
        if whitelist_only:
            sections.append(
                '<section class="scope-group"><div class="scope-group-head"><b>Whitelists</b>'
                f'<span>{len(whitelist_only)}</span></div>'
                + "".join(blocklist_option(item, selected) for item in whitelist_only)
                + '</section>'
            )
        return '<div class="scope-list-grid">' + "".join(sections) + '</div>'


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
              <form method="post" action="/admin/scopes/{int(scope["id"])}/delete" onsubmit="return confirm('Delete this scope and its list assignments?')">
                <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">
                <button class="small-button danger">Delete</button>
              </form>
            </div>
          </div>
          <details class="scope-editor" id="edit-scope-{int(scope["id"])}">
            <summary><span><b>Edit {esc(scope_kind_label.lower())}</b><small>Identity, target, state, schedule and list assignments</small></span><span class="editor-chevron">⌄</span></summary>
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
                    <div><b>List assignments</b><p>Select block lists and whitelists that should explicitly apply to this scope. Lists marked Global already apply according to the configured global-list reach.</p></div>
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
          <div><div class="panel-kicker">Policy targets</div><h3>Networks, endpoints & hostnames</h3><p>Edit targets, schedules, pause/resume enforcement, and block-list and whitelist assignments without leaving this page.</p></div>
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
            <div class="form-section-head"><div><b>Initial list assignments</b><p>Optional. Assign scoped block lists and whitelists; Global lists apply automatically.</p></div></div>
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

    engine.reload_scopes()
    return redirect(
        f"/scopes#scope-{scope_id}",
        notice=f"Added {name} with {assigned} list assignment{'s' if assigned != 1 else ''}",
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

    engine.reload_scopes()
    return redirect(
        f"/scopes#scope-{scope_id}",
        notice=f"Saved {name}; {assigned} list assignment{'s' if assigned != 1 else ''}",
    )


@app.post("/admin/scopes/{scope_id}/toggle")
async def toggle_scope(scope_id: int, request: Request):
    await require_post_session(request)
    with db.connect() as con:
        con.execute("UPDATE scopes SET state=CASE state WHEN 'active' THEN 'paused' ELSE 'active' END WHERE id=?", (scope_id,))
    engine.reload_scopes()
    return redirect(f"/scopes#scope-{scope_id}", notice="Scope state updated")


@app.post("/admin/scopes/{scope_id}/delete")
async def delete_scope(scope_id: int, request: Request):
    await require_post_session(request)
    with db.connect() as con:
        con.execute("DELETE FROM scopes WHERE id=?", (scope_id,))
    engine.reload_scopes()
    return redirect("/scopes", notice="Scope deleted")

@app.get("/queries", response_class=HTMLResponse)
def queries_page(
    request: Request,
    q: str = "",
    client: str = "",
    server: str = "",
    target: str = "",
    blocklist: str = "",
    decision: str = "",
    limit: int = 100,
    refresh: int = 0,
):
    s = require_session(request)
    clauses, args = [], []
    if q:
        clauses.append("qname LIKE ?")
        args.append("%" + q + "%")
    if client:
        clauses.append(
            "(client_ip LIKE ? OR client_name LIKE ? OR "
            "client_ip IN (SELECT client_ip FROM client_identities WHERE client_name LIKE ?))"
        )
        client_pattern = "%" + client + "%"
        args.extend([client_pattern, client_pattern, client_pattern])
    if server:
        clauses.append("server_id = ?")
        args.append(server)
    if target:
        clauses.append("matched_scope = ?")
        args.append(target)
    if blocklist:
        clauses.append("matched_list LIKE ?")
        args.append("%" + blocklist + "%")
    if decision in {"blocked", "allowed"}:
        clauses.append("blocked=?")
        args.append(1 if decision == "blocked" else 0)

    limit = max(25, min(limit, 500))
    refresh = refresh if refresh in {0, 5, 10, 15, 30, 60} else 0
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
        target_rows = con.execute(
            """
            SELECT DISTINCT matched_scope
            FROM query_log
            WHERE matched_scope IS NOT NULL AND TRIM(matched_scope) <> ''
            ORDER BY matched_scope COLLATE NOCASE
            """
        ).fetchall()
        blocklist_rows = con.execute(
            """
            SELECT DISTINCT matched_list
            FROM query_log
            WHERE matched_list IS NOT NULL AND TRIM(matched_list) <> ''
            ORDER BY matched_list COLLATE NOCASE
            """
        ).fetchall()

    query_client_names = log_client_names(rows)
    display_timezone = system_default_timezone()
    trs = "".join(
        f'<tr><td title="Stored in UTC">{esc(format_timestamp_for_timezone(r["ts"], display_timezone))}</td>'
        f'<td>{querying_server_html(r["server_id"])}</td>'
        f'<td>{client_identity_html(r["client_ip"], query_client_names)}</td>'
        f'<td>{esc(r["qname"])}</td>'
        f'<td>{esc(r["qtype"])}</td>'
        f'<td>{esc((r["policy_scheme"] or "").upper() or "—")}</td>'
        f'<td>{esc(response_time_text(r["response_time_ms"]))}</td>'
        f'<td>{esc(r["matched_scope"] or "—")}</td>'
        f'<td><span class="pill {"red" if r["blocked"] else "green"}">'
        f'{"Blocked" if r["blocked"] else "Allowed"}</span></td>'
        f'<td>{esc(decision_match_text(r))}</td></tr>'
        for r in rows
    ) or '<tr><td colspan="10" class="empty">No matching queries.</td></tr>'

    server_options = '<option value="">All servers</option>' + "".join(
        f'<option value="{esc(row["server_id"])}"'
        f'{" selected" if server == row["server_id"] else ""}>'
        f'{esc(row["server_id"])}</option>'
        for row in server_rows
    )
    target_options = '<option value="">All policy targets</option>' + "".join(
        f'<option value="{esc(row["matched_scope"])}"'
        f'{" selected" if target == row["matched_scope"] else ""}>'
        f'{esc(row["matched_scope"])}</option>'
        for row in target_rows
    )
    blocklist_options = "".join(
        f'<option value="{esc(row["matched_list"])}"></option>'
        for row in blocklist_rows
    )
    refresh_options = "".join(
        f'<option value="{seconds}"{" selected" if refresh == seconds else ""}>{label}</option>'
        for seconds, label in (
            (0, "Auto refresh off"),
            (5, "Refresh every 5s"),
            (10, "Refresh every 10s"),
            (15, "Refresh every 15s"),
            (30, "Refresh every 30s"),
            (60, "Refresh every 60s"),
        )
    )

    body = f'''<section class="panel" data-query-log-refresh="{refresh}">
      <div class="panel-head query-head">
        <div><div class="panel-kicker">DNS activity</div><h3>Decision history</h3>
        <p>Showing {len(rows)} most recent matching requests, including the DNS server, policy API scheme, and matched policy target · times shown in {esc(display_timezone)}.</p></div>
        <span class="result-count">{len(rows)} results</span>
      </div>
      <form class="filter-bar query-filter-bar" method="get">
        <input name="q" value="{esc(q)}" placeholder="Domain contains…">
        <input name="client" value="{esc(client)}" placeholder="Client IP or hostname…">
        <select name="server">{server_options}</select>
        <select name="target">{target_options}</select>
        <input name="blocklist" value="{esc(blocklist)}" list="query-blocklists" placeholder="List name contains…">
        <datalist id="query-blocklists">{blocklist_options}</datalist>
        <select name="decision">
          <option value="">All decisions</option>
          <option value="blocked" {"selected" if decision=="blocked" else ""}>Blocked</option>
          <option value="allowed" {"selected" if decision=="allowed" else ""}>Allowed</option>
        </select>
        <select name="limit">
          <option value="{limit}">{limit}</option>
          <option>50</option><option>100</option><option>250</option><option>500</option>
        </select>
        <select name="refresh" title="Query log auto refresh interval">{refresh_options}</select>
        <button class="primary-button">Filter</button>
      </form>
      <div class="table-wrap"><table>
        <thead><tr><th>Time</th><th>Server</th><th>Client</th><th>Domain</th><th>Type</th><th>Policy API</th><th>Response time</th><th>Policy target</th><th>Decision</th><th>Match</th></tr></thead>
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
    snapshot = engine.snapshot
    mode = snapshot.response_mode
    unmatched_scope_action = snapshot.unmatched_scope_action
    global_blocklist_scope_mode = snapshot.global_blocklist_scope_mode
    retention = str(engine.logger.max_rows)
    retention_days = str(engine.logger.max_age_days)
    log_request_json = engine.logger.capture_request_json
    default_timezone = system_default_timezone()
    ui_theme = application_theme()
    tls_status = tls_manager.status()
    tls_settings = tls_status.settings
    https_port = os.getenv("HTTPS_PORT", "8443")
    request_is_https = request.url.scheme == "https"
    http_behavior_label = (
        "Redirect to HTTPS" if tls_settings.http_redirect else "Direct HTTP allowed"
    )
    tls_mode_label = {
        "http": "HTTP only",
        "upload": "Uploaded certificate",
        "acme": "ACME",
    }.get(tls_settings.mode, "HTTP only")
    cert_info = tls_status.uploaded_certificate
    cert_expiry = (
        cert_info.not_after.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        if cert_info is not None
        else "—"
    )
    cert_sans = ", ".join(cert_info.dns_names) if cert_info and cert_info.dns_names else "—"
    tls_error_html = (
        f'<div class="list-warning"><b>Last TLS error:</b> {esc(tls_status.last_error)}</div>'
        if tls_status.last_error
        else ""
    )
    age_summary = (
        "Disabled"
        if str(retention_days) == "0"
        else f'{esc(retention_days)} day{"s" if str(retention_days) != "1" else ""}'
    )
    tls_http_hidden = "" if tls_settings.mode == "http" else " hidden"
    tls_upload_hidden = "" if tls_settings.mode == "upload" else " hidden"
    tls_acme_hidden = "" if tls_settings.mode == "acme" else " hidden"
    tls_http_disabled = "" if tls_settings.mode == "http" else " disabled"
    tls_upload_disabled = "" if tls_settings.mode == "upload" else " disabled"
    tls_acme_disabled = "" if tls_settings.mode == "acme" else " disabled"

    body = f'''<div class="settings-page" data-settings-tabs>
      <nav class="settings-tabs" role="tablist" aria-label="System Settings sections">
        <button type="button" class="settings-tab-button" role="tab" data-settings-tab="general" aria-controls="settings-general">
          <span class="settings-tab-icon">⚙</span>
          <span><b>DNS & logs</b><small>Responses, retention, timezone</small></span>
        </button>
        <button type="button" class="settings-tab-button" role="tab" data-settings-tab="tls" aria-controls="settings-tls">
          <span class="settings-tab-icon">◆</span>
          <span><b>HTTPS & TLS</b><small>Certificates and ACME</small></span>
        </button>
        <button type="button" class="settings-tab-button" role="tab" data-settings-tab="appearance" aria-controls="settings-appearance">
          <span class="settings-tab-icon">◐</span>
          <span><b>Appearance</b><small>Light or dark interface</small></span>
        </button>
        <button type="button" class="settings-tab-button" role="tab" data-settings-tab="runtime" aria-controls="settings-runtime">
          <span class="settings-tab-icon">◈</span>
          <span><b>Runtime</b><small>Service and storage status</small></span>
        </button>
      </nav>

      <section id="settings-general" class="settings-tab-panel" role="tabpanel" data-settings-panel="general">
        <section class="panel action-panel">
          <div class="panel-kicker">DNS behavior</div>
          <h3>Blocked response & logging</h3>
          <p class="panel-help">Configure blocked DNS responses, unmatched-target behavior, query-history retention, and the system timezone.</p>
          <form method="post" action="/admin/settings" class="form-grid">
            <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">

            <div class="form-section full">
              <div class="form-section-head">
                <div><b>Global list reach</b><p>Control whether lists marked Global also apply to clients that do not match an active policy target.</p></div>
                <span>{"All clients" if global_blocklist_scope_mode == "all_clients" else "Matched targets only"}</span>
              </div>
              <label class="full">Apply global lists to
                <select name="global_blocklist_scope_mode">
                  <option value="all_clients" {"selected" if global_blocklist_scope_mode=="all_clients" else ""}>All clients, including clients with no matching policy target</option>
                  <option value="matched_scopes" {"selected" if global_blocklist_scope_mode=="matched_scopes" else ""}>Matched policy targets only</option>
                </select>
                <small>Matched policy targets only means globally assigned lists are skipped when no active endpoint, hostname, or network target matches.</small>
              </label>
            </div>

            <div class="form-section full">
              <div class="form-section-head">
                <div><b>No matching policy target</b><p>Choose what happens after applicable whitelists and block lists are evaluated when no active endpoint, hostname, or network target matches the client.</p></div>
                <span>{"Allow" if unmatched_scope_action == "allow" else "Deny"}</span>
              </div>
              <label class="full">Default action
                <select name="unmatched_scope_action">
                  <option value="allow" {"selected" if unmatched_scope_action=="allow" else ""}>Allow</option>
                  <option value="deny" {"selected" if unmatched_scope_action=="deny" else ""}>Deny</option>
                </select>
                <small>If global lists are limited to matched targets, an unmatched client skips those lists first and then uses this Allow/Deny fallback.</small>
              </label>
            </div>

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
              <label class="full checkbox-row">
                <input type="checkbox" name="log_request_json" value="1" {"checked" if log_request_json else ""}>
                <span><b>Store full policy request JSON</b><small>Disabled by default to reduce serialization work, database writes, and log size. Enable only when raw request payloads are needed for troubleshooting.</small></span>
              </label>
            </div>

            <div class="form-section full">
              <div class="form-section-head">
                <div><b>Default timezone</b><p>Used to display log timestamps and as the default for new schedules. Existing schedules keep their saved timezone.</p></div>
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

            <button class="primary-button full">Save DNS & log settings</button>
          </form>
        </section>
      </section>

      <section id="settings-tls" class="settings-tab-panel" role="tabpanel" data-settings-panel="tls" hidden>
        <section class="panel action-panel tls-settings-panel">
          <div class="panel-kicker">Transport security</div>
          <h3>HTTPS & certificates</h3>
          <p class="panel-help">Choose how Blockinator should handle HTTPS. Only settings for the selected setup type are shown.</p>
          {tls_error_html}
          <form method="post" action="/admin/settings/tls" enctype="multipart/form-data" class="form-grid" data-tls-settings-form>
            <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">

            <div class="tls-mode-selector full">
              <label>HTTPS setup type
                <select name="tls_mode" data-tls-mode-select>
                  <option value="http" {"selected" if tls_settings.mode=="http" else ""}>HTTP only</option>
                  <option value="upload" {"selected" if tls_settings.mode=="upload" else ""}>Use my certificate</option>
                  <option value="acme" {"selected" if tls_settings.mode=="acme" else ""}>Automatic certificate with ACME</option>
                </select>
              </label>
              <div class="tls-mode-description" data-tls-mode-description>
                Choose a setup type to see only the options needed for that configuration.
              </div>
            </div>

            <fieldset class="tls-mode-fields full" data-tls-mode-fields="http"{tls_http_hidden}{tls_http_disabled}>
              <div class="tls-mode-empty">
                <span class="tls-mode-empty-icon">○</span>
                <div>
                  <b>HTTP only</b>
                  <p>Blockinator will stay on the HTTP listener and Caddy will not configure an HTTPS site. No certificate settings are required.</p>
                </div>
              </div>
            </fieldset>

            <fieldset class="tls-mode-fields full" data-tls-mode-fields="upload"{tls_upload_hidden}{tls_upload_disabled}>
              <div class="form-section full">
                <div class="form-section-head">
                  <div><b>HTTPS identity</b><p>Choose the DNS name clients will use and provide the certificate that covers it.</p></div>
                  <span>Port {esc(https_port)}</span>
                </div>
                <label class="full">HTTPS hostname
                  <input name="tls_hostname" value="{esc(tls_settings.hostname)}" placeholder="blockinator.example.com">
                  <small>Use a fully qualified DNS hostname covered by the uploaded certificate.</small>
                </label>
              </div>

              <div class="form-section full">
                <div class="form-section-head">
                  <div><b>Certificate files</b><p>Upload a PEM certificate/full-chain and matching unencrypted PEM private key. Leave a file blank to keep the currently stored copy.</p></div>
                  <span>{"Certificate + key stored" if tls_status.uploaded_cert_present and tls_status.uploaded_key_present else "Incomplete"}</span>
                </div>
                <label>Certificate / full chain
                  <input type="file" name="tls_certificate" accept=".pem,.crt,.cer,application/x-pem-file">
                  <small>{"Stored certificate available." if tls_status.uploaded_cert_present else "No certificate stored."}</small>
                </label>
                <label>Private key
                  <input type="file" name="tls_private_key" accept=".pem,.key,application/x-pem-file">
                  <small>{"Stored private key available." if tls_status.uploaded_key_present else "No private key stored."}</small>
                </label>
                <div class="tls-cert-summary full">
                  <span><b>Subject</b><small>{esc(cert_info.subject if cert_info else "—")}</small></span>
                  <span><b>Issuer</b><small>{esc(cert_info.issuer if cert_info else "—")}</small></span>
                  <span><b>Expires</b><small>{esc(cert_expiry)}</small></span>
                  <span><b>DNS SANs</b><small>{esc(cert_sans)}</small></span>
                </div>
              </div>

              <div class="form-section full">
                <div class="form-section-head">
                  <div><b>HTTP access</b><p>Optionally turn the HTTP listener into a redirect to the configured HTTPS hostname.</p></div>
                  <span>{esc(http_behavior_label)}</span>
                </div>
                <label class="check full">
                  <input type="checkbox" name="tls_http_redirect" value="1"
                         {"checked" if tls_settings.http_redirect else ""}
                         {"" if request_is_https else "disabled"}>
                  Redirect direct HTTP requests to HTTPS
                </label>
                <p class="schedule-help full">{
                  "This control is unlocked because this page is being accessed over HTTPS."
                  if request_is_https
                  else "Open System Settings over HTTPS before changing redirect-only HTTP. This protects against accidentally locking out the control panel."
                }</p>
              </div>
            </fieldset>

            <fieldset class="tls-mode-fields full" data-tls-mode-fields="acme"{tls_acme_hidden}{tls_acme_disabled}>
              <div class="form-section full">
                <div class="form-section-head">
                  <div><b>HTTPS identity</b><p>Choose the DNS name for the certificate Caddy will obtain automatically.</p></div>
                  <span>Port {esc(https_port)}</span>
                </div>
                <label class="full">HTTPS hostname
                  <input name="tls_hostname" value="{esc(tls_settings.hostname)}" placeholder="blockinator.example.com">
                  <small>Use the hostname that resolves to this Blockinator instance.</small>
                </label>
              </div>

              <div class="form-section full">
                <div class="form-section-head">
                  <div><b>ACME server</b><p>Use Let's Encrypt by default or point Blockinator at a compatible public or private ACME directory.</p></div>
                  <span>{"Custom directory" if tls_settings.acme_directory != DEFAULT_ACME_DIRECTORY else "Let's Encrypt"}</span>
                </div>
                <label>Account email
                  <input type="email" name="tls_acme_email" value="{esc(tls_settings.acme_email)}" placeholder="admin@example.com">
                </label>
                <label>ACME directory URL
                  <input name="tls_acme_directory" value="{esc(tls_settings.acme_directory)}" placeholder="{esc(DEFAULT_ACME_DIRECTORY)}">
                </label>
                <label>Custom CA root PEM
                  <input type="file" name="tls_acme_ca_root" accept=".pem,.crt,.cer,application/x-pem-file">
                  <small>{"Custom root stored." if tls_status.acme_ca_root_present else "Uses the container trust store."}</small>
                </label>
                <label class="check"><input type="checkbox" name="remove_acme_ca_root" value="1"> Remove stored custom CA root</label>
              </div>

              <div class="form-section full">
                <div class="form-section-head">
                  <div><b>External Account Binding</b><p>Only configure EAB if your ACME provider requires it.</p></div>
                  <span>{"Configured" if tls_settings.acme_eab_key_id and tls_status.acme_eab_hmac_present else "Optional"}</span>
                </div>
                <label>EAB key ID
                  <input name="tls_acme_eab_key_id" value="{esc(tls_settings.acme_eab_key_id)}" autocomplete="off">
                </label>
                <label>EAB HMAC key
                  <input type="password" name="tls_acme_eab_hmac" value="" autocomplete="new-password" placeholder="Leave blank to keep stored secret">
                  <small>{"HMAC secret stored." if tls_status.acme_eab_hmac_present else "No HMAC secret stored."}</small>
                </label>
                <label class="check full"><input type="checkbox" name="remove_acme_eab_hmac" value="1"> Remove stored EAB HMAC secret</label>
              </div>

              <div class="form-section full">
                <div class="form-section-head">
                  <div><b>HTTP access</b><p>Optionally turn the HTTP listener into a redirect after ACME HTTPS is working.</p></div>
                  <span>{esc(http_behavior_label)}</span>
                </div>
                <label class="check full">
                  <input type="checkbox" name="tls_http_redirect" value="1"
                         {"checked" if tls_settings.http_redirect else ""}
                         {"" if request_is_https else "disabled"}>
                  Redirect direct HTTP requests to HTTPS
                </label>
                <p class="schedule-help full">{
                  "This control is unlocked because this page is being accessed over HTTPS."
                  if request_is_https
                  else "Open System Settings over HTTPS before changing redirect-only HTTP. This protects against accidentally locking out the control panel."
                }</p>
                <p class="schedule-help full">Public ACME HTTP-01/TLS-ALPN-01 validation normally requires public ports 80 and/or 443 to reach Caddy. Use POLICY_PORT=80 and HTTPS_PORT=443 when standard challenge ports are required. DNS-01 provider plugins are not included in this branch.</p>
              </div>
            </fieldset>

            <button class="primary-button full" type="submit">Apply HTTPS settings</button>
          </form>
        </section>
      </section>

      <section id="settings-appearance" class="settings-tab-panel" role="tabpanel" data-settings-panel="appearance" hidden>
        <section class="panel action-panel appearance-settings-panel">
          <div class="panel-kicker">Interface</div>
          <h3>Appearance</h3>
          <p class="panel-help">Choose the color scheme used throughout Blockinator, including the sign-in screen.</p>
          <form method="post" action="/admin/settings/appearance" class="appearance-theme-form">
            <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">
            <div class="appearance-choice-grid">
              <label class="appearance-choice {"selected" if ui_theme == "dark" else ""}">
                <input type="radio" name="ui_theme" value="dark" {"checked" if ui_theme == "dark" else ""}>
                <span class="appearance-preview appearance-preview-dark" aria-hidden="true">
                  <i class="appearance-preview-sidebar"></i>
                  <i class="appearance-preview-header"></i>
                  <i class="appearance-preview-card first"></i>
                  <i class="appearance-preview-card second"></i>
                </span>
                <span class="appearance-choice-copy">
                  <b>Dark</b>
                  <small>Blockinator's original dark control-plane interface.</small>
                </span>
              </label>
              <label class="appearance-choice {"selected" if ui_theme == "light" else ""}">
                <input type="radio" name="ui_theme" value="light" {"checked" if ui_theme == "light" else ""}>
                <span class="appearance-preview appearance-preview-light" aria-hidden="true">
                  <i class="appearance-preview-sidebar"></i>
                  <i class="appearance-preview-header"></i>
                  <i class="appearance-preview-card first"></i>
                  <i class="appearance-preview-card second"></i>
                </span>
                <span class="appearance-choice-copy">
                  <b>Light</b>
                  <small>A bright workspace with the same Blockinator layout and controls.</small>
                </span>
              </label>
            </div>
            <div class="appearance-current">
              <span>Current theme</span>
              <b>{esc(ui_theme.title())}</b>
            </div>
            <button class="primary-button" type="submit">Save appearance</button>
          </form>
        </section>
      </section>

      <section id="settings-runtime" class="settings-tab-panel" role="tabpanel" data-settings-panel="runtime" hidden>
        <section class="panel">
          <div class="panel-kicker">Service details</div><h3>Runtime</h3>
          <p class="panel-help">Current application, proxy, and storage information for this Blockinator instance.</p>
          <div class="info-grid">
            <div><span>Version</span><b>{APP_VERSION}</b></div>
            <div><span>Database</span><b class="mono">{esc(db.backend_summary())}</b></div>
            <div><span>Decision API</span><b class="mono">/api/v1/decision</b></div>
            <div><span>Service</span><b>Blockinator</b></div>
            <div><span>Log age limit</span><b>{age_summary}</b></div>
            <div><span>Log row limit</span><b>{int(retention):,}</b></div>
            <div><span>Default timezone</span><b class="mono">{esc(default_timezone)}</b></div>
            <div><span>Interface theme</span><b>{esc(ui_theme.title())}</b></div>
            <div><span>Unmatched target action</span><b>{esc(unmatched_scope_action.title())}</b></div>
            <div><span>Global list reach</span><b>{"All clients" if global_blocklist_scope_mode == "all_clients" else "Matched targets only"}</b></div>
            <div><span>TLS mode</span><b>{esc(tls_mode_label)}</b></div>
            <div><span>Caddy</span><b>{"Reachable" if tls_status.caddy_reachable else "Unavailable"}</b></div>
            <div><span>HTTPS port</span><b class="mono">{esc(https_port)}</b></div>
            <div><span>HTTP behavior</span><b>{esc(http_behavior_label)}</b></div>
            <div><span>Last TLS apply</span><b class="mono">{esc(tls_status.last_applied or "Never")}</b></div>
          </div>
        </section>
      </section>
    </div>'''
    return page(request, "System Settings", "settings", body, s)

@app.post("/admin/settings/appearance")
async def save_appearance_settings(request: Request):
    _, form = await require_post_session(request)
    ui_theme = str(form.get("ui_theme", "dark")).strip().lower()
    if ui_theme not in {"dark", "light"}:
        return redirect(
            "/settings#appearance",
            error="Appearance must be set to Dark or Light",
        )
    db.set_setting("ui_theme", ui_theme)
    _update_runtime_settings_cache(ui_theme=ui_theme)
    return redirect(
        "/settings#appearance",
        notice=f"Appearance changed to {ui_theme.title()}",
    )


@app.post("/admin/settings")
async def save_settings(request: Request):
    _, form = await require_post_session(request)
    mode = str(form.get("block_response","nxdomain"))
    if mode not in {"nxdomain","refused","nodata","zero"}:
        mode = "nxdomain"
    unmatched_scope_action = str(form.get("unmatched_scope_action", "allow")).strip().lower()
    if unmatched_scope_action not in {"allow", "deny"}:
        unmatched_scope_action = "allow"
    global_blocklist_scope_mode = str(
        form.get("global_blocklist_scope_mode", "all_clients")
    ).strip().lower()
    if global_blocklist_scope_mode not in {"all_clients", "matched_scopes"}:
        global_blocklist_scope_mode = "all_clients"
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
            "/settings#general",
            error="Default timezone must be a valid IANA timezone such as America/New_York",
        )

    log_request_json = str(form.get("log_request_json", "")).strip() == "1"
    db.set_settings(
        {
            "block_response": mode,
            "unmatched_scope_action": unmatched_scope_action,
            "global_blocklist_scope_mode": global_blocklist_scope_mode,
            "max_query_logs": str(retention),
            "max_query_log_age_days": str(retention_days),
            "log_request_json": "1" if log_request_json else "0",
            "default_timezone": default_timezone,
        }
    )
    _update_runtime_settings_cache(default_timezone=default_timezone)
    engine.logger.configure_retention(
        retention,
        retention_days,
        capture_request_json=log_request_json,
    )
    engine.reload_settings()

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

    return redirect("/settings#general", notice=notice)


async def _optional_upload_bytes(form, field_name: str, max_bytes: int = 1024 * 1024) -> bytes | None:
    upload = form.get(field_name)
    if not getattr(upload, "filename", None):
        return None
    data = await upload.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"{field_name} exceeds the 1 MiB upload limit")
    if not data.strip():
        raise ValueError(f"{field_name} is empty")
    return data


@app.post("/admin/settings/tls")
async def save_tls_settings(request: Request):
    _, form = await require_post_session(request)
    current_tls_settings = await run_in_threadpool(tls_manager.load_settings)
    requested_http_redirect = str(form.get("tls_http_redirect", "")) == "1"
    try:
        validate_http_redirect_change(
            current_tls_settings.http_redirect,
            requested_http_redirect,
            request.url.scheme == "https",
        )
    except ValueError as exc:
        return redirect("/settings#tls", error=str(exc))

    settings = TlsSettings(
        mode=str(form.get("tls_mode", "http")).strip().lower(),
        hostname=str(form.get("tls_hostname", "")).strip(),
        acme_email=str(form.get("tls_acme_email", "")).strip(),
        acme_directory=str(
            form.get("tls_acme_directory", DEFAULT_ACME_DIRECTORY)
        ).strip(),
        acme_eab_key_id=str(form.get("tls_acme_eab_key_id", "")).strip(),
        http_redirect=requested_http_redirect,
    )
    try:
        certificate_pem = await _optional_upload_bytes(form, "tls_certificate")
        private_key_pem = await _optional_upload_bytes(form, "tls_private_key")
        ca_root_pem = await _optional_upload_bytes(form, "tls_acme_ca_root")
        eab_hmac_raw = str(form.get("tls_acme_eab_hmac", ""))
        eab_hmac = eab_hmac_raw if eab_hmac_raw.strip() else None
        await run_in_threadpool(
            tls_manager.configure,
            settings,
            certificate_pem=certificate_pem,
            private_key_pem=private_key_pem,
            ca_root_pem=ca_root_pem,
            eab_hmac=eab_hmac,
            remove_ca_root=str(form.get("remove_acme_ca_root", "")) == "1",
            remove_eab_hmac=str(form.get("remove_acme_eab_hmac", "")) == "1",
        )
    except Exception as exc:
        return redirect("/settings#tls", error=f"TLS settings were not applied: {exc}")

    mode_label = {
        "http": "HTTP-only mode",
        "upload": "uploaded-certificate HTTPS",
        "acme": "ACME-managed HTTPS",
    }.get(settings.mode, "TLS configuration")
    redirect_label = (
        "HTTP now redirects to HTTPS"
        if settings.mode != "http" and settings.http_redirect
        else "direct HTTP remains enabled"
    )
    return redirect(
        "/settings#tls",
        notice=f"Applied {mode_label}; {redirect_label}; Caddy reloaded without restarting Blockinator",
    )
