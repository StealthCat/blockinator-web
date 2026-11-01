from __future__ import annotations

import html
import ipaddress
import json
import os
import re
import secrets
from datetime import datetime, time as dt_time, timezone
from time import perf_counter_ns
from pathlib import Path
from urllib.parse import quote, urlencode
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

from fastapi import FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .schedules import extra_schedule_windows, MAX_SCHEDULE_WINDOWS
from .ui import icon, query_details_html
from .auth import AuthManager, SESSION_COOKIE, SESSION_TTL_SECONDS
from .blocklists import MAX_BYTES, fetch_url, normalize_domain, parse_blocklist
from .safe_fetch import validate_source_url
from .admin import blocking_action, admin_action, run_admin, BodyLimitMiddleware, login_limiter, console_read, MAX_FORM_FIELDS
from .db import Database
from .policy import PolicyEngine, normalize_hostname_pattern
from .rdns import ReverseDnsResolver
from .refresher import BlocklistRefresher
from .statistics import StatisticsCache
from .rollups import retained_totals
from .query_cache import query_counts, query_choices, literal_pattern
from .timeutil import format_timestamp_for_timezone, query_range_bound, parse_utc_timestamp
from .inspector import inspect_policy, target_status
from .tls import DEFAULT_ACME_DIRECTORY, TlsManager, TlsSettings, validate_http_redirect_change

BASE_DIR = Path(__file__).resolve().parent
APP_VERSION = "1.20.13"

DNS_RECORD_TYPE_OPTIONS = (
    ("A", "IPv4 host addresses"),
    ("AAAA", "IPv6 host addresses"),
    ("ANY", "All available record types"),
    ("CAA", "Certificate authority authorization"),
    ("CERT", "Certificates stored in DNS"),
    ("CNAME", "Canonical-name aliases"),
    ("DNAME", "Subtree aliases"),
    ("DNSKEY", "DNSSEC zone signing keys"),
    ("DS", "DNSSEC delegation signer records"),
    ("HINFO", "Host information"),
    ("HTTPS", "HTTPS service bindings"),
    ("IXFR", "Incremental zone transfers"),
    ("LOC", "Geographic location records"),
    ("MX", "Mail exchangers"),
    ("NAPTR", "Naming authority pointer records"),
    ("NS", "Authoritative name servers"),
    ("NSEC", "DNSSEC authenticated denial records"),
    ("NSEC3", "Hashed DNSSEC denial records"),
    ("PTR", "Reverse-DNS pointers"),
    ("RRSIG", "DNSSEC signatures"),
    ("SOA", "Start of authority"),
    ("SRV", "Service location records"),
    ("SSHFP", "SSH host key fingerprints"),
    ("SVCB", "Service bindings"),
    ("TLSA", "TLS certificate associations"),
    ("TXT", "Text records"),
    ("URI", "Uniform resource identifier records"),
    ("AXFR", "Full zone transfers"),
)


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


@app.exception_handler(OverflowError)
async def _integer_overflow_handler(request: Request, exc: OverflowError):
    # Path/query integers are unbounded in Python but SQLite INTEGER is
    # 64-bit; IDs and cursors beyond that range cannot exist, so answer 400
    # instead of an internal server error.
    if "SQLite INTEGER" in str(exc) or "out of range" in str(exc):
        return JSONResponse({"detail": "Numeric value out of range"}, status_code=400)
    return JSONResponse({"detail": "Internal Server Error"}, status_code=500)

db = Database()
statistics_cache = StatisticsCache(db)
_runtime_settings = db.get_settings(
    {
        "default_timezone": os.getenv("TZ", "UTC").strip() or "UTC",
        "ui_theme": "system",
    }
)
_runtime_default_timezone = (
    _runtime_settings["default_timezone"].strip() or "UTC"
)
_runtime_ui_theme = _runtime_settings["ui_theme"].strip().lower() or "system"

auth = AuthManager(db)
rdns = ReverseDnsResolver()
engine = PolicyEngine(db, rdns=rdns)
app.add_middleware(PolicyResponseTimingMiddleware, engine=engine)
app.add_middleware(BodyLimitMiddleware, upload_limit=MAX_BYTES)
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
    name: str = Field(min_length=1, max_length=254)
    type: str = Field(default="A", pattern=r"^[A-Za-z0-9]{1,16}$")
    class_: str = Field(default="IN", alias="class", pattern=r"^[A-Za-z0-9]{1,16}$")

    @field_validator("name")
    @classmethod
    def valid_name(cls, value):
        if value == ".":
            return value
        try:
            labels = [label.encode("idna").decode("ascii") for label in value.rstrip(".").split(".")]
        except UnicodeError as exc:
            raise ValueError("invalid DNS name") from exc
        if any(not label or len(label) > 63 or any(ord(c) < 33 or ord(c) > 126 for c in label) for label in labels):
            raise ValueError("invalid DNS label")
        if len(".".join(labels)) > 253:
            raise ValueError("DNS name is too long")
        return ".".join(labels).lower() + ("." if value.endswith(".") else "")

    model_config = {"populate_by_name": True}

class DnsInfo(BaseModel):
    questions: list[Question] = Field(min_length=1, max_length=16)
    identifier: int | None = None
    is_response: bool | None = None
    opcode: str | None = None
    recursion_desired: bool | None = None
    rcode: str | None = None
    has_edns: bool | None = None
    wire_base64: str | None = Field(default=None, max_length=87380)

class ClientInfo(BaseModel):
    ip: str = Field(max_length=45)
    port: int | None = Field(default=None, ge=0, le=65535)

    @field_validator("ip")
    @classmethod
    def valid_ip(cls, value):
        ip = ipaddress.ip_address(value)
        # Dual-stack DNS servers report IPv4 clients as ::ffff:a.b.c.d; use the
        # IPv4 form so client, network, and PTR identity scopes still match.
        return str(getattr(ip, "ipv4_mapped", None) or ip)


class DecisionRequest(BaseModel):
    server_id: str | None = Field(default=None, max_length=255)
    protocol: str | None = Field(default=None, max_length=32)
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


def decision_kind(row) -> str:
    if bool(row["blocked"]):
        return "blocked"
    list_type = str(row["matched_list_type"] or "").strip().lower()
    reason = str(row["reason"] or "").strip().lower()
    if list_type == "whitelist" or reason in {"whitelist_match", "endpoint_whitelisted", "scope_whitelisted"}:
        return "whitelisted"
    return "allowed"


def decision_pill_html(row) -> str:
    kind = decision_kind(row)
    if kind == "blocked":
        css_class, icon, label, title = (
            "red blocked",
            "×",
            "Blocked",
            "Blocked by policy",
        )
    elif kind == "whitelisted":
        matched_list = str(row["matched_list"] or "").strip()
        css_class, icon, label = "whitelist whitelisted", "✦", "Whitelisted"
        title = (
            f"Allowed by whitelist: {matched_list}"
            if matched_list
            else "Allowed by whitelist"
        )
    else:
        css_class, icon, label, title = (
            "green allowed",
            "✓",
            "Allowed",
            "Allowed by policy",
        )
    return (
        f'<span class="pill decision-pill {css_class}" title="{esc(title)}">'
        f'<span class="decision-icon" aria-hidden="true">{icon}</span>'
        f'<span>{label}</span></span>'
    )


def decision_match_text(row) -> str:
    matched_list = str(row["matched_list"] or "").strip()
    if matched_list:
        if decision_kind(row) == "whitelisted":
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


def parse_schedule_form(form, label: str = "block list") -> tuple[bool, str, str, str, str, str]:
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
        if not re.fullmatch(r"[0-2][0-9]:[0-5][0-9]", start) or not re.fullmatch(r"[0-2][0-9]:[0-5][0-9]", end):
            raise ValueError("Use HH:MM local times without seconds or offsets")
        dt_time.fromisoformat(start)
        dt_time.fromisoformat(end)
    except ValueError as exc:
        raise ValueError("Schedule start and end must use HH:MM local times without seconds or offsets") from exc

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

    window_ids = form.getlist("schedule_window")
    if len(window_ids) >= MAX_SCHEDULE_WINDOWS or len(set(window_ids)) != len(window_ids):
        raise ValueError(f"Use at most {MAX_SCHEDULE_WINDOWS} unique schedule windows")
    windows = []
    for window_id in window_ids:
        if not re.fullmatch(r"[1-9][0-9]{0,5}", str(window_id)):
            raise ValueError("Invalid schedule window identifier")
        try:
            extra_days = [int(day) for day in form.getlist(f"schedule_day_{window_id}")]
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid schedule day") from exc
        windows.append({"days": extra_days,
                        "start": str(form.get(f"schedule_start_{window_id}", "")),
                        "end": str(form.get(f"schedule_end_{window_id}", ""))})
    windows_text = json.dumps(extra_schedule_windows(json.dumps(windows)))
    return enabled, ",".join(str(day) for day in sorted(days)), start, end, tz_name, windows_text


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
    try:
        windows = extra_schedule_windows(row["schedule_windows"] if "schedule_windows" in row.keys() else None)
    except ValueError:
        return "Invalid schedule windows"
    if windows:
        first = {key: row[key] for key in ("schedule_enabled", "schedule_days", "schedule_start", "schedule_end", "schedule_timezone")}
        summaries = [schedule_summary(first)]
        for window in windows:
            summaries.append(schedule_summary({**first, "schedule_days": ",".join(map(str, window['days'])),
                "schedule_start": window['start'], "schedule_end": window['end']}))
        return " OR ".join(summaries)
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


def schedule_window_html(index, days, start, end):
    suffix = f"_{index}" if index else ""
    marker = f'<input type="hidden" name="schedule_window" value="{index}">' if index else ""
    day_buttons = "".join(
        f'<label class="schedule-day"><input type="checkbox" name="schedule_day{suffix}" value="{day}"'
        f'{" checked" if day in days else ""}><span>{label}</span></label>' for day, label in DAY_LABELS)
    remove = '<button type="button" class="small-button danger" data-remove-schedule-window>Remove window</button>' if index else ''
    return f'''<div class="schedule-window" data-schedule-window="{index}">{marker}
      <div class="schedule-window-head"><b>Window <span data-window-number>{index + 1}</span></b>{remove}</div>
      <div class="schedule-days"><span class="schedule-label">Days the schedule starts</span>
        <div class="schedule-presets" role="group" aria-label="Select schedule days">
          <button type="button" class="small-button" data-schedule-days="0,1,2,3,4,5,6">Every day</button>
          <button type="button" class="small-button" data-schedule-days="0,1,2,3,4">Weekdays</button>
          <button type="button" class="small-button" data-schedule-days="5,6">Weekends</button>
        </div><div class="schedule-day-grid">{day_buttons}</div>
      </div>
      <label>Start time<input type="time" name="schedule_start{suffix}" value="{esc(start)}"></label>
      <label>End time<input type="time" name="schedule_end{suffix}" value="{esc(end)}"></label>
    </div>'''


def schedule_fields_html(row=None, default_timezone: str = "UTC", *, policy_target: bool = False) -> str:
    enabled = bool(row["schedule_enabled"]) if row is not None else False
    days = schedule_days_set(row["schedule_days"]) if row is not None else set(range(7))
    start = str(row["schedule_start"] or "00:00") if row is not None else "00:00"
    end = str(row["schedule_end"] or "00:00") if row is not None else "00:00"
    tz_name = str(row["schedule_timezone"] or default_timezone) if row is not None else default_timezone
    if row is None:
        try:
            ZoneInfo(tz_name)
        except (ZoneInfoNotFoundError, ValueError):
            tz_name = "UTC"
    error = ""
    try:
        extras = extra_schedule_windows(row["schedule_windows"] if row is not None and "schedule_windows" in row.keys() else None)
    except ValueError:
        extras = []
        error = '<p class="list-warning">Stored schedule windows are invalid. Review and save the schedule to repair it.</p>'
    windows = schedule_window_html(0, days, start, end) + "".join(
        schedule_window_html(index, set(window['days']), window['start'], window['end'])
        for index, window in enumerate(extras, 1))
    return f'''<div class="schedule-editor full{" target-schedule-editor" if policy_target else ""}" data-schedule-editor>
      <label class="check schedule-toggle"><input type="checkbox" name="schedule_enabled" value="1" data-schedule-toggle{" checked" if enabled else ""}>
        {"Use a target schedule" if policy_target else "Enforce only during a schedule"}</label>
      <p class="schedule-status" data-schedule-status aria-live="polite"></p>{error}
      <div class="schedule-controls{" schedule-disabled" if not enabled else ""}" data-schedule-controls>
        <label class="schedule-timezone">Timezone<input name="schedule_timezone" value="{esc(tz_name)}" placeholder="America/New_York"></label>
        <div class="schedule-windows" data-schedule-windows>{windows}</div>
        <button type="button" class="small-button" data-add-schedule-window>Add time window</button>
        <p class="schedule-help full">Active when any window matches. Selected days are the days the window begins. Overnight ranges such as 22:00–06:00 continue into the following morning. Equal start/end times mean the full selected day. Use 00:00 as the end time for midnight.</p>
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

def require_post_session(request: Request):
    return request.state.admin_session, request.state.admin_form


def desired_enabled(form, current: bool) -> bool:
    """Return the state a toggle button asked for.

    Toggle forms send the target state rendered on the button so a stale tab or
    a repeated submit sets that state instead of flipping it back. Requests
    without the field keep the legacy invert behaviour.
    """
    value = str(form.get("enabled", "") if form is not None else "").strip()
    if value in {"0", "1"}:
        return value == "1"
    return not current


def set_session_cookie(response, request, session):
    response.set_cookie(
        SESSION_COOKIE, session.token, max_age=SESSION_TTL_SECONDS, httponly=True,
        secure=(request.url.scheme == "https" or os.getenv("ADMIN_COOKIE_SECURE", "0").lower() in {"1", "true", "yes", "on"}),
        samesite="strict", path="/",
    )


def read_upload(upload, max_bytes=MAX_BYTES):
    data = upload.file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"Upload exceeds the {max_bytes} byte limit")
    return data


def application_theme() -> str:
    theme = _runtime_ui_theme
    return theme if theme in {"system", "dark", "light"} else "system"


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
        "policy-test": "Preview a decision and see how targets, schedules and lists interact.",
        "security": "Manage administrator access and the API credentials used by connected DNS resolvers.",
        "settings": "Tune Blockinator's response behavior, retention, and core service preferences.",
    }
    page_actions = {
        "dashboard": ('/queries', 'View activity', 'arrow'),
        "statistics": (None, None, None),
        "lists": ('#add-list', 'Import a list', 'plus'),
        "whitelists": ('#add-list', 'Add whitelist', 'plus'),
        "scopes": ('/scopes#add-scope', 'Add target', 'plus'),
        "queries": ('/queries', 'Reset filters', 'refresh'),
        "policy-test": (None, None, None),
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
        ("/policy-test", "policy-test", "Policy Tester", "◇"),
    ]
    admin_nav = [
        ("/security", "security", "Access & Security", "◈"),
        ("/settings", "settings", "System Settings", "⚙"),
    ]

    def render_nav(items):
        links = []
        for href, key, label, _glyph in items:
            current = ' aria-current="page"' if key == active else ""
            css = "nav-link active" if key == active else "nav-link"
            links.append(
                f'<a class="{css}" href="{href}"{current}><span class="nav-icon">'
                f'{icon(key)}</span><span>{label}</span></a>'
            )
        return "".join(links)

    flash = ""
    if notice:
        flash += f'<div class="flash ok"><span class="flash-icon">✓</span><div><b>Success</b><span>{esc(notice)}</span></div></div>'
    if error:
        flash += f'<div class="flash bad"><span class="flash-icon">!</span><div><b>Something needs attention</b><span>{esc(error)}</span></div></div>'

    if engine.last_reload_error:
        flash += '<div class="flash bad" role="alert">Policy changes are saved but activation is pending. Automatic retry is running. <a href="/settings#runtime">View runtime status</a></div>'
    global_on = engine.snapshot.global_blocking
    ui_theme = application_theme()
    theme_color = "#f4f7fb" if ui_theme == "light" else "#071018"
    status_label = "Protection active" if global_on else "Protection paused"
    status_detail = "DNS policy is being enforced" if global_on else "Requests are currently allowed"
    action_href, action_label, action_icon = page_actions.get(active, (None, None, None))
    header_action = (
        f'<a class="primary-button header-primary" href="{action_href}"><span>{icon(action_icon)}</span>{esc(action_label)}</a>'
        if action_href and action_label else ""
    )
    user_initial = esc(session.username[:1].upper()) if session else "A"
    username = esc(session.username) if session else "Administrator"
    logout = ""
    if session:
        logout = f"""
        <form method="post" action="/logout" class="logout-form">
          <input type="hidden" name="csrf_token" value="{esc(session.csrf_token)}">
          <button class="icon-button" type="submit" title="Sign out" aria-label="Sign out">{icon("logout")}</button>
        </form>"""

    return HTMLResponse(f"""<!doctype html>
<html lang="en" data-theme="{ui_theme}" data-theme-preference="{ui_theme}">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="{theme_color}">
<title>{esc(title)} · Blockinator</title>
<link rel="icon" href="/static/blockinator-mark.svg">
<script src="/static/theme.js?v={APP_VERSION}"></script><link rel="stylesheet" href="/static/style.css"><link rel="stylesheet" href="/static/interface.css">
</head>
<body>
<a class="skip-link" href="#main-content">Skip to content</a>
<div class="app-shell">
  <aside class="sidebar" id="app-navigation">
    <a class="brand" href="/"><span class="brand-mark"><img src="/static/blockinator-mark.svg" alt=""></span><div><b>Blockinator</b><small>DNS Policy Control</small></div></a>
    <div class="nav-section-label">Policy</div>
    <nav>{render_nav(nav)}</nav>
    <div class="nav-section-label nav-section-spacer">Administration</div>
    <nav>{render_nav(admin_nav)}</nav>
    <div class="sidebar-foot">
      <div class="sidebar-status"><span class="status-dot"></span><div><b>Service online</b><small>Blockinator v{APP_VERSION}</small></div></div>
    </div>
  </aside>
  <main class="main" id="main-content" tabindex="-1">
    <header class="workspace-header">
      <button class="navigation-toggle ghost-button" type="button" aria-controls="app-navigation" aria-expanded="false" data-navigation-toggle>{icon("menu")}<span>Menu</span></button>
      <div class="header-copy">
        <div class="breadcrumb"><span>Blockinator</span><i>›</i><b>{esc(title)}</b></div>
        <h1>{esc(title)}</h1>
        <p>{esc(page_descriptions.get(active, ""))}</p>
      </div>
      <div class="header-tools">
        <a class="protection-chip {"active" if global_on else "paused"}" href="/">
          <span class="protection-icon">{icon("shield")}</span>
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
                last_error=NULL,source_hash=NULL,source_etag=NULL,source_last_modified=NULL
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
    return {"status": "ok", "version": APP_VERSION}

@app.get("/readyz")
def readyz():
    ready = engine.generation > 0 and engine.last_reload_error is None
    return JSONResponse({"status": "ready" if ready else "degraded"}, status_code=200 if ready else 503)

@app.get("/api/v1/runtime")
@console_read
def runtime_status(request: Request):
    require_session(request)
    return JSONResponse({"policy_generation": engine.generation,
                         "policy_reload_error": engine.last_reload_error,
                         "logger": engine.logger.status(),
                         "refresher": refresher.status(),
                         "ptr": engine.ptr_status()}, headers={"Cache-Control": "no-store"})

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
@console_read
def login_page(request: Request):
    if session_for(request):
        return RedirectResponse("/", status_code=303)
    error = request.query_params.get("error", "")
    ui_theme = application_theme()
    theme_color = "#f4f7fb" if ui_theme == "light" else "#071018"
    return HTMLResponse(f"""<!doctype html><html data-theme="{ui_theme}" data-theme-preference="{ui_theme}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="{theme_color}"><title>Sign in · Blockinator</title><link rel="icon" href="/static/blockinator-mark.svg"><script src="/static/theme.js?v={APP_VERSION}"></script><link rel="stylesheet" href="/static/style.css"><link rel="stylesheet" href="/static/interface.css"></head>
<body class="login-body"><section class="login-visual"><div class="login-shade"></div><div class="login-copy"><img src="/static/blockinator-mark.svg" alt=""><p>DNS POLICY CONTROL</p><h1>Bad traffic<br>stops here.</h1><span>Block · Filter · Protect</span></div></section>
<section class="login-panel"><form method="post" action="/login" class="login-card"><div class="mini-brand"><img src="/static/blockinator-mark.svg" alt=""><b>Blockinator</b></div><h2>Welcome back</h2><p>Sign in to manage DNS policy, endpoints, block lists and access keys.</p>
{"<div class='flash bad'>" + esc(error) + "</div>" if error else ""}
<label>Username<input name="username" autocomplete="username" required autofocus></label>
<label>Password<input type="password" name="password" autocomplete="current-password" required></label>
<button class="primary-button wide" type="submit">Sign in</button><small>Blockinator v{APP_VERSION}</small></form></section></body></html>""")

@app.post("/login")
@blocking_action
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    login_limiter.check(request.client.host if request.client else "unknown")
    result = auth.authenticate(username[:255], password[:4096])
    if not result:
        return redirect("/login", error="Invalid username or password")
    user_id, canonical = result
    s = auth.create_session(user_id, canonical)
    response = RedirectResponse("/", status_code=303)
    set_session_cookie(response, request, s)
    return response

@app.post("/logout")
@admin_action(require_session)
def logout(request: Request):
    s, _ = require_post_session(request)
    auth.delete_session(request.cookies.get(SESSION_COOKIE))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response

@app.get("/", response_class=HTMLResponse)
@console_read
def dashboard(request: Request):
    s = require_session(request)
    snapshot = engine.snapshot
    with db.connect() as con:
        query_totals = retained_totals(con)
        query_totals["blocked"] = query_totals["blocks"]
        recent = con.execute(
            """
            SELECT
              id,ts,server_id,client_ip,client_name,qname,qtype,protocol,client_port,blocked,reason,
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
        f'<tr><td class="query-domain"><b>{esc(r["qname"])}</b><small>{esc(r["qtype"])}</small></td>'
        f'<td>{client_identity_html(r["client_ip"], recent_client_names)}</td>'
        f'<td>{decision_pill_html(r)}<small class="query-match">{esc(decision_match_text(r))}</small></td>'
        f'<td class="query-response">{esc(response_time_text(r["response_time_ms"]))}</td>'
        f'<td>{esc(format_timestamp_for_timezone(r["ts"], display_timezone))}'
        f'{query_details_html(r, format_timestamp_for_timezone(r["ts"], display_timezone))}</td></tr>'
        for r in recent
    ) or '<tr><td colspan="5" class="empty">No DNS decisions recorded yet.</td></tr>'
    body = f'''
    {dashboard_alerts_html()}
    <section class="hero-card"><img src="/static/blockinator-network.svg" alt="" width="1200" height="560" fetchpriority="high"><div class="hero-overlay"><p>BLOCK · FILTER · PROTECT</p><h2>Your network. Your policy.</h2><span>Centralized DNS policy control with client-aware filtering.</span></div></section>
    <div class="stat-grid">
      <article class="stat"><span>Queries</span><strong>{totals["queries"]:,}</strong><small>Recorded decisions</small></article>
      <article class="stat"><span>Blocked</span><strong>{totals["blocked"]:,}</strong><small>Rejected requests</small></article>
      <article class="stat"><span>Policy domains</span><strong>{totals["entries"]:,}</strong><small>{totals["block_entries"]:,} block · {totals["whitelist_entries"]:,} whitelist</small></article>
      <article class="stat"><span>Policy targets</span><strong>{totals["clients"] + totals["networks"] + totals["hostnames"]:,}</strong><small>{totals["networks"]} networks · {totals["clients"]} endpoints · {totals["hostnames"]} hostnames</small></article>
    </div>
    <section class="panel status-panel"><div><span class="big-dot {"green" if global_on else "amber"}"></span><div><h3>Global blocking is {"active" if global_on else "paused"}</h3><p>{"Policy decisions are enforced." if global_on else "All requests are currently allowed."}</p></div></div>
      <form method="post" action="/admin/global-toggle"><input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}"><input type="hidden" name="enabled" value="{"0" if global_on else "1"}"><button class="{"danger-button" if global_on else "primary-button"}">{"Pause blocking" if global_on else "Resume blocking"}</button></form>
    </section>
    <section class="panel"><div class="panel-head"><div><h3>Recent DNS activity</h3><p>Latest policy decisions from connected resolvers · times shown in {esc(display_timezone)}.</p></div><a class="text-link" href="/queries">View all →</a></div>
      <div class="table-wrap"><table class="query-table"><thead><tr><th>Domain / type</th><th>Client</th><th>Decision / reason</th><th>Response time</th><th>Time / details</th></tr></thead><tbody>{rows}</tbody></table></div>
    </section>'''
    return page(request, "Dashboard", "dashboard", body, s)

@app.get("/statistics", response_class=HTMLResponse)
@console_read
def statistics_page(request: Request):
    s = require_session(request)
    display_timezone = system_default_timezone()
    snapshot = statistics_cache.snapshot(
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
            <p>Queries, blocked requests, and average policy response time per interval · times shown in {esc(display_timezone)}.</p>
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
            <span><i class="statistics-legend-swatch response"></i>Average response time</span>
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
            aria-label="Live DNS queries, blocks, and average response time statistics"
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
@console_read
def statistics_api(
    request: Request,
    minutes: int = 60,
):
    require_session(request)
    return statistics_cache.snapshot(
        minutes=minutes,
        timezone_name=system_default_timezone(),
    )


@app.post("/admin/global-toggle")
@admin_action(require_session)
def global_toggle(request: Request):
    _, form = require_post_session(request)
    current = db.get_setting("global_blocking", "1") == "1"
    enabled = desired_enabled(form, current)
    db.set_setting("global_blocking", "1" if enabled else "0")
    engine.reload_settings()
    return redirect("/", notice="Global blocking resumed" if enabled else "Global blocking paused")

@app.get("/lists", response_class=HTMLResponse)
@console_read
def lists_page(request: Request):
    return _managed_lists_page(request, "block")


@app.get("/whitelists", response_class=HTMLResponse)
@console_read
def whitelists_page(request: Request):
    return _managed_lists_page(request, "whitelist")


def _managed_lists_page(request: Request, list_type: str):
    s = require_session(request)
    is_whitelist = list_type == "whitelist"
    base_path = "/whitelists" if is_whitelist else "/lists"
    active_key = "whitelists" if is_whitelist else "lists"
    singular_label = "whitelist" if is_whitelist else "block list"
    plural_label = "whitelists" if is_whitelist else "block lists"
    display_timezone = system_default_timezone()
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
      …36812 tokens truncated…etry tracked clients in the background. Query history is preserved. Hostname targets cannot match until fresh PTR answers arrive.</p>
          {f'<div class="list-warning"><b>PTR resolver error:</b> {esc(ptr_status["last_error"])}</div>' if ptr_status["last_error"] else ""}
        </section>
      </section>
    </div>'''
    return page(request, "System Settings", "settings", body, s)

@app.post("/admin/settings/ptr-cache/flush")
@admin_action(require_session)
def flush_ptr_cache(request: Request):
    require_post_session(request)
    count = engine.flush_ptr_cache()
    return redirect("/settings#runtime", notice=f"PTR cache flushed; {count:,} tracked clients queued for fresh lookups")


@app.post("/admin/settings/appearance")
@admin_action(require_session)
def save_appearance_settings(request: Request):
    _, form = require_post_session(request)
    ui_theme = str(form.get("ui_theme", "system")).strip().lower()
    if ui_theme not in {"system", "dark", "light"}:
        return redirect(
            "/settings#appearance",
            error="Appearance must be set to Use system theme, Dark, or Light",
        )
    db.set_setting("ui_theme", ui_theme)
    _update_runtime_settings_cache(ui_theme=ui_theme)
    return redirect(
        "/settings#appearance",
        notice=f"Appearance changed to {ui_theme.title()}",
    )


@app.post("/admin/settings/ignored-record-types")
@admin_action(require_session)
def save_ignored_record_types(request: Request):
    _, form = require_post_session(request)
    allowed = {record_type for record_type, _description in DNS_RECORD_TYPE_OPTIONS}
    selected = {
        str(value).strip().upper()
        for value in form.getlist("ignored_record_types")
        if str(value).strip().upper() in allowed
    }
    persisted = ",".join(
        record_type
        for record_type, _description in DNS_RECORD_TYPE_OPTIONS
        if record_type in selected
    )
    db.set_setting("ignored_record_types", persisted)
    engine.reload_settings()

    count = len(selected)
    notice = (
        "Ignored record types cleared"
        if count == 0
        else f"Saved {count} ignored DNS record type{'s' if count != 1 else ''}"
    )
    return redirect("/settings#record-types", notice=notice)


@app.post("/admin/settings")
@admin_action(require_session)
def save_settings(request: Request):
    _, form = require_post_session(request)
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


def _optional_upload_bytes(form, field_name: str, max_bytes: int = 1024 * 1024) -> bytes | None:
    upload = form.get(field_name)
    if not getattr(upload, "filename", None):
        return None
    data = read_upload(upload, max_bytes)
    if len(data) > max_bytes:
        raise ValueError(f"{field_name} exceeds the 1 MiB upload limit")
    if not data.strip():
        raise ValueError(f"{field_name} is empty")
    return data


@app.post("/admin/settings/tls")
@admin_action(require_session)
def save_tls_settings(request: Request):
    _, form = require_post_session(request)
    current_tls_settings = tls_manager.load_settings()
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
        certificate_pem = _optional_upload_bytes(form, "tls_certificate")
        private_key_pem = _optional_upload_bytes(form, "tls_private_key")
        ca_root_pem = _optional_upload_bytes(form, "tls_acme_ca_root")
        eab_hmac_raw = str(form.get("tls_acme_eab_hmac", ""))
        eab_hmac = eab_hmac_raw if eab_hmac_raw.strip() else None
        tls_manager.configure(settings,
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
