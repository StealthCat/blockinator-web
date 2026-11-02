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
APP_VERSION = "1.20.17"

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
    end = str(form.get("schedule_end", "00:00")).strip(…63058 tokens truncated…        updated.classList.add("error");
        }
      }).finally(function () {
        window.clearTimeout(timeout);
        if (version === requestVersion) loading = false;
      });
    }

    root.querySelectorAll("[data-statistics-window]").forEach(function (button) {
      button.addEventListener("click", function () {
        windowMinutes = parseInt(button.getAttribute("data-statistics-window") || "60", 10);
        root.setAttribute("data-window", String(windowMinutes));
        root.querySelectorAll("[data-statistics-window]").forEach(function (candidate) {
          candidate.classList.toggle("active", candidate === button);
        });
        if (controller) controller.abort();
        requestVersion += 1;
        loading = false;
        load();
      });
    });

    document.addEventListener("visibilitychange", function () {
      if (!document.hidden) load();
    });

    var resizeObserver = null;
    if (window.ResizeObserver) {
      var lastWidth = 0;
      resizeObserver = new ResizeObserver(function (entries) {
        var width = Math.round(entries[0].contentRect.width);
        if (width !== lastWidth && lastPayload) renderStatisticsChart(root, lastPayload);
        lastWidth = width;
      });
      resizeObserver.observe(root.querySelector("[data-statistics-chart]"));
    }
    load();
    timer = window.setInterval(load, 5000);
    window.addEventListener("pagehide", function () {
      if (controller) controller.abort();
      requestVersion += 1;
      loading = false;
      if (timer !== null) window.clearInterval(timer);
      timer = null;
      if (resizeObserver) resizeObserver.disconnect();
    });
    window.addEventListener("pageshow", function () {
      if (timer === null) timer = window.setInterval(load, 5000);
      if (resizeObserver) resizeObserver.observe(root.querySelector("[data-statistics-chart]"));
      load();
    });
  }

  window.addEventListener("hashchange", openHashDetails);
  openHashDetails();
  initializeFormRecovery();
  initializeGlobalAssignmentControls();
  initializeScheduleControls();
  initializeScopeKindFields();
  initializeTlsSettings();
  initializeSettingsTabs();
  initializeListEditNavigation();
  initializeNavigation();
  initializeTableDensity();
  initializeQueryLogRefresh();
  initializeStatisticsDashboard();
})();
