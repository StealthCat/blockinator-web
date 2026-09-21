from __future__ import annotations

import html
import ipaddress
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .auth import AuthManager, SESSION_COOKIE, SESSION_TTL_SECONDS
from .blocklists import fetch_url, parse_blocklist
from .db import Database
from .policy import PolicyEngine

BASE_DIR = Path(__file__).resolve().parent
APP_VERSION = "1.4.0"

app = FastAPI(title="Blockinator", version=APP_VERSION)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

db = Database()
auth = AuthManager(db)
engine = PolicyEngine(db)

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

def redirect(path: str, notice: str | None = None, error: str | None = None):
    parts = []
    if notice:
        parts.append("notice=" + quote(notice))
    if error:
        parts.append("error=" + quote(error))
    if parts:
        path += ("&" if "?" in path else "?") + "&".join(parts)
    return RedirectResponse(path, status_code=303)

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
    nav = [
        ("/", "dashboard", "Dashboard", "⌂"),
        ("/lists", "lists", "Block Lists", "☷"),
        ("/scopes", "scopes", "Networks & Endpoints", "◎"),
        ("/queries", "queries", "Query Log", "≡"),
        ("/security", "security", "Access & Security", "◈"),
        ("/settings", "settings", "System Settings", "⚙"),
    ]
    nav_html = "".join(
        f'<a class="nav-link {"active" if key == active else ""}" href="{href}"><span>{icon}</span>{label}</a>'
        for href, key, label, icon in nav
    )
    flash = ""
    if notice:
        flash += f'<div class="flash ok">{esc(notice)}</div>'
    if error:
        flash += f'<div class="flash bad">{esc(error)}</div>'
    logout = ""
    if session:
        logout = f'''
        <form method="post" action="/logout" class="logout-form">
          <input type="hidden" name="csrf_token" value="{esc(session.csrf_token)}">
          <button class="ghost-button" type="submit">Sign out</button>
        </form>'''
    return HTMLResponse(f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} · Blockinator</title>
<link rel="icon" href="/static/blockinator-mark.webp">
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
<div class="app-shell">
  <aside class="sidebar">
    <a class="brand" href="/"><img src="/static/blockinator-mark.webp" alt=""><div><b>Blockinator</b><small>DNS Policy Control</small></div></a>
    <nav>{nav_html}</nav>
    <div class="sidebar-foot"><span class="status-dot"></span>Policy service online<small>v{APP_VERSION}</small></div>
  </aside>
  <main class="main">
    <header class="topbar"><div><p class="eyebrow">Blockinator Control Plane</p><h1>{esc(title)}</h1></div>{logout}</header>
    {flash}
    {body}
  </main>
</div>
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
              (SELECT COUNT(*) FROM query_log WHERE blocked=1) blocked,
              (SELECT COUNT(*) FROM query_log) queries
        """).fetchone())
        recent = con.execute("SELECT ts,client_ip,qname,blocked,reason FROM query_log ORDER BY id DESC LIMIT 8").fetchall()
    global_on = db.get_setting("global_blocking", "1") == "1"
    rows = "".join(
        f'<tr><td>{esc(r["ts"])}</td><td class="mono">{esc(r["client_ip"])}</td><td>{esc(r["qname"])}</td><td><span class="pill {"red" if r["blocked"] else "green"}">{"Blocked" if r["blocked"] else "Allowed"}</span></td><td>{esc(r["reason"])}</td></tr>'
        for r in recent
    ) or '<tr><td colspan="5" class="empty">No DNS decisions recorded yet.</td></tr>'
    body = f'''
    <section class="hero-card"><img src="/static/blockinator-hero.webp" alt="Blockinator"><div class="hero-overlay"><p>BLOCK · FILTER · PROTECT</p><h2>Your network. Your policy.</h2><span>Centralized DNS policy control with client-aware filtering.</span></div></section>
    <div class="stat-grid">
      <article class="stat"><span>Queries</span><strong>{totals["queries"]:,}</strong><small>Recorded decisions</small></article>
      <article class="stat"><span>Blocked</span><strong>{totals["blocked"]:,}</strong><small>Rejected requests</small></article>
      <article class="stat"><span>Block entries</span><strong>{totals["entries"]:,}</strong><small>Across enabled lists</small></article>
      <article class="stat"><span>Managed clients</span><strong>{totals["clients"]:,}</strong><small>{totals["networks"]} network scopes</small></article>
    </div>
    <section class="panel status-panel"><div><span class="big-dot {"green" if global_on else "amber"}"></span><div><h3>Global blocking is {"active" if global_on else "paused"}</h3><p>{"Policy decisions are enforced." if global_on else "All requests are currently allowed."}</p></div></div>
      <form method="post" action="/admin/global-toggle"><input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}"><button class="{"danger-button" if global_on else "primary-button"}">{"Pause blocking" if global_on else "Resume blocking"}</button></form>
    </section>
    <section class="panel"><div class="panel-head"><div><h3>Recent DNS activity</h3><p>Latest policy decisions from connected resolvers.</p></div><a class="text-link" href="/queries">View all →</a></div>
      <div class="table-wrap"><table><thead><tr><th>Time</th><th>Client</th><th>Domain</th><th>Decision</th><th>Reason</th></tr></thead><tbody>{rows}</tbody></table></div>
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
    cards = ""
    for r in rows:
        cards += f'''<article class="list-card"><div class="list-card-top"><div><h3>{esc(r["name"])}</h3><p>{esc(r["source_url"] or "Manual / uploaded list")}</p></div><span class="pill {"green" if r["enabled"] else "gray"}">{"Enabled" if r["enabled"] else "Disabled"}</span></div>
        <div class="list-meta"><span><b>{int(r["entry_count"]):,}</b> entries</span><span>{esc(r["format"])}</span><span>{"Global" if r["use_globally"] else "Scoped"}</span></div>
        <div class="actions"><form method="post" action="/admin/lists/{r["id"]}/toggle"><input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}"><button class="small-button">{"Disable" if r["enabled"] else "Enable"}</button></form>
        <form method="post" action="/admin/lists/{r["id"]}/delete" onsubmit="return confirm('Delete this list?')"><input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}"><button class="small-button danger">Delete</button></form></div></article>'''
    if not cards:
        cards = '<div class="empty-card">No block lists yet. Add one below.</div>'
    body = f'''<div class="split-grid"><section class="panel"><div class="panel-head"><div><h3>Managed block lists</h3><p>Multiple independent lists can be enabled globally or attached to individual scopes.</p></div></div><div class="card-grid">{cards}</div></section>
    <section class="panel"><h3>Add block list</h3><form method="post" action="/admin/lists" enctype="multipart/form-data" class="form-grid">
      <input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">
      <label>Name<input name="name" required></label><label>Format<select name="format"><option>auto</option><option>hosts</option><option>adblock</option><option>domains</option></select></label>
      <label class="full">Source URL (optional)<input name="source_url" placeholder="https://example.com/list.txt"></label>
      <label class="full">Upload file (optional)<input type="file" name="file"></label>
      <label class="full">Paste domains / hosts / adblock rules<textarea name="text" rows="8"></textarea></label>
      <label class="check"><input type="checkbox" name="global_list" value="1" checked> Use globally</label>
      <button class="primary-button" type="submit">Import list</button>
    </form></section></div>'''
    return page(request, "Block Lists", "lists", body, s)

@app.post("/admin/lists")
async def add_list(request: Request, name: str = Form(...), format: str = Form("auto"), source_url: str = Form(""), text: str = Form(""), global_list: str | None = Form(None), file: UploadFile | None = File(default=None)):
    s, _ = await require_post_session(request)
    source_type = "manual"
    content = text
    if file and file.filename:
        content = (await file.read()).decode("utf-8", errors="replace")
        source_type = "upload"
    elif source_url.strip():
        content = fetch_url(source_url.strip())
        source_type = "url"
    if not content.strip():
        return redirect("/lists", error="Provide a URL, upload, or pasted list content")
    with db.connect() as con:
        try:
            cur = con.execute("INSERT INTO blocklists(name,source_type,source_url,format,use_globally) VALUES(?,?,?,?,?)", (name.strip(), source_type, source_url.strip() or None, format, 1 if global_list else 0))
        except Exception as e:
            return redirect("/lists", error=str(e))
        list_id = int(cur.lastrowid)
    try:
        count, ignored = import_list(list_id, content, format)
    except Exception as e:
        with db.connect() as con:
            con.execute("DELETE FROM blocklists WHERE id=?", (list_id,))
        return redirect("/lists", error=f"Import failed: {e}")
    return redirect("/lists", notice=f"Imported {count:,} entries ({ignored:,} ignored)")

@app.post("/admin/lists/{list_id}/toggle")
async def toggle_list(list_id: int, request: Request):
    await require_post_session(request)
    with db.connect() as con:
        con.execute("UPDATE blocklists SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?", (list_id,))
    engine.reload()
    return redirect("/lists", notice="List state updated")

@app.post("/admin/lists/{list_id}/delete")
async def delete_list(list_id: int, request: Request):
    await require_post_session(request)
    with db.connect() as con:
        con.execute("DELETE FROM blocklists WHERE id=?", (list_id,))
    engine.reload()
    return redirect("/lists", notice="Block list deleted")

@app.get("/scopes", response_class=HTMLResponse)
def scopes_page(request: Request):
    s = require_session(request)
    with db.connect() as con:
        scopes = con.execute("SELECT * FROM scopes ORDER BY kind,name COLLATE NOCASE").fetchall()
    rows = "".join(
        f'''<tr><td><b>{esc(r["name"])}</b></td><td><span class="pill">{esc(r["kind"])}</span></td><td class="mono">{esc(r["target"])}</td><td><span class="pill {"green" if r["state"]=="active" else "amber"}">{esc(r["state"])}</span></td><td><div class="actions"><form method="post" action="/admin/scopes/{r["id"]}/toggle"><input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}"><button class="small-button">Toggle</button></form><form method="post" action="/admin/scopes/{r["id"]}/delete"><input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}"><button class="small-button danger">Delete</button></form></div></td></tr>'''
        for r in scopes
    ) or '<tr><td colspan="5" class="empty">No managed networks or clients yet.</td></tr>'
    body = f'''<section class="panel"><div class="panel-head"><div><h3>Networks & endpoints</h3><p>Pause or resume blocking for CIDR networks and exact client addresses.</p></div></div><div class="table-wrap"><table><thead><tr><th>Name</th><th>Type</th><th>Target</th><th>State</th><th></th></tr></thead><tbody>{rows}</tbody></table></div></section>
    <section class="panel narrow"><h3>Add network or client</h3><form method="post" action="/admin/scopes" class="form-grid"><input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}">
    <label>Name<input name="name" required></label><label>Type<select name="kind"><option value="network">Network</option><option value="client">Client</option></select></label>
    <label class="full">Address / CIDR<input name="target" placeholder="192.168.20.0/24 or 192.168.20.44" required></label><label>Initial state<select name="state"><option value="active">Active</option><option value="paused">Paused</option></select></label>
    <button class="primary-button" type="submit">Add scope</button></form></section>'''
    return page(request, "Networks & Endpoints", "scopes", body, s)

@app.post("/admin/scopes")
async def add_scope(request: Request, name: str = Form(...), kind: str = Form(...), target: str = Form(...), state: str = Form("active")):
    await require_post_session(request)
    try:
        if kind == "client":
            target = str(ipaddress.ip_address(target.strip()))
        else:
            target = str(ipaddress.ip_network(target.strip(), strict=False))
        with db.connect() as con:
            con.execute("INSERT INTO scopes(name,kind,target,state) VALUES(?,?,?,?)", (name.strip(), kind, target, state))
        engine.reload()
        return redirect("/scopes", notice="Scope added")
    except Exception as e:
        return redirect("/scopes", error=str(e))

@app.post("/admin/scopes/{scope_id}/toggle")
async def toggle_scope(scope_id: int, request: Request):
    await require_post_session(request)
    with db.connect() as con:
        con.execute("UPDATE scopes SET state=CASE state WHEN 'active' THEN 'paused' ELSE 'active' END WHERE id=?", (scope_id,))
    engine.reload()
    return redirect("/scopes", notice="Scope state updated")

@app.post("/admin/scopes/{scope_id}/delete")
async def delete_scope(scope_id: int, request: Request):
    await require_post_session(request)
    with db.connect() as con:
        con.execute("DELETE FROM scopes WHERE id=?", (scope_id,))
    engine.reload()
    return redirect("/scopes", notice="Scope deleted")

@app.get("/queries", response_class=HTMLResponse)
def queries_page(request: Request, q: str = "", client: str = "", decision: str = "", limit: int = 100):
    s = require_session(request)
    clauses, args = [], []
    if q:
        clauses.append("qname LIKE ?"); args.append("%" + q + "%")
    if client:
        clauses.append("client_ip LIKE ?"); args.append("%" + client + "%")
    if decision in {"blocked","allowed"}:
        clauses.append("blocked=?"); args.append(1 if decision=="blocked" else 0)
    limit = max(25, min(limit, 500))
    sql = "SELECT * FROM query_log" + (" WHERE " + " AND ".join(clauses) if clauses else "") + " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with db.connect() as con:
        rows = con.execute(sql, args).fetchall()
    trs = "".join(
        f'<tr><td>{esc(r["ts"])}</td><td class="mono">{esc(r["client_ip"])}</td><td>{esc(r["qname"])}</td><td>{esc(r["qtype"])}</td><td><span class="pill {"red" if r["blocked"] else "green"}">{"Blocked" if r["blocked"] else "Allowed"}</span></td><td>{esc(r["matched_list"] or r["reason"])}</td></tr>'
        for r in rows
    ) or '<tr><td colspan="6" class="empty">No matching queries.</td></tr>'
    body = f'''<section class="panel"><form class="filter-bar" method="get"><input name="q" value="{esc(q)}" placeholder="Domain contains…"><input name="client" value="{esc(client)}" placeholder="Client IP…"><select name="decision"><option value="">All decisions</option><option value="blocked" {"selected" if decision=="blocked" else ""}>Blocked</option><option value="allowed" {"selected" if decision=="allowed" else ""}>Allowed</option></select><select name="limit"><option>{limit}</option><option>50</option><option>100</option><option>250</option><option>500</option></select><button class="primary-button">Filter</button></form>
    <div class="table-wrap"><table><thead><tr><th>Time</th><th>Client</th><th>Domain</th><th>Type</th><th>Decision</th><th>Match</th></tr></thead><tbody>{trs}</tbody></table></div></section>'''
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
    body = f'''{reveal_box}<div class="split-grid"><section class="panel"><h3>Administrator credentials</h3><form method="post" action="/admin/credentials" class="form-grid"><input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}"><label>Username<input name="username" value="{esc(s.username)}" required></label><label>Current password<input type="password" name="current_password" required></label><label>New password<input type="password" name="new_password"></label><label>Confirm new password<input type="password" name="confirm_password"></label><button class="primary-button">Update credentials</button></form></section>
    <section class="panel"><h3>Create API key</h3><form method="post" action="/admin/api-keys" class="form-grid"><input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}"><label class="full">Key name<input name="name" placeholder="Primary Technitium" required></label><button class="primary-button">Generate key</button></form></section></div>
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
    body = f'''<div class="split-grid"><section class="panel"><h3>Blocked response</h3><form method="post" action="/admin/settings" class="form-grid"><input type="hidden" name="csrf_token" value="{esc(s.csrf_token)}"><label class="full">Response mode<select name="block_response"><option value="nxdomain" {"selected" if mode=="nxdomain" else ""}>NXDOMAIN</option><option value="refused" {"selected" if mode=="refused" else ""}>REFUSED</option><option value="nodata" {"selected" if mode=="nodata" else ""}>NODATA</option><option value="zero" {"selected" if mode=="zero" else ""}>0.0.0.0 / ::</option></select></label><label class="full">Maximum query log rows<input type="number" min="1000" max="5000000" name="max_query_logs" value="{esc(retention)}"></label><button class="primary-button">Save settings</button></form></section>
    <section class="panel"><h3>Runtime</h3><div class="info-grid"><div><span>Version</span><b>{APP_VERSION}</b></div><div><span>Database</span><b class="mono">{esc(db.path)}</b></div><div><span>Decision API</span><b class="mono">/api/v1/decision</b></div><div><span>Service</span><b>Blockinator</b></div></div></section></div>'''
    return page(request, "System Settings", "settings", body, s)

@app.post("/admin/settings")
async def save_settings(request: Request):
    _, form = await require_post_session(request)
    mode = str(form.get("block_response","nxdomain"))
    if mode not in {"nxdomain","refused","nodata","zero"}:
        mode = "nxdomain"
    try:
        retention = max(1000, min(int(form.get("max_query_logs","25000")), 5_000_000))
    except ValueError:
        retention = 25000
    db.set_setting("block_response", mode)
    db.set_setting("max_query_logs", str(retention))
    engine.reload()
    return redirect("/settings", notice="Settings saved")
