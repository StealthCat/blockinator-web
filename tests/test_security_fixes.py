"""Regression coverage for the 1.20.17 code-scanning remediations."""
import ast
import importlib
import io
import os
import re
import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.auth import (
    API_KEY_HASH_PREFIX,
    API_KEY_SALT_SETTING,
    AuthManager,
    SESSION_COOKIE,
)
from app.db import Database

# Shape of a key stored before 1.20.17 (64 lowercase hex characters). The
# tests only need the legacy format, not a digest of real key material.
LEGACY_KEY_HASH = "5f" * 32
from app.policy import PolicyEngine
from app.query_cache import query_choices, query_counts
from app.refresher import BlocklistRefresher
from app.statistics import StatisticsCache


@pytest.fixture
def web(tmp_path, monkeypatch):
    with patch.dict(os.environ, DATA_DIR=str(tmp_path / "bootstrap"), DATABASE_BACKEND="sqlite",
                    ADMIN_PASSWORD="review-test-password", POLICY_API_KEY="review-policy-key-long-enough"):
        main = importlib.import_module("app.main")
        db = Database(str(tmp_path / "test.db"))
        auth = AuthManager(db)
    engine = PolicyEngine(db)
    monkeypatch.setattr(main, "db", db)
    monkeypatch.setattr(main, "auth", auth)
    monkeypatch.setattr(main, "engine", engine)
    monkeypatch.setattr(main, "statistics_cache", StatisticsCache(db))
    monkeypatch.setattr(main, "refresher", BlocklistRefresher(db, engine))
    query_counts.entries.clear()
    query_choices.entries.clear()
    session = auth.create_session(*auth.authenticate("admin", "review-test-password"))
    client = TestClient(main.app, follow_redirects=False)
    client.cookies.set(SESSION_COOKIE, session.token)
    yield main, client, session
    client.close()
    engine.close()
    auth.close()


# ---- URL redirection (CodeQL #19) ----

@pytest.mark.parametrize("path", [
    "/lists", "/lists/3/edit", "/settings#tls", "/lists/3/domains?page_num=2&q=a%22b",
])
def test_local_redirect_paths_are_kept(web, path):
    main, _, _ = web
    assert main.local_redirect_path(path) == path


@pytest.mark.parametrize("path", [
    "https://evil.example/", "//evil.example/", "/\\evil.example/", "\\\\evil.example",
    "/\t/evil.example", "/\n/evil.example", "javascript:alert(1)", "lists", "",
])
def test_external_redirect_targets_fall_back_to_root(web, path):
    main, _, _ = web
    assert main.local_redirect_path(path) == "/"
    response = main.redirect(path, error="x")
    assert response.headers["location"] == "/?error=x"


@pytest.mark.parametrize("path", [
    "/lists/3/domains?page_num=2&q=a%22b#entries", "/settings#tls", "/",
])
def test_redirect_keeps_local_target_when_messages_contain_urls(web, path):
    from urllib.parse import parse_qs, urlsplit

    main, _, _ = web
    response = main.redirect(path, notice="//evil.example/", error="https://evil.example/?x=1#bad")
    location = urlsplit(response.headers["location"])
    expected = urlsplit(path)
    assert location.scheme == location.netloc == ""
    assert location.path == expected.path
    assert location.fragment == expected.fragment
    query = parse_qs(location.query)
    assert query["notice"] == ["//evil.example/"]
    assert query["error"] == ["https://evil.example/?x=1#bad"]
    for key, value in parse_qs(expected.query).items():
        assert query[key] == value


# ---- Exception exposure (CodeQL #17, #18) ----

def test_runtime_api_hides_reload_exception_details(web):
    main, client, _ = web
    main.engine.last_reload_error = "reload: OperationalError near secret_table"
    body = client.get("/api/v1/runtime").json()
    assert body["policy_reload_error"] == "Policy reload failed; see the server log"
    main.engine.last_reload_error = None
    assert client.get("/api/v1/runtime").json()["policy_reload_error"] is None


def test_policy_preview_reports_input_problem_without_exception_text(web):
    main, client, _ = web
    page = client.get("/policy-test", params={"client": "not-an-ip<script>", "domain": "example.org"}).text
    assert "Client IP must be a valid IPv4 or IPv6 address" in page
    assert "does not appear to be" not in page
    assert "<script>" not in page


def test_public_failure_hides_internal_errors(web):
    main, _, _ = web
    assert main.public_failure("Import failed", ValueError("List name is required")) == (
        "Import failed: List name is required"
    )
    http_error = urllib.error.HTTPError("https://example.org", 404, "secret detail", {}, io.BytesIO())
    assert main.public_failure("Could not fetch list URL", http_error) == (
        "Could not fetch list URL: the source returned HTTP 404"
    )
    internal = main.public_failure("Could not save list", RuntimeError("database at /data/x.db is locked"))
    assert "/data/x.db" not in internal
    assert internal == "Could not save list; details are in the server log"
    network = main.public_failure("Could not fetch list URL", OSError("10.0.0.5 refused"))
    assert "10.0.0.5" not in network


# ---- Reflected XSS (CodeQL #16) ----

def test_manual_list_pagination_escapes_search_text(web):
    main, client, session = web
    with main.db.connect() as con:
        list_id = con.execute(
            "INSERT INTO blocklists(name,source_type,format) VALUES('Manual','manual','domains')"
        ).lastrowid
        main.db.replace_list_domains(con, list_id, {f"host{i:03}.example.org" for i in range(150)})
    payload = '"><script>alert(1)</script>'
    page = client.get(f"/lists/{list_id}/domains", params={"q": "host" + payload}).text
    assert "<script>alert(1)</script>" not in page
    page = client.get(f"/lists/{list_id}/domains", params={"q": "host"}).text
    assert f'href="/lists/{list_id}/domains?page_num=2&amp;q=host"' in page


# ---- Client-side request forgery (CodeQL #15) ----

def test_query_refresh_uses_fixed_path_and_known_parameters():
    javascript = Path("app/static/app.js").read_text(encoding="utf-8")
    assert 'fetch("/queries/rows" + window.location.search' not in javascript
    assert "fetch(queryRowsUrl()" in javascript
    allowed = set(re.findall(r'"([a-z_]+)"', re.search(
        r"QUERY_ROW_PARAMS = \[(.*?)\];", javascript, re.S).group(1)))

    tree = ast.parse(Path("app/main.py").read_text(encoding="utf-8"))
    handler = next(node for node in tree.body
                   if isinstance(node, ast.FunctionDef) and node.name == "queries_page")
    accepted = set()
    defaults = handler.args.defaults
    params = handler.args.args[-len(defaults):]
    for param, default in zip(params, defaults):
        alias = next((kw.value.value for kw in getattr(default, "keywords", [])
                      if kw.arg == "alias"), None)
        accepted.add(alias or param.arg)
    assert allowed == accepted


# ---- API key hashing (CodeQL #7) ----

def _auth(tmp_path, monkeypatch, key="primary-api-key-that-is-long-enough"):
    monkeypatch.setenv("ADMIN_PASSWORD", "some-password-for-testing")
    monkeypatch.setenv("POLICY_API_KEY", key)
    db = Database(str(tmp_path / "auth.db"))
    return db, AuthManager(db)


def test_api_keys_are_stored_with_salted_scrypt(tmp_path, monkeypatch):
    db, auth = _auth(tmp_path, monkeypatch)
    _, raw = auth.create_api_key("Secondary")
    with db.connect() as con:
        stored = [str(r["key_hash"]) for r in con.execute("SELECT key_hash FROM api_keys")]
    assert len(stored) == 2
    assert all(value.startswith(API_KEY_HASH_PREFIX) for value in stored)
    assert len(bytes.fromhex(db.get_setting(API_KEY_SALT_SETTING))) == 16
    assert auth.verify_api_key(raw) is not None
    auth.close()

    # The installation salt is reused, so existing keys keep verifying.
    salt = db.get_setting(API_KEY_SALT_SETTING)
    second = AuthManager(db)
    assert db.get_setting(API_KEY_SALT_SETTING) == salt
    assert second.verify_api_key(raw) is not None
    second.close()


def test_legacy_api_key_is_rejected_and_flagged_for_rotation(tmp_path, monkeypatch):
    db, auth = _auth(tmp_path, monkeypatch)
    legacy_raw = "legacy-key-created-before-scrypt-storage"
    with db.connect() as con:
        legacy_id = con.execute(
            "INSERT INTO api_keys(name,key_hash,key_prefix) VALUES(?,?,?)",
            ("Legacy", LEGACY_KEY_HASH, "legacy-k…"),
        ).lastrowid
    auth.reload_api_keys()

    assert auth.verify_api_key(legacy_raw) is None
    flags = {key["name"]: key["needs_rotation"] for key in auth.list_api_keys()}
    assert flags == {"Primary": False, "Legacy": True}
    assert all("key_hash" not in key for key in auth.list_api_keys())

    rotated = auth.rotate_api_key(legacy_id)
    assert auth.verify_api_key(rotated)["name"] == "Legacy"
    assert not any(key["needs_rotation"] for key in auth.list_api_keys())
    auth.close()


def test_console_warns_about_api_keys_needing_rotation(web):
    main, client, _ = web
    with main.db.connect() as con:
        con.execute(
            "INSERT INTO api_keys(name,key_hash,key_prefix) VALUES(?,?,?)",
            ("Old resolver", LEGACY_KEY_HASH, "old-reso…"),
        )
    main.auth.reload_api_keys()
    assert "Rotation required" in client.get("/security").text
    assert "1 API key from before 1.20.17 no longer authenticates; rotate it" in client.get("/").text


def test_rejected_api_key_is_accepted_after_it_is_created(tmp_path, monkeypatch):
    _, auth = _auth(tmp_path, monkeypatch)
    raw = "administrator-supplied-api-key-value"
    assert auth.verify_api_key(raw) is None
    auth.create_api_key("Supplied", raw)
    assert auth.verify_api_key(raw)["name"] == "Supplied"
    auth.close()


def test_cached_api_key_stops_working_when_disabled(tmp_path, monkeypatch):
    _, auth = _auth(tmp_path, monkeypatch)
    key_id, raw = auth.create_api_key("Secondary")
    assert auth.verify_api_key(raw) is not None
    assert auth.verify_api_key(raw) is not None
    auth.set_api_key_enabled(key_id, False)
    assert auth.verify_api_key(raw) is None
    auth.close()
