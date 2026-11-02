"""Regressions for backend defects found in code review."""
from __future__ import annotations

from pathlib import Path

import app.policy as policy_module
from app.blocklists import parse_blocklist
from app.db import Database
from app.policy import PolicyEngine
from app.refresher import BlocklistRefresher, RefreshResult
from app.tls import TlsManager, TlsSettings
from tools.migrate_database import Endpoint, find_mysql_name_conflicts


def _engine(tmp_path: Path):
    db = Database(str(tmp_path / "test.db"))
    with db.connect() as con:
        lid = con.execute("INSERT INTO blocklists(name,use_globally) VALUES('global',1)").lastrowid
        con.execute("INSERT INTO block_entries(blocklist_id,domain) VALUES(?,?)", (lid, "ads.example.com"))
        con.execute("UPDATE blocklists SET entry_count=1 WHERE id=?", (lid,))
    return db, PolicyEngine(db)


def test_utf8_bom_does_not_corrupt_first_entry():
    for list_format in ("auto", "hosts"):
        parsed = parse_blocklist("﻿0.0.0.0 ads.example.com\ntracker.example.com\n", list_format)
        assert parsed.domains == ({"ads.example.com", "tracker.example.com"} if list_format == "auto" else {"ads.example.com"})
        assert "0.0.0.0" not in parsed.domains


def test_ipv4_mapped_client_matches_ipv4_scope(tmp_path):
    db, engine = _engine(tmp_path)
    try:
        with db.connect() as con:
            con.execute("INSERT INTO scopes(name,kind,target,state) VALUES('pc','client','192.168.1.20','paused')")
        engine.reload()
        assert engine.decide("192.168.1.20", "ads.example.com").block is False
        assert engine.decide("::ffff:192.168.1.20", "ads.example.com").block is False
        assert engine.decide("::ffff:192.168.1.21", "ads.example.com").block is True
    finally:
        engine.close()


def test_reload_keeps_identity_removed_while_rebuilding(tmp_path, monkeypatch):
    db, engine = _engine(tmp_path)
    try:
        with db.connect() as con:
            con.execute("INSERT INTO client_identities(client_ip,client_name) VALUES('192.0.2.7','kids-ipad.lan')")
        engine.reload()
        assert engine.snapshot.client_identities.get("192.0.2.7") == "kids-ipad.lan"

        real_snapshot = policy_module.PolicySnapshot

        def snapshot_after_concurrent_removal(*args, **kwargs):
            # The PTR worker commits "no PTR" after reload() read identities.
            with db.connect() as con:
                con.execute("DELETE FROM client_identities WHERE client_ip='192.0.2.7'")
            engine._remember_client_identities({"192.0.2.7": None})
            return real_snapshot(*args, **kwargs)

        monkeypatch.setattr(policy_module, "PolicySnapshot", snapshot_after_concurrent_removal)
        engine.reload()
        assert "192.0.2.7" not in engine.snapshot.client_identities
    finally:
        engine.close()


def test_restart_does_not_resurrect_removed_identities(tmp_path):
    path = str(tmp_path / "identities.db")
    db = Database(path)
    with db.connect() as con:
        con.execute(
            "INSERT INTO query_log(client_ip,client_name,qname,blocked) VALUES('192.0.2.7','kids-ipad.lan','a.example',0)"
        )
        con.execute("DELETE FROM client_identities")
    Database(path)  # restart
    with db.connect() as con:
        assert con.execute("SELECT COUNT(*) c FROM client_identities").fetchone()["c"] == 0


def test_one_failing_list_does_not_skip_policy_reload(tmp_path, monkeypatch):
    class Engine:
        reloads = 0

        def reload_lists(self):
            Engine.reloads += 1

    db = Database(str(tmp_path / "refresh.db"))
    refresher = BlocklistRefresher(db, Engine(), fetcher=lambda url: "")
    monkeypatch.setattr(refresher, "due_list_ids", lambda: [1, 2])

    def refresh(list_id, reload_engine=True):
        if list_id == 2:
            raise TimeoutError("pool exhausted")
        return RefreshResult(list_id=list_id, refreshed=True, changed=True)

    monkeypatch.setattr(refresher, "_refresh_list", refresh)
    results = refresher.refresh_due_once()
    assert Engine.reloads == 1
    assert [r.error for r in results] == [None, "pool exhausted"]


def test_tls_configure_recovers_when_saved_mode_cannot_render(tmp_path, monkeypatch):
    db = Database(str(tmp_path / "tls.db"))
    manager = TlsManager(db, tls_dir=tmp_path / "tls", caddy_admin_url="http://caddy.invalid:2019", reconcile_seconds=5)
    # Saved upload mode whose certificate files were lost.
    db.set_setting("tls_mode", "upload")
    db.set_setting("tls_hostname", "blockinator.example.com")
    loaded: list[dict] = []
    monkeypatch.setattr(manager, "_load", lambda config: loaded.append(config))
    manager.configure(TlsSettings())
    assert db.get_setting("tls_mode") == "http"
    assert loaded


def test_migration_detects_names_that_collide_in_mysql(tmp_path):
    path = tmp_path / "source.db"
    db = Database(str(path))
    with db.connect() as con:
        con.execute("INSERT INTO blocklists(name) VALUES('Kids'),('kids'),('Adults')")
        con.execute("INSERT INTO scopes(name,kind,target) VALUES('Café','client','192.0.2.1'),('Cafe ','client','192.0.2.2')")
    with Endpoint("sqlite", sqlite_path=path, readonly=True) as source:
        conflicts = find_mysql_name_conflicts(source)
    assert len(conflicts) == 2
    assert any("'Kids'" in item and "'kids'" in item for item in conflicts)
    assert any(item.startswith("scopes.name") for item in conflicts)
