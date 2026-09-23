from __future__ import annotations

import tempfile
from pathlib import Path

from app.db import Database
from app.policy import PolicyEngine


def _engine():
    temp_dir = tempfile.TemporaryDirectory()
    db = Database(str(Path(temp_dir.name) / "efficiency.db"))
    with db.connect() as con:
        cur = con.execute(
            "INSERT INTO blocklists(name,use_globally) VALUES(?,1)",
            ("benchmark",),
        )
        list_id = int(cur.lastrowid)
        db._insert_domain_memberships(
            con,
            list_id,
            ["ads.example.com"],
        )
        con.execute(
            "UPDATE blocklists SET entry_count=1 WHERE id=?",
            (list_id,),
        )
    return temp_dir, db, PolicyEngine(db)


def test_settings_reload_preserves_domain_index():
    temp_dir, db, engine = _engine()
    try:
        original_domains = engine.snapshot.domain_masks
        db.set_setting("block_response", "refused")
        engine.reload_settings()

        assert engine.snapshot.domain_masks is original_domains
        assert engine.decide(
            "192.0.2.10",
            "ads.example.com",
        ).response_mode == "refused"
    finally:
        engine.close()
        temp_dir.cleanup()


def test_scope_reload_preserves_domain_index():
    temp_dir, db, engine = _engine()
    try:
        original_domains = engine.snapshot.domain_masks
        with db.connect() as con:
            con.execute(
                """
                INSERT INTO scopes(name,kind,target,state)
                VALUES(?,?,?,'active')
                """,
                ("endpoint", "client", "192.0.2.10"),
            )

        engine.reload_scopes()

        assert engine.snapshot.domain_masks is original_domains
        decision = engine.decide("192.0.2.10", "not-listed.example")
        assert decision.matched_scope == "endpoint"
    finally:
        engine.close()
        temp_dir.cleanup()


def test_list_reload_preserves_scope_index():
    temp_dir, db, engine = _engine()
    try:
        original_clients = engine.snapshot.client_scopes
        with db.connect() as con:
            con.execute(
                "UPDATE blocklists SET enabled=0 WHERE name=?",
                ("benchmark",),
            )

        engine.reload_lists()

        assert engine.snapshot.client_scopes == original_clients
        assert engine.decide("192.0.2.10", "ads.example.com").block is False
    finally:
        engine.close()
        temp_dir.cleanup()


def test_request_json_capture_defaults_off_and_can_be_enabled():
    temp_dir, _db, engine = _engine()
    request = {
        "client": {"ip": "192.0.2.10"},
        "dns": {
            "questions": [
                {"name": "ads.example.com", "type": "A", "class": "IN"}
            ]
        },
    }
    try:
        assert engine.logger.capture_request_json is False
        _decision, row = engine.decide_with_log_row(request)
        assert row["request_obj"] is None

        engine.logger.configure_retention(
            engine.logger.max_rows,
            engine.logger.max_age_days,
            capture_request_json=True,
        )
        _decision, row = engine.decide_with_log_row(request)
        assert row["request_obj"] is request
    finally:
        engine.close()
        temp_dir.cleanup()
