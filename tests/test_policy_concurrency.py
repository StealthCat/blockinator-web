from __future__ import annotations

import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from app.db import Database
from app.policy import PolicyEngine


def _engine_with_lists(
    list_specs: list[tuple[str, str, str]],
) -> tuple[tempfile.TemporaryDirectory, Database, PolicyEngine]:
    temp_dir = tempfile.TemporaryDirectory()
    db = Database(str(Path(temp_dir.name) / "test.db"))
    with db.connect() as con:
        for name, list_type, domain in list_specs:
            cursor = con.execute(
                """
                INSERT INTO blocklists(name,list_type,use_globally)
                VALUES(?,?,1)
                """,
                (name, list_type),
            )
            list_id = int(cursor.lastrowid)
            db._insert_domain_memberships(con, list_id, [domain])
            con.execute(
                "UPDATE blocklists SET entry_count=1 WHERE id=?",
                (list_id,),
            )
    return temp_dir, db, PolicyEngine(db)


def test_decision_path_does_not_wait_for_policy_write_lock():
    temp_dir, _db, engine = _engine_with_lists(
        [("block", "block", "ads.example.com")]
    )
    try:
        results = []
        with engine._write_lock:
            thread = threading.Thread(
                target=lambda: results.append(
                    engine.decide("192.0.2.10", "ads.example.com")
                )
            )
            thread.start()
            thread.join(timeout=0.5)
            assert not thread.is_alive()

        assert results
        assert results[0].block is True
        assert results[0].matched_list == "block"
    finally:
        engine.close()
        temp_dir.cleanup()


def test_concurrent_decisions_remain_correct_during_reloads():
    temp_dir, _db, engine = _engine_with_lists(
        [("block", "block", "ads.example.com")]
    )
    try:
        stop = threading.Event()
        failures: list[str] = []

        def reloader() -> None:
            for _ in range(40):
                engine.reload()
            stop.set()

        reload_thread = threading.Thread(target=reloader)
        reload_thread.start()

        def worker() -> None:
            for _ in range(1000):
                decision = engine.decide(
                    "192.0.2.10",
                    "sub.ads.example.com",
                )
                if not decision.block or decision.matched_list != "block":
                    failures.append(repr(decision))
                    return

        with ThreadPoolExecutor(max_workers=16) as executor:
            futures = [executor.submit(worker) for _ in range(16)]
            for future in futures:
                future.result()

        reload_thread.join(timeout=5)
        assert stop.is_set()
        assert failures == []
    finally:
        engine.close()
        temp_dir.cleanup()


def test_domain_index_stores_one_key_with_multiple_list_bits():
    temp_dir, _db, engine = _engine_with_lists(
        [
            ("first", "block", "shared.example.com"),
            ("second", "block", "shared.example.com"),
        ]
    )
    try:
        mask = engine.snapshot.domain_masks["shared.example.com"]
        assert mask.bit_count() == 2
        assert list(engine.snapshot.domain_masks) == ["shared.example.com"]

        decision = engine.decide("192.0.2.10", "shared.example.com")
        assert decision.block is True
        assert decision.matched_list == "first"
    finally:
        engine.close()
        temp_dir.cleanup()


def test_whitelist_precedence_is_preserved_by_bitmask_index():
    temp_dir, _db, engine = _engine_with_lists(
        [
            ("block-first", "block", "shared.example.com"),
            ("allow-second", "whitelist", "shared.example.com"),
        ]
    )
    try:
        decision = engine.decide("192.0.2.10", "sub.shared.example.com")
        assert decision.block is False
        assert decision.reason == "whitelist_match"
        assert decision.matched_list == "allow-second"
        assert decision.matched_list_type == "whitelist"
    finally:
        engine.close()
        temp_dir.cleanup()
