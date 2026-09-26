#!/usr/bin/env python3
"""Probe the actual instance plus deterministic allow/block behavior before opening traffic."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.db import Database
from app.policy import PolicyEngine


def probe(sha):
    runtime = Path(os.getenv("UPDATER_RUNTIME_DIR", "/run/blockinator-update"))
    token = (runtime / "probe-token").read_text().strip()
    base = "http://127.0.0.1:" + os.getenv("WEB_PORT", "8080")
    def get(path):
        request = urllib.request.Request(base + path, headers={"X-Blockinator-Probe": token})
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response)
    assert get("/readyz")["status"] == "ready"
    actual = get("/api/v1/update-probe")
    assert actual["sha"] == sha and actual["database"] == "ok"
    try:
        get("/api/v1/ping")
    except urllib.error.HTTPError as exc:
        assert exc.code == 401
    else:
        raise RuntimeError("Policy API accepted an unauthenticated request")
    with tempfile.TemporaryDirectory() as directory:
        db = Database(str(Path(directory) / "probe.db"))
        with db.connect() as con:
            cur = con.execute("INSERT INTO blocklists(name,use_globally) VALUES('Update probe',1)")
            db.replace_list_domains(con, int(cur.lastrowid), {"blocked.example"})
        engine = PolicyEngine(db)
        try:
            assert engine.decide("192.0.2.5", "blocked.example").block
            assert not engine.decide("192.0.2.5", "allowed.example").block
        finally:
            engine.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sha", required=True)
    probe(parser.parse_args().sha)
    print("Update probes passed")
