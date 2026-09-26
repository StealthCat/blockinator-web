#!/usr/bin/env python3
"""Docker CI: actual application gate/probes, then an offline SQLite backup round-trip."""
import json
import subprocess
import tempfile
from pathlib import Path


def call(*args):
    return subprocess.check_output(["docker", "compose", *args], text=True).strip()


if __name__ == "__main__":
    # The smoke-test Compose stack already runs the freshly built image.
    try:
        call("exec", "-T", "blockinator", "python", "-c",
             "from pathlib import Path; p=Path('/run/blockinator-update'); p.mkdir(exist_ok=True); "
             "(p/'maintenance').write_text('CI'); (p/'probe-token').write_text('ci-probe-token')")
        call("exec", "-T", "blockinator", "python", "/srv/tools/update_probe.py", "--sha", "development")
        call("stop", "-t", "30", "blockinator")
        with tempfile.TemporaryDirectory() as temporary:
            def data(action):
                return call("run", "--rm", "--no-deps", "-T", "-v", temporary + ":/backup",
                            "blockinator", "python", "/srv/tools/update_data.py", action)
            data("backup")
            data("restore")
    finally:
        call("start", "blockinator")
        call("exec", "-T", "blockinator", "python", "-c",
             "from pathlib import Path; p=Path('/run/blockinator-update'); "
             "(p/'maintenance').unlink(missing_ok=True); (p/'probe-token').unlink(missing_ok=True)")
    print("Container update probes and offline backup/restore passed")
