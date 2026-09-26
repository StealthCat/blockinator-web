import copy
import json
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

import pytest

from app.db import Database
from tools.update_data import run as backup_data
from updater.service import IMAGE, Updater, compatible, validate_manifest


def release(**changes):
    value = {"channel": "release", "sha": "b" * 40, "digest": "sha256:" + "b" * 64,
             "version": "1.20.1", "schema": 1, "minimum_schema": 1, "protocol": 1, "automatic": True, "sequence": 5}
    value.update(changes)
    value["image"] = IMAGE + "@" + value["digest"]
    return value


class Harness(Updater):
    def __init__(self, directory):
        self.commands = []
        self.fail_probe = False
        self.fail_restore = False
        self.fail_backup = False
        self.interrupt = False
        self.data_dir = directory / "data"
        self.data_dir.mkdir(exist_ok=True)
        self.db = Database(str(self.data_dir / "policy.db"))
        self.db.set_setting("test_value", "original")
        self.candidate = release()
        deployment = directory / "deployment.json"
        deployment.write_text("{}")
        super().__init__({"state_dir": str(directory / "state"), "runtime_dir": str(directory / "runtime"),
                          "project": "blockinator-test", "deployment": str(deployment), "minimum_free_bytes": 0,
                          "initial": release(sha="a" * 40, digest="sha256:" + "a" * 64, version="1.20.0")}, self.runner)
    def runner(self, args, timeout=300):
        self.commands.append(args)
        if args[:3] == ["docker", "image", "inspect"]:
            return json.dumps({"org.opencontainers.image.revision": self.candidate["sha"],
                               "org.opencontainers.image.version": self.candidate["version"],
                               "io.blockinator.schema": str(self.candidate["schema"]), "io.blockinator.updater-protocol": "1"})
        return ""
    def check(self):
        self.state.update(candidate=copy.deepcopy(self.candidate), checked_at=9999999999)
        self.save()
        return self.candidate
    def data(self, action, backup):
        if self.fail_backup and action == "backup":
            raise RuntimeError("Backup unavailable")
        if self.fail_restore and action == "restore":
            raise RuntimeError("Restore unavailable")
        backup_data(action, backup, self.data_dir)
    def start(self):
        image = json.loads((self.root / "active.json").read_text())["services"]["blockinator"]["image"]
        self.commands.append(["start", image])
        if image == self.candidate["image"]:
            self.db.set_setting("test_value", "candidate-write")
            if self.interrupt:
                raise KeyboardInterrupt("host power loss")
    def probe(self, expected):
        self.commands.append(["probe", expected["sha"]])
        if self.fail_probe and expected["sha"] == self.candidate["sha"]:
            raise RuntimeError("Bad candidate")


@pytest.fixture
def updater(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_BACKEND", "sqlite")
    return Harness(tmp_path)


def test_success_keeps_previous_image_backup_and_audit(updater):
    old = copy.deepcopy(updater.state["current"])
    updater.install(updater.candidate)
    assert updater.state["phase"] == "complete"
    assert updater.state["previous"] == old
    assert updater.state["current"]["sha"] == "b" * 40
    assert len(list((updater.root / "backups").glob("*/complete.json"))) == 1
    assert not (updater.runtime / "maintenance").exists()
    assert updater.state["history"][-1]["result"] == "installed"
    verification = next(c for c in updater.commands if c[:3] == ["gh", "attestation", "verify"])
    assert "--source-ref" in verification and "--signer-workflow" in verification


def test_candidate_failure_restores_data_before_reopening_traffic(updater):
    updater.fail_probe = True
    updater.install(updater.candidate)
    assert updater.state["phase"] == "recovered"
    assert updater.db.get_setting("test_value") == "original"
    assert updater.state["current"]["sha"] == "a" * 40
    assert not (updater.runtime / "maintenance").exists()


def test_failed_restore_keeps_gate_and_job_for_retry(updater):
    updater.fail_probe = updater.fail_restore = True
    updater.install(updater.candidate)
    assert updater.state["phase"] == "recovery_failed"
    assert updater.state["job"] and (updater.runtime / "maintenance").exists()
    updater.fail_restore = False
    updater.recover()
    assert updater.state["phase"] == "recovered"
    assert updater.db.get_setting("test_value") == "original"


def test_backup_failure_never_starts_candidate(updater):
    updater.fail_backup = True
    updater.install(updater.candidate)
    assert updater.state["phase"] == "recovered"
    assert ["start", updater.candidate["image"]] not in updater.commands
    assert updater.db.get_setting("test_value") == "original"


def test_journal_recovers_interrupted_migration(updater):
    updater.interrupt = True
    with pytest.raises(KeyboardInterrupt):
        updater.install(updater.candidate)
    saved = json.loads(updater.state_path.read_text())
    assert saved["job"]["candidate_started"] is True
    assert (updater.runtime / "maintenance").exists()
    # Reconstruct from disk as a restarted helper, retaining the live candidate's
    # database instead of accidentally creating a fresh fixture.
    restarted = Harness.__new__(Harness)
    restarted.__dict__.update(updater.__dict__)
    restarted.interrupt = False
    Updater.__init__(restarted, updater.config, restarted.runner)
    restarted.recover()
    assert restarted.state["phase"] == "recovered"
    assert restarted.db.get_setting("test_value") == "original"


@pytest.mark.parametrize("changes", [{"channel": "main"}, {"digest": "latest"}, {"sha": "../shell"},
                                      {"protocol": 2}, {"schema": True}, {"automatic": "yes"},
                                      {"minimum_schema": 3}, {"version": "1.2.3; touch /tmp/x"}])
def test_manifest_contract_rejects_unsafe_or_unknown_values(changes):
    with pytest.raises(ValueError):
        validate_manifest(release(**changes), "release")


def test_automatic_major_and_schema_changes_require_manual_action():
    current = release()
    for new in (release(version="2.0.0"), release(schema=2), release(automatic=False)):
        with pytest.raises(ValueError, match="manual"):
            compatible(current, new, automatic=True)
        compatible(current, new, automatic=False)
    with pytest.raises(ValueError, match="schema"):
        compatible(release(schema=2), release(schema=1))


def test_install_requires_exact_reviewed_digest(updater):
    updater.check()
    with pytest.raises(ValueError, match="exact candidate"):
        updater.request("install", {"digest": "sha256:" + "c" * 64})
    assert not updater.lock.locked()


def test_channel_change_invalidates_candidate_and_checks_timezone(updater):
    updater.check()
    updater.request("configure", {"channel": "preview", "mode": "notify", "hour": 4, "timezone": "America/New_York"})
    assert updater.state["candidate"] is None
    with pytest.raises(Exception):
        updater.request("configure", {"channel": "preview", "mode": "notify", "hour": 4, "timezone": "Invalid/Zone"})
    assert not updater.lock.locked()


def test_scheduling_obeys_local_window_and_postpone(updater):
    updater.configure({"channel": "release", "mode": "automatic", "hour": 3, "timezone": "America/New_York"})
    updater.tick(datetime(2026, 9, 26, 6, 0, tzinfo=timezone.utc))  # 02:00 local
    assert updater.state["current"]["sha"] == "a" * 40
    updater.state["postponed_until"] = datetime(2026, 9, 27, tzinfo=timezone.utc).timestamp()
    updater.tick(datetime(2026, 9, 26, 7, 0, tzinfo=timezone.utc))
    assert updater.state["current"]["sha"] == "a" * 40
    updater.tick(datetime(2026, 9, 27, 7, 0, tzinfo=timezone.utc))
    assert updater.state["current"]["sha"] == "b" * 40


def test_status_available_but_second_operation_rejected_during_job(updater):
    updater.lock.acquire()
    try:
        assert updater.request("status", {})["current"]
        with pytest.raises(ValueError, match="already running"):
            updater.request("check", {})
    finally:
        updater.lock.release()


def test_backup_checksum_failure_prevents_restore(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_BACKEND", "sqlite")
    data = tmp_path / "data"
    db = Database(str(data / "policy.db"))
    db.set_setting("sentinel", "before")
    (data / "tls").mkdir()
    (data / "tls" / "key.pem").write_text("test key material")
    backup = tmp_path / "backup"
    backup_data("backup", backup, data)
    db.set_setting("sentinel", "after")
    (backup / "tls" / "key.pem").write_text("corrupt")
    with pytest.raises(ValueError, match="checksum"):
        backup_data("restore", backup, data)
    assert db.get_setting("sentinel") == "after"


def test_sqlite_restore_includes_tls_and_removes_new_schema(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_BACKEND", "sqlite")
    data = tmp_path / "data"
    db = Database(str(data / "policy.db"))
    (data / "tls").mkdir()
    (data / "tls" / "key.pem").write_text("before")
    backup = tmp_path / "backup"
    backup_data("backup", backup, data)
    (data / "tls" / "key.pem").write_text("after")
    with db.connect() as con:
        con.execute("CREATE TABLE new_schema_only (id INTEGER)")
    backup_data("restore", backup, data)
    assert (data / "tls" / "key.pem").read_text() == "before"
    with db.connect() as con:
        assert not con.execute("SELECT name FROM sqlite_master WHERE name='new_schema_only'").fetchone()


def test_newer_schema_is_rejected_without_downgrade(tmp_path):
    path = tmp_path / "policy.db"
    db = Database(str(path))
    db.set_setting("schema_version", "999")
    with pytest.raises(RuntimeError, match="newer"):
        Database(str(path))
    assert db.get_setting("schema_version") == "999"


def test_image_identity_failure_happens_before_stopping_instance(updater):
    updater.candidate = release(sha="c" * 40)
    with pytest.raises(ValueError, match="Image does not match"):
        updater.install(release())
    assert not (updater.runtime / "maintenance").exists()
    assert not any("stop" in command for command in updater.commands)


def test_bad_attestation_never_pulls_or_stops(updater):
    def reject(*args):
        raise RuntimeError("Invalid attestation")
    updater.verify = reject
    with pytest.raises(RuntimeError):
        updater.install(updater.candidate)
    assert not updater.commands


def test_channel_manifest_replay_is_rejected(updater):
    def runner(args, timeout=300):
        if args[:3] == ["gh", "release", "download"]:
            directory = Path(args[args.index("--dir") + 1])
            (directory / "manifest.json").write_text(json.dumps(release(sequence=2)))
        return ""
    updater.run = runner
    updater.state["high_water"]["release"] = 3
    with pytest.raises(ValueError, match="replay"):
        Updater.check(updater)
    assert updater.state["candidate"] is None


def test_timed_out_docker_task_is_removed_before_recovery(updater):
    commands = []
    exists = [False]
    def runner(args, timeout=300):
        commands.append(args)
        if args[:3] == ["docker", "ps", "-aq"]:
            return "1234" if exists[0] else ""
        if args[:3] == ["docker", "rm", "--force"]:
            exists[0] = False
            return ""
        if "run" in args:
            exists[0] = True
            raise TimeoutError("CLI timed out")
        return ""
    updater.run = runner
    with pytest.raises(TimeoutError):
        Updater.data(updater, "backup", updater.root / "backup")
    assert not exists[0]
    assert any(c[:3] == ["docker", "rm", "--force"] for c in commands)


def test_automatic_updates_do_not_undo_manual_rollback(updater):
    updater.configure({"channel": "release", "mode": "automatic", "hour": 3, "timezone": "UTC"})
    updater.state["blocked_digest"] = updater.candidate["digest"]
    updater.tick(datetime(2026, 9, 26, 3, 0, tzinfo=timezone.utc))
    assert updater.state["current"]["sha"] == "a" * 40
    updater.install(updater.candidate, automatic=False)
    assert not updater.state.get("blocked_digest")


@pytest.mark.parametrize("gh_state,git_present,expected", [
    ("current", True, "gh"), ("current", False, "gh"),
    ("old", True, "git"), ("failed", True, "git"), ("missing", True, "git"),
    ("missing", False, None), ("old", False, None), ("failed", False, None),
])
def test_backend_detection(gh_state, git_present, expected):
    from updater.service import select_backend
    def which(name):
        return "/usr/bin/" + name if (name == "gh" and gh_state != "missing") or (name == "git" and git_present) else None
    def runner(args):
        if args[0].endswith("/git"):
            return "git version 2.43"
        if gh_state == "failed":
            raise RuntimeError("gh command failed (exit 1)")
        if gh_state == "old":
            return "--source-ref --deny-self-hosted-runners"
        return "--source-ref --source-digest --signer-workflow --deny-self-hosted-runners"
    if expected is None:
        with pytest.raises(RuntimeError, match="Install Git or a current GitHub CLI"):
            select_backend(runner, which)
    else:
        assert select_backend(runner, which) == {"backend": expected, "tool": "/usr/bin/" + expected}


def test_git_discovery_and_cached_identity(updater, monkeypatch):
    updater.config.update(backend="git", tool="/usr/bin/git")
    monkeypatch.setattr(updater, "git_manifest", lambda channel: release())
    candidate = Updater.check(updater)
    updater.verify("oci://" + candidate["image"], "release", candidate["sha"])
    with pytest.raises(ValueError, match="does not match"):
        updater.verify("oci://" + candidate["image"], "release", "c" * 40)
    with pytest.raises(FileNotFoundError):
        updater.verify("oci://" + candidate["image"], "preview", candidate["sha"])
    updater.state["high_water"]["release"] = 6
    with pytest.raises(ValueError, match="replay"):
        Updater.check(updater)
    assert not updater.commands


def test_git_metadata_fetch_uses_real_git(updater, tmp_path):
    import subprocess
    from updater.service import command
    source = tmp_path / "upstream"
    source.mkdir()
    def git(*args):
        return subprocess.check_output(["git", "-C", str(source), *args], text=True).strip()
    git("init", "-q")
    git("config", "user.name", "Test")
    git("config", "user.email", "test@example.invalid")
    git("commit", "--allow-empty", "-qm", "source")
    sha = git("rev-parse", "HEAD")
    (source / "manifest.json").write_text(json.dumps(release(sha=sha)))
    git("add", "manifest.json")
    git("commit", "-qm", "metadata")
    git("branch", "updates/release")
    updater.config.update(backend="git", tool="git")
    calls = []
    def run(args, timeout=300):
        calls.append(args)
        return command([str(source) if arg == "https://github.com/StealthCat/blockinator-web.git" else arg
                        for arg in args], timeout=timeout)
    updater.run = run
    candidate = Updater.check(updater)
    assert candidate["sha"] == sha
    updater.verify("oci://" + candidate["image"], "release", sha)
    assert any("https://github.com/StealthCat/blockinator-web.git" in args for args in calls)
    # A manifest with a forged source SHA must never become an approved candidate.
    (source / "manifest.json").write_text(json.dumps(release()))
    git("add", "manifest.json")
    git("commit", "--amend", "--no-edit", "-q")
    git("branch", "-f", "updates/release")
    with pytest.raises(ValueError, match="source commit"):
        Updater.check(updater)
