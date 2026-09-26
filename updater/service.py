#!/usr/bin/env python3
"""Restricted, root-owned Linux/Docker Compose update service (stdlib only)."""
from __future__ import annotations

import copy
import fcntl
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socketserver
import subprocess
import threading
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

REPOSITORY = "StealthCat/blockinator-web"
IMAGE = "ghcr.io/stealthcat/blockinator-web"
WORKFLOW = REPOSITORY + "/.github/workflows/publish-updates.yml"
CHANNELS = {"release", "preview"}
TERMINAL = {"idle", "complete", "failed", "recovered", "recovery_failed"}


def atomic_json(path, value):
    path = Path(path)
    tmp = path.with_suffix(".tmp")
    with tmp.open("w") as out:
        os.chmod(tmp, 0o600)
        json.dump(value, out)
        out.flush()
        os.fsync(out.fileno())
    os.replace(tmp, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def command(args, timeout=300):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        # Avoid leaking environment/configuration secrets through error output.
        raise RuntimeError(f"{Path(args[0]).name} command failed (exit {result.returncode})")
    return result.stdout.strip()


def select_backend(runner=command, which=shutil.which):
    """Choose once at installation; never downgrade after a verification failure."""
    gh = which("gh")
    if gh:
        try:
            help_text = runner([gh, "attestation", "verify", "--help"])
            if all(flag in help_text for flag in (
                    "--source-ref", "--source-digest", "--signer-workflow", "--deny-self-hosted-runners")):
                return {"backend": "gh", "tool": gh}
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            pass
    git = which("git")
    if git:
        try:
            runner([git, "--version"])
            return {"backend": "git", "tool": git}
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            pass
    raise RuntimeError("Install Git or a current GitHub CLI with attestation verify support, then retry the installer")


def validate_manifest(value, channel):
    if channel not in CHANNELS or value.get("channel") != channel:
        raise ValueError("Invalid release channel")
    if not re.fullmatch(r"[0-9a-f]{40}", value.get("sha", "")):
        raise ValueError("Invalid source commit")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value.get("digest", "")):
        raise ValueError("Invalid image digest")
    if not re.fullmatch(r"\d+\.\d+\.\d+", value.get("version", "")):
        raise ValueError("Invalid release version")
    for key in ("schema", "minimum_schema", "protocol", "sequence"):
        if type(value.get(key)) is not int or value[key] < 1:
            raise ValueError("Invalid release compatibility metadata")
    if value["protocol"] != 1 or value["minimum_schema"] > value["schema"]:
        raise ValueError("This release requires a newer updater")
    if type(value.get("automatic")) is not bool:
        raise ValueError("Invalid automatic-update policy")
    return {k: value[k] for k in ("channel", "sha", "digest", "version", "schema", "minimum_schema", "protocol", "sequence", "automatic")}


def compatible(current, candidate, automatic=False):
    schema = current["schema"]
    if not candidate["minimum_schema"] <= schema <= candidate["schema"]:
        raise ValueError("Database schema does not support this channel/version change")
    if automatic and (not candidate["automatic"] or candidate["schema"] != schema or
                      candidate["version"].split(".")[0] != current["version"].split(".")[0]):
        raise ValueError("This update requires manual installation")


class Updater:
    def __init__(self, config, runner=command):
        self.config = config
        self.run = runner
        self.root = Path(config["state_dir"])
        self.runtime = Path(config["runtime_dir"])
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.runtime.mkdir(parents=True, exist_ok=True, mode=0o755)
        self.state_path = self.root / "state.json"
        self.lock = threading.Lock()
        self.state_lock = threading.RLock()
        self.state = (json.loads(self.state_path.read_text()) if self.state_path.exists() else {
            "phase": "idle", "settings": {"channel": "release", "mode": "notify", "hour": 3, "timezone": "UTC"},
            "current": config["initial"], "history": [], "candidate": None, "high_water": {}, "checked_at": 0,
        })
        self.save()
        if not (self.root / "active.json").exists():
            self.override(self.state["current"]["image"])

    def save(self):
        with self.state_lock:
            atomic_json(self.state_path, self.state)

    def phase(self, phase, **values):
        with self.state_lock:
            self.state.update(values, phase=phase)
            self.save()

    def status(self):
        with self.state_lock:
            return {"backend": self.config.get("backend", "gh"), **copy.deepcopy({k: self.state.get(k) for k in (
                "phase", "settings", "current", "candidate", "previous", "history", "error", "checked_at", "postponed_until", "blocked_digest")})}

    def compose(self, *args, timeout=300):
        return self.run(["docker", "compose", "--project-name", self.config["project"],
                         "-f", self.config["deployment"], "-f", str(self.root / "active.json"), *args], timeout=timeout)

    def override(self, image):
        atomic_json(self.root / "active.json", {"services": {"blockinator": {
            "image": image, "pull_policy": "never",
            "environment": {"UPDATER_RUNTIME_DIR": "/run/blockinator-update"},
            "volumes": [{"type": "bind", "source": str(self.runtime), "target": "/run/blockinator-update", "read_only": True}],
        }}})

    def git(self, *args):
        return self.run([self.config.get("tool", "git"), "-c", "credential.interactive=false",
                         "-c", "core.askPass=/bin/false", "-c", "core.hooksPath=/dev/null",
                         "--git-dir", str(self.root / "metadata.git"), *args], timeout=120)

    def git_manifest(self, channel):
        if channel not in CHANNELS:
            raise ValueError("Invalid release channel")
        if not (self.root / "metadata.git").exists():
            self.git("init", "--bare")
        # Fetch only metadata from the fixed upstream; never execute checkout code.
        self.git("fetch", "--no-tags", "--depth=2", "https://github.com/" + REPOSITORY + ".git",
                 "+refs/heads/updates/" + channel + ":refs/heads/updates/" + channel)
        ref = "refs/heads/updates/" + channel
        size = int(self.git("cat-file", "-s", ref + ":manifest.json"))
        if size > 16384:
            raise ValueError("Release metadata is too large")
        value = validate_manifest(json.loads(self.git("show", ref + ":manifest.json")), channel)
        # CI makes the metadata commit a direct child of the built source commit.
        if self.git("rev-parse", ref + "^") != value["sha"]:
            raise ValueError("Git metadata does not match its source commit")
        return value

    def verify(self, subject, channel, sha=None):
        if channel not in CHANNELS:
            raise ValueError("Invalid release channel")
        if self.config.get("backend", "gh") == "git":
            # These records are written only after fetching/validating fixed-repo
            # metadata. Retain them so previous-image rollback survives promotion.
            records = self.root / "verified-git"
            digest = subject.removeprefix("oci://" + IMAGE + "@")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                raise ValueError("Invalid Git update image")
            value = validate_manifest(json.loads((records / (channel + "-" + digest[7:] + ".json")).read_text()), channel)
            if value["sha"] != sha or value["digest"] != digest:
                raise ValueError("Image does not match trusted Git metadata")
            return
        args = [self.config.get("tool", "gh"), "attestation", "verify", subject, "--repo", REPOSITORY,
                  "--signer-workflow", WORKFLOW, "--source-ref", "refs/heads/" + channel,
                  "--deny-self-hosted-runners"]
        if sha:
            args.extend(["--source-digest", sha])
        self.run(args, timeout=120)

    def check(self):
        channel = self.state["settings"]["channel"]
        directory = self.root / "download"
        directory.mkdir(exist_ok=True, mode=0o700)
        manifest = directory / "manifest.json"
        manifest.unlink(missing_ok=True)
        if self.config.get("backend", "gh") == "git":
            candidate = self.git_manifest(channel)
        else:
            self.run([self.config.get("tool", "gh"), "release", "download", "updates-" + channel, "--repo", REPOSITORY,
                      "--pattern", "manifest.json", "--dir", str(directory)], timeout=120)
            if manifest.stat().st_size > 16384:
                raise ValueError("Release metadata is too large")
            self.verify(str(manifest), channel)
            candidate = validate_manifest(json.loads(manifest.read_text()), channel)
        high_water = self.state["high_water"].get(channel, 0)
        if candidate["sequence"] < high_water:
            raise ValueError("Refusing replay of older channel metadata")
        if self.config.get("backend", "gh") == "git":
            records = self.root / "verified-git"
            records.mkdir(mode=0o700, exist_ok=True)
            atomic_json(records / (channel + "-" + candidate["digest"][7:] + ".json"), candidate)
        candidate["image"] = IMAGE + "@" + candidate["digest"]
        with self.state_lock:
            self.state["high_water"][channel] = candidate["sequence"]
            self.state.update(candidate=candidate, checked_at=time.time(), error=None)
            self.save()
        return candidate

    def gate(self, enabled):
        gate = self.runtime / "maintenance"
        if enabled:
            atomic_json(gate, {"maintenance": True})
            token = self.runtime / "probe-token"
            with token.open("w") as out:
                os.chmod(token, 0o600)
                out.write(secrets.token_hex(32))
                out.flush()
                os.fsync(out.fileno())
        else:
            gate.unlink(missing_ok=True)
            (self.runtime / "probe-token").unlink(missing_ok=True)

    def cleanup_task(self):
        name = self.config["project"] + "-update-task"
        def exists():
            return self.run(["docker", "ps", "-aq", "--filter", "name=^/" + re.escape(name) + "$"], timeout=30)
        if exists():
            try:
                self.run(["docker", "rm", "--force", name], timeout=30)
            except Exception:
                if exists():
                    raise

    def data(self, action, backup):
        self.cleanup_task()
        try:
            self.compose("run", "--rm", "--no-deps", "-T", "--name", self.config["project"] + "-update-task",
                         "--volume", str(backup) + ":/backup", "blockinator", "python",
                         "/srv/tools/update_data.py", action, timeout=1800)
        finally:
            # A timed-out Docker CLI does not terminate its container. Stop that
            # task before any old/new application is allowed to resume writing.
            self.cleanup_task()

    def probe(self, expected):
        deadline = time.monotonic() + 120
        while True:
            try:
                self.compose("exec", "-T", "blockinator", "python", "/srv/tools/update_probe.py",
                             "--sha", expected["sha"], timeout=30)
                return
            except Exception:
                if time.monotonic() >= deadline:
                    raise RuntimeError("New instance failed readiness/policy checks")
                time.sleep(2)

    def start(self):
        self.compose("up", "-d", "--no-deps", "--no-build", "--force-recreate", "blockinator")

    def record(self, result):
        with self.state_lock:
            self.state["history"] = (self.state["history"] + [{"time": datetime.now(timezone.utc).isoformat(),
                "result": result, "version": self.state["current"]["version"], "error": self.state.get("error")}])[-30:]
            self.save()

    def recover(self):
        job = self.state.get("job")
        if not job:
            return
        self.phase("recovering")
        self.gate(True)
        try:
            self.cleanup_task()
            self.compose("stop", "-t", "30", "blockinator")
            old = job["old"]
            self.override(old["image"])
            if job.get("candidate_started"):
                # Recovery is repeatable: never start the old application until
                # the complete pre-upgrade database and TLS state are restored.
                self.data("restore", Path(job["backup"]))
            self.start()
            self.probe(old)
            self.phase("recovered", current=old, job=None)
            self.gate(False)
            self.record("recovered")
        except Exception as exc:
            self.phase("recovery_failed", error="Recovery failed: " + str(exc))
            self.record("recovery_failed")
            # Keep traffic gated; the next restart/recover action retries safely.

    def install(self, candidate, automatic=False):
        current = copy.deepcopy(self.state["current"])
        compatible(current, candidate, automatic)
        if candidate["image"] == current["image"]:
            raise ValueError("This image is already installed")
        self.phase("verifying", error=None)
        if not candidate.get("trusted_local"):
            self.verify("oci://" + candidate["image"], candidate["channel"], candidate["sha"])
            self.run(["docker", "pull", candidate["image"]], timeout=900)
        labels = json.loads(self.run(["docker", "image", "inspect", candidate["image"], "--format", "{{json .Config.Labels}}"]))
        if (labels.get("org.opencontainers.image.revision") != candidate["sha"]
                or labels.get("io.blockinator.schema") != str(candidate["schema"])
                or labels.get("org.opencontainers.image.version") != candidate["version"]
                or labels.get("io.blockinator.updater-protocol") != "1"):
            raise ValueError("Image does not match verified release metadata")
        if shutil.disk_usage(self.root).free < self.config.get("minimum_free_bytes", 1024 ** 3):
            raise ValueError("Insufficient backup disk space")
        backup = self.root / "backups" / secrets.token_hex(12)
        backup.mkdir(parents=True, mode=0o700)
        shutil.copyfile(self.config["deployment"], backup / "deployment.json")
        self.phase("backing_up", job={"old": current, "target": candidate, "backup": str(backup), "candidate_started": False})
        self.gate(True)
        try:
            self.compose("stop", "-t", "30", "blockinator")
            self.data("backup", backup)
            if not (backup / "complete.json").is_file():
                raise RuntimeError("Backup completion marker is missing")
            # fsync backup files and directories before recording that migration
            # may start. This journal survives helper/host restarts.
            for path in backup.rglob("*"):
                if path.is_file():
                    with path.open("rb") as inp:
                        os.fsync(inp.fileno())
            for directory in [p for p in backup.rglob("*") if p.is_dir()] + [backup, backup.parent]:
                fd = os.open(directory, os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            self.state["job"]["candidate_started"] = True
            self.phase("installing")
            self.override(candidate["image"])
            self.start()
            self.phase("validating")
            self.probe(candidate)
            if not automatic and self.state.get("blocked_digest") == candidate["digest"]:
                self.state.pop("blocked_digest", None)
            self.phase("complete", previous=current, current=candidate, job=None)
            self.gate(False)
            self.record("installed")
            self.prune_backups()
        except Exception as exc:
            self.state["error"] = str(exc)
            self.save()
            self.recover()

    def prune_backups(self):
        backups = sorted((self.root / "backups").iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
        for directory in backups[3:]:
            shutil.rmtree(directory)

    def configure(self, values):
        channel, mode = values.get("channel"), values.get("mode")
        hour = int(values.get("hour", 3))
        tz = values.get("timezone", "UTC")
        if channel not in CHANNELS or mode not in {"notify", "automatic"} or not 0 <= hour <= 23:
            raise ValueError("Invalid update settings")
        ZoneInfo(tz)
        with self.state_lock:
            if channel != self.state["settings"]["channel"]:
                self.state["candidate"] = None
                self.state["checked_at"] = 0
            self.state["settings"] = {"channel": channel, "mode": mode, "hour": hour, "timezone": tz}
            self.save()

    def request(self, action, values):
        if action == "status":
            return self.status()
        if action not in {"configure", "postpone", "check", "install", "rollback", "recover"}:
            raise ValueError("Unknown updater action")
        if not self.lock.acquire(blocking=False):
            raise ValueError("An update operation is already running")
        try:
            if self.state.get("job") and action != "recover":
                raise ValueError("Recovery is required before another operation")
            if action == "configure":
                self.configure(values)
            elif action == "postpone":
                self.state["postponed_until"] = time.time() + 86400
                self.save()
            else:
                candidate = copy.deepcopy(self.state.get("previous" if action == "rollback" else "candidate"))
                if action in {"install", "rollback"}:
                    if not candidate or candidate.get("digest") != values.get("digest"):
                        raise ValueError("Check for updates and review the exact candidate before installing")
                    if action == "rollback" and candidate["schema"] != self.state["current"]["schema"]:
                        raise ValueError("Rollback would require restoring older data; use offline recovery")
                if action == "rollback":
                    self.state["blocked_digest"] = self.state["current"]["digest"]
                self.phase("queued")
                thread = threading.Thread(target=self.work, args=(action, candidate), daemon=True)
                thread.start()
                return {"accepted": True}
        except BaseException:
            self.lock.release()
            raise
        self.lock.release()
        return self.status()

    def work(self, action, candidate=None, automatic=False):
        try:
            if action == "check":
                self.check()
                self.phase("idle")
            elif action == "recover":
                self.recover()
                if not self.state.get("job"):
                    self.phase("recovered")
            else:
                self.install(candidate, automatic)
        except Exception as exc:
            if action == "check":
                self.state["candidate"] = None
            self.phase("failed", error=str(exc))
            self.record("failed")
        finally:
            self.lock.release()

    def tick(self, now=None):
        now = now or datetime.now(timezone.utc)
        if self.state.get("job") or not self.lock.acquire(blocking=False):
            return
        try:
            if now.timestamp() - self.state.get("checked_at", 0) >= 86400:
                try:
                    self.check()
                except Exception as exc:
                    self.state.update(error=str(exc), checked_at=now.timestamp(), candidate=None)
                    self.save()
                    return
            settings = self.state["settings"]
            local = now.astimezone(ZoneInfo(settings["timezone"]))
            candidate = self.state.get("candidate")
            attempt = f'{local.date()}:{candidate["digest"]}' if candidate else ""
            if (settings["mode"] == "automatic" and local.hour == settings["hour"] and candidate
                    and now.timestamp() >= self.state.get("postponed_until", 0)
                    and candidate["image"] != self.state["current"]["image"]
                    and candidate["digest"] != self.state.get("blocked_digest")
                    and self.state.get("last_attempt") != attempt):
                self.state["last_attempt"] = attempt
                self.save()
                try:
                    self.install(copy.deepcopy(candidate), automatic=True)
                except Exception as exc:
                    self.phase("failed", error=str(exc))
                    self.record("failed")
        finally:
            self.lock.release()


def serve(config):
    root = Path(config["state_dir"])
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    lock_file = (root / "service.lock").open("w")
    fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    updater = Updater(config)
    if updater.state.get("job"):
        updater.recover()
    elif updater.state["phase"] not in TERMINAL:
        updater.phase("failed", error="Interrupted before installation; check and retry")
    if not updater.state.get("job"):
        updater.gate(False)

    class Handler(http.server.BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(5)
            super().setup()
        def log_message(self, *args):
            pass
        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 8192:
                    raise ValueError("Invalid request size")
                values = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(values, dict):
                    raise ValueError("Expected an object")
                result, status = updater.request(self.path.lstrip("/"), values), 200
            except Exception as exc:
                result, status = {"error": str(exc)}, 400
            body = json.dumps(result).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    socket_path = updater.runtime / "updater.sock"
    socket_path.unlink(missing_ok=True)
    server = socketserver.UnixStreamServer(str(socket_path), Handler)
    socket_path.chmod(0o600)
    def schedule():
        while True:
            try:
                updater.tick()
            except Exception:
                pass
            time.sleep(60)
    threading.Thread(target=schedule, daemon=True).start()
    server.serve_forever()


if __name__ == "__main__":
    os.umask(0o077)
    config_path = Path("/etc/blockinator-update/config.json")
    if os.geteuid() != 0 or config_path.stat().st_uid != 0 or config_path.stat().st_mode & 0o022:
        raise SystemExit("Updater configuration must be root-owned and not writable by other users")
    serve(json.loads(config_path.read_text()))
