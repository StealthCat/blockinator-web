#!/usr/bin/env python3
"""Install the optional updater on a Linux systemd Docker host. Requires root."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

if __package__:
    from .service import atomic_json, command, select_backend, Updater
else:
    from service import atomic_json, command, select_backend, Updater


def install(compose_file):
    if os.geteuid() != 0:
        raise SystemExit("Run this installer with sudo on the Docker host")
    config_dir = Path("/etc/blockinator-update")
    if (config_dir / "config.json").exists():
        raise SystemExit("Updater is already installed; follow the documented host-service upgrade procedure")
    command(["docker", "compose", "version"])
    try:
        backend = select_backend()
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from None
    print("Update backend: " + backend["backend"] +
          (" (trusted GitHub repository metadata; no attestation verification)"
           if backend["backend"] == "git" else " (GitHub provenance verification)"))
    compose_file = str(Path(compose_file).resolve())
    config = json.loads(command(["docker", "compose", "-f", compose_file, "config", "--format", "json"]))
    cid = command(["docker", "compose", "-f", compose_file, "ps", "-q", "blockinator"])
    if not cid or "\n" in cid:
        raise SystemExit("Exactly one running Blockinator instance is required")
    container = json.loads(command(["docker", "inspect", cid]))[0]
    if container["Config"].get("User") not in {None, "", "0", "root", "0:0", "root:root"}:
        raise SystemExit("This installer supports the standard root-user Blockinator image; custom UID mappings require a reviewed socket-permission configuration")
    image_id = container["Image"]
    labels = json.loads(command(["docker", "image", "inspect", image_id]))[0]["Config"].get("Labels") or {}
    if labels.get("io.blockinator.updater-protocol") != "1":
        raise SystemExit("Rebuild/recreate Blockinator from an updater-enabled version first")
    initial = {"image": image_id, "digest": image_id, "sha": labels["org.opencontainers.image.revision"],
               "version": labels["org.opencontainers.image.version"], "schema": int(labels["io.blockinator.schema"]),
               "minimum_schema": int(labels["io.blockinator.schema"]), "channel": "development", "trusted_local": True}
    # Freeze resolved deployment settings, including credentials, in a root-only
    # file. The web container can never supply Compose paths or command arguments.
    config_dir.mkdir(mode=0o700, exist_ok=True)
    for service in config["services"].values():
        service.pop("build", None)
    config["services"]["blockinator"]["image"] = image_id
    atomic_json(config_dir / "deployment.json", config)
    settings = {"deployment": str(config_dir / "deployment.json"), "project": config["name"],
                "state_dir": "/var/lib/blockinator-update", "runtime_dir": "/var/lib/blockinator-update-runtime",
                "initial": initial, "minimum_free_bytes": 1073741824, **backend}
    atomic_json(config_dir / "config.json", settings)
    binary = Path("/usr/local/lib/blockinator-update")
    binary.mkdir(parents=True, mode=0o755, exist_ok=True)
    shutil.copyfile(Path(__file__).with_name("service.py"), binary / "service.py")
    shutil.copyfile(Path(__file__).with_name("blockinator-update.service"), "/etc/systemd/system/blockinator-update.service")
    updater = Updater(settings)
    updater.phase("activating", job={"old": initial, "target": initial, "backup": "", "candidate_started": False})
    updater.gate(True)
    try:
        updater.start()  # One-time recreation mounts the restricted local socket.
        updater.probe(initial)
        updater.phase("complete", job=None)
        updater.gate(False)
    except Exception:
        raise SystemExit("Activation failed; maintenance remains enabled. See updater recovery documentation.")
    command(["systemctl", "daemon-reload"])
    command(["systemctl", "enable", "--now", "blockinator-update.service"])
    print("Updater installed. Open System Settings → Updates. Automatic installation is disabled by default.")


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-file", default="docker-compose.yml")
    install(parser.parse_args().compose_file)
