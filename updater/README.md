# Blockinator application updates

The optional updater supports Linux hosts running Docker Engine, Docker Compose v2,
Python 3.11+ (with system IANA timezone data), and systemd. The application never
receives the Docker socket. A root-owned host service exposes a small Unix-socket
API for checking, scheduling, installing and recovering **this deployment only**.
Docker Desktop and non-systemd installations require a separately managed host
service; the supplied installer targets Linux/systemd and the standard root-user
Blockinator container. Custom container UID mappings require an explicitly reviewed
socket/maintenance-file permission configuration.

## Channels and publishing

- `main`: development; no published update channel.
- `preview`: opt-in builds after the entire SQLite/MySQL/Compose test workflow passes.
- `release`: approved stable builds after the same validation.
- `fixes`: this implementation; pushing here tests code but does not publish an update.

Promote reviewed commits to `preview`, then to `release`. Protect both branches,
require reviews/checks, and prohibit force pushes. The implementation does not
create these branches or change repository protection settings.

`.github/workflows/publish-updates.yml` builds `linux/amd64` and `linux/arm64` images
under `ghcr.io/stealthcat/blockinator-web`. GitHub provenance attestations cover both
the image digest and channel manifest. Discovery metadata is published as
`manifest.json` on the `updates-preview` / `updates-release` GitHub releases only
after image publication and attestations succeed. The same manifest is then published
on `updates/release` or `updates/preview` for Git-only hosts. Those releases are marked as
channel metadata, not conventional numbered stable releases. Images use commit
identifiers; installation always uses the immutable digest from the reviewed manifest.

Update `app/version.py`, `updater/release.json` and the matching Docker build-argument
defaults together when making a release. Increase `SCHEMA_VERSION` when a schema
change breaks compatibility with the prior application. Set `minimum_schema` to
the oldest schema that startup migrations actually support. Set `automatic: false`
for changes requiring operator attention. The schema compatibility declaration is
a release contract and must be backed by upgrade tests; it is not inferred from SQL.
Never change a released migration retroactively.

## One-time installation on the Docker host

1. Deploy this updater-enabled code normally first:

   ```bash
   docker compose up -d --build
   ```

2. Have either Git or a current GitHub CLI (`gh`) available to root. The installer
   prefers `gh` only when `attestation verify --help` succeeds and supports all four
   identity restrictions (`--source-ref`, `--source-digest`, `--signer-workflow`,
   `--deny-self-hosted-runners`). Missing/older/broken `gh` falls back to Git.
   If neither works, installation exits with an actionable message before changing
   the deployment. The chosen absolute executable path and backend are saved in
   root-only configuration; verification failures never trigger a backend downgrade.

   **Trust model:** `gh` verifies GitHub provenance for the manifest and image.
   Git mode trusts metadata fetched over HTTPS from this fixed repository's
   `updates/release` or `updates/preview` branch; it does **not** verify Sigstore
   attestations. CI publishes those refs only after tests, image publication and
   attestations succeed. Protect these metadata branches against writes except by
   the publishing workflow (which must be allowed to replace their tips). Each
   metadata commit is a direct child of the source commit named in the manifest.
   Both modes enforce manifest validation, replay protection, exact image digests,
   image labels, schema compatibility and post-install probes. Git mode caches
   accepted metadata in root-only storage to allow previous-image rollback.

   For `gh`, authenticate as root with `sudo gh auth login`, or supply `GH_TOKEN`
   through `/etc/blockinator-update/github.env` (root-only, loaded by systemd).
   Git mode works anonymously for public repositories; private repositories need
   a noninteractive HTTPS credential helper configured for root. `GH_TOKEN` alone
   does not configure Git authentication. Never put credentials in remote URLs.
   The GHCR package must be public or root's Docker registry login must have
   `read:packages` access. Never put credentials in the application container or
   committed configuration files.

3. From the checked-out repository, run:

   ```bash
   sudo python3 updater/install.py --compose-file docker-compose.yml
   ```

   This snapshots the resolved Compose configuration (including environment
   credentials) into `/etc/blockinator-update/deployment.json` with mode `0600`.
   It recreates only Blockinator once to mount the update-control directory;
   Caddy and its published ports remain managed by the existing Compose project.
   Expect a brief policy outage during activation. The initial locally built image
   is pinned by image ID and retained as an eligible rollback target.

4. Open **System Settings → Updates**, choose `Release` or `Preview`, and select
   **Check now**. Until a channel branch publishes its first build, checking will
   report that channel metadata is unavailable. This never interrupts policy service.

Automatic installation is disabled by default. To enable it, select **Automatic
compatible updates** and an IANA timezone/hour. The service checks daily, installs
only inside that one-hour local window, and attempts each build at most once per
local calendar date (including repeated daylight-saving hours). **Postpone 24 hours**
defers scheduled installation. Manual installation uses the exact digest displayed
when the administrator submits the form.

## What the updater manages

- Only the Blockinator service image, preserving captured volumes, networks and
  environment. Caddy and the host updater are not automatically upgraded.
- A bounded recent history and the three most recent backup directories.
- SQLite backups via the SQLite backup API and integrity checking; TLS files are
  included and checksummed.
- MySQL full table definitions/data and views from the configured dedicated
  Blockinator database. All Blockinator writers must be stopped, and **no external
  writer may share that database** during the operation. Backup/restore requires
  the application's DDL privileges plus view-definition visibility. Custom
  triggers/routines are rejected instead of silently producing an incomplete backup.

Backups are stored under `/var/lib/blockinator-update/backups` with root-only access.
Keep independent off-host backups: local update backups are not disaster recovery.
The host's free-space check is a minimum reserve; a backup that runs out of space
aborts the update and restarts the original image.

The host-owned maintenance flag and journal survive reboots. During installation,
policy requests receive HTTP 503; existing UI pages retry their status requests.
Before enabling unattended updates, verify the resolver plugin's behavior when
Blockinator is unavailable. There is no zero-downtime guarantee.

## Validation and rollback

After backing up, the helper starts the candidate behind the maintenance gate.
It checks readiness, the actual application's database and administrator/API-key
records, expected commit identity, policy authentication rejection, and isolated
known allow/block decisions. Only a passing candidate receives normal traffic.

On failure, the candidate is stopped, the old image is selected, and the complete
pre-upgrade database and TLS backup are restored before the old instance is probed.
A failed recovery leaves maintenance enabled; the helper will not silently resume
service against an uncertain database. Interrupted operations use the same recovery
path after the helper restarts. Backup/restore jobs have a 30-minute timeout; size
large installations accordingly and perform upgrades offline if they exceed it.

**Roll back previous image** after a successful update preserves current data and
is permitted only when schema versions match. It creates another fresh backup and
validates the rollback candidate. The rolled-back digest is then excluded from
automatic installation; a different build or an explicit manual reinstall is required. Returning from Preview to Release can therefore
be refused if the stable image cannot read the current schema. Restoring an older
backup after normal service has resumed can lose newer data and is a separate,
explicit offline administrator procedure.

## Host administration and recovery

Inspect service state and logs:

```bash
sudo systemctl status blockinator-update
sudo journalctl -u blockinator-update
sudo cat /var/lib/blockinator-update/state.json
```

After correcting disk/database/registry access problems, restart the helper to
retry an interrupted recovery:

```bash
sudo systemctl restart blockinator-update
```

Do not delete the maintenance flag or journal while a job is unresolved. If initial
activation fails before systemd is enabled, correct the startup problem and verify
the existing deployment manually before enabling the service; the maintenance gate
and activation journal are deliberately retained. After correcting the problem,
run `sudo systemctl daemon-reload` and
`sudo systemctl enable --now blockinator-update.service` to resume recovery. An unavailable application may require host recovery
because its web UI cannot serve a recovery button.

The frozen deployment configuration is authoritative for updates. To change mounts,
ports or environment later, stop the helper and update the root-owned deployment
snapshot deliberately; do not run the original development Compose file afterward
without retaining the updater's active override. Inspect the rendered configuration
before recreating services. The active image/mount override lives at
`/var/lib/blockinator-update/active.json`.

To update the host helper itself, wait for an idle/completed state, stop its systemd
unit, install a reviewed `service.py` into `/usr/local/lib/blockinator-update/`, then
restart the unit. Existing configurations retain the `gh` backend by default. To
switch an existing idle installation to Git, explicitly set `"backend": "git"` and
`"tool"` to the absolute Git executable path in root-only `config.json`, restart,
and run **Check now** to populate trusted Git metadata before installing. The Git
trust model above applies. Preserve the journal, deployment snapshot and backups. Protocol
changes require a documented host-helper upgrade before publishing dependent images.

## Verification

Unit tests exercise invalid/replayed manifests, exact-digest approval, failed
backups, schema incompatibility, failed probes, failed restoration, interrupted
installation, maintenance gating, CSRF/session checks, scheduling and SQLite
restoration. The MySQL CI job exercises same-backend schema/data recovery. Docker
CI probes the actual built container behind its maintenance gate and round-trips
an offline backup. Publishing validates the full test workflow before releasing
channel metadata.
