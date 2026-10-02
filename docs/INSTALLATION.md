# Alternative installations

[Back to README](../README.md) · [Recommended source installation](../README.md#quick-start-git-clone-and-docker-compose-recommended)

For the recommended stable `main` setup, follow the README. This guide covers [Docker Hub](#docker-hub-with-docker-compose-and-caddy), [fixed release tags](#fixed-version-installation-optional), and [moving an existing tag checkout to main](#moving-an-existing-tag-checkout-to-main).

Published image: **`stealthcat128/blockinator`**. Release `1.20.1` and `latest`
support **Linux AMD64 and ARM64**. The examples pin `1.20.1` for predictable
upgrades. Pulling `latest` does not update an already-running container.

Use this alternative if you prefer a prebuilt image instead of building from the
Git checkout. Within this alternative, Compose with Caddy provides the full
HTTPS/certificate-management features; standalone Docker serves HTTP only.
Both require credentials before the first startup; there is no default password. For MySQL, complete [MySQL setup](OPERATIONS.md#mysql) before starting either deployment.

## Docker Hub with Docker Compose and Caddy

Requirements: Docker Engine, Docker Compose v2, Git, Bash, and OpenSSL. Run the
commands on the Docker host. Use `sudo` for Docker if your account requires it.

### 1. Get the matching deployment configuration

```bash
git clone --branch v1.20.1 --single-branch https://github.com/StealthCat/blockinator-web.git
cd blockinator-web
```

The recommended source build tracks stable `main` as described in the README.
This prebuilt-image alternative pins the Compose and Caddy configuration to the `v1.20.1` release
tag. A detached HEAD is expected. The application will be pulled from the matching
`1.20.1` Docker image; no local image build is needed.

### 2. Create first-run credentials

Create `.env` using [Create first-run credentials](../README.md#2-create-first-run-credentials)
in the primary installation instructions. Use the same password/API-key requirements
and optional database settings. Preserve an existing `.env` when changing methods.

### 3. Select the Docker Hub image

Create an override alongside `docker-compose.yml`:

```bash
cat > docker-compose.hub.yml <<'EOF'
services:
  blockinator:
    image: stealthcat128/blockinator:1.20.1
EOF
```

Pull and start both services:

```bash
docker compose -f docker-compose.yml -f docker-compose.hub.yml pull
docker compose -f docker-compose.yml -f docker-compose.hub.yml up -d --no-build
```

Always include both `-f` arguments when managing this deployment. `--no-build`
prevents the base Compose file's development build configuration from being used.
Caddy is pulled separately; it is not bundled into the Blockinator image.

### 4. Open and configure Blockinator

Open **`http://DOCKER-HOST:8080/`**. Login, Technitium integration, HTTPS configuration,
and the `./data` persistence layout are the same as [Open and configure Blockinator](../README.md#4-open-and-configure-blockinator)
in the primary setup. For this Docker Hub deployment, use both Compose files when
checking status or logs:

```bash
docker compose -f docker-compose.yml -f docker-compose.hub.yml ps
docker compose -f docker-compose.yml -f docker-compose.hub.yml logs --tail=100 blockinator caddy
```

## Standalone Docker: HTTP only

For a minimal setup without Caddy, create a working directory and create `.env`
using the [first-run credential block](../README.md#2-create-first-run-credentials). No repository checkout is required.

```bash
mkdir -p ~/blockinator
cd ~/blockinator
# Create .env here using the README first-run credential block before continuing.
```

Start the application with a persistent named volume and published HTTP port:

```bash
docker run -d \
  --name blockinator \
  --restart unless-stopped \
  --env-file ./.env \
  -e FORWARDED_ALLOW_IPS=127.0.0.1 \
  -p 8080:8080 \
  -v blockinator-data:/data \
  stealthcat128/blockinator:1.20.1
```

Open **`http://DOCKER-HOST:8080/`**. The administrator login and plugin API key are
the same as described above. `-p 8080:8080` publishes the port on the host;
`-v blockinator-data:/data` preserves SQLite data when the container is replaced.
`POLICY_PORT` and `HTTPS_PORT` in `.env` are Compose settings and do not change
this command's port mapping. For a different host port, change the left-hand port
in `-p`, for example `-p 8180:8080`.

This example trusts proxy headers only from loopback. If you put the application
behind your own reverse proxy, configure `FORWARDED_ALLOW_IPS` for that trusted
proxy. Built-in certificate/ACME controls require the managed Caddy setup above.

```bash
docker logs --tail=100 blockinator
docker inspect --format '{{.State.Health.Status}}' blockinator
```

## Updating an existing Docker Hub deployment

Back up your data before upgrading; see [Data and backups](OPERATIONS.md#data-and-backups).
For Compose, stop the stack for a consistent SQLite backup, preserve `./data` and
`.env`, check out the matching release tag, and set the image tag in
`docker-compose.hub.yml` to the same version without the `v` prefix. For the current
release, use `v1.20.1` for Git and `1.20.1` for Docker:

```bash
docker compose -f docker-compose.yml -f docker-compose.hub.yml stop
# Back up ./data and .env now; back up remote MySQL separately if used.
git fetch origin tag v1.20.1
git checkout --detach v1.20.1
# Set image: stealthcat128/blockinator:1.20.1 in docker-compose.hub.yml.
docker compose -f docker-compose.yml -f docker-compose.hub.yml pull
docker compose -f docker-compose.yml -f docker-compose.hub.yml up -d --no-build
```

For future upgrades, replace both Git tag references and the Docker image version
together. Preserve local configuration edits before switching tags; do not force
the checkout. Review each release's deployment/configuration changes when upgrading.
An existing source-built Compose installation can use the same override while retaining its
original project directory, `.env`, and `./data`.

For standalone Docker, stop the container, back up the `blockinator-data` volume
(and remote MySQL if used), remove only the stopped container, and repeat the
`docker run` command with the new image tag and the **same named volume**:

```bash
docker stop blockinator
# Back up persistent data before continuing.
docker rm blockinator
# Pull the desired version, then repeat docker run with that version and volume.
```

Do not delete the data volume or data directory to upgrade or resolve a login issue.
Removing the container alone preserves the named volume. Neither installation
method automatically updates a running deployment.

## Startup troubleshooting

| Symptom | Resolution |
| --- | --- |
| `Set a unique ADMIN_PASSWORD ... before first startup` | Supply `.env` via `--env-file` (standalone) or Compose; use a non-example password of at least 12 characters. A bare `docker run stealthcat128/blockinator` does not supply credentials. |
| `Set a unique POLICY_API_KEY ... before first startup` | Set a non-example API key of at least 24 characters. Both bootstrap values are required for a fresh database. |
| Container runs but the console is unreachable | Publish the port with `-p 8080:8080` for standalone Docker; check host firewall rules and container logs. |
| Port already allocated / container name already in use | An existing deployment may already occupy that port/name. Choose another host port/name or deliberately replace the old deployment; do not run both examples unchanged on the same host. |
| New environment password does not change the login | Credentials are already stored in the database. Manage them through **Access & Security**; preserve the database. |
| HTTPS/ACME does not work with the standalone image | Deploy the Caddy Compose stack or manage TLS with your own external reverse proxy. |

## Moving an existing tag checkout to main

If you used the earlier tag-based instructions, back up first and run these commands
from the existing checkout before using the [README update procedure](../README.md#updating). This also adds
`main` to the fetch configuration of a `--single-branch` tag clone:

```bash
git remote set-branches --add origin main
git fetch origin
git switch main
git pull --ff-only
```

## Fixed-version installation (optional)

To build the exact published release instead of tracking stable updates:

```bash
git clone --branch v1.20.1 --single-branch https://github.com/StealthCat/blockinator-web.git
cd blockinator-web
```

Continue with [first-run credentials](../README.md#2-create-first-run-credentials) and the
remaining README setup steps. A detached HEAD is normal when checking out a tag.
For a later release, stop and back up the deployment, replace `v1.20.1` in both
commands below with the desired published tag, then rebuild:

```bash
git fetch origin tag v1.20.1
git checkout --detach v1.20.1
docker compose up -d --build
```

Tag-based installations use explicit tag changes instead of `git pull`.
