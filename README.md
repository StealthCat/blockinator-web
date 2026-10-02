<p align="center">
  <img src="app/static/blockinator-mark.svg" alt="Blockinator" width="112" height="112">
</p>

# Blockinator

Current source version: **1.20.1**. See [CHANGELOG.md](CHANGELOG.md) for version history. Source versions and published Docker tags are tracked separately; the pinned Docker examples below remain on the published 1.19.2 image.

**Blockinator** is a self-hosted DNS policy engine and management console designed to sit beside DNS servers such as Technitium DNS Server.

It accepts authenticated DNS query metadata, applies configurable pre-policy record-type bypasses, resolves the applicable client policy, evaluates whitelists and block lists, and returns an allow/block decision. The web console provides policy targeting, list management, schedules, live statistics, query history, authentication, SQLite/MySQL-backed persistence, and managed HTTPS.

The primary installation method is to **clone this repository and run Docker Compose**, which builds Blockinator locally and starts Caddy for managed HTTPS. A prebuilt [Docker Hub image](https://hub.docker.com/r/stealthcat128/blockinator) is available as an alternative. It supports either:

- **SQLite** — local, zero-configuration persistence and the default backend.
- **MySQL 8.x** — remote persistence with connection pooling and optional TLS.

> The companion Technitium integration is maintained separately in the `blockinator-technitium` repository.

## Changes in 1.20.0

- **Policy Tester:** preview a domain, client IP, record type, and optional local time using the active policy and learned PTR hostname. The result explains matching targets, schedules, candidate lists, and the winning rule. It does not perform DNS lookups or record test queries.
- **Policy Targets:** search by name/address/hostname, filter by type, browse 25 targets per page, and open a dedicated editor. Cards show effective state and the next schedule transition. Overlapping rules can still override a target; use Policy Tester for the final decision.
- **Query Log:** choose Contains, Starts with, or Exact text matching. Next/Previous use ID cursors; explicit page-number bookmarks and Last remain supported. Filtered counts are cached for up to five seconds and filter choices for 30 seconds. Retention may remove rows while browsing a snapshot.
- **Domain shortcuts:** expand a query's Details to open the logged target/list or add the domain to a selected manual block list or whitelist. Renamed/deleted resources and expired log rows produce an explanatory message.
- **Form recovery:** with JavaScript enabled, validation and save failures keep entered text, assignments, and selected files in the current form. Values are not copied into browser storage. Network errors preserve inputs, but the write may already have completed; check the saved state before retrying.
- **Operational health:** dashboard warnings surface logger drops, uncertain commits, overdue/failed list refreshes, and stopped background workers. A pending policy rebuild is visible throughout the console and automatically retries until the committed configuration becomes active.
- **Isolation:** console reads use a separate bounded four-thread pool (12 admitted requests); overload returns HTTP 503 with Retry-After, preserving policy-worker capacity.
- **Schedules and imports:** schedules accept local HH:MM times, using the selected IANA zone. Seconds and UTC offsets are rejected; malformed persisted schedules are inactive and shown as invalid. Multipart pasted content uses MAX_BLOCKLIST_BYTES (100 MiB by default), with up to 4,096 form fields and four files. File upload and total-request limits still apply.
- **Retained statistics:** transactional minute rollups and total counters replace repeated raw-log scans. Counters describe retained queries and decrease when logs are pruned. Existing installs receive a one-time backfill on startup; allow extra startup time for large databases. SQLite uses triggers; MySQL maintains counters in application write transactions using ordinary database permissions, without SUPER or trigger creation. Offline migration rebuilds derived counters after copying and verifying the source tables. Direct external MySQL history edits require an offline counter rebuild with `app.rollups.rebuild_rollups`.
- **Maintenance:** age retention runs without incoming traffic, deleting at most 1,000 age-expired and 1,000 excess-count rows per transaction. Large reductions are applied progressively. PTR history backfill uses durable ID checkpoints and bounded per-client jobs instead of repeatedly scanning all retained queries.
- **HTTPS:** Docker Compose passes HTTPS_PORT to the application so redirects and displayed URLs match the published port.

The application still runs as one process with an in-memory policy snapshot; do not add Uvicorn workers or replicas without cross-process policy coordination. This source release does not change the pinned published Docker image examples.

## Management interface

The console includes dark and light themes, scalable SVG branding and icons, and responsive navigation. Select **Use system theme**, **Dark**, or **Light** under **System Settings → Appearance**. New installations default to Use system theme, which follows each device’s preference and updates automatically when it changes. Existing saved Dark/Light choices are preserved.

- **Query Log:** filter by domain, client, DNS server, policy target, list, decision, or date/time range. Page through matching history and choose 25–500 results per page. Expand **Details** in a row for the full timestamp, DNS server, client IP, record type, policy API scheme, matched policy target, DNS transport, and client port.
- **Table density:** choose Comfortable or Compact on Query Log. This browser-local preference also applies to other tables.
- **Auto refresh:** applies when you submit the filter form; updates the table without reloading the page. Updates pause while you inspect an expanded record, focus a control, edit filters, or hide the tab. Submit edited filters to resume; refresh failures leave the previous results visible.
- **Mobile navigation:** use Menu to open navigation; Escape closes it and returns focus. Navigation remains available when JavaScript is disabled.
- **Statistics:** vector charts resize their labels and ticks to the available width.

## What it does

- Policy targeting by IPv4/IPv6 network, exact client IP, exact PTR hostname, or wildcard PTR hostname.
- Dual-stack network targets with shared schedules and list assignments.
- Independent **block lists and whitelists** with whitelist precedence.
- URL, file, pasted-rule, and manual list sources.
- Hosts-file, domain-list, and common DNS-oriented Adblock parsing.
- Per-list and per-target recurring schedules with IANA timezones.
- Configurable behavior for clients that do not match a policy target.
- Configurable DNS record-type bypasses that skip policy evaluation, PTR work, and logging.
- Asynchronous query logging and durable background reverse-DNS identity learning.
- Distinct **Allowed**, **Blocked**, and **Whitelisted** decisions in the Dashboard and Query Log.
- Query-log filtering by domain, client, server, policy target, list, and decision.
- End-to-end policy response-time logging for evaluated requests.
- Live Statistics charts for queries, blocks, and average response time.
- Dark and light application themes.
- SQLite or remote MySQL persistence, with an offline verified migration utility.
- Managed HTTPS through Caddy with uploaded certificates or ACME.
- API-key authentication for resolvers and database-backed administrator sessions.
- Lock-free policy reads through immutable in-memory snapshots.

## Quick start: Git clone and Docker Compose (recommended)

This is the primary installation method. It builds the application from the
checked-out source and starts it alongside Caddy. Requirements: Docker Engine,
Docker Compose v2, Git, Bash, and OpenSSL. Run these commands on the Docker host;
use `sudo` for Docker if your account requires it.

### 1. Clone the repository

```bash
git clone https://github.com/StealthCat/blockinator-web.git
cd blockinator-web
```

### 2. Create first-run credentials

For a **new installation**, run this Bash block to create a private `.env` file
with randomly generated credentials. It refuses to overwrite an existing file.

```bash
(
  set -eu
  umask 077
  set -o noclobber
  admin_password=$(openssl rand -hex 24)
  policy_api_key=$(openssl rand -hex 32)
  cat > .env <<EOF
ADMIN_USERNAME=admin
ADMIN_PASSWORD=$admin_password
POLICY_API_KEY=$policy_api_key
DATABASE_BACKEND=sqlite
TZ=UTC
POLICY_PORT=8080
HTTPS_PORT=8443
EOF
)
```

If `.env` already exists, keep it and edit the required values instead. Optional
settings are listed in `.env.example`. Set `TZ` to your IANA timezone, such as
`America/New_York`. The admin password must be at least **12 characters**, and
the policy API key at least **24 characters**; known example credentials are rejected.

View the generated credentials locally when needed:

```bash
cat .env
```

Keep this file private. Once the database is initialized, change credentials in
**Access & Security**. Changing `.env` does not reset existing database credentials.

### 3. Build and start Blockinator

```bash
docker compose up -d --build
```

Compose builds Blockinator locally and pulls the Caddy image. No Docker Hub
override file is needed. SQLite is the default; for MySQL, configure `.env` using
[Using MySQL instead of SQLite](#using-mysql-instead-of-sqlite) before starting.

### 4. Open and configure Blockinator

Open **`http://DOCKER-HOST:8080/`** and sign in as `admin` using the password in
`.env`. Create your networks/endpoints, add block lists or whitelists, and configure
the companion Technitium plugin with:

- **Endpoint:** `http://DOCKER-HOST:8080/api/v1/decision`
- **API key:** the `POLICY_API_KEY` value from `.env`, or a key created in **Access & Security**.

For HTTPS, open **System Settings → HTTPS & TLS**, then configure an uploaded
certificate or ACME. See [HTTPS and TLS](#https-and-tls) for hostname, port, and
certificate settings. The default HTTPS port is `8443`; setting `HTTPS_PORT=443`
and `POLICY_PORT=80` in `.env` uses standard host ports after recreating the stack.
ACME validation must be reachable at the ports required by your chosen CA.

SQLite data is persisted at `./data/policy.db`; TLS files and Caddy state are also
under `./data`. Preserve that directory and `.env` when recreating containers.
The Caddy admin API and application port stay inside the Compose network.

Check status and logs:

```bash
docker compose ps
docker compose logs --tail=100 blockinator caddy
```

### Updating a Git clone installation

Back up `.env` and `./data` before updating (stop the stack for a consistent SQLite
backup); back up remote MySQL separately if used. From the existing project directory:

```bash
docker compose stop
# Back up .env and ./data now; back up remote MySQL separately if used.
git pull --ff-only
docker compose up -d --build
```

Keep the same project directory and persistent data. Review release notes for
configuration changes before upgrading. Use this procedure for the source-built
installation; Docker Hub deployments have their own update steps below.

## Alternative: install from Docker Hub

Published image: **`stealthcat128/blockinator`**. Release `1.19.2` and `latest`
support **Linux AMD64 and ARM64**. The examples pin `1.19.2` for predictable
upgrades. Pulling `latest` does not update an already-running container.

Use this alternative if you prefer a prebuilt image instead of building from the
Git checkout. Within this alternative, Compose with Caddy provides the full
HTTPS/certificate-management features; standalone Docker serves HTTP only.
Both require credentials before the first startup; there is no default password.

### Docker Hub with Docker Compose and Caddy

Requirements: Docker Engine, Docker Compose v2, Git, Bash, and OpenSSL. Run the
commands on the Docker host. Use `sudo` for Docker if your account requires it.

#### 1. Get the matching deployment configuration

```bash
git clone --branch release/v1.19.2 --single-branch https://github.com/StealthCat/blockinator-web.git
cd blockinator-web
```

This obtains the Compose and Caddy configuration for the release. The application
will be pulled from Docker Hub; no local image build is needed.

#### 2. Create first-run credentials

Create `.env` using [Create first-run credentials](#2-create-first-run-credentials)
in the primary installation instructions. Use the same password/API-key requirements
and optional database settings. Preserve an existing `.env` when changing methods.

#### 3. Select the Docker Hub image

Create an override alongside `docker-compose.yml`:

```bash
cat > docker-compose.hub.yml <<'EOF'
services:
  blockinator:
    image: stealthcat128/blockinator:1.19.2
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

#### 4. Open and configure Blockinator

Open **`http://DOCKER-HOST:8080/`**. Login, Technitium integration, HTTPS configuration,
and the `./data` persistence layout are the same as [Open and configure Blockinator](#4-open-and-configure-blockinator)
in the primary setup. For this Docker Hub deployment, use both Compose files when
checking status or logs:

```bash
docker compose -f docker-compose.yml -f docker-compose.hub.yml ps
docker compose -f docker-compose.yml -f docker-compose.hub.yml logs --tail=100 blockinator caddy
```

### Standalone Docker: HTTP only

For a minimal setup without Caddy, create a working directory and create `.env`
using the credential-generation block above. No repository checkout is required.

```bash
mkdir -p ~/blockinator
cd ~/blockinator
# Create .env here using the first-run credential block above before continuing.
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
  stealthcat128/blockinator:1.19.2
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

### Using MySQL instead of SQLite

Before first startup, set these values in `.env`:

```env
DATABASE_BACKEND=mysql
MYSQL_HOST=mysql.example.internal
MYSQL_PORT=3306
MYSQL_DATABASE=blockinator
MYSQL_USER=blockinator
MYSQL_PASSWORD=<your-database-password>
```

The MySQL database/user must already exist, with privileges to create/alter the
application's tables, indexes, views, and foreign keys. See [Database backends](#database-backends)
for pooling and TLS settings. In a container, `localhost` refers to that container,
not the Docker host or another MySQL container.

With MySQL, configuration, credentials, policy data, and query history live in the
remote database; retain local `/data` storage for TLS material. Changing
`DATABASE_BACKEND` selects a different store and does not migrate existing data.
Use the [offline migration procedure](#offline-database-migration) when switching.

### Updating an existing Docker Hub deployment

Back up your data before upgrading; see [Data and backups](#data-and-backups).
For Compose, stop the stack for a consistent SQLite backup, preserve `./data` and
`.env`, change the image tag in `docker-compose.hub.yml` to the desired published
version, then pull and recreate:

```bash
docker compose -f docker-compose.yml -f docker-compose.hub.yml stop
# Back up ./data and .env now; back up remote MySQL separately if used.
# Edit the image tag in docker-compose.hub.yml before continuing.
docker compose -f docker-compose.yml -f docker-compose.hub.yml pull
docker compose -f docker-compose.yml -f docker-compose.hub.yml up -d --no-build
```

Review each release's deployment/configuration changes when upgrading. An existing
source-built Compose installation can use the same override while retaining its
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

### Startup troubleshooting

| Symptom | Resolution |
| --- | --- |
| `Set a unique ADMIN_PASSWORD ... before first startup` | Supply `.env` via `--env-file` (standalone) or Compose; use a non-example password of at least 12 characters. A bare `docker run stealthcat128/blockinator` does not supply credentials. |
| `Set a unique POLICY_API_KEY ... before first startup` | Set a non-example API key of at least 24 characters. Both bootstrap values are required for a fresh database. |
| Container runs but the console is unreachable | Publish the port with `-p 8080:8080` for standalone Docker; check host firewall rules and container logs. |
| Port already allocated / container name already in use | An existing deployment may already occupy that port/name. Choose another host port/name or deliberately replace the old deployment; do not run both examples unchanged on the same host. |
| New environment password does not change the login | Credentials are already stored in the database. Manage them through **Access & Security**; preserve the database. |
| HTTPS/ACME does not work with the standalone image | Deploy the Caddy Compose stack or manage TLS with your own external reverse proxy. |

## Policy model

### Target precedence

Policy handling proceeds in this order:

1. Ignored DNS record-type bypass.
2. Global pause.
3. Any matching whitelisted target whose schedule is active (Endpoint, Network, or reverse-DNS hostname).
4. Exact client-IP Endpoint.
5. Matching reverse-DNS hostname.
6. Most-specific matching Network.
7. Unmatched-client fallback.

The record-type bypass occurs before PTR observation, policy-target matching, list evaluation, and Query Log creation. If all questions use ignored types, Blockinator immediately returns an allow decision with reason `ignored_record_type`; otherwise non-ignored questions are evaluated normally.

A paused matching target permits the query instead of continuing to a lower-priority target.

To whitelist clients, open **Policy Targets**, create or edit an **Endpoint**, **Network**, or **Reverse-DNS Hostname**, and check **Whitelist target**. Networks support IPv4, IPv6, or both; PTR targets support exact names and wildcard suffixes. PTR matching uses learned reverse-DNS identities, so hostname exemptions apply after the client's identity is known.

Any matching whitelist with an active enforcement schedule takes precedence over all filtering targets and lists, even if another target is more specific or was created earlier. Outside the whitelist's schedule, normal policy applies. When several whitelists match, the logged target is selected by exact IP, then exact/most-specific PTR hostname, then most-specific network, with oldest ID breaking ties.

List-assignment boxes disappear while **Whitelist target** is checked. Existing assignments remain saved for reuse when it is unchecked. To restore filtering, uncheck the option and leave the blocking state **Active**. Queries remain logged as Whitelisted with the matching target name and reason `endpoint_whitelisted` (exact IP) or `scope_whitelisted` (network/PTR); ignored record types still bypass logging.

A Network target may contain IPv4, IPv6, or both. Dual-stack targets share one name, state, schedule, and assignment set.

### List precedence

List assignments are additive. The active policy set may include:

- globally applied lists;
- lists assigned to the matching Network;
- lists assigned to the matching PTR hostname; and
- lists assigned to the matching Endpoint.

Every active list is still subject to its own enabled state and schedule.

**Whitelists are evaluated before block lists.** If a domain matches an active whitelist, the decision is allowed even if that domain also appears in one or more active block lists.

The policy API reports a whitelist match as:

```json
{
  "block": false,
  "reason": "whitelist_match",
  "matched_scope": "Guest Wi-Fi",
  "matched_list": "Required Services",
  "matched_list_type": "whitelist",
  "matched_domain": "updates.example.com",
  "response_mode": "nxdomain"
}
```

In the web UI, that same event is shown as the distinct **Whitelisted** decision rather than a generic Allowed result.

### Unmatched clients

Under **System Settings → DNS & logs**, two controls define unmatched-client behavior.

**Global list reach**

- **All clients** — global lists apply to every client.
- **Matched policy targets only** — global lists apply only when a Network, Endpoint, or hostname target matched.

**Default action**

- **Allow** — permit an otherwise-unmatched query.
- **Deny** — block it with `no_scope_default_deny`.

This supports both open-by-default and closed-by-default policy models.

### Ignored DNS record types

**System Settings → Ignored records** controls which DNS question types Blockinator should leave entirely to the upstream DNS server.

Current selectable types are:

`A`, `AAAA`, `ANY`, `CAA`, `CERT`, `CNAME`, `DNAME`, `DNSKEY`, `DS`, `HINFO`, `HTTPS`, `IXFR`, `LOC`, `MX`, `NAPTR`, `NS`, `NSEC`, `NSEC3`, `PTR`, `RRSIG`, `SOA`, `SRV`, `SSHFP`, `SVCB`, `TLSA`, `TXT`, `URI`, and `AXFR`.

If a policy request contains any selected type, Blockinator:

- returns `block: false` with reason `ignored_record_type`;
- skips PTR observation and background PTR scheduling for that request;
- skips policy-target, whitelist, and block-list evaluation;
- does not create a Query Log row; and
- does not add a response-time sample to Statistics.

Ignored types bypass only their own question; a mixed request still evaluates its other questions.

## Block lists and whitelists

Block lists and whitelists use the same management model. Each list has its own:

- source;
- parser format;
- enabled state;
- global/target assignments;
- schedule;
- automatic refresh interval; and
- entry set.

### Supported sources

A list may come from:

- a remote URL;
- an uploaded file;
- pasted rules; or
- a manually maintained domain list.

Supported input includes:

- one domain per line;
- hosts-file entries; and
- common DNS-oriented Adblock rules.

Domains are normalized before storage. IDNs are stored in ASCII/punycode form, and wildcard-style inputs such as `*.example.com` normalize to the blockable domain.

A stored `example.com` entry also matches its subdomains.

### Normalized domain storage

Domains are stored once in a shared global domain table. If the same domain appears in several block lists, whitelists, or both, each list stores only its membership reference.

This avoids duplicate domain storage while preserving independent list membership and refresh behavior.

### Editors

**Block Lists → Edit** and **Whitelists → Edit** open dedicated editor pages for:

- list/source configuration;
- policy-target assignments;
- scheduling;
- URL refresh/import actions; and
- current-entry previews.

Manual lists also have a dedicated domain manager with search, pagination, add, and remove operations.

### URL refresh behavior

URL-backed lists refresh independently on their configured intervals.

The refresher:

- uses ETag and Last-Modified validators when available;
- streams remote content through the parser instead of retaining an extra full decoded copy;
- computes SHA-256 while downloading rather than hashing the source again afterward;
- skips parsing/database writes when an unchanged source can be identified;
- downloads and parses multiple due lists concurrently;
- serializes database writes to avoid SQLite writer contention;
- applies membership deltas rather than replacing unchanged data;
- keeps the last known-good list after download/parse failures; and
- reloads only the policy list snapshot after a changed refresh batch.

An upstream response with no usable domains is rejected rather than replacing a working list with an empty one.

Refresh controls:

```env
BLOCKLIST_REFRESH_POLL_SECONDS=30
BLOCKLIST_REFRESH_WORKERS=4
MAX_BLOCKLIST_BYTES=104857600
```

## Scheduling

Recurring weekly schedules can be applied to:

- Block Lists;
- Whitelists;
- Networks;
- Endpoints; and
- PTR hostname targets.

Schedules support:

- selectable weekdays;
- start/end times;
- overnight windows; and
- IANA timezones such as `America/New_York`.

Selected weekdays represent the day the schedule starts. For example, Monday `22:00–06:00` remains active until Tuesday at 06:00.

If start and end are equal, the schedule covers the full selected day.

The **System Settings → Default timezone** controls Query Log display and is the initial timezone for newly created schedules. Existing schedules retain their own saved timezone.

## Reverse DNS

PTR lookup is kept completely off the DNS decision request path.

Every non-ignored policy request performs only a fast, in-memory observation of the client IP. A dedicated durable PTR resolver runs in parallel with policy evaluation and persists one state for every observed client:

- **pending** — discovered but not yet resolved;
- **resolved** — a valid PTR hostname is known;
- **no_ptr** — the resolver authoritatively reports no PTR record; or
- **retry** — a timeout, SERVFAIL, unavailable resolver, or other transient failure will be retried.

Transient failures use exponential backoff. Resolved names are periodically refreshed so DHCP/PTR changes are learned, and authoritative no-PTR results are rechecked so newly created PTR records eventually appear.

PTR state is stored in `client_ptr_status`. Successful names are also stored in `client_identities`, backfilled into Query Log rows that did not yet have a hostname, and propagated into the immutable policy snapshot without rebuilding block-list domain indexes.

Startup and periodic reconciliation scan retained Query Log history for client IPs that are not yet represented in the durable PTR state table. This makes resolution recoverable even after restarts and avoids relying on a single in-memory queue.

PTR identities are used for:

- exact and wildcard hostname policy targets;
- Dashboard client labels;
- Query Log client labels;
- Endpoint selectors; and
- Query Log client searching.

The first evaluated request from a previously unknown client never waits for PTR. Hostname policy can begin applying as soon as the background resolver learns the name.

A wildcard such as:

```text
*.kids.home.arpa
```

matches `tablet.kids.home.arpa`, but not the bare `kids.home.arpa` suffix.

For internal reverse zones:

```env
RDNS_NAMESERVERS=192.168.1.2,192.168.1.3
```

Resolver controls include:

```env
RDNS_RESOLVER_WORKERS=8
RDNS_RESOLVED_REFRESH_SECONDS=86400
RDNS_NO_PTR_REFRESH_SECONDS=21600
RDNS_RECONCILE_SECONDS=1
```

**System Settings → Runtime** shows PTR resolver status, tracked/resolved/no-PTR/retry counts, queue depth, in-flight work, worker count, and the active resolver source.

Hostname policy is only as trustworthy as the PTR data supplied by the configured resolver/reverse zones.

## Dashboard and Query Log

Evaluated DNS decisions are written through a bounded asynchronous logger so normal database logging does not block the policy request path. Requests bypassed by **Ignored records** are deliberately not logged.

The Dashboard shows recent activity. The full Query Log records:

- timestamp;
- originating DNS server (`server_id`);
- client IP and learned PTR hostname;
- client port;
- DNS transport/protocol;
- HTTP or HTTPS policy scheme;
- query name, type, and class;
- end-to-end policy response time;
- matched policy target;
- matched list and list type;
- allow/block state and reason; and
- optionally, the original request JSON.

### Decision display

The UI uses three distinct decision states:

- **Allowed** — permitted without a whitelist match.
- **Blocked** — rejected by a block list or blocking policy condition.
- **Whitelisted** — explicitly permitted by a whitelist.

Whitelist rows continue to show the matched whitelist in the Match/Reason column.

The Query Log decision filter treats these as three separate choices. Selecting **Allowed** does not include Whitelisted rows.

### Query Log filters

Filters include:

- domain;
- client IP or partial/full PTR hostname;
- querying DNS server;
- matched policy target;
- matched list;
- decision state;
- date/time range; and
- results per page.

Optional auto-refresh intervals are available at 5, 10, 15, 30, or 60 seconds and preserve the active filter URL.

### Query Log pagination and time ranges

Use **Results per page** to choose any page size from 25 to 500. **First**,
**Previous**, **Next**, and **Last** retain all active filters. The result count
shows the total matches, and the heading shows the current row range. Applying
filters or changing page size starts again on the first page.

**From** and **Through** use the timezone named beside the fields (the system
default timezone), not the browser timezone. Either boundary can be omitted.
The end includes the entire selected second. Invalid or reversed ranges are
rejected. During daylight-saving fall-back, ambiguous boundaries include both
occurrences; nonexistent spring-forward times are rejected.

Page navigation pins the newest query ID so incoming requests cannot shift
results between pages. Auto refresh pauses while browsing that snapshot; choose
**Latest results** to return to live results with the same filters. Normal log
retention can still remove rows from a snapshot. Live refresh updates the rows,
total count and page links together.

### Raw request JSON

Full policy request JSON is **disabled by default** to reduce serialization CPU, database bandwidth, WAL traffic, and storage use.

Enable **Store full policy request JSON** under **System Settings → DNS & logs** only when raw payload retention is useful for troubleshooting.

### Retention

Two retention limits are available:

- **Maximum age (days)** — `0` disables age pruning.
- **Maximum rows** — retains only the newest configured number of rows.

When both are set, both apply.

Timestamps are stored in UTC and converted for display using the configured system timezone, including daylight-saving-time handling.

## Live Statistics

The **Statistics** page provides a live operational view with:

- total retained queries;
- total retained blocks;
- overall average measured policy response time;
- query count per interval;
- blocked-query count per interval; and
- **average response time per interval as a separate chart line**.

The response-time series uses an independent right-side millisecond axis so traffic volume does not distort latency visibility. Buckets with no response-time samples render as gaps instead of false 0 ms values.

Available windows:

- 15 minutes;
- 1 hour;
- 6 hours;
- 24 hours.

The page refreshes every five seconds without a full browser reload. Longer windows automatically use larger buckets.

Statistics use transactionally maintained rollups of retained Query Log data, so retention pruning limits statistics history and ignored record-type requests are intentionally excluded.

## Performance architecture

Blockinator keeps the policy request path intentionally small.

### Record-type short circuit

Ignored record types are checked against the in-memory policy snapshot before client PTR observation, target resolution, list matching, or log-row construction. This makes the bypass both a policy control and a low-overhead way to remove unwanted DNS question classes from Blockinator processing.

### Immutable policy snapshots

Policy configuration is compiled into an immutable in-memory snapshot. Decision threads capture the current snapshot without acquiring the policy write lock.

The snapshot contains:

- precompiled schedules;
- exact client/hostname indexes;
- wildcard hostname suffix indexes;
- IPv4/IPv6 prefix indexes;
- one shared `domain → list-membership bitmask` index; and
- list type/global/schedule masks.

Administrative changes build replacement state and swap it atomically.

### Targeted reloads

Configuration changes no longer automatically rebuild every part of the policy engine.

Separate reload paths update:

- settings;
- scopes; or
- list/domain indexes.

For example, changing a fallback setting does not reread the entire domain membership table, and changing one policy target does not rebuild all list domains.

### Decision lookup

Domain suffix masks are calculated once per query and reused for whitelist and block-list matching.

### Async logging and identity work

- Query writes are batched through a dedicated writer.
- SQLite uses WAL mode and one serialized writer.
- API-key `last_used_at` updates happen asynchronously.
- PTR learning/backfill runs outside UI and policy request paths.
- Ignored record-type requests never enter the logger or PTR queues.

## Database backends

### SQLite

SQLite is the default and requires no extra infrastructure.

Blockinator uses WAL mode and serialized writes to reduce lock contention.

### MySQL

MySQL 8.x is supported for configuration, credentials, policy data, and query history.

The application uses a bounded reusable connection pool rather than opening a new physical connection for every web/database operation.

Pool controls:

```env
MYSQL_POOL_SIZE=10
MYSQL_POOL_TIMEOUT_SECONDS=5
MYSQL_POOL_RECYCLE_SECONDS=300
```

Optional MySQL TLS is supported through `MYSQL_SSL_*` settings.

### Offline database migration

Blockinator includes `tools/migrate_database.py` to move the complete database-resident dataset between SQLite and MySQL in either direction.

**Blockinator must be stopped for the entire migration.** The tool requires `--confirm-offline` before it will write anything. The destination database is initialized with the current Blockinator schema, cleared, populated in foreign-key-safe order, then verified with row counts and SHA-256 table-content digests.

SQLite → MySQL:

```bash
docker compose down

export MYSQL_HOST=mysql.example.internal
export MYSQL_DATABASE=blockinator
export MYSQL_USER=blockinator
export MYSQL_PASSWORD='replace-with-password'

python tools/migrate_database.py \
  --source sqlite \
  --destination mysql \
  --sqlite-path ./data/policy.db \
  --confirm-offline
```

MySQL → SQLite:

```bash
docker compose down

export MYSQL_HOST=mysql.example.internal
export MYSQL_DATABASE=blockinator
export MYSQL_USER=blockinator
export MYSQL_PASSWORD='replace-with-password'

python tools/migrate_database.py \
  --source mysql \
  --destination sqlite \
  --sqlite-path ./data/policy.db \
  --confirm-offline
```

Use `--dry-run` to validate the source and show table counts without modifying the destination. Use `--yes` for non-interactive operation and `--skip-content-verification` when row-count verification alone is desired.

The migration preserves Blockinator database data including settings, block lists, whitelists, normalized domains and memberships, policy targets, Query Log history, PTR resolution state, learned client identities, administrator accounts/sessions, and API keys.

Filesystem state under `./data/tls/` and `./data/caddy/` is not stored in either database and is therefore not copied by the database migration tool. Keep or copy those directories separately when moving Blockinator to another host.

After a successful migration, set `DATABASE_BACKEND` to the destination type before restarting Blockinator.

## Appearance

**System Settings → Appearance** provides application-wide **Dark** and **Light** themes.

The selected theme is stored in the active database backend and applies to the full administration console, including authentication and list editor surfaces.

## HTTPS and TLS

Blockinator uses a managed **Caddy 2.11.4** sidecar as the host-facing HTTP/HTTPS reverse proxy. The application itself remains on the private Compose network.

Default host ports:

```text
HTTP   8080
HTTPS  8443
```

Override them with:

```env
POLICY_PORT=80
HTTPS_PORT=443
```

HTTPS is published over both TCP and UDP so Caddy can use HTTP/3 where supported.

### TLS modes

Under **System Settings → HTTPS & TLS**:

- **HTTP only**
- **Uploaded certificate**
- **ACME / custom ACME server**

Uploaded PEM certificates/keys are validated before activation, including certificate/key matching, validity dates, and DNS SAN coverage.

ACME supports:

- account email;
- custom directory URL;
- optional private CA root;
- External Account Binding (EAB); and
- persistent Caddy account/certificate state.

Blockinator generates Caddy JSON and loads it atomically through the internal Caddy admin API. If activation fails, the previous configuration is restored.

A background reconciler restores the desired configuration after Caddy restarts:

```env
TLS_RECONCILE_SECONDS=30
```

### Redirect-only HTTP

After HTTPS is active, HTTP application access can be switched to redirect-only mode.

Blockinator then returns **308 Permanent Redirect**, preserving URI, query string, POST method/body semantics, and configured non-standard HTTPS ports.

The Caddy admin API is never published to the host.

## Administration and security

Security features include:

- database-backed administrator accounts;
- salted `scrypt` password hashes;
- database-backed login sessions;
- HTTP-only cookies;
- Secure cookies when appropriate;
- CSRF protection for administrative forms;
- configurable administrator session lifetime;
- multiple named API keys;
- API-key enable/disable and deletion;
- API-key fingerprints and last-used timestamps;
- API keys stored only as SHA-256 hashes; and
- in-memory API-key verification on the hot path.

## Technitium integration

A companion Technitium DNS application can call Blockinator for every DNS request.

Example:

```json
{
  "endpoint": "http://192.168.1.50:8080/api/v1/decision",
  "apiKey": "one-enabled-blockinator-api-key",
  "serverId": "technitium-1",
  "timeoutMs": 250,
  "failMode": "open"
}
```

When HTTPS is enabled, use the configured HTTPS hostname/port instead.

If Technitium and Blockinator share a Docker network and you intentionally want to bypass Caddy:

```json
{
  "endpoint": "http://blockinator:8080/api/v1/decision"
}
```

## Decision API

### Authentication check

```text
GET /api/v1/ping
X-Api-Key: <enabled Blockinator API key>
```

Example:

```bash
curl -i \
  -H 'X-Api-Key: YOUR_KEY' \
  http://DOCKER-HOST:8080/api/v1/ping
```

### Policy decision

```text
POST /api/v1/decision
X-Api-Key: <enabled Blockinator API key>
Content-Type: application/json
```

Example request:

```json
{
  "server_id": "technitium-1",
  "protocol": "Udp",
  "client": {
    "ip": "192.168.20.44",
    "port": 53012
  },
  "dns": {
    "identifier": 1234,
    "is_response": false,
    "opcode": "StandardQuery",
    "recursion_desired": true,
    "rcode": "NoError",
    "has_edns": true,
    "question_count": 1,
    "wire_base64": "EjQBAAABAAAAAAAB...",
    "questions": [
      {
        "name": "ads.example.com",
        "type": "A",
        "class": "IN"
      }
    ]
  }
}
```

Example blocked response:

```json
{
  "block": true,
  "reason": "blocklist_match",
  "matched_scope": "Guest Wi-Fi",
  "matched_list": "Advertising",
  "matched_list_type": "block",
  "matched_domain": "ads.example.com",
  "response_mode": "nxdomain"
}
```

The API validates client IP addresses, port ranges, DNS label/name lengths and accepts 1–16 questions per request. Policy request bodies are limited to 256 KiB and `wire_base64` to 87,380 characters. Invalid payloads return HTTP 422; oversized bodies return HTTP 413.

When multiple DNS questions are supplied, Blockinator evaluates them in order and returns the first blocking decision. If none block, the first allow decision is returned.

Questions using types selected under **System Settings → Ignored records** are skipped individually; other questions still receive normal policy evaluation. Only when all questions are ignored does Blockinator short-circuit before PTR observation or policy evaluation. It returns an immediate allow decision with reason `ignored_record_type`; the request is not added to Query Log and does not contribute a response-time sample.

## System Settings

### DNS & logs

Controls include:

- blocked response mode: NXDOMAIN, REFUSED, NODATA, or `0.0.0.0 / ::`;
- Global list reach;
- unmatched-client Allow/Deny fallback;
- query-log age/row retention;
- optional raw request JSON retention; and
- default timezone.

Global protection pause/resume is available from the Dashboard rather than this settings tab.

### Ignored records

Provides checkboxes for common address, service-binding, mail, reverse-DNS, DNSSEC, text, certificate, and zone-transfer record types. A selected type bypasses Blockinator policy processing for the entire policy request. The DNS server receives an immediate allow result, while Blockinator performs no PTR observation, target/list evaluation, Query Log write, or response-time logging for that request.

### Appearance

Controls the global Dark/Light theme.

### HTTPS & TLS

Controls TLS mode, hostname/certificate identity, uploaded certificate/key, ACME configuration, private CA trust, EAB, redirect-only HTTP, and TLS health/error status.

### Runtime

Shows application/storage information, the active ignored-record summary, proxy/TLS status, and detailed background PTR resolver health.

## Environment variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `ADMIN_USERNAME` | Bootstrap administrator username | `admin` |
| `ADMIN_PASSWORD` | Bootstrap administrator password | required on first startup |
| `POLICY_API_KEY` | Bootstrap API key | required on first startup |
| `DATABASE_BACKEND` | `sqlite` or `mysql` | `sqlite` |
| `MYSQL_HOST` | MySQL hostname/address | blank |
| `MYSQL_PORT` | MySQL TCP port | `3306` |
| `MYSQL_DATABASE` | MySQL database/schema | `blockinator` |
| `MYSQL_USER` | MySQL username | `blockinator` |
| `MYSQL_PASSWORD` | MySQL password | blank |
| `MYSQL_CONNECT_TIMEOUT` | MySQL connect timeout, seconds | `10` |
| `MYSQL_POOL_SIZE` | Maximum pooled MySQL connections | `10` |
| `MYSQL_POOL_TIMEOUT_SECONDS` | Pool checkout timeout | `5` |
| `MYSQL_POOL_RECYCLE_SECONDS` | Recycle pooled connections after this age | `300` |
| `MYSQL_SSL_ENABLED` | Request MySQL TLS | `0` |
| `MYSQL_SSL_CA` | Optional CA path inside container | blank |
| `MYSQL_SSL_CERT` | Optional client certificate path | blank |
| `MYSQL_SSL_KEY` | Optional client private-key path | blank |
| `MYSQL_SSL_VERIFY_CERT` | Verify MySQL server certificate/identity | `1` |
| `POLICY_PORT` | Host-facing HTTP port | `8080` |
| `HTTPS_PORT` | Host-facing HTTPS TCP/UDP port | `8443` |
| `MAX_BLOCKLIST_BYTES` | Maximum accepted list size | `104857600` |
| `BLOCKLIST_REFRESH_POLL_SECONDS` | Due-list scan frequency | `30` |
| `BLOCKLIST_REFRESH_WORKERS` | Concurrent list download/parse workers | `4` |
| `ADMIN_COOKIE_SECURE` | Force Secure admin cookies when appropriate | `0` |
| `ADMIN_SESSION_TTL_SECONDS` | Administrator session lifetime | `43200` |
| `TZ` | Bootstrap/default timezone for a new database | `UTC` |
| `RDNS_NAMESERVERS` | Optional comma-separated PTR resolvers | blank |
| `RDNS_TIMEOUT_SECONDS` | Per-lookup PTR timeout | `0.5` |
| `RDNS_PAGE_BUDGET_SECONDS` | PTR resolver UI budget compatibility setting | `1.25` |
| `RDNS_CACHE_TTL_SECONDS` | Positive PTR cache lifetime | `300` |
| `RDNS_NEGATIVE_TTL_SECONDS` | Negative PTR cache lifetime | `60` |
| `RDNS_WORKERS` | Concurrent cache/UI PTR workers | `12` |
| `RDNS_RESOLVER_WORKERS` | Durable parallel PTR-resolution workers | `8` |
| `RDNS_RESOLVED_REFRESH_SECONDS` | Refresh interval for resolved PTR names | `86400` |
| `RDNS_NO_PTR_REFRESH_SECONDS` | Recheck interval for authoritative no-PTR results | `21600` |
| `RDNS_RECONCILE_SECONDS` | Durable PTR scheduler/reconciliation interval | `1` |
| `TLS_RECONCILE_SECONDS` | Caddy/TLS reconciliation interval | `30` |

The persisted System Settings timezone becomes authoritative after initialization; changing `TZ` later does not rewrite existing schedule timezones.

## Data and backups

### SQLite

```text
./data/policy.db   Configuration, credentials, policy data, and query history
./data/tls/        Uploaded TLS material and protected ACME EAB secret
./data/caddy/      Caddy ACME account and certificate state
```

Back up the full `./data` directory.

### MySQL

```text
Remote MySQL       Configuration, credentials, policy data, and query history
./data/tls/        Uploaded TLS material and protected ACME EAB secret
./data/caddy/      Caddy ACME account and certificate state
```

Back up both the remote MySQL database and local `./data`.

Blockinator does not automatically synchronize database backends while running. Use `tools/migrate_database.py` while Blockinator is offline to perform a verified one-time migration.

## Repository layout

```text
.
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
├── CHANGELOG.md
├── LICENSE
├── app/
│   ├── main.py
│   ├── auth.py
│   ├── policy.py
│   ├── blocklists.py
│   ├── refresher.py
│   ├── rdns.py
│   ├── statistics.py
│   ├── tls.py
│   ├── timeutil.py
│   ├── db.py
│   ├── mysql_backend.py
│   └── static/
├── caddy/
│   └── caddy.bootstrap.json
├── docs/
│   └── ACME_TLS_PLAN.md
├── tests/
└── tools/
```

## Testing

Run the test suite:

```bash
python -m pytest -q
```

CI covers:

- Python compilation;
- SQLite behavior and migrations;
- MySQL 8.4 integration;
- block-list/whitelist parsing and refresh;
- schedules and policy precedence;
- concurrent lock-free policy reads;
- Query Log and reverse-DNS behavior;
- ignored record-type short-circuit behavior;
- settings and UI regression checks;
- Caddy/TLS configuration;
- Docker image/Compose validation;
- policy-engine microbenchmark smoke testing; and
- direct-vs-Caddy policy latency benchmarking.

## Performance benchmarks

Pure policy-engine benchmark:

```bash
python /srv/tools/benchmark_policy_engine.py --domains 100000 --requests 100000
```

End-to-end direct-vs-Caddy benchmark:

```bash
python /srv/tools/benchmark_policy_latency.py --requests 1000 --warmup 20
```

The latency benchmark reports throughput plus mean/p50/p95/p99 latency across several concurrency levels. CI uses smaller smoke runs; benchmark values are informational rather than hard performance gates because shared-runner performance varies.

## Security recommendations

- Replace bootstrap credentials before first startup.
- Rotate administrator credentials and API keys from **Access & Security**.
- Prefer HTTPS for both the control panel and policy API.
- Keep `./data` private and backed up.
- Back up the remote database separately when using MySQL.
- Protect PTR/reverse-DNS infrastructure if hostname-based policy is enabled.
- Do not expose Caddy's internal admin API.
- Use MySQL TLS when the database connection crosses an untrusted network.

## License

Blockinator is licensed under the **GNU General Public License v3.0**. See [LICENSE](LICENSE) for the full license text.

## Reddit User Reviews

Selected feedback from the r/technitium community:

> “Vibe coded slop.  
> Hard pass.”  
> — u/Resistant4375

> “AI Slop.”  
> — Anonymous

> “So, built a $20 a month app.”  
> — u/Superb_Raccoon

> “Thanks ChatGPT!”  
> — u/Key_Pace_2496

> “it deserves to be called slop. I’d argue that “slop” is too kind”  
> — Anonymous



## Operational protections and monitoring

- Administrator writes run in a separate four-thread pool with bounded admission. Saturation returns HTTP 503 with `Retry-After`; policy workers remain separate. Sign-in attempts are limited to 10 per peer and 100 globally per minute (HTTP 429). Configure trusted proxy forwarding correctly so peers are identified accurately.
- Session cookies preserve HTTPS/`ADMIN_COOKIE_SECURE` settings after credential changes. New API keys appear only in the creating POST response with `Cache-Control: no-store` and no-referrer protection; copy them before leaving the page.
- List downloads accept only HTTP(S). Every connection, including redirects, validates resolved addresses and connects to those exact addresses. Private/local destinations require explicit `BLOCKLIST_PRIVATE_HOSTS` entries (comma-separated exact hostnames or CIDRs). Example: `feeds.internal,10.20.0.0/16`. Environment HTTP proxies are intentionally ignored for these downloads. Uploads and pasted lists obey `MAX_BLOCKLIST_BYTES` too.
- Policy rebuild writers are serialized; decisions continue using the current snapshot. List creation/replacement commits metadata, assignments and membership together. Changing source URL/format clears conditional-download validators so the next refresh reparses the source.
- Query logging stays asynchronous. Confirmed pre-commit failures receive up to three write attempts. Ambiguous commits are counted as uncertain and never replayed, preventing duplicates. Shutdown allows up to five seconds to drain; logging is best-effort and cannot guarantee delivery during process termination or prolonged database outages.
- `/healthz` reports process liveness. `/readyz` reports policy readiness and returns 503 following a failed reload. The authenticated `/api/v1/runtime` endpoint and **System Settings → Runtime** expose policy generation, logger queue/drop/failure metrics, and background worker state. Monitoring should alert on worker stoppage, errors, drops and uncertain writes separately from policy readiness.
- Statistics snapshots are shared for five seconds per window/timezone. Query Log refresh requests only authenticated row fragments, avoiding repeated filter-option scans. Statistics refreshes time out after 15 seconds and resume after browser back/forward restoration.

Run regression tests with `pip install -r requirements.txt pytest httpx==0.28.1` followed by `python -m pytest -q`.


## Docker Hub publishing (maintainers)

For installation instructions, see [Alternative: install from Docker Hub](#alternative-install-from-docker-hub).

The `Publish Docker Hub` GitHub Actions workflow builds published stable release
source for `linux/amd64` and `linux/arm64`, after the SQLite/Docker and MySQL test
jobs pass. Images are published to `stealthcat128/blockinator` with a version tag
such as `1.19.2`. The `latest` image tag is updated only when that version is the
current latest GitHub release. Publishing an older release does not move `latest`.

Maintainers must add a Docker Hub access token with write permission as the
repository's `DOCKERHUB_TOKEN` Actions secret. The login account is `stealthcat128`.
Do not commit the token or put it in application environment files.

New published releases trigger the workflow. For an existing release, open
**Actions → Publish Docker Hub → Run workflow**, select `main`, and enter the
published tag (for example, `v1.19.2`). The workflow resolves the tag once and
uses that exact commit for testing and building. Drafts and prereleases are rejected.

Once the workflow succeeds, pull the application image with:

```bash
docker pull stealthcat128/blockinator:1.19.2
```

The image contains the Blockinator application; Caddy remains a separate service.
Keep the existing deployment's environment, data volumes, and Caddy configuration
when switching from a local build to this image. This publishing workflow does
not install updates on running deployments.
