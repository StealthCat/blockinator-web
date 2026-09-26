<p align="center">
  <img src="app/static/blockinator-mark.svg" alt="Blockinator" width="112" height="112">
</p>

# Blockinator

**Blockinator** is a self-hosted DNS policy engine and management console designed to sit beside DNS servers such as Technitium DNS Server.

It accepts authenticated DNS query metadata, applies configurable pre-policy record-type bypasses, resolves the applicable client policy, evaluates whitelists and block lists, and returns an allow/block decision. The web console provides policy targeting, list management, schedules, live statistics, query history, authentication, SQLite/MySQL-backed persistence, and managed HTTPS.

Blockinator runs with Docker Compose and supports either:

- **SQLite** — local, zero-configuration persistence and the default backend.
- **MySQL 8.x** — remote persistence with connection pooling and optional TLS.

> The companion Technitium integration is maintained separately in the `blockinator-technitium` repository.

## Management interface

The console includes dark and light themes, scalable SVG branding and icons, and responsive navigation. Select the theme under **System Settings → Appearance**.

- **Query Log:** filter by domain, client, DNS server, policy target, list, or decision. Expand **Details** in a row for the full timestamp, DNS server, client IP, record type, policy API scheme, matched policy target, DNS transport, and client port.
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

## Quick start

### 1. Create the local configuration

```bash
cp .env.example .env
```

Before first startup, replace at least:

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<unique-password-at-least-12-characters>
POLICY_API_KEY=<unique-random-key-at-least-24-characters>
```

Generate each secret with `openssl rand -hex 32`. A fresh database refuses missing or known example credentials. Existing database credentials continue to take precedence.

SQLite is the default:

```env
DATABASE_BACKEND=sqlite
```

To use MySQL instead:

```env
DATABASE_BACKEND=mysql
MYSQL_HOST=mysql.example.internal
MYSQL_PORT=3306
MYSQL_DATABASE=blockinator
MYSQL_USER=blockinator
MYSQL_PASSWORD=replace-with-a-long-random-password
```

Blockinator creates and upgrades its own tables. The MySQL database and user must already exist, and that user needs the privileges required to create/alter Blockinator tables, indexes, views, and foreign keys.

Changing `DATABASE_BACKEND` selects a different store at the next startup. It does **not** migrate data automatically. To preserve an existing installation while switching backends, stop Blockinator and use `tools/migrate_database.py` as described under **Offline database migration**.

### 2. Start Blockinator

```bash
docker compose up -d --build
```

### 3. Open the console

With the default port mapping:

```text
http://DOCKER-HOST:8080/
```

Local runtime files are stored under `./data/`.

With SQLite, the primary database is:

```text
./data/policy.db
```

With MySQL, configuration, credentials, policy data, and query history live in the remote database while TLS/ACME files remain under `./data`.

Bootstrap administrator credentials and the bootstrap API key are only used when the database has no existing records. After initialization, manage them from **Access & Security**.

## Policy model

### Target precedence

Policy handling proceeds in this order:

1. Ignored DNS record-type bypass.
2. Global pause.
3. Exact client-IP Endpoint.
4. Matching reverse-DNS hostname.
5. Most-specific matching Network.
6. Unmatched-client fallback.

The record-type bypass occurs before PTR observation, policy-target matching, list evaluation, and Query Log creation. If all questions use ignored types, Blockinator immediately returns an allow decision with reason `ignored_record_type`; otherwise non-ignored questions are evaluated normally.

A paused matching target permits the query instead of continuing to a lower-priority target.

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
- decision state; and
- result limit.

Optional auto-refresh intervals are available at 5, 10, 15, 30, or 60 seconds and preserve the active filter URL.

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

Statistics are derived from retained Query Log data, so retention pruning limits statistics history and ignored record-type requests are intentionally excluded.

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
