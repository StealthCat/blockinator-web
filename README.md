<p align="center">
  <img src="app/static/blockinator-hero.webp" alt="Blockinator" width="100%">
</p>

# Blockinator

**Blockinator** is a self-hosted DNS policy, block-list, and whitelist management service designed to work with DNS servers such as Technitium DNS Server.

It accepts DNS query metadata through an authenticated policy API, determines which policy applies to the client, evaluates configured whitelists and block lists, and returns an allow/block decision. A responsive web console provides policy management, list imports, schedules, query logging, security controls, and managed HTTPS.

Blockinator is packaged for Docker Compose and supports either a local SQLite database or a remote MySQL 8.x database for persistent configuration and history. SQLite remains the default.

> The companion Technitium integration is maintained separately in the `blockinator-technitium` repository.

## Highlights

### Policy targeting

Blockinator can apply policy by:

- **Network** — IPv4 CIDR, IPv6 CIDR, or both on the same target.
- **Endpoint** — one exact IPv4 or IPv6 client address.
- **Reverse-DNS hostname** — exact PTR names such as `desktop-01.home.arpa`.
- **Reverse-DNS wildcard** — suffix patterns such as `*.kids.home.arpa`.
- **Global policy** — settings, whitelists, and block lists that apply beyond individually defined targets.

A dual-stack Network target shares one name, state, schedule, and list assignment set across both address families.

### Policy precedence

Client policy state is evaluated in this order:

1. Global pause.
2. Exact client-IP Endpoint.
3. Matching reverse-DNS hostname.
4. Most-specific matching Network.
5. Unmatched-client fallback.

A paused matching target permits the query rather than continuing to a lower-priority target.

List assignments are **additive**. The active policy set can contain:

- enabled Global block lists and whitelists;
- lists assigned to the matching Network;
- lists assigned to the matching reverse-DNS hostname; and
- lists assigned to the matching Endpoint.

All active lists are still subject to their own enabled state and schedule. Within the resulting active set, **whitelist matches are evaluated before block-list matches**. A whitelist match explicitly allows the query even when the same domain also appears in one or more active block lists. If no whitelist matches, normal block-list evaluation continues.

### Unmatched clients

Under **System Settings → DNS & logs**, Blockinator provides two controls for clients that do not match any active policy target:

- **Global list reach**
  - **All clients** — Global lists are evaluated for every client.
  - **Matched policy targets only** — Global lists are evaluated only when an active Network, Endpoint, or hostname target matched.
- **Default action**
  - **Allow** — permit an unmatched query after any applicable lists are evaluated.
  - **Deny** — block an otherwise-allowed unmatched query with `no_scope_default_deny`.

This makes it possible to run either an open-by-default or closed-by-default policy model.

## Block-list and whitelist management

Blockinator supports multiple independent block lists and whitelists with their own source, parser, assignments, state, and schedule. Whitelists use the same management features as block lists but produce an explicit allow decision when matched.

Domains are stored in a normalized global domain table. If the same domain appears in multiple block lists, whitelists, or both, the domain text is stored once and each list keeps a lightweight membership reference to that shared entry. Removing or refreshing one list does not remove the shared domain until its final list membership is gone.

### Sources

Lists can be created from:

- a remote URL;
- an uploaded file;
- pasted rules; or
- a manually maintained domain list.

Supported input formats include:

- one domain per line;
- hosts-file style entries; and
- common DNS-oriented Adblock rules.

Imported domains are normalized before storage. IDNs are stored in ASCII/punycode form, and wildcard-style inputs such as `*.example.com` are normalized to the blockable domain.

A stored entry for `example.com` also matches subdomains such as `ads.example.com`.

### Assignments

Each list can be:

- enabled or disabled;
- applied globally; or
- assigned to individual Networks, Endpoints, and reverse-DNS hostname targets.

Assignments can be managed from either side:

- **Block Lists → Edit & assign** shows every target for a selected block list.
- **Whitelists → Edit & assign** shows every target for a selected whitelist.
- **Policy Targets → Edit & assign** shows both block lists and whitelists for a selected target.

Global lists cannot be redundantly assigned to individual targets while **Apply globally** is enabled.

Assignment and policy changes reload the in-memory policy engine immediately.

### Manual list editor

Manual lists have a dedicated **Manage domains** page with:

- single-domain add and remove;
- search;
- alphabetical sorting;
- pagination; and
- immediate policy reload after changes.

### Automatic URL refresh

Every URL-backed list can have its own automatic refresh interval.

On a successful refresh, Blockinator:

- downloads and parses the source;
- atomically replaces that list's entries;
- updates timestamps and entry counts;
- clears the previous refresh error; and
- reloads the policy engine.

If a download or parse fails, the last known-good list remains active. An upstream response containing no usable domains is rejected rather than replacing a working list with an empty one.

**Save & refresh URL** performs an immediate import and resets that list's refresh interval clock.

The scheduler scan frequency is controlled by:

```env
BLOCKLIST_REFRESH_POLL_SECONDS=30
```

## Scheduling

Recurring weekly schedules can be applied independently to:

- Block Lists;
- Whitelists;
- Networks;
- Endpoints; and
- Reverse-DNS hostname targets.

Each schedule supports:

- selectable weekdays;
- start and end times;
- overnight windows; and
- an IANA timezone such as `America/New_York`.

Selected weekdays represent the day the window **starts**. For example, a Monday `22:00–06:00` schedule remains active through Tuesday at 06:00.

If start and end times are equal, the schedule covers the entire selected day.

When a target is outside its schedule, it is ignored and policy falls back to the next applicable layer. When a paused target has a schedule, its pause applies only while that schedule is active.

**System Settings → Default timezone** controls query-log display and becomes the default timezone for newly created schedules. Existing schedules retain the timezone already saved with them.

## Reverse DNS

Blockinator resolves client PTR records outside the DNS decision path.

Resolved hostnames are used for:

- reverse-DNS hostname policy targets;
- Dashboard client display;
- Query Log client display;
- Endpoint selectors; and
- Query Log client searching.

The asynchronous query logger learns and persists IP-to-hostname identities in the configured database, then updates the in-memory policy cache. A new client may initially use only its IP/network/global policy until its PTR identity has been learned.

Exact hostname targets match one normalized PTR name. A pattern such as:

```text
*.kids.home.arpa
```

matches `tablet.kids.home.arpa`, but not the bare `kids.home.arpa` suffix itself.

For internal reverse zones, custom resolvers can be configured in `.env`:

```env
RDNS_NAMESERVERS=192.168.1.2,192.168.1.3
```

Reverse-DNS identity is only as trustworthy as the resolver and reverse zones providing it, so hostname policy is best suited to networks where you control PTR data.

## Query logging and Dashboard

DNS decisions are written asynchronously so logging does not block the policy path.

The Dashboard shows recent DNS activity, and the full Query Log records:

- timestamp;
- originating DNS server (`server_id`);
- client IP and learned PTR hostname;
- client port;
- DNS transport/protocol;
- whether the policy request arrived over HTTP or HTTPS;
- query name, type, and class;
- allow/block result;
- block reason;
- matched policy target;
- matched policy list; and
- the original request payload for detail inspection.

Allowed queries intentionally leave the **Reason/Match** display blank. Blocked queries show the relevant blocking reason or list.

### Query Log filters

The Query Log supports filtering by information including:

- querying DNS server;
- client IP or partial/full PTR hostname;
- matched policy list; and
- matched policy target.

Policy-target matching is exact, while client hostname filtering supports partial names.

Optional auto-refresh intervals are available at **5, 10, 15, 30, or 60 seconds**. Active filters remain in the URL and are preserved during refresh.

### Retention

Two independent retention controls are available:

- **Maximum age (days)** — `0` disables age-based pruning.
- **Maximum rows** — keeps only the newest configured number of rows.

When both are enabled, both limits apply. Saving new retention settings immediately prunes existing history, and the same limits are enforced as new query batches are written.

Query timestamps are stored in UTC and converted for display using the configured System Settings timezone, including daylight-saving-time handling.

## Administration and security

The administration console includes Dashboard, Block Lists, Policy Targets, Query Log, Access & Security, and System Settings pages with responsive desktop/mobile layouts.

Security features include:

- database-backed administrator accounts;
- salted `scrypt` password hashes;
- database-backed login sessions;
- HTTP-only session cookies;
- automatic Secure cookies when the login arrives over HTTPS;
- CSRF protection for administrative forms;
- configurable administrator session lifetime;
- multiple named API keys;
- API-key enable/disable, rotation, deletion, fingerprints, and last-used timestamps;
- API keys stored only as SHA-256 hashes; and
- an in-memory API-key cache to keep authentication overhead off the hot path.

Bootstrap credentials are used only when the database has no administrator or API-key records. After initialization, manage credentials from **Access & Security**.

## HTTPS and TLS

Blockinator uses a managed **Caddy 2.11.4** sidecar as the host-facing HTTP/HTTPS reverse proxy. The Blockinator application itself remains on the internal Compose network.

Default host ports are:

```text
HTTP   8080
HTTPS  8443
```

They can be changed in `.env`:

```env
POLICY_PORT=80
HTTPS_PORT=443
```

The HTTPS port is published for both TCP and UDP, allowing Caddy to use HTTP/3 where supported.

### TLS modes

Under **System Settings → HTTPS & TLS**, choose one of:

- **HTTP only**
- **Uploaded certificate**
- **ACME / custom ACME server**

Existing installations remain HTTP-only until TLS is configured.

### Uploaded certificates

Blockinator accepts a PEM certificate/full chain and matching unencrypted PEM private key.

Before activation it validates:

- certificate/key match;
- certificate validity period; and
- DNS SAN coverage for the configured HTTPS hostname.

Private key material is stored under `/data/tls` with restrictive filesystem permissions.

### ACME

ACME mode supports:

- account email;
- a configurable ACME directory URL;
- an optional PEM trust root for a private/internal CA; and
- optional External Account Binding (EAB) key ID and HMAC secret.

The EAB HMAC secret is stored as a protected file under `/data/tls`, not in SQLite.

Caddy certificate/account state persists under `./data/caddy`.

For public HTTP-01 or TLS-ALPN-01 validation, the normal public challenge ports generally need to reach Caddy on ports 80 and/or 443. Set `POLICY_PORT=80` and `HTTPS_PORT=443` where required.

DNS-01 provider plugins are not included.

### Safe apply and reconciliation

Blockinator generates native Caddy JSON and loads it atomically through Caddy's Docker-internal admin API.

If a new configuration fails to activate:

- uploaded TLS material is restored; and
- the previous Caddy configuration is re-applied.

The Caddy admin API is not published to the host.

A background reconciler also detects a restarted Caddy instance or changed desired state and restores the saved configuration when needed. In steady state it performs a lightweight health/configuration check without repeatedly reloading unchanged configuration.

The default reconciliation interval is:

```env
TLS_RECONCILE_SECONDS=30
```

### Redirect-only HTTP

After HTTPS is verified, direct HTTP application access can be disabled from the HTTPS-served control panel.

In redirect-only mode:

- the HTTP listener remains open;
- application requests receive **308 Permanent Redirect** to HTTPS;
- path and query string are preserved;
- POST method/body semantics are preserved; and
- non-standard `HTTPS_PORT` values are included in the redirect target.

Keeping the HTTP listener available also allows normal HTTP-to-HTTPS navigation and ACME HTTP challenge traffic.

## System Settings

System Settings is divided into three areas:

### DNS & logs

Controls include:

- NXDOMAIN or REFUSED blocked responses;
- global pause/resume;
- Global list reach;
- unmatched-client Allow/Deny fallback;
- query-log age and row retention; and
- default display/schedule timezone.

### HTTPS & TLS

Controls include:

- TLS mode;
- hostname and certificate identity;
- uploaded certificate/key;
- ACME server configuration;
- private CA trust root;
- EAB;
- redirect-only HTTP; and
- TLS status/error information.

Only controls relevant to the selected TLS mode are submitted.

### Runtime

Shows application, proxy, storage, and current TLS/runtime information.

## Quick start

### 1. Create local configuration

```bash
cp .env.example .env
```

Before first startup, replace at least:

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=replace-with-a-long-random-password
POLICY_API_KEY=change-this-long-random-api-key
```

SQLite is the default:

```env
DATABASE_BACKEND=sqlite
```

To use a remote MySQL 8.x server instead:

```env
DATABASE_BACKEND=mysql
MYSQL_HOST=mysql.example.internal
MYSQL_PORT=3306
MYSQL_DATABASE=blockinator
MYSQL_USER=blockinator
MYSQL_PASSWORD=replace-with-a-long-random-password
```

Blockinator creates the required tables in the selected MySQL database. The database itself and the configured MySQL user must already exist, and that user needs permission to create/alter Blockinator tables, views, indexes, and foreign keys.

Changing `DATABASE_BACKEND` selects a different persistent store on the next startup. It **does not copy or migrate data** between SQLite and MySQL.

### 2. Start Blockinator

```bash
docker compose up -d --build
```

### 3. Open the control panel

With the default ports:

```text
http://DOCKER-HOST:8080/
```

Local application files are stored under:

```text
./data/
```

With `DATABASE_BACKEND=sqlite`, the database is:

```text
./data/policy.db
```

With `DATABASE_BACKEND=mysql`, configuration, credentials, policy data, and query history are stored in the configured remote MySQL database instead. TLS/ACME files remain under `./data`.

On the first startup, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, and `POLICY_API_KEY` seed the database. Once records exist, the values in `.env` no longer replace them.

## Technitium integration

A companion Technitium DNS application can call Blockinator for each DNS request.

Example configuration:

```json
{
  "endpoint": "http://192.168.1.50:8080/api/v1/decision",
  "apiKey": "one-enabled-blockinator-api-key",
  "serverId": "technitium-1",
  "timeoutMs": 250,
  "failMode": "open"
}
```

When HTTPS is enabled, the endpoint can use the configured HTTPS hostname/port instead.

If Technitium and Blockinator share a Docker network and you intentionally want to call the application directly rather than through Caddy:

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
  "matched_domain": "ads.example.com",
  "response_mode": "nxdomain"
}
```

Example whitelist response:

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

Whitelist matches take precedence over block-list matches within the same active policy set.

When multiple DNS questions are supplied, Blockinator evaluates them in order and returns the first blocking decision. If none block, the first allow decision is returned.

## Environment variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `ADMIN_USERNAME` | Bootstrap administrator username | `admin` |
| `ADMIN_PASSWORD` | Bootstrap administrator password | change-me value |
| `POLICY_API_KEY` | Bootstrap API key | change-me value |
| `DATABASE_BACKEND` | Persistent database backend: `sqlite` or `mysql` | `sqlite` |
| `MYSQL_HOST` | Remote MySQL hostname/address | blank |
| `MYSQL_PORT` | Remote MySQL TCP port | `3306` |
| `MYSQL_DATABASE` | MySQL database/schema name | `blockinator` |
| `MYSQL_USER` | MySQL username | `blockinator` |
| `MYSQL_PASSWORD` | MySQL password | blank |
| `MYSQL_CONNECT_TIMEOUT` | MySQL connection timeout in seconds | `10` |
| `MYSQL_SSL_ENABLED` | Request TLS for the MySQL connection | `0` |
| `MYSQL_SSL_CA` | In-container path to optional MySQL CA certificate | blank |
| `MYSQL_SSL_CERT` | In-container path to optional MySQL client certificate | blank |
| `MYSQL_SSL_KEY` | In-container path to optional MySQL client private key | blank |
| `MYSQL_SSL_VERIFY_CERT` | Verify the MySQL server certificate/identity when TLS is used | `1` |
| `POLICY_PORT` | Host-facing HTTP port | `8080` |
| `HTTPS_PORT` | Host-facing HTTPS TCP/UDP port | `8443` |
| `MAX_BLOCKLIST_BYTES` | Maximum accepted block-list size | `104857600` |
| `BLOCKLIST_REFRESH_POLL_SECONDS` | Background due-list scan frequency | `30` |
| `ADMIN_COOKIE_SECURE` | Force Secure admin cookies when appropriate | `0` |
| `ADMIN_SESSION_TTL_SECONDS` | Administrator session lifetime | `43200` |
| `TZ` | Bootstrap/default timezone for a new database | `UTC` |
| `RDNS_NAMESERVERS` | Optional comma-separated PTR resolvers | blank |
| `RDNS_TIMEOUT_SECONDS` | Per-lookup reverse-DNS timeout | `0.5` |
| `RDNS_PAGE_BUDGET_SECONDS` | UI reverse-DNS render budget | `1.25` |
| `RDNS_CACHE_TTL_SECONDS` | Positive PTR cache lifetime | `300` |
| `RDNS_NEGATIVE_TTL_SECONDS` | Negative PTR cache lifetime | `60` |
| `TLS_RECONCILE_SECONDS` | Caddy/TLS reconciliation interval | `30` |

The persisted System Settings timezone becomes authoritative after initialization; changing `TZ` later does not rewrite existing schedule timezones.

## Data and backups

Blockinator always stores TLS/ACME file state under `./data`, but database backups depend on the selected backend.

With SQLite:

```text
./data/policy.db   Configuration, credentials, policy data, and query history
./data/tls/        Uploaded TLS material and protected ACME EAB secret
./data/caddy/      Caddy ACME account and certificate state
```

Back up the entire `./data` directory.

With MySQL:

```text
Remote MySQL       Configuration, credentials, policy data, and query history
./data/tls/        Uploaded TLS material and protected ACME EAB secret
./data/caddy/      Caddy ACME account and certificate state
```

Back up both the remote MySQL database and the local `./data` directory. Blockinator does not automatically synchronize or migrate records between database backends.

For remote MySQL, use a dedicated database/user and restrict network access to the Blockinator host. Enable MySQL TLS when the database connection crosses an untrusted network.

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

Run the test suite with:

```bash
python -m pytest -q
```

The suite covers authentication, persistence/migrations, block-list and whitelist parsing/imports, schedules, policy precedence, reverse-DNS behavior, query logging, settings, TLS configuration, and SQLite/MySQL persistence. CI also runs dedicated integration tests against MySQL 8.4.

## Policy latency benchmark

`tools/benchmark_policy_latency.py` compares the decision API directly against Uvicorn and through the Caddy sidecar using persistent HTTP connections.

Inside the Blockinator container:

```bash
python /srv/tools/benchmark_policy_latency.py --requests 200 --warmup 20
```

CI also runs a smaller smoke benchmark. Results are informational rather than a hard performance threshold because shared runner performance varies.

## Security recommendations

- Replace bootstrap credentials before the first startup.
- Rotate administrator credentials and API keys from **Access & Security** after initialization.
- Prefer HTTPS for the control panel and policy API.
- Keep `./data` private and backed up; when using MySQL, back up the remote database separately.
- Protect internal DNS/PTR data if reverse-DNS hostname policy is used.
- Expose Caddy's public HTTP/HTTPS ports as needed, but do not expose its internal admin API.

## License

Blockinator is licensed under the **GNU General Public License v3.0**. See [LICENSE](LICENSE) for the full license text.
