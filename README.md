<p align="center">
  <img src="app/static/blockinator-hero.webp" alt="Blockinator" width="100%">
</p>

# Blockinator

**Blockinator** is a self-hosted DNS policy-control service designed to sit behind DNS servers such as Technitium DNS Server. It receives DNS request metadata over an authenticated API and returns an allow/block decision based on global policy, network, exact-client, reverse-DNS hostname scopes, and imported block lists.

The application is packaged as a Docker service and includes a responsive, multi-page administration console.

## Features

- Polished Blockinator web console with dashboard, block-list, scope, query-log, security, and settings pages.
- Optional HTTPS termination through a managed Caddy sidecar, with uploaded PEM certificates or ACME issuance.
- Custom ACME directory URLs, private CA root certificates, and External Account Binding (EAB) are supported from System Settings.
- Global pause/resume for DNS blocking.
- Editable policy targets for networks, exact client IPs, and reverse-DNS hostnames, with block-list assignment directly from the Policy Targets page.
- A single Network target can carry dual-stack IPv4 and IPv6 CIDRs concurrently, sharing one state, schedule, and block-list assignment set.
- Reverse-DNS hostname targets support exact PTR names and wildcard suffixes such as `*.kids.home.arpa`.
- Networks, exact endpoints, and reverse-DNS hostname targets can have recurring weekly schedules with selectable days, times, overnight windows, and IANA timezones.
- Policy precedence is exact IP endpoint → reverse-DNS hostname → most-specific network → global policy.
- Multiple independent block lists with URL, upload, and pasted-text imports.
- URL-backed block lists refresh automatically on each list's independently configured interval.
- Block lists are editable directly from the Block Lists page, including name, source URL, format, refresh interval, enabled state, and optional content replacement.
- Manual lists can be edited one domain at a time on a dedicated page, with search, pagination, add, and remove controls.
- Per-list global assignment plus editable per-network/per-client/per-hostname assignments from the same Block Lists screen.
- Recurring weekly enforcement schedules per block list, with selectable days, start/end times, overnight windows, and IANA timezones.
- Hosts-file, one-domain-per-line, and common DNS-oriented Adblock rule parsing.
- Database-backed administrator credentials with salted `scrypt` password hashes.
- Database-backed login sessions, HTTP-only cookies, and CSRF-protected admin forms.
- Multiple named API keys with enable/disable, rotation, deletion, fingerprints, and last-used timestamps.
- API keys stored only as SHA-256 hashes.
- In-memory API-key cache keeps the DNS decision path lightweight.
- Query audit log with filtering and full request-detail inspection, including the querying DNS server on every log row.
- Client filter accepts either an IP address or reverse-DNS hostname, including partial hostname matches.
- Configurable row-count and time-based query-log retention, enforced together with immediate pruning when settings change.
- Reverse-DNS client names displayed alongside client IP addresses, with bounded lookups and caching.
- SQLite persistence and automatic schema migration.

## System Settings layout

System Settings is organized into three tabs:

- **DNS & logs** — blocked-response behavior, query-log retention, and default timezone.
- **HTTPS & TLS** — HTTP-only, uploaded-certificate, and ACME configuration.
- **Runtime** — application, proxy, storage, and current TLS status.

The HTTPS & TLS tab shows only the controls required for the currently selected setup type. Hidden modes are also disabled, so irrelevant fields are not submitted with the form.

## HTTPS, uploaded certificates, and ACME

The `acme-tls` branch adds a Caddy sidecar in front of Blockinator. Blockinator itself continues to listen only on the Docker-internal HTTP port, while Caddy owns the host-facing HTTP and HTTPS ports.

Default port mappings are:

```text
HTTP   host:8080 -> Caddy:80
HTTPS  host:8443 -> Caddy:443
```

Change these in `.env` when desired:

```env
POLICY_PORT=80
HTTPS_PORT=443
```

Existing installations remain in **HTTP only** mode after upgrade.

Open **System Settings → HTTPS & certificates** to select one of three modes:

- **HTTP only** — no TLS listener is configured.
- **Uploaded certificate** — upload a PEM certificate/full-chain and matching unencrypted PEM private key.
- **ACME / custom ACME server** — let Caddy issue and renew the certificate automatically.

Uploaded certificates are validated before activation. Blockinator verifies that the certificate and private key match, checks the validity period, and confirms that the configured HTTPS hostname is covered by the certificate's DNS SANs. The private key is stored under `/data/tls` with restrictive filesystem permissions.

ACME mode supports:

- account email;
- a configurable ACME directory URL;
- an optional PEM root certificate for a private/internal ACME CA;
- optional External Account Binding (EAB) key ID and HMAC secret.

The EAB HMAC secret is stored as a protected file under `/data/tls`; it is not stored in SQLite. Caddy configuration persistence is disabled so the generated Caddy configuration is not autosaved with the EAB secret embedded. Caddy's certificate storage under `./data/caddy` remains persistent for normal ACME account/certificate lifecycle data.

Blockinator generates native Caddy JSON and submits it atomically through Caddy's internal `/load` API. Caddy validates the candidate before activation; if activation fails, uploaded TLS material is restored and the previous configuration is re-applied. The Caddy admin API is available only on the Compose network and is not published to the host.

A background TLS state check detects an independent Caddy restart or a changed desired configuration. In steady state it performs only a lightweight read and does **not** reload Caddy or rewrite TLS status timestamps. Its default interval is 30 seconds:

```env
TLS_RECONCILE_SECONDS=30
```

TLS settings are read/written in batches, repeated errors are de-duplicated, and certificate parsing dependencies are loaded only when X.509 work is actually required. Applying TLS settings runs outside FastAPI's async request loop so a slow Caddy operation cannot stall the DNS decision API.

For public ACME HTTP-01/TLS-ALPN-01 validation, the public challenge ports normally need to reach Caddy on standard ports 80 and/or 443. Set `POLICY_PORT=80` and `HTTPS_PORT=443` where required. DNS-01 provider plugins are intentionally not included in this first implementation.

### Redirect-only HTTP

After HTTPS is working, **System Settings → HTTPS & certificates** can disable direct HTTP access while leaving the HTTP listener available for redirects.

The switch can only be changed while the control panel itself is being accessed over HTTPS. This prevents an administrator from enabling redirect-only mode before verifying that HTTPS is reachable.

When enabled:

- requests arriving on the HTTP port receive a **308 Permanent Redirect** to the configured HTTPS hostname;
- the original path and query string are preserved;
- POST requests keep their method/body semantics across the redirect;
- redirects include the configured external `HTTPS_PORT` when it is not the standard port 443; and
- the Docker HTTP port remains open so browsers, API clients, and ACME HTTP challenge traffic can still reach Caddy.

For example, with:

```env
POLICY_PORT=8080
HTTPS_PORT=8443
```

a request to:

```text
http://blockinator.example.com:8080/api/v1/decision
```

is redirected to:

```text
https://blockinator.example.com:8443/api/v1/decision
```

With `HTTPS_PORT=443`, the redirect omits the explicit port.

Administrator session cookies automatically become Secure when the request arrives through HTTPS. Blockinator trusts forwarding headers from its internal reverse proxy so the application can correctly detect the original scheme.

## Quick start

```bash
cp .env.example .env
# Set strong bootstrap values in .env before first startup.
docker compose up -d --build
```

Open:

```text
http://DOCKER-HOST:8080/
```

Persistent application data is stored under:

```text
./data/policy.db
```

The first startup seeds the database administrator and initial API key using `ADMIN_USERNAME`, `ADMIN_PASSWORD`, and `POLICY_API_KEY` from `.env`. Once records exist in SQLite, credentials and API keys are managed from **Access & Security** in the UI.

## Repository layout

```text
.
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
├── app/
│   ├── main.py
│   ├── auth.py
│   ├── policy.py
│   ├── blocklists.py
│   ├── tls.py
│   ├── db.py
│   └── static/
├── caddy/
│   └── caddy.bootstrap.json
├── docs/
│   └── ACME_TLS_PLAN.md
└── tests/
```


## Policy proxy latency benchmark

The repository includes `tools/benchmark_policy_latency.py` to compare the decision API directly against Uvicorn and through the Caddy sidecar using persistent HTTP connections.

Inside the Blockinator container:

```bash
python /srv/tools/benchmark_policy_latency.py --requests 200 --warmup 20
```

CI runs a shorter smoke benchmark after starting the real Compose stack. The benchmark is informational rather than a hard performance threshold because shared CI runners vary. On the optimization validation run, 50 requests averaged about **0.431 ms direct** and **0.592 ms through Caddy**, roughly **0.16 ms mean proxy overhead**.

## Decision API

Blockinator exposes an authenticated policy endpoint:

```text
POST /api/v1/decision
X-Api-Key: <enabled Blockinator API key>
```

Health/authentication check:

```bash
curl -i \
  -H 'X-Api-Key: YOUR_KEY' \
  http://DOCKER-HOST:8080/api/v1/ping
```

Example decision request:

```json
{
  "server_id": "technitium-1",
  "protocol": "Udp",
  "client": {"ip": "192.168.20.44", "port": 53012},
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
      {"name": "ads.example.com", "type": "A", "class": "IN"}
    ]
  }
}
```

Example response:

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






## Dual-stack network targets

A single **Network** policy target can contain an IPv4 CIDR, an IPv6 CIDR, or both at the same time.

For example:

```text
Name: Home LAN
IPv4 CIDR: 192.168.50.0/24
IPv6 CIDR: 2001:db8:50::/64
```

Both address families share the same:

- Active/Paused state;
- recurring schedule;
- block-list assignments; and
- display name.

Blockinator evaluates the most-specific matching network independently for the client's address family. An IPv4 query is compared against IPv4 members of network targets, and an IPv6 query is compared against IPv6 members. This means a dual-stack network can coexist with a more-specific IPv4-only or IPv6-only network without changing precedence behavior.

Existing single-stack Network targets are migrated automatically into the new address-family storage. They remain single-stack until you add the other CIDR in **Policy Targets → Edit & assign**.

## Reverse-DNS hostname policy targets

The **Policy Targets** page supports a third target type in addition to Network and Endpoint: **Reverse-DNS Hostname**.

Examples:

```text
desktop-01.home.arpa
*.kids.home.arpa
```

An exact hostname target matches one learned PTR name. A leading `*.` creates a suffix target and matches names below that suffix, such as `tablet.kids.home.arpa`. The wildcard does not match the bare suffix `kids.home.arpa`.

Hostname targets support the same controls as network and endpoint targets:

- Active/Paused state;
- recurring enforcement schedules;
- per-target block-list assignments;
- editing and deletion from the Policy Targets page; and
- assignment from the Block Lists page.

Policy state precedence is:

1. Global pause.
2. Exact client-IP endpoint.
3. Reverse-DNS hostname.
4. Most-specific matching network.
5. Default/global policy.

Block-list assignments remain additive: enabled global lists plus matching network, hostname, and exact-client assignments form the active set, subject to their schedules.

### PTR identity learning

PTR resolution remains outside the DNS decision path. The asynchronous query-log worker resolves client addresses, normalizes the PTR hostname, stores the IP→hostname identity in SQLite, and updates the in-memory policy cache.

This means a completely new client may initially use its IP/network/global policy until Blockinator has learned its PTR name. Once learned, subsequent requests can match hostname policy without waiting on a reverse lookup. Learned identities persist across restarts and are refreshed when successful PTR lookups return a new name.

Hostname identity is only as trustworthy as the reverse-DNS service supplying it. It is best suited to internal DNS environments where you control the reverse zones.

## Network and endpoint schedules

Networks, endpoints, and reverse-DNS hostname targets support the same recurring weekly schedule model as block lists.

Open **Policy Targets → Edit & assign → Enforcement schedule** to configure:

- one or more days of the week;
- start and end times;
- an IANA timezone such as `America/New_York`; and
- whether scheduling is enabled.

When scheduling is off, the scope participates in policy at all times. When scheduling is on, the scope only participates during its active window.

This is important for precedence:

- an endpoint outside its schedule is ignored, so hostname/network policy can apply;
- a hostname target outside its schedule is ignored, so network/global policy can apply;
- a network outside its schedule is ignored, allowing a broader matching network or global policy to apply;
- a **Paused** target with a schedule only pauses blocking during that schedule; outside the window, normal fallback policy applies.

Overnight behavior matches block-list schedules: selected days are the days the window begins. A Monday `22:00–06:00` schedule remains active until Tuesday 06:00. Equal start/end times cover the full selected day.

## Editing networks and endpoints

The **Policy Targets** page provides the reverse view of block-list assignments. Open **Edit & assign** on any scope to change:

- display name;
- scope type (**Network**, **Endpoint**, or **Reverse-DNS Hostname**);
- IPv4/IPv6 CIDRs for Network targets, exact IPv4/IPv6 address, exact PTR hostname, or wildcard PTR suffix;
- active/paused blocking state; and
- every block list explicitly assigned to that scope.

A target can be converted among Network, Endpoint, and Reverse-DNS Hostname. Network targets expose separate IPv4 and IPv6 CIDR fields and require at least one address family.

The block-list picker shows each list's enabled state, entry count, format, and whether it is already global. Global lists apply automatically everywhere, so their per-scope assignment checkbox is shaded and disabled. Scoped lists remain selectable normally.

New networks, endpoints, and hostname targets can also receive their initial block-list assignments during creation. All edits reload the in-memory policy engine immediately.


## Manual list domain editor

Manual block lists have a dedicated **Manage domains** action on the Block Lists page.

The separate editor supports:

- adding one domain at a time;
- removing one domain at a time;
- searching the current list;
- alphabetical sorting;
- pagination for larger manual lists; and
- immediate policy-engine reload after every add/remove operation.

Domains are normalized with the same Blockinator parser used for imports. For example, `*.example.com` is stored as `example.com`, and IDNs are stored in ASCII/punycode form.

Only lists whose source type is **manual** expose this editor. URL-backed and uploaded lists remain managed through their normal source/import workflow.




### Log timestamp timezone

Query-log timestamps are stored in UTC for stable ordering and retention, then converted for display using **System Settings → Default timezone**.

This applies to both the Dashboard's recent DNS activity and the full Query Log. The displayed timestamp includes the active timezone abbreviation, such as `EDT` or `EST`, and automatically follows daylight-saving-time rules for the configured IANA timezone.

Older rows written by SQLite as timezone-less `CURRENT_TIMESTAMP` values are also interpreted as UTC before display conversion.

### Default schedule timezone

**System Settings** includes a **Default timezone** field. Enter any valid IANA timezone such as `America/New_York`.

The saved system timezone is used for query-log display and to prefill the timezone for newly created block-list and policy-target schedules. Changing it does not rewrite existing schedules; each existing schedule keeps the timezone already saved with it.

The `TZ` environment value remains a bootstrap/fallback value. On a new database, Blockinator seeds the persisted default timezone from `TZ`; after that, changes made in System Settings remain authoritative across restarts.

## Block-list enforcement schedules

Each block list can optionally be limited to a recurring weekly schedule from **Block Lists → Edit & assign → Enforcement schedule**.

A schedule includes:

- one or more days of the week;
- a start time;
- an end time; and
- an IANA timezone such as `America/New_York`.

When scheduling is disabled, the list behaves normally and is eligible for enforcement at all times. When scheduling is enabled, the list participates in policy decisions only while its window is active.

Selected days represent the day the window **starts**. This makes overnight schedules intuitive. For example:

```text
Days: Monday-Friday
Start: 22:00
End: 06:00
Timezone: America/New_York
```

enforces from 10:00 PM Monday through 6:00 AM Tuesday, and repeats for each selected start day. A Friday 22:00 window therefore remains active until Saturday 06:00.

If start and end are equal—for example `00:00–00:00`—the schedule covers the entire selected day.

Timezone conversion uses Python's IANA timezone database and observes daylight-saving-time changes. The optional `TZ` value in `.env` controls the default timezone offered when creating a new schedule; each block list stores its own timezone after it is saved.

Schedules apply equally to Global lists and lists assigned only to specific networks/endpoints. A list outside its schedule is treated as inactive for that DNS decision.


## Automatic URL block-list refresh

URL-backed block lists are refreshed automatically in the background using each list's own **Automatic refresh interval (minutes)** value on the Block Lists page.

For example, these can coexist independently:

```text
Advertising list     60 minutes
Malware list         15 minutes
Telemetry list     1440 minutes
```

The background scheduler checks for due lists periodically and refreshes only those whose configured interval has elapsed. The default scheduler scan frequency is 30 seconds, so a list normally refreshes within roughly one scheduler scan after becoming due.

On a successful refresh, Blockinator:

- downloads the configured source URL;
- parses it using that list's selected format;
- atomically replaces that list's domain entries;
- updates the entry count and refresh timestamps;
- clears any prior refresh error; and
- reloads the in-memory policy engine.

A failed download or parse **does not remove the last known-good list**. Blockinator stores the error, records the attempt time, and waits for that list's configured interval before trying again. An upstream response containing no usable domains is also rejected rather than replacing a working list with an empty one.

Using **Save & refresh URL** performs an immediate refresh and resets the same interval clock, preventing an automatic refresh from immediately following a manual one.

Automatic refresh applies only to URL-backed lists. Uploaded and manual lists are not scheduled for remote refresh.

The scheduler's internal scan frequency can be adjusted with:

```text
BLOCKLIST_REFRESH_POLL_SECONDS=30
```

This controls how often Blockinator checks whether lists are due; it does not replace the per-list refresh interval.

## Editing block lists and scope assignments

The **Block Lists** page is now the central place to manage both list settings and where each list applies.

Open **Edit & assign** on any list to change:

- list name and parser format;
- source URL and refresh interval;
- enabled/disabled state;
- whether the list applies globally;
- assigned network scopes;
- assigned exact-client/endpoint and reverse-DNS hostname scopes; and
- list contents by uploading or pasting replacement rules.

For URL-backed lists, **Save & refresh URL** saves the edited metadata and immediately re-imports the list from the configured URL.

Global and scoped assignments are mutually exclusive in the UI. When a list is marked **Global**, individual network/endpoint/hostname assignment controls are shaded and disabled because the list already applies everywhere. Unchecking **Apply globally** immediately re-enables the scope selectors. Global lists cannot be assigned redundantly to individual scopes. Assignment changes reload the in-memory policy engine immediately.

## Policy precedence

Blocking state is evaluated in this order:

1. Global pause: all clients are allowed.
2. Exact client-IP endpoint.
3. Matching reverse-DNS hostname scope.
4. Most-specific matching network scope.
5. No matching scope: blocking remains active by default.

The active block-list set is the union of enabled global lists and lists assigned to every matching active layer: network, reverse-DNS hostname, and exact client.




### Reverse-DNS log filtering

The **Query Log → Client** filter matches either the client IP address or its persisted PTR/reverse-DNS hostname. Full or partial hostname searches work, so both `desktop-01` and `desktop-01.home.arpa` can match the same client.

PTR lookups remain outside the DNS decision path. New query-log rows are enriched asynchronously by the log writer, and older retained rows are backfilled opportunistically as their client identities are displayed or searched.

### Querying server identity

Every DNS log view includes the `server_id` supplied by the Technitium plugin, so deployments with multiple DNS resolvers can immediately see which server received each client request. The Dashboard recent-activity table and full Query Log both show the originating DNS server, and the Query Log can be filtered by server.

If an older or custom client submits a request without `server_id`, Blockinator displays **Unknown server** rather than hiding the field.


## Query log retention

Blockinator supports two independent query-log retention limits under **System Settings**:

- **Maximum age (days)** — removes query-log rows older than the configured age. Set this to `0` to disable time-based retention.
- **Maximum rows** — retains only the newest configured number of query-log rows.

When both limits are enabled, **both apply**. A row is removed as soon as it exceeds either threshold. For example, with a 30-day age limit and a 250,000-row cap, Blockinator retains no more than 30 days and no more than 250,000 rows.

Changing retention settings triggers an immediate prune of existing log history. The same retention rules are also applied automatically as new query-log batches are written.

Existing installations preserve their prior behavior after upgrade because time-based retention defaults to `0` (disabled) until you choose an age limit.

## Reverse DNS client names

Blockinator performs PTR lookups for client IP addresses shown in the administration UI. Resolved names appear above the original IP address on the Dashboard, Query Log, and exact client scopes.

By default, PTR lookups use the container's normal DNS configuration. If your local reverse zones are hosted by Technitium or another internal resolver and Docker's resolver cannot reach them directly, set one or more DNS server IPs in `.env`:

```text
RDNS_NAMESERVERS=192.168.1.2
```

Multiple resolvers can be comma-separated:

```text
RDNS_NAMESERVERS=192.168.1.2,192.168.1.3
```

Lookups are intentionally kept off the DNS decision path. The defaults use a 0.5-second lookup timeout, a 1.25-second page-render budget, a five-minute positive cache, and a one-minute negative cache. These can be adjusted with `RDNS_TIMEOUT_SECONDS`, `RDNS_PAGE_BUDGET_SECONDS`, `RDNS_CACHE_TTL_SECONDS`, and `RDNS_NEGATIVE_TTL_SECONDS`.

## Technitium integration

The companion Technitium DNS application should point its policy endpoint at this container, for example:

```json
{
  "endpoint": "http://192.168.1.50:8080/api/v1/decision",
  "apiKey": "one-enabled-blockinator-api-key",
  "serverId": "technitium-1",
  "timeoutMs": 250,
  "failMode": "open"
}
```

If Technitium and Blockinator share a Docker network, use the Compose service name:

```json
"endpoint": "http://blockinator:8080/api/v1/decision"
```

## Security notes

- Use a long random bootstrap password and API key before first startup.
- Once the database has been initialized, rotate credentials through **Access & Security**.
- Set `ADMIN_COOKIE_SECURE=1` when the panel is served exclusively over HTTPS.
- API secrets are shown only when created or rotated; only hashes are stored.
- Keep `./data/` private and backed up.

## Testing

```bash
python -m pytest -q
```

Current suite: **59 tests** covering authentication, block-list parsing/import behavior, and policy decisions.

## Branding

The Blockinator logo, mark, hero art, and UI styling are stored under `app/static/` and are bundled into the Docker image.
