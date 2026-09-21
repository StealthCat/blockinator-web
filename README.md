<p align="center">
  <img src="app/static/blockinator-hero.webp" alt="Blockinator" width="100%">
</p>

# Blockinator

**Blockinator** is a self-hosted DNS policy-control service designed to sit behind DNS servers such as Technitium DNS Server. It receives DNS request metadata over an authenticated API and returns an allow/block decision based on global policy, network/client scopes, and imported block lists.

The application is packaged as a Docker service and includes a responsive, multi-page administration console.

## Features

- Polished Blockinator web console with dashboard, block-list, scope, query-log, security, and settings pages.
- Global pause/resume for DNS blocking.
- Editable IPv4/IPv6 CIDR network scopes and exact client-IP endpoint scopes, with block-list assignment directly from the Networks & Endpoints page.
- Client rules can override network pause/resume state.
- Multiple independent block lists with URL, upload, and pasted-text imports.
- Block lists are editable directly from the Block Lists page, including name, source URL, format, refresh interval, enabled state, and optional content replacement.
- Manual lists can be edited one domain at a time on a dedicated page, with search, pagination, add, and remove controls.
- Per-list global assignment plus editable per-network/per-client assignments from the same Block Lists screen.
- Hosts-file, one-domain-per-line, and common DNS-oriented Adblock rule parsing.
- Database-backed administrator credentials with salted `scrypt` password hashes.
- Database-backed login sessions, HTTP-only cookies, and CSRF-protected admin forms.
- Multiple named API keys with enable/disable, rotation, deletion, fingerprints, and last-used timestamps.
- API keys stored only as SHA-256 hashes.
- In-memory API-key cache keeps the DNS decision path lightweight.
- Query audit log with filtering and full request-detail inspection, including the querying DNS server on every log row.
- Reverse-DNS client names displayed alongside client IP addresses, with bounded lookups and caching.
- SQLite persistence and automatic schema migration.

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
│   ├── db.py
│   └── static/
└── tests/
```

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



## Editing networks and endpoints

The **Networks & Endpoints** page provides the reverse view of block-list assignments. Open **Edit & assign** on any scope to change:

- display name;
- scope type (**Network** or **Endpoint**);
- CIDR or exact IPv4/IPv6 address;
- active/paused blocking state; and
- every block list explicitly assigned to that scope.

A scope can be converted between Network and Endpoint; Blockinator validates the address against the newly selected type when the change is saved.

The block-list picker shows each list's enabled state, entry count, format, and whether it is already global. Global lists apply automatically everywhere, so their per-scope assignment checkbox is shaded and disabled. Scoped lists remain selectable normally.

New networks/endpoints can also receive their initial block-list assignments during creation. All edits reload the in-memory policy engine immediately.


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

## Editing block lists and scope assignments

The **Block Lists** page is now the central place to manage both list settings and where each list applies.

Open **Edit & assign** on any list to change:

- list name and parser format;
- source URL and refresh interval;
- enabled/disabled state;
- whether the list applies globally;
- assigned network scopes;
- assigned exact-client/endpoint scopes; and
- list contents by uploading or pasting replacement rules.

For URL-backed lists, **Save & refresh URL** saves the edited metadata and immediately re-imports the list from the configured URL.

Global and scoped assignments are mutually exclusive in the UI. When a list is marked **Global**, individual network/endpoint assignment controls are shaded and disabled because the list already applies everywhere. Unchecking **Apply globally** immediately re-enables the scope selectors. Global lists cannot be assigned redundantly to individual scopes. Assignment changes reload the in-memory policy engine immediately.

## Policy precedence

Blocking state is evaluated in this order:

1. Global pause: all clients are allowed.
2. Exact client scope: overrides a containing network's pause/resume state.
3. Most-specific matching network scope.
4. No matching scope: blocking remains active by default.

The active block-list set is the union of enabled global lists, lists assigned to the most-specific matching network, and lists assigned to the exact client.



### Querying server identity

Every DNS log view includes the `server_id` supplied by the Technitium plugin, so deployments with multiple DNS resolvers can immediately see which server received each client request. The Dashboard recent-activity table and full Query Log both show the originating DNS server, and the Query Log can be filtered by server.

If an older or custom client submits a request without `server_id`, Blockinator displays **Unknown server** rather than hiding the field.

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

Current suite: **11 tests** covering authentication, block-list parsing/import behavior, and policy decisions.

## Branding

The Blockinator logo, mark, hero art, and UI styling are stored under `app/static/` and are bundled into the Docker image.
