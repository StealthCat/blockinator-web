<p align="center">
  <img src="policy-server/app/static/assets/blockinator-hero.webp" alt="Blockinator" width="100%">
</p>

# Blockinator

**Blockinator** is a self-hosted DNS policy-control service designed to sit behind DNS servers such as Technitium DNS Server. It receives DNS request metadata over an authenticated API and returns an allow/block decision based on global policy, network/client scopes, and imported block lists.

The application is packaged as a Docker service and includes a responsive, multi-page administration console.

## Features

- Polished Blockinator web console with dashboard, block-list, scope, query-log, security, and settings pages.
- Global pause/resume for DNS blocking.
- IPv4/IPv6 CIDR policy scopes and exact client-IP scopes.
- Client rules can override network pause/resume state.
- Multiple independent block lists with URL, upload, and pasted-text imports.
- Per-list global assignment plus per-network/per-client assignments.
- Hosts-file, one-domain-per-line, and common DNS-oriented Adblock rule parsing.
- Database-backed administrator credentials with salted `scrypt` password hashes.
- Database-backed login sessions, HTTP-only cookies, and CSRF-protected admin forms.
- Multiple named API keys with enable/disable, rotation, deletion, fingerprints, and last-used timestamps.
- API keys stored only as SHA-256 hashes.
- In-memory API-key cache keeps the DNS decision path lightweight.
- Query audit log with filtering and full request-detail inspection.
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

## Docker layout

```text
.
├── docker-compose.yml
├── .env.example
└── policy-server/
    ├── Dockerfile
    ├── requirements.txt
    ├── app/
    │   ├── main.py
    │   ├── auth.py
    │   ├── policy.py
    │   ├── blocklists.py
    │   ├── db.py
    │   ├── templates/
    │   └── static/
    │       └── assets/
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

## Policy precedence

Blocking state is evaluated in this order:

1. Global pause: all clients are allowed.
2. Exact client scope: overrides a containing network's pause/resume state.
3. Most-specific matching network scope.
4. No matching scope: blocking remains active by default.

The active block-list set is the union of enabled global lists, lists assigned to the most-specific matching network, and lists assigned to the exact client.

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

If Technitium and Blockinator share a Docker network, use the compose service name:

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
cd policy-server
python -m pytest -q
```

Current suite: **8 tests** covering authentication, block-list parsing/import behavior, and policy decisions.

## Branding

The Blockinator logo, mark, hero art, and splash art used by the application are stored under `policy-server/app/static/assets/` and are bundled into the Docker image with the rest of the web application.
