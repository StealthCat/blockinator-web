# Operations and configuration

[Back to README](../README.md)

Applies to the current source version. For installation, use the [README](../README.md) or [Docker Hub guide](INSTALLATION.md).

## Database backends

### SQLite

SQLite is the default and requires no extra infrastructure.

Blockinator uses WAL mode, batched query logging, and serialized list-refresh commits to reduce lock contention.

### MySQL

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
application's tables, indexes, views, and foreign keys. Pooling and TLS controls are described below. In a container, `localhost` refers to that container,
not the Docker host or another MySQL container.

With MySQL, configuration, credentials, policy data, and query history live in the
remote database; retain local `/data` storage for TLS material. Changing
`DATABASE_BACKEND` selects a different store and does not migrate existing data.
Use the [offline migration procedure](#offline-database-migration) when switching.

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

Run the migration from the repository root with Python 3.12 and dependencies from `requirements.txt` installed (see [development setup](DEVELOPMENT.md#testing)). The script reads exported MySQL variables or command-line options; it does not automatically load `.env`.

**Back up both databases first: the destination is cleared. Blockinator must be stopped for the entire migration.** The tool requires `--confirm-offline` before it will write anything. The destination database is initialized with the current Blockinator schema, cleared, populated in foreign-key-safe order, then verified with row counts and SHA-256 table-content digests.

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

Derived statistics are rebuilt after source tables have been copied and verified. After a successful migration, set `DATABASE_BACKEND` to the destination type before restarting Blockinator.

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

The built-in TLS configuration does not provide DNS-01 provider plugins, external secret-manager integration, or client-certificate authentication. MySQL client-certificate TLS is a separate database feature. For public ACME issuance, make the chosen CA's challenge ports reachable; a nonstandard public HTTPS port alone does not satisfy standard port 80/443 challenges.

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
| `BLOCKLIST_PRIVATE_HOSTS` | Comma-separated exact hosts/CIDRs allowed for private list downloads | blank |
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

The table describes the supplied Compose deployment. `MYSQL_DATABASE` and `MYSQL_USER` default to `blockinator` in Compose; direct application launches must supply them for MySQL. Only variables explicitly passed in `docker-compose.yml` reach the container; adding arbitrary keys to `.env` alone does not pass them through.

Additional container/runtime settings:

| Variable | Purpose | Default |
| --- | --- | --- |
| `DATA_DIR` | Application data and SQLite directory | `/data` |
| `CADDY_ADMIN_URL` | Internal managed Caddy API; never expose publicly | `http://caddy:2019` |
| `WEB_BIND` | Uvicorn bind address in the Docker image | `0.0.0.0` |
| `WEB_PORT` | Uvicorn port in the Docker image | `8080` |
| `FORWARDED_ALLOW_IPS` | Trusted proxy peers in the Docker entrypoint | `*` for the private Compose network |

Standalone Docker examples restrict forwarded-header trust to loopback. Behind your own proxy, set its trusted addresses explicitly. `WEB_PORT` changes also require matching health-check and proxy configuration; `POLICY_PORT` is only the Compose host HTTP mapping.

The persisted System Settings timezone becomes authoritative after initialization; changing `TZ` later does not rewrite existing schedule timezones.

## Data and backups

### SQLite backups

```text
./data/policy.db   Configuration, credentials, policy data, and query history
./data/tls/        Uploaded TLS material and protected ACME EAB secret
./data/caddy/      Caddy ACME account and certificate state
```

Stop the stack before a filesystem copy of SQLite and back up the full `./data` directory plus `.env`. Keep any WAL/SHM files with the database if present; do not copy only a live `policy.db`. For standalone Docker, back up the mounted `blockinator-data` volume instead of a host `./data` directory.

### MySQL backups

```text
Remote MySQL       Configuration, credentials, policy data, and query history
./data/tls/        Uploaded TLS material and protected ACME EAB secret
./data/caddy/      Caddy ACME account and certificate state
```

Back up both the remote MySQL database and local `./data`, plus `.env`. Protect backup copies because they contain authentication and TLS material.

Blockinator does not automatically synchronize database backends while running. Use `tools/migrate_database.py` while Blockinator is offline to perform a verified one-time migration.

## Operational protections and monitoring

- Console reads and administrator writes each have a separate four-thread pool with up to 12 admitted requests. Saturation returns HTTP 503 with `Retry-After`; policy workers remain separate. Sign-in attempts are limited to 10 per peer and 100 globally per minute (HTTP 429). Configure trusted proxy forwarding correctly so peers are identified accurately.
- Session cookies preserve HTTPS/`ADMIN_COOKIE_SECURE` settings after credential changes. New API keys appear only in the creating POST response with `Cache-Control: no-store` and no-referrer protection; copy them before leaving the page.
- List downloads accept only HTTP(S). Every connection, including redirects, validates resolved addresses and connects to those exact addresses. Private/local destinations require explicit `BLOCKLIST_PRIVATE_HOSTS` entries (comma-separated exact hostnames or CIDRs). Example: `feeds.internal,10.20.0.0/16`. Environment HTTP proxies are intentionally ignored for these downloads. Uploads and pasted lists obey `MAX_BLOCKLIST_BYTES` too.
- Policy rebuild writers are serialized; decisions continue using the current snapshot. List creation/replacement commits metadata, assignments and membership together. Changing source URL/format clears conditional-download validators so the next refresh reparses the source.
- Query logging stays asynchronous. Confirmed pre-commit failures receive up to three write attempts. Ambiguous commits are counted as uncertain and never replayed, preventing duplicates. Shutdown allows up to five seconds to drain; logging is best-effort and cannot guarantee delivery during process termination or prolonged database outages.
- `/healthz` reports process liveness. `/readyz` reports policy readiness and returns 503 following a failed reload. The administrator-session-authenticated `/api/v1/runtime` endpoint (a resolver API key alone is insufficient) and **System Settings → Runtime** expose policy generation, logger queue/drop/failure metrics, and background worker state. Monitoring should alert on worker stoppage, errors, drops and uncertain writes separately from policy readiness.
- Statistics snapshots are shared for five seconds per window/timezone. Query Log refresh requests only authenticated row fragments, avoiding repeated filter-option scans. Statistics refreshes time out after 15 seconds and resume after browser back/forward restoration.

Dashboard warnings surface pending rebuilds, dropped or uncertain log writes, failed/overdue URL refreshes, and stopped workers. A failed rebuild retries automatically while decisions continue using the previous policy snapshot. Readiness and logger health are separate signals.

## Retained statistics and maintenance

Totals and minute summaries describe retained log rows, not lifetime activity. Pruning reduces both history and counters; ignored-only requests are excluded. Existing installations receive a one-time startup backfill, which may take longer with large databases.

SQLite triggers maintain summaries. MySQL application writes and pruning maintain them in the same transaction, without creating triggers or requiring server-level SUPER privileges. The offline migration tool rebuilds summaries after import. If you manually change MySQL query history outside Blockinator, rebuild counters while Blockinator is stopped using the same database environment:

```python
from app.db import Database
from app.rollups import rebuild_rollups

db = Database()
with db.connect() as connection:
    rebuild_rollups(connection)
```

Run one application process. Policy snapshots, cache state, and background workers are process-local; do not add Uvicorn workers or replicas without cross-process coordination.

## Security recommendations

- Replace bootstrap credentials before first startup.
- Rotate administrator credentials and API keys from **Access & Security**.
- Prefer HTTPS for both the control panel and policy API.
- Keep `./data` private and backed up.
- Back up the remote database separately when using MySQL.
- Protect PTR/reverse-DNS infrastructure if hostname-based policy is enabled.
- Do not expose Caddy's internal admin API.
- Use MySQL TLS when the database connection crosses an untrusted network.
