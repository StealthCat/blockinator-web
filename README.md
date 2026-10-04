<p align="center">
  <img src="app/static/blockinator-mark.svg" alt="Blockinator" width="112" height="112">
</p>

# Blockinator

Self-hosted DNS policy management with block lists, whitelists, schedules, and query history. Your DNS server sends query metadata; Blockinator returns an allow/block decision. Connect Technitium using the [companion plugin](https://github.com/StealthCat/blockinator-technitium).

Current source version: **1.20.11** · [Changelog](CHANGELOG.md) · [Releases](https://github.com/StealthCat/blockinator-web/releases)

## Features

- Target IPv4/IPv6 networks, individual clients, or PTR hostnames, with whitelist precedence and timezone-aware schedules.
- Import lists from URLs, files, or pasted rules, or manage domains manually.
- Explain decisions with Policy Tester; search query history and view traffic and response-time statistics.
- Use SQLite or MySQL, managed HTTPS through Caddy, administrator accounts, and named API keys.
- Choose system, dark, or light themes in a responsive management console.

## Quick start: Git clone and Docker Compose (recommended)

Build from stable `main` with Docker Compose. You need Docker Engine, Compose v2, Git, Bash, and OpenSSL on the Docker host. Use `sudo` for Docker if required.

### 1. Clone the repository

```bash
git clone https://github.com/StealthCat/blockinator-web.git
cd blockinator-web
```

### 2. Create first-run credentials

For a new installation, run this Bash block. It generates private credentials and refuses to overwrite an existing `.env`:

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

Keep `.env` private; view it locally with `cat .env` to retrieve your credentials. Set `TZ` to your IANA timezone and see [.env.example](.env.example) for other options. If choosing your own credentials, use a unique password of at least 12 characters and API key of at least 24 characters. Existing database credentials are managed in **Access & Security**, not reset through `.env`.

### 3. Build and start Blockinator

```bash
docker compose up -d --build
```

SQLite is the default. For MySQL, complete [database setup](docs/OPERATIONS.md#mysql) before starting. Preserve `.env` and `./data`, which contains SQLite data, TLS files, and Caddy state.

### 4. Open and configure Blockinator

Open **`http://DOCKER-HOST:8080/`** and sign in as `admin` with the password from `.env`.

1. Add block lists or whitelists and assign them globally or to policy targets.
2. Use **Policy Tester** to verify a decision.
3. Configure your resolver plugin with endpoint `http://DOCKER-HOST:8080/api/v1/decision` and the API key from `.env` or **Access & Security**.
4. Check activity in **Query Log** and **Statistics**.

Configure HTTPS under **System Settings → HTTPS & TLS**. The default HTTPS port is `8443`; see the [TLS guide](docs/OPERATIONS.md#https-and-tls) for certificates, ACME, and port settings.

For status and troubleshooting:

```bash
docker compose ps
docker compose logs --tail=100 blockinator caddy
```

## Updating

From your existing `main` checkout, stop the stack and [back up your data](docs/OPERATIONS.md#data-and-backups), then update and rebuild:

```bash
docker compose stop
# Back up .env and ./data now; back up remote MySQL separately if used.
git pull --ff-only
docker compose up -d --build
```

Review release notes and preserve local edits. If Git reports a conflict, resolve it without forcing or resetting the checkout. For existing tag checkouts, follow [Moving to main](docs/INSTALLATION.md#moving-an-existing-tag-checkout-to-main) first.

## Guides and alternatives

| Guide | Contents |
| --- | --- |
| [Alternative installations](docs/INSTALLATION.md) | Docker Hub, fixed-version tags, upgrade paths, and startup troubleshooting |
| [User guide](docs/USER_GUIDE.md) | Targets, policy precedence, lists, schedules, query history, and settings |
| [Operations](docs/OPERATIONS.md) | Databases, migration, HTTPS, environment variables, monitoring, and backups |
| [Integration and API](docs/API.md) | Resolver configuration, authentication, and request/response examples |
| [Development](docs/DEVELOPMENT.md) | Branch policy, tests, benchmarks, and releases |

`main` contains stable code and current documentation; unreleased application work belongs on `dev`. Tags pin exact releases; Docker examples retain the previously published **1.20.1** image until a newer image is verified as published.

## License

[GNU General Public License v3.0](LICENSE).

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
