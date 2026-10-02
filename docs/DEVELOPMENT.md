# Development and releases

[Back to README](../README.md)

Run commands from the repository root unless noted otherwise.

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
- SQLite uses WAL mode; list-refresh database commits are serialized to reduce writer contention.
- API-key `last_used_at` updates happen asynchronously.
- PTR learning/backfill runs outside UI and policy request paths.
- Requests containing only ignored record types never enter the logger or PTR queues; mixed requests still evaluate and log the remaining questions.

## Testing

Use Python 3.12 and an isolated environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt pytest httpx==0.28.1
python -m pytest -q
```

The standard suite skips MySQL-dependent tests unless `MYSQL_TEST=1` and the `MYSQL_*` connection variables are configured. The dedicated CI job runs MySQL integration and migration tests against MySQL 8.4.

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
python tools/benchmark_policy_engine.py --domains 100000 --requests 100000
```

With the Compose stack running, benchmark direct versus Caddy policy latency from inside the application container:

```bash
docker compose exec -T blockinator python /srv/tools/benchmark_policy_latency.py --requests 1000 --warmup 20
```

The latency tool uses HTTP endpoints, so run it against a test stack with HTTP application access enabled and an active `POLICY_API_KEY`. It sends real policy requests and may add query history; it does not measure upstream DNS resolution.

The latency benchmark reports throughput plus mean/p50/p95/p99 latency across several concurrency levels. CI uses smaller smoke runs; benchmark values are informational rather than hard performance gates because shared-runner performance varies.

## Versioning and release workflow

| Reference | Purpose |
| --- | --- |
| `main` (default) | Stable application code and current documentation; recommended source installation |
| `dev` | Unreleased application changes and integration testing |
| `vX.Y.Z` tag | Exact published release snapshot; never move an existing tag |
| `release/vX.Y.Z` | Optional maintenance branch for that release |

Develop application changes on `dev` or a feature branch targeting `dev`. Merge
tested application changes into `main` when ready to release. Documentation-only
updates, including the required source-version metadata, may go directly to `main`.
Keep `dev` up to date with `main` before starting the next development cycle.


Follow [AGENTS.md](../AGENTS.md) for every update, including documentation: increment `APP_VERSION` in `app/main.py`, add a matching top changelog entry, and synchronize the README source version. UI, health, and OpenAPI versions derive from `APP_VERSION`.

Before publishing, replace `BASE_COMMIT_SHA` with the previous commit SHA:

```bash
python tools/check_version.py --base-ref BASE_COMMIT_SHA
```

Publish a release from a tested `main` commit: create a `release/vX.Y.Z` branch and `vX.Y.Z` tag pointing to that commit, then publish a stable GitHub release with release and upgrade notes. Never move an existing release tag or rewrite historical commits. Later documentation updates increment the source version without changing the released snapshot.

A source commit or tag alone does not publish a Docker image. Keep the recommended source-installation commands on stable `main`, using ordinary clone and fast-forward pull. After the image publish workflow succeeds, update the optional fixed-version example and Docker Hub guide together: Git tags use `vX.Y.Z`, while Docker image tags use `X.Y.Z`. The prebuilt deployment keeps its Compose configuration pinned to the matching image release.

## Docker Hub publishing (maintainers)

For installation instructions, see [Docker Hub installation](INSTALLATION.md).

The `Publish Docker Hub` GitHub Actions workflow builds published stable release
source for `linux/amd64` and `linux/arm64`, after the SQLite/Docker and MySQL test
jobs pass. Images are published to `stealthcat128/blockinator` with a version tag
such as `1.20.1`. The `latest` image tag is updated only when that version is the
current latest GitHub release. Publishing an older release does not move `latest`.

Maintainers must add a Docker Hub access token with write permission as the
repository's `DOCKERHUB_TOKEN` Actions secret. The login account is `stealthcat128`.
Do not commit the token or put it in application environment files.

New published releases trigger the workflow. For an existing release, open
**Actions → Publish Docker Hub → Run workflow**, select `main`, and enter the
published tag (for example, `v1.20.1`). The workflow resolves the tag once and
uses that exact commit for testing and building. Drafts and prereleases are rejected.

Once the workflow succeeds, pull the application image with:

```bash
docker pull stealthcat128/blockinator:1.20.1
```

The image contains the Blockinator application; Caddy remains a separate service.
Keep the existing deployment's environment, data volumes, and Caddy configuration
when switching from a local build to this image. This publishing workflow does
not install updates on running deployments.

## Repository layout

| Path | Purpose |
| --- | --- |
| `app/main.py`, `app/admin.py`, `app/ui.py`, `app/static/` | HTTP endpoints, bounded admin/console workers, and web interface |
| `app/policy.py`, `app/inspector.py` | Policy snapshots, evaluation, logging, and explanations |
| `app/blocklists.py`, `app/refresher.py` | Parsing and remote list refresh |
| `app/rdns.py`, `app/ptr_resolver.py` | PTR lookup and durable background reconciliation |
| `app/db.py`, `app/mysql_backend.py`, `app/rollups.py` | Storage and retained statistics maintenance |
| `app/statistics.py`, `app/query_cache.py` | Statistics presentation and query-browser caches |
| `app/auth.py`, `app/tls.py`, `caddy/` | Authentication and managed HTTPS |
| `docs/` | User, API, deployment, operations, and contributor guides |
| `tools/`, `tests/`, `.github/workflows/` | Migration, benchmarks, validation, and release automation |
