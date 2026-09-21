# Changelog

## 1.4.0 — Blockinator branding

- Renamed the Docker policy application to **Blockinator**.
- Added Blockinator shield/logo artwork and favicon.
- Added a branded dashboard hero graphic.
- Added a branded split-screen login experience.
- Updated FastAPI service metadata and API ping service name.
- Renamed the Docker Compose service/container to `blockinator`.
- Reworked the repository README for the Docker-only application.
- Preserved all v1.3 database migrations, authentication, API-key management, block-list, scope, and query-log behavior.

## 1.3.0

- Added the multi-page administration console.
- Moved administrator credentials and API keys into SQLite.
- Added multiple API keys, sessions, CSRF protection, query filtering, and editable policy metadata.
