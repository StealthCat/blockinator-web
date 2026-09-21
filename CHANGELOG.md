# Changelog

## 1.7.0 — Editable networks, endpoints, and list assignments

- Reworked the Networks & Endpoints page into editable scope cards.
- Networks and endpoints can now be renamed and have their address/CIDR edited in place.
- A scope can be converted between Network and Endpoint with type-specific IP/CIDR validation.
- Active/paused policy state can be edited alongside the scope identity.
- Block lists can now be assigned or unassigned directly from each network/endpoint editor.
- Added enabled, global, entry-count, and format context to the block-list assignment picker.
- Added block-list assignment during network/endpoint creation.
- Preserved reverse-DNS hostname display for exact endpoint scopes.
- Policy-engine state reloads immediately after scope or assignment changes.
- Added regression coverage for changing a network into an endpoint while changing its assigned list.
- Updated the application version to 1.7.0.

## 1.6.0 — Editable block lists and scope assignments

- Added an expandable editor to every block list on the Block Lists page.
- List name, format, source URL, refresh interval, enabled state, and global-assignment state can now be edited in place.
- Network and exact-client/endpoint assignments can now be changed directly from each block-list editor.
- Added initial scope assignments when importing a new block list.
- Added optional block-list content replacement by file upload or pasted rules.
- Added **Save & refresh URL** for immediate re-import of URL-backed lists.
- Added reverse-DNS client identities to endpoint assignment choices.
- Policy-engine cache reloads immediately after assignment changes.
- Improved fragment-aware redirects so validation errors reopen the correct editor.
- Added a policy regression test covering list reassignment from a network to an exact client.
- Updated the application version to 1.6.0.

## 1.5.1 — Client reverse DNS

- Added PTR lookups for client IP addresses displayed in the administration UI.
- Dashboard activity, Query Log rows, and exact client scopes now show both the reverse-DNS hostname and original IP address.
- Added bounded concurrent lookups so slow or missing PTR records do not stall the UI or DNS decision path.
- Added positive and negative reverse-DNS caches.
- Added optional `RDNS_NAMESERVERS` configuration for internal/local reverse DNS zones.
- Added configurable reverse-DNS timeout, page budget, and cache TTL settings.

## 1.5.0 — Control-panel polish

- Rebuilt the shared application header with breadcrumbs, page descriptions, protection status, signed-in administrator identity, contextual primary actions, and compact sign-out control.
- Grouped sidebar navigation into policy and administration sections with clearer active-state styling.
- Refined dashboard cards, panels, tables, forms, filters, buttons, status indicators, and empty states.
- Added clearer guidance to block-list imports, endpoint creation, API-key creation, administrator credentials, query history, and settings.
- Improved responsive layouts for tablet and mobile use.
- Updated the application version to 1.5.0.

## 1.4.1 — Repository layout

- Moved the Docker application contents from `policy-server/` to the repository root.
- Updated Docker Compose build context, README paths, testing instructions, and branding paths for the flattened layout.

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
