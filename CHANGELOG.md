# Changelog

## 1.10.0 — Scheduled networks and endpoints

- Added optional recurring weekly schedules to networks and exact endpoints.
- Added automatic SQLite migration for scope schedule fields.
- Networks/endpoints can now select weekdays, start/end times, and IANA timezones from the existing schedule editor.
- Out-of-schedule endpoints fall back to their containing network policy.
- Out-of-schedule networks fall back to broader matching networks or global policy.
- Scheduled paused scopes only suppress blocking during their configured window.
- Added schedule summaries and Scheduled indicators to Networks & Endpoints.
- Added regression coverage for scheduled networks, endpoint fallback, and scheduled pause behavior.
- Updated the application version to 1.10.0.

## 1.9.0 — Scheduled block-list enforcement

- Added optional recurring weekly enforcement schedules to every block list.
- Added selectable weekdays, start/end times, and per-list IANA timezone configuration.
- Scheduled lists are excluded from DNS policy decisions outside their active window.
- Added overnight-window handling, where a selected day owns the interval beginning that evening and ending the following morning.
- Equal start/end times represent a full selected day.
- Added automatic SQLite migration for schedule fields on existing databases.
- Added schedule summaries to Block Lists, manual-list management, and Networks & Endpoints assignment pickers.
- Added `tzdata` to the container runtime for reliable IANA timezone support.
- Added `TZ` environment configuration as the default timezone for newly created schedules.
- Added deterministic regression tests for normal weekly windows, overnight schedules, and `America/New_York` timezone conversion.
- Updated the application version to 1.9.0.

## 1.8.1 — Global assignment lockout

- Shaded and disabled network/endpoint assignment checkboxes whenever a block list is globally assigned.
- Block Lists editors now disable scope assignment controls dynamically while **Apply globally** is checked.
- Unchecking **Apply globally** immediately restores the network and endpoint assignment controls.
- Networks & Endpoints now renders Global block lists as read-only assignment choices.
- Added server-side validation so Global lists cannot be stored as redundant per-scope mappings.
- Updated the application version to 1.8.1.

## 1.8.0 — Manual list domain editor

- Added a dedicated **Manage domains** page for manual block lists.
- Manual lists can now add or remove one domain at a time without replacing the entire list.
- Added searchable, alphabetically sorted domain browsing with 100 entries per page.
- Added pagination and preserved search/page position after individual removals.
- Added domain normalization and duplicate-safe insertion.
- Updated manual-list entry counts and timestamps after each single-domain edit.
- Policy-engine state reloads immediately after add/remove operations.
- Added regression coverage proving single-domain add/remove changes blocking behavior without affecting unrelated entries.
- Updated the application version to 1.8.0.

## 1.7.3 — Startup syntax fix

- Fixed a Python syntax error caused by inline JavaScript being embedded inside the shared HTML f-string.
- Moved expandable-editor hash handling into `app/static/app.js`.
- The shared page shell now loads the JavaScript as a normal static asset.
- Updated the application version to 1.7.3.

## 1.7.2 — Sidebar navigation cleanup

- Fixed sidebar menu labels inheriting the icon span width.
- Every selectable navigation item now stays on a single line.
- Long labels use the available sidebar width without wrapping.
- Mobile navigation switches to a single-column menu to preserve one-line labels.
- Updated the application version to 1.7.2.

## 1.7.1 — Querying server identity in logs

- Added the querying DNS server to every current log-data view.
- Dashboard recent DNS activity now shows the originating `server_id`.
- Query Log now includes a dedicated Server column.
- Added server filtering to the Query Log for multi-resolver deployments.
- Added a clear **Unknown server** state for legacy requests without `server_id`.
- Added polished server identity styling alongside client hostname/IP information.
- Updated the application version to 1.7.1.

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
