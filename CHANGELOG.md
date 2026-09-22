# Changelog

## 1.15.4 — Query log policy metadata and refresh

- Query Log and Dashboard activity now show the matched policy target for each DNS decision.
- Query Log and Dashboard activity now show whether the policy API request arrived over HTTP or HTTPS.
- Added persisted `policy_scheme` metadata with automatic migration for existing SQLite databases.
- Added a Query Log block-list name filter with historical match-name suggestions.
- Added optional Query Log auto-refresh intervals of 5, 10, 15, 30, or 60 seconds; refresh preserves the active URL filters.
- Added an index for matched block-list names and regression coverage for the new query-log metadata.
- Updated the application version to 1.15.4.

## 1.15.3 — TLS efficiency hardening

- Replaced generated Caddyfiles and the separate `/adapt` request with deterministic native Caddy JSON loaded directly through `/load`.
- Converted the Caddy bootstrap configuration to native JSON.
- Reworked TLS reconciliation so unchanged configurations are not repeatedly loaded every polling interval.
- Added Caddy restart/bootstrap detection using a small `/config/apps/http/servers` state request.
- TLS status now uses cached Caddy health instead of issuing a live admin request on every System Settings render.
- Batched TLS settings reads and writes through SQLite and made multi-setting writes transactional.
- De-duplicated repeated TLS error writes and update `tls_last_applied` only after an actual configuration load.
- Moved TLS apply operations to Starlette's threadpool so slow Caddy/file operations cannot block FastAPI's async event loop.
- Avoided parsing uploaded X.509 certificates twice and lazy-load the cryptography X.509 modules only when needed.
- Reduced Caddy health-check traffic to a 30-second steady-state cadence with a fast startup interval and a smaller config endpoint.
- Added real Caddy 2.11.4 validation for generated HTTP-only, uploaded-certificate, and custom-ACME JSON.
- Added a direct-vs-Caddy policy latency benchmark and CI smoke run; the validation run measured approximately 0.16 ms mean Caddy overhead.
- Kept HTTP/3 support unchanged, including the UDP 443 publication.
- Expanded regression coverage for no-op reconciliation, restart restoration, error-write de-duplication, and batched settings access.
- Updated the application version to 1.15.3.

 1.15.2 — Tabbed System Settings

- Reorganized **System Settings** into **DNS & logs**, **HTTPS & TLS**, and **Runtime** tabs.
- Tab selection is retained in the URL fragment so saves and validation errors return to the relevant configuration area.
- Added keyboard left/right navigation between settings tabs.
- Simplified the HTTPS setup workflow around a single setup-type selector.
- TLS configuration now renders separate HTTP-only, uploaded-certificate, and ACME fieldsets.
- Only the selected TLS setup type is visible and enabled; irrelevant controls are hidden and excluded from form submission.
- Added contextual setup descriptions for each TLS mode.
- Split uploaded-certificate and ACME settings into clearer identity, certificate/issuer, EAB, and HTTP-access sections.
- Added regression checks for the tab and TLS mode-selection hooks.
- Updated the application version to 1.15.2.

## 1.15.1 — HTTPS redirect-only HTTP mode

- Added a control under **System Settings → HTTPS & certificates** to disable direct HTTP access after HTTPS is working.
- The HTTP behavior switch can only be changed from a control-panel request that arrived over HTTPS.
- Redirect-only mode keeps the HTTP listener open but redirects all application traffic to HTTPS.
- Redirects use HTTP **308 Permanent Redirect** so Blockinator's POST decision requests retain their method/body semantics.
- Redirect targets preserve the request URI and include a non-standard configured `HTTPS_PORT` when required.
- HTTP-only TLS mode always keeps direct HTTP enabled.
- Added runtime display of the current HTTP behavior.
- Added persisted `tls_http_redirect` configuration.
- Added regression coverage for standard/non-standard HTTPS ports and the HTTPS-only control guard.
- Updated the application version to 1.15.1.

## 1.15.0 — Managed HTTPS and ACME

- Added a Caddy 2.11.4 sidecar as Blockinator's host-facing HTTP/HTTPS reverse proxy.
- Preserved HTTP access on `POLICY_PORT` and added configurable `HTTPS_PORT`.
- Added **HTTP only**, **Uploaded certificate**, and **ACME** TLS modes under System Settings.
- Added PEM certificate/full-chain and private-key uploads with X.509 validity, SAN, and key-match validation.
- Added custom ACME directory URL support.
- Added optional private/internal ACME CA root PEM support.
- Added ACME External Account Binding (EAB) key ID and protected HMAC-secret storage.
- TLS private keys and EAB secrets are stored under `/data/tls`, not in SQLite.
- Disabled Caddy config persistence so EAB secrets are not written into Caddy's autosaved configuration.
- Added Caddy config adaptation/loading through its Docker-internal admin API with rollback on failure.
- Added a TLS reconciler that restores the saved configuration after independent Caddy restarts.
- Added automatic Secure cookies when administrator sessions are established over HTTPS.
- Added TLS status, certificate metadata, and last-error information to System Settings.
- Added X.509, ACME rendering, file-permission, and rollback regression tests.
- Added `docs/ACME_TLS_PLAN.md` describing architecture, work items, and non-goals.
- Updated the application version to 1.15.0.

## 1.14.1 — Dashboard allow-reason cleanup

- Dashboard recent DNS activity now leaves the **Reason** column blank for allowed queries.
- Blocked queries continue to display their blocking reason.
- Dashboard behavior now matches the full Query Log display.
- Updated the application version to 1.14.1.

## 1.14.0 — Automatic per-list URL refresh

- Added a background refresh worker for URL-backed block lists.
- Each URL list now refreshes independently using its configured refresh interval.
- Added `last_refresh_attempt` tracking so failed sources retry on their normal per-list cadence instead of being hammered continuously.
- Successful refreshes atomically replace list entries, update counts/timestamps, clear errors, and reload the policy engine.
- Failed downloads/parses preserve the last known-good list and store the refresh error.
- Empty upstream lists are rejected instead of wiping an existing working list.
- Manual **Save & refresh URL** imports now reset the automatic refresh interval clock.
- Added visible automatic-refresh cadence/status on Block List cards.
- Added `BLOCKLIST_REFRESH_POLL_SECONDS` for the scheduler's internal due-list scan frequency.
- Added regression coverage for independent intervals, successful refresh, failure preservation, and empty-list protection.
- Updated the application version to 1.14.0.

## 1.13.2 — Timezone-aware query log display

- Query-log timestamps remain stored in UTC but are now converted for display using the configured System Settings timezone.
- Updated both Dashboard recent activity and the full Query Log.
- Displayed timestamps now include the active timezone abbreviation and follow DST rules automatically.
- Legacy SQLite `CURRENT_TIMESTAMP` rows are treated as UTC before conversion.
- System Settings now describes the timezone as the display timezone for logs as well as the default for new schedules.
- Added regression coverage for ISO UTC timestamps, legacy SQLite timestamps, DST-aware conversion, and invalid-timezone fallback.
- Updated the application version to 1.13.2.

## 1.13.1 — Configurable default timezone

- Added **Default schedule timezone** to System Settings.
- The setting accepts validated IANA timezone names such as `America/New_York`.
- New block-list and policy-target schedules now use the saved system timezone as their default.
- Existing schedules retain their individually saved timezone when the system default changes.
- The `TZ` environment variable now acts as the initial/bootstrap default for new databases.
- Added persistence tests confirming UI-managed timezone settings survive reinitialization.
- Updated the application version to 1.13.1.

## 1.13.0 — Dual-stack network targets

- A single Network policy target can now hold IPv4 and IPv6 CIDRs concurrently.
- Added separate IPv4 CIDR and IPv6 CIDR controls to Network creation and editing.
- Network state, schedules, and block-list assignments apply identically to both address families.
- Added normalized `scope_network_targets` storage keyed by scope and address family.
- Existing single-stack Network targets are migrated automatically.
- Policy matching now selects the most-specific matching Network independently for IPv4 and IPv6.
- Added regression coverage for dual-stack blocking, dual-stack pause behavior, family-specific specificity, and single-stack migration.
- Updated the application version to 1.13.0.

## 1.12.0 — Reverse-DNS hostname policy targets

- Added **Reverse-DNS Hostname** as a third policy-target type alongside Network and Endpoint.
- Added exact PTR hostname matching and wildcard suffix matching such as `*.kids.home.arpa`.
- Added policy precedence of exact IP endpoint → reverse-DNS hostname → most-specific network → global policy.
- Added block-list assignment to hostname targets from both Policy Targets and Block Lists.
- Added Active/Paused state and recurring schedules to hostname targets.
- Added a persistent `client_identities` IP→PTR cache populated by the asynchronous query logger.
- Hostname matching remains off the PTR lookup path; newly learned identities update the in-memory policy cache without restarting Blockinator.
- Added automatic migration of existing SQLite scope tables to allow the new hostname target type.
- Added regression coverage for exact matching, wildcard matching, precedence, schedules, and legacy-schema migration.
- Updated the application version to 1.12.0.

## 1.10.2 — Reverse-DNS client filtering

- Added persisted reverse-DNS client names to query-log records.
- Query Log **Client** filtering now matches either client IP or PTR hostname.
- Partial hostname searches are supported.
- PTR enrichment runs asynchronously in the query-log writer and remains off the DNS decision path.
- Existing log rows are backfilled opportunistically when client identities are displayed or searched.
- Added an automatic SQLite migration and hostname index for existing databases.
- Added regression coverage for upgrading the legacy query-log schema and filtering by hostname.
- Updated the application version to 1.10.2.

## 1.11.0 — Time-based query log retention

- Added configurable query-log retention by age in days.
- Time-based retention defaults to disabled (`0` days) to preserve existing installations.
- Existing maximum-row retention remains available and both limits are enforced together.
- Saving System Settings immediately prunes existing query logs against the new limits.
- Query logging continues to enforce retention automatically as new batches are written.
- Added retention status to the System Settings runtime summary.
- Added regression coverage for age-based pruning and combined age/row limits.
- Updated the application version to 1.11.0.

## 1.10.1 — Query log Match cleanup

- Allowed DNS queries now display a blank value in the Query Log **Match** column.
- Blocked queries continue to show the matched block list or blocking reason.
- Updated the application version to 1.10.1.

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
