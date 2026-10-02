# User guide

[Back to README](../README.md)

Use this guide to configure policy and interpret results in the management console.

[Policy model](#policy-model) · [Lists](#block-lists-and-whitelists) · [Schedules](#scheduling) · [Reverse DNS](#reverse-dns) · [Query Log](#dashboard-and-query-log) · [Statistics](#live-statistics) · [Policy Tester](#policy-targets-and-policy-tester) · [Settings](#console-behavior-and-settings)

## Policy model

### Target precedence

Policy handling proceeds in this order:

1. Ignored DNS record-type bypass.
2. Global pause.
3. Any matching whitelisted target whose schedule is active (Endpoint, Network, or reverse-DNS hostname).
4. Exact client-IP Endpoint.
5. Matching reverse-DNS hostname.
6. Most-specific matching Network.
7. Unmatched-client fallback.

The record-type bypass occurs before PTR observation, policy-target matching, list evaluation, and Query Log creation. If all questions use ignored types, Blockinator immediately returns an allow decision with reason `ignored_record_type`; otherwise non-ignored questions are evaluated normally.

The highest-priority scheduled matching target determines the displayed target and pause behavior. If that target is paused, the query is permitted. Otherwise, list assignments from the matching Endpoint, hostname, and Network are combined as described below.

To whitelist clients, open **Policy Targets**, create or edit an **Endpoint**, **Network**, or **Reverse-DNS Hostname**, and check **Whitelist target**. Networks support IPv4, IPv6, or both; PTR targets support exact names and wildcard suffixes. PTR matching uses learned reverse-DNS identities, so hostname exemptions apply after the client's identity is known.

Any matching whitelist with an active enforcement schedule takes precedence over all filtering targets and lists, even if another target is more specific or was created earlier. Outside the whitelist's schedule, normal policy applies. When several whitelists match, the logged target is selected by exact IP, then exact/most-specific PTR hostname, then most-specific network, with oldest ID breaking ties.

List-assignment boxes disappear while **Whitelist target** is checked. Existing assignments remain saved for reuse when it is unchecked. To restore filtering, uncheck the option and leave the blocking state **Active**. Queries remain logged as Whitelisted with the matching target name and reason `endpoint_whitelisted` (exact IP) or `scope_whitelisted` (network/PTR); ignored record types still bypass logging.

A Network target may contain IPv4, IPv6, or both. Dual-stack targets share one name, state, schedule, and assignment set.

### List precedence

List assignments are additive. The active policy set may include:

- globally applied lists;
- lists assigned to the matching Network;
- lists assigned to the matching PTR hostname; and
- lists assigned to the matching Endpoint.

Every active list is still subject to its own enabled state and schedule.

**Whitelists are evaluated before block lists.** If a domain matches an active whitelist, the decision is allowed even if that domain also appears in one or more active block lists.

The policy API reports a whitelist match as:

```json
{
  "block": false,
  "reason": "whitelist_match",
  "matched_scope": "Guest Wi-Fi",
  "matched_list": "Required Services",
  "matched_list_type": "whitelist",
  "matched_domain": "updates.example.com",
  "response_mode": "nxdomain"
}
```

In the web UI, that same event is shown as the distinct **Whitelisted** decision rather than a generic Allowed result.

### Unmatched clients

Under **System Settings → DNS & logs**, two controls define unmatched-client behavior.

**Global list reach**

- **All clients** — global lists apply to every client.
- **Matched policy targets only** — global lists apply only when a Network, Endpoint, or hostname target matched.

**Default action**

- **Allow** — permit an otherwise-unmatched query.
- **Deny** — block it with `no_scope_default_deny`.

Eligible global whitelists and block lists are evaluated before this fallback. A whitelist match can allow an unmatched client even when Default action is Deny; if no rule decides the query, the configured fallback applies.

### Ignored DNS record types

**System Settings → Ignored records** controls which DNS question types Blockinator should leave entirely to the upstream DNS server.

Current selectable types are:

`A`, `AAAA`, `ANY`, `CAA`, `CERT`, `CNAME`, `DNAME`, `DNSKEY`, `DS`, `HINFO`, `HTTPS`, `IXFR`, `LOC`, `MX`, `NAPTR`, `NS`, `NSEC`, `NSEC3`, `PTR`, `RRSIG`, `SOA`, `SRV`, `SSHFP`, `SVCB`, `TLSA`, `TXT`, `URI`, and `AXFR`.

If **all questions** in a policy request use selected types, Blockinator:

- returns `block: false` with reason `ignored_record_type`;
- skips PTR observation and background PTR scheduling for that request;
- skips policy-target, whitelist, and block-list evaluation;
- does not create a Query Log row; and
- does not add a response-time sample to Statistics.

Ignored types bypass only their own question; a mixed request still evaluates its other questions.

## Block lists and whitelists

Block lists and whitelists use the same management model. Each list has its own:

- source;
- parser format;
- enabled state;
- global/target assignments;
- schedule;
- automatic refresh interval; and
- entry set.

### Supported sources

A list may come from:

- a remote URL;
- an uploaded file;
- pasted rules; or
- a manually maintained domain list.

Supported input includes:

- one domain per line;
- hosts-file entries; and
- common DNS-oriented Adblock rules.

Domains are normalized before storage. IDNs are stored in ASCII/punycode form, and wildcard-style inputs such as `*.example.com` normalize to the blockable domain.

A stored `example.com` entry also matches its subdomains.

### Normalized domain storage

Domains are stored once in a shared global domain table. If the same domain appears in several block lists, whitelists, or both, each list stores only its membership reference.

This avoids duplicate domain storage while preserving independent list membership and refresh behavior.

### Editors

**Block Lists → Edit** and **Whitelists → Edit** open dedicated editor pages for:

- list/source configuration;
- policy-target assignments;
- scheduling;
- URL refresh/import actions; and
- current-entry previews.

Manual lists also have a dedicated domain manager with search, pagination, add, and remove operations.

Uploaded and pasted lists obey `MAX_BLOCKLIST_BYTES` (100 MiB by default). Multipart forms permit up to 4,096 fields and four files, with a total list-request limit of the list size plus 1 MiB for form overhead.

### URL refresh behavior

URL-backed lists refresh independently on their configured intervals.

The refresher:

- uses ETag and Last-Modified validators when available;
- streams remote content through the parser instead of retaining an extra full decoded copy;
- computes SHA-256 while downloading rather than hashing the source again afterward;
- skips parsing/database writes when an unchanged source can be identified;
- downloads and parses multiple due lists concurrently;
- serializes database writes to avoid SQLite writer contention;
- applies membership deltas rather than replacing unchanged data;
- keeps the last known-good list after download/parse failures; and
- reloads only the policy list snapshot after a changed refresh batch.

An upstream response with no usable domains is rejected rather than replacing a working list with an empty one.

Refresh controls:

```env
BLOCKLIST_REFRESH_POLL_SECONDS=30
BLOCKLIST_REFRESH_WORKERS=4
MAX_BLOCKLIST_BYTES=104857600
```

## Scheduling

Recurring weekly schedules can be applied to:

- Block Lists;
- Whitelists;
- Networks;
- Endpoints; and
- PTR hostname targets.

Schedules accept local **HH:MM** values; seconds and UTC offsets are rejected. Invalid saved schedules are inactive. Schedules support:

- selectable weekdays;
- start/end times;
- overnight windows; and
- IANA timezones such as `America/New_York`.

Selected weekdays represent the day the schedule starts. For example, Monday `22:00–06:00` remains active until Tuesday at 06:00.

If start and end are equal, the schedule covers the full selected day.

The **System Settings → Default timezone** controls Query Log display and is the initial timezone for newly created schedules. Existing schedules retain their own saved timezone.

## Reverse DNS

PTR lookup is kept completely off the DNS decision request path.

Every non-ignored policy request performs only a fast, in-memory observation of the client IP. A dedicated durable PTR resolver runs in parallel with policy evaluation and persists one state for every observed client:

- **pending** — discovered but not yet resolved;
- **resolved** — a valid PTR hostname is known;
- **no_ptr** — the resolver authoritatively reports no PTR record; or
- **retry** — a timeout, SERVFAIL, unavailable resolver, or other transient failure will be retried.

Transient failures use exponential backoff. Resolved names are periodically refreshed so DHCP/PTR changes are learned, and authoritative no-PTR results are rechecked so newly created PTR records eventually appear.

PTR state is stored in `client_ptr_status`. Successful names are also stored in `client_identities`, backfilled into Query Log rows that did not yet have a hostname, and propagated into the immutable policy snapshot without rebuilding block-list domain indexes.

Periodic reconciliation advances a durable Query Log ID checkpoint in bounded batches and creates PTR state for newly discovered clients. Name backfills use bounded per-client jobs with persisted progress. Work resumes after restarts without repeatedly scanning all retained history.

PTR identities are used for:

- exact and wildcard hostname policy targets;
- Dashboard client labels;
- Query Log client labels;
- Endpoint selectors; and
- Query Log client searching.

The first evaluated request from a previously unknown client never waits for PTR. Hostname policy can begin applying as soon as the background resolver learns the name.

A wildcard such as:

```text
*.kids.home.arpa
```

matches `tablet.kids.home.arpa`, but not the bare `kids.home.arpa` suffix.

For internal reverse zones:

```env
RDNS_NAMESERVERS=192.168.1.2,192.168.1.3
```

Resolver controls include:

```env
RDNS_RESOLVER_WORKERS=8
RDNS_RESOLVED_REFRESH_SECONDS=86400
RDNS_NO_PTR_REFRESH_SECONDS=21600
RDNS_RECONCILE_SECONDS=1
```

**System Settings → Runtime** shows PTR resolver status, tracked/resolved/no-PTR/retry counts, queue depth, in-flight work, worker count, and the active resolver source.

Hostname policy is only as trustworthy as the PTR data supplied by the configured resolver/reverse zones.

## Dashboard and Query Log

Evaluated DNS decisions are written through a bounded asynchronous logger so normal database logging does not block the policy request path. Requests bypassed by **Ignored records** are deliberately not logged.

The Dashboard shows recent activity. The full Query Log records:

- timestamp;
- originating DNS server (`server_id`);
- client IP and learned PTR hostname;
- client port;
- DNS transport/protocol;
- HTTP or HTTPS policy scheme;
- query name, type, and class;
- end-to-end policy response time;
- matched policy target;
- matched list and list type;
- allow/block state and reason; and
- optionally, the original request JSON.

### Decision display

The UI uses three distinct decision states:

- **Allowed** — permitted without a whitelist match.
- **Blocked** — rejected by a block list or blocking policy condition.
- **Whitelisted** — explicitly permitted by a whitelist.

Whitelist rows continue to show the matched whitelist in the Match/Reason column.

The Query Log decision filter treats these as three separate choices. Selecting **Allowed** does not include Whitelisted rows.

### Query Log filters

Domain, client, and list text filters support **Contains**, **Starts with**, and **Exact** matching. `%` and `_` are treated literally. Contains searches and uncached filtered counts may still be costly on large histories.

Filters include:

- domain;
- client IP or partial/full PTR hostname;
- querying DNS server;
- matched policy target;
- matched list;
- decision state;
- date/time range; and
- results per page.

Optional auto-refresh intervals are available at 5, 10, 15, 30, or 60 seconds and preserve the active filter URL.

### Query Log pagination and time ranges

Use **Results per page** to choose any page size from 25 to 500. **First**,
**Previous**, **Next**, and **Last** retain all active filters. The result count
shows the total matches, and the heading shows the current row range. Applying
filters or changing page size starts again on the first page.

**From** and **Through** use the timezone named beside the fields (the system
default timezone), not the browser timezone. Either boundary can be omitted.
The end includes the entire selected second. Invalid or reversed ranges are
rejected. During daylight-saving fall-back, ambiguous boundaries include both
occurrences; nonexistent spring-forward times are rejected.

Page navigation pins the newest query ID so incoming requests cannot shift
results between pages. Auto refresh pauses while browsing that snapshot; choose
**Latest results** to return to live results with the same filters. Normal log
retention can still remove rows from a snapshot. Live refresh updates the rows,
total count and page links together.

Next/Previous use ID cursors. Last and explicit page-number bookmarks retain OFFSET compatibility. Exact filtered counts are cached for up to five seconds; filter choices are cached for 30 seconds. These caches may briefly lag new activity.

Expand a row's **Details** for **Open target**, **Open list**, and **Domain actions**. Domain actions can add the logged domain to a selected manual block list or whitelist. Expired rows and renamed/deleted resources produce an explanatory message.

### Raw request JSON

Full policy request JSON is **disabled by default** to reduce serialization CPU, database bandwidth, WAL traffic, and storage use.

Enable **Store full policy request JSON** under **System Settings → DNS & logs** only when raw payload retention is useful for troubleshooting.

### Retention

Two retention limits are available:

- **Maximum age (days)** — `0` disables age pruning.
- **Maximum rows** — configurable from 1,000 to 5,000,000 on either backend.

When both are set, both apply. Age pruning also runs without incoming traffic. Each pruning transaction removes at most 1,000 age-expired and 1,000 excess-count rows, so large retention reductions take effect progressively.

Timestamps are stored in UTC and converted for display using the configured system timezone, including daylight-saving-time handling.

## Live Statistics

The **Statistics** page provides a live operational view with:

- total retained queries;
- total retained blocks;
- overall average measured policy response time;
- query count per interval;
- blocked-query count per interval; and
- **average response time per interval as a separate chart line**.

The response-time series uses an independent right-side millisecond axis so traffic volume does not distort latency visibility. Buckets with no response-time samples render as gaps instead of false 0 ms values.

Available windows:

- 15 minutes;
- 1 hour;
- 6 hours;
- 24 hours.

The page refreshes every five seconds without a full browser reload. Longer windows automatically use larger buckets.

Statistics use transactionally maintained rollups of retained Query Log data, so retention pruning limits statistics history and requests containing only ignored record types are intentionally excluded.

## Policy Targets and Policy Tester

Search targets by name, address, or hostname, filter by type, and browse 25 targets per page. Each target opens in a dedicated editor. Cards show effective state and the next schedule transition; overlapping targets can still affect the final decision.

**Policy Tester** accepts a client IP, domain, record type, and optional local time. It uses the active in-memory policy snapshot and learned PTR identity to explain matching targets, list schedules, and the winning rule. It does not perform DNS/PTR lookups, record test queries, or change policy. Times use the system timezone; the first occurrence is used for an ambiguous fall-back time.

If a configuration save commits but policy activation fails, the console shows a pending-rebuild warning. The previous snapshot continues serving decisions while automatic retries attempt to activate the saved configuration. Use the tester again after activation succeeds.

## Console behavior and settings

With JavaScript enabled, editable list, target, settings, and domain-action forms preserve entered values and selected files after failed saves. Values stay in the current page, not browser storage; closing or reloading the page loses them. A network error may happen after a write completes, so check saved state before retrying.

Query Log auto refresh updates rows without reloading the page. It pauses while a record is expanded, a control is focused, filters are edited, or the tab is hidden. Submit edited filters to resume. Refresh failures leave the previous results visible. Comfortable/Compact table density is stored in the browser.

Mobile navigation opens with **Menu**; Escape closes it and restores focus. Navigation also works without JavaScript.

| System Settings tab | Controls |
| --- | --- |
| DNS & logs | Blocked response mode (NXDOMAIN, REFUSED, NODATA, or `0.0.0.0 / ::`), global list reach, unmatched-client fallback, retention, request JSON, and default timezone |
| Ignored records | Per-question bypass types; see [Ignored DNS record types](#ignored-dns-record-types) |
| Appearance | **Use system theme** (default), **Dark**, or **Light**, including sign-in and editor pages |
| HTTPS & TLS | Certificate/ACME configuration, redirects, and TLS status; see [HTTPS and TLS](OPERATIONS.md#https-and-tls) |
| Runtime | Storage, policy, logger, refresh, PTR, and TLS diagnostics; see [monitoring](OPERATIONS.md#operational-protections-and-monitoring) |

Theme preferences are stored in the database. Use system theme follows each device's preference and changes with it; previously saved Dark/Light choices are retained. Global blocking pause/resume is on the Dashboard.
