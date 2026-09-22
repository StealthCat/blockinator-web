from __future__ import annotations

import ipaddress
import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class Database:
    def __init__(self, path: str | None = None) -> None:
        data_dir = Path(os.getenv("DATA_DIR", "/data"))
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = str(Path(path) if path else data_dir / "policy.db")
        self._init_lock = threading.Lock()
        self.initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        con.execute("PRAGMA busy_timeout=30000")
        try:
            yield con
        finally:
            con.close()

    def initialize(self) -> None:
        with self._init_lock, self.connect() as con:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS blocklists (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    source_type TEXT NOT NULL DEFAULT 'manual',
                    source_url TEXT,
                    format TEXT NOT NULL DEFAULT 'auto',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    use_globally INTEGER NOT NULL DEFAULT 1,
                    refresh_minutes INTEGER NOT NULL DEFAULT 1440,
                    schedule_enabled INTEGER NOT NULL DEFAULT 0,
                    schedule_days TEXT NOT NULL DEFAULT '0,1,2,3,4,5,6',
                    schedule_start TEXT NOT NULL DEFAULT '00:00',
                    schedule_end TEXT NOT NULL DEFAULT '00:00',
                    schedule_timezone TEXT NOT NULL DEFAULT 'UTC',
                    last_updated TEXT,
                    last_refresh_attempt TEXT,
                    last_error TEXT,
                    entry_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS block_entries (
                    blocklist_id INTEGER NOT NULL,
                    domain TEXT NOT NULL,
                    PRIMARY KEY (blocklist_id, domain),
                    FOREIGN KEY (blocklist_id) REFERENCES blocklists(id) ON DELETE CASCADE
                ) WITHOUT ROWID;
                CREATE INDEX IF NOT EXISTS idx_block_entries_domain ON block_entries(domain);

                CREATE TABLE IF NOT EXISTS scopes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    kind TEXT NOT NULL CHECK(kind IN ('network','client','hostname')),
                    target TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','paused')),
                    schedule_enabled INTEGER NOT NULL DEFAULT 0,
                    schedule_days TEXT NOT NULL DEFAULT '0,1,2,3,4,5,6',
                    schedule_start TEXT NOT NULL DEFAULT '00:00',
                    schedule_end TEXT NOT NULL DEFAULT '00:00',
                    schedule_timezone TEXT NOT NULL DEFAULT 'UTC',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS scope_blocklists (
                    scope_id INTEGER NOT NULL,
                    blocklist_id INTEGER NOT NULL,
                    PRIMARY KEY (scope_id, blocklist_id),
                    FOREIGN KEY (scope_id) REFERENCES scopes(id) ON DELETE CASCADE,
                    FOREIGN KEY (blocklist_id) REFERENCES blocklists(id) ON DELETE CASCADE
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS query_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    server_id TEXT,
                    client_ip TEXT NOT NULL,
                    client_name TEXT,
                    client_port INTEGER,
                    protocol TEXT,
                    qname TEXT,
                    qtype TEXT,
                    qclass TEXT,
                    blocked INTEGER NOT NULL,
                    reason TEXT,
                    matched_scope TEXT,
                    matched_list TEXT,
                    request_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_query_log_ts ON query_log(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_query_log_client ON query_log(client_ip, ts DESC);
                CREATE INDEX IF NOT EXISTS idx_query_log_qname ON query_log(qname, ts DESC);

                CREATE TABLE IF NOT EXISTS client_identities (
                    client_ip TEXT PRIMARY KEY,
                    client_name TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_client_identities_name
                    ON client_identities(client_name);

                CREATE TABLE IF NOT EXISTS admin_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS admin_sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    csrf_token TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    last_seen_at INTEGER NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_admin_sessions_user ON admin_sessions(user_id);
                CREATE INDEX IF NOT EXISTS idx_admin_sessions_expiry ON admin_sessions(expires_at);

                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    key_hash TEXT NOT NULL UNIQUE,
                    key_prefix TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_used_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_api_keys_enabled ON api_keys(enabled);
                """
            )
            # Lightweight forward migration for databases created by older Blockinator releases.
            blocklist_columns = {
                row["name"] for row in con.execute("PRAGMA table_info(blocklists)")
            }
            schedule_columns = {
                "schedule_enabled": "INTEGER NOT NULL DEFAULT 0",
                "schedule_days": "TEXT NOT NULL DEFAULT '0,1,2,3,4,5,6'",
                "schedule_start": "TEXT NOT NULL DEFAULT '00:00'",
                "schedule_end": "TEXT NOT NULL DEFAULT '00:00'",
                "schedule_timezone": "TEXT NOT NULL DEFAULT 'UTC'",
            }
            for column_name, definition in schedule_columns.items():
                if column_name not in blocklist_columns:
                    con.execute(
                        f"ALTER TABLE blocklists ADD COLUMN {column_name} {definition}"
                    )
            if "last_refresh_attempt" not in blocklist_columns:
                con.execute(
                    "ALTER TABLE blocklists ADD COLUMN last_refresh_attempt TEXT"
                )

            scope_columns = {
                row["name"] for row in con.execute("PRAGMA table_info(scopes)")
            }
            for column_name, definition in schedule_columns.items():
                if column_name not in scope_columns:
                    con.execute(
                        f"ALTER TABLE scopes ADD COLUMN {column_name} {definition}"
                    )

            scope_table_row = con.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='scopes'"
            ).fetchone()
            scope_table_sql = (scope_table_row["sql"] or "") if scope_table_row else ""
            if "'hostname'" not in scope_table_sql:
                con.execute("PRAGMA foreign_keys=OFF")
                try:
                    con.execute("BEGIN")
                    con.execute(
                        "ALTER TABLE scope_blocklists RENAME TO scope_blocklists_legacy"
                    )
                    con.execute("ALTER TABLE scopes RENAME TO scopes_legacy")
                    con.execute(
                        """
                        CREATE TABLE scopes (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT NOT NULL UNIQUE,
                            kind TEXT NOT NULL CHECK(kind IN ('network','client','hostname')),
                            target TEXT NOT NULL,
                            state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','paused')),
                            schedule_enabled INTEGER NOT NULL DEFAULT 0,
                            schedule_days TEXT NOT NULL DEFAULT '0,1,2,3,4,5,6',
                            schedule_start TEXT NOT NULL DEFAULT '00:00',
                            schedule_end TEXT NOT NULL DEFAULT '00:00',
                            schedule_timezone TEXT NOT NULL DEFAULT 'UTC',
                            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                        )
                        """
                    )
                    con.execute(
                        """
                        INSERT INTO scopes(
                            id,name,kind,target,state,schedule_enabled,schedule_days,
                            schedule_start,schedule_end,schedule_timezone,created_at
                        )
                        SELECT
                            id,name,kind,target,state,schedule_enabled,schedule_days,
                            schedule_start,schedule_end,schedule_timezone,created_at
                        FROM scopes_legacy
                        """
                    )
                    con.execute(
                        """
                        CREATE TABLE scope_blocklists (
                            scope_id INTEGER NOT NULL,
                            blocklist_id INTEGER NOT NULL,
                            PRIMARY KEY (scope_id, blocklist_id),
                            FOREIGN KEY (scope_id) REFERENCES scopes(id) ON DELETE CASCADE,
                            FOREIGN KEY (blocklist_id) REFERENCES blocklists(id) ON DELETE CASCADE
                        ) WITHOUT ROWID
                        """
                    )
                    con.execute(
                        """
                        INSERT INTO scope_blocklists(scope_id,blocklist_id)
                        SELECT scope_id,blocklist_id FROM scope_blocklists_legacy
                        """
                    )
                    con.execute("DROP TABLE scope_blocklists_legacy")
                    con.execute("DROP TABLE scopes_legacy")
                    con.execute("COMMIT")
                except Exception:
                    con.execute("ROLLBACK")
                    raise
                finally:
                    con.execute("PRAGMA foreign_keys=ON")

            con.execute(
                """
                CREATE TABLE IF NOT EXISTS scope_network_targets (
                    scope_id INTEGER NOT NULL,
                    family INTEGER NOT NULL CHECK(family IN (4,6)),
                    target TEXT NOT NULL,
                    PRIMARY KEY (scope_id, family),
                    FOREIGN KEY (scope_id) REFERENCES scopes(id) ON DELETE CASCADE
                ) WITHOUT ROWID
                """
            )

            # Backfill the address-family table from legacy single-target networks.
            for row in con.execute(
                """
                SELECT s.id,s.target
                FROM scopes s
                WHERE s.kind='network'
                  AND NOT EXISTS (
                    SELECT 1 FROM scope_network_targets n WHERE n.scope_id=s.id
                  )
                """
            ):
                try:
                    network = ipaddress.ip_network(row["target"], strict=False)
                except ValueError:
                    continue
                con.execute(
                    """
                    INSERT OR REPLACE INTO scope_network_targets(scope_id,family,target)
                    VALUES(?,?,?)
                    """,
                    (row["id"], network.version, str(network)),
                )

            query_log_columns = {
                row["name"] for row in con.execute("PRAGMA table_info(query_log)")
            }
            if "client_name" not in query_log_columns:
                con.execute("ALTER TABLE query_log ADD COLUMN client_name TEXT")
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_query_log_client_name "
                "ON query_log(client_name, ts DESC)"
            )

            for row in con.execute(
                """
                SELECT client_ip, client_name, MAX(id) AS latest_id
                FROM query_log
                WHERE client_name IS NOT NULL AND TRIM(client_name) <> ''
                GROUP BY client_ip
                """
            ):
                con.execute(
                    """
                    INSERT INTO client_identities(client_ip,client_name,updated_at)
                    VALUES(?,?,CURRENT_TIMESTAMP)
                    ON CONFLICT(client_ip) DO UPDATE SET
                        client_name=excluded.client_name,
                        updated_at=CURRENT_TIMESTAMP
                    """,
                    (row["client_ip"], row["client_name"]),
                )

            con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('global_blocking','1')")
            con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('block_response','nxdomain')")
            con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('max_query_logs','25000')")
            con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('max_query_log_age_days','0')")
            bootstrap_timezone = os.getenv("TZ", "UTC").strip() or "UTC"
            con.execute(
                "INSERT OR IGNORE INTO settings(key,value) VALUES('default_timezone',?)",
                (bootstrap_timezone,),
            )
            con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('tls_mode','http')")
            con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('tls_hostname','')")
            con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('tls_acme_email','')")
            con.execute(
                "INSERT OR IGNORE INTO settings(key,value) "
                "VALUES('tls_acme_directory','https://acme-v02.api.letsencrypt.org/directory')"
            )
            con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('tls_acme_eab_key_id','')")
            con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('tls_http_redirect','0')")
            con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('tls_last_applied','')")
            con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('tls_last_error','')")

    def get_settings(self, defaults: dict[str, str]) -> dict[str, str]:
        if not defaults:
            return {}
        keys = tuple(defaults)
        placeholders = ",".join("?" for _ in keys)
        values = dict(defaults)
        with self.connect() as con:
            rows = con.execute(
                f"SELECT key,value FROM settings WHERE key IN ({placeholders})",
                keys,
            ).fetchall()
        for row in rows:
            values[str(row["key"])] = str(row["value"])
        return values

    def set_settings(self, values: dict[str, str]) -> None:
        if not values:
            return
        with self.connect() as con:
            con.execute("BEGIN")
            try:
                con.executemany(
                    """
                    INSERT INTO settings(key,value)
                    VALUES(?,?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value
                    """,
                    [(key, value) for key, value in values.items()],
                )
                con.execute("COMMIT")
            except Exception:
                con.execute("ROLLBACK")
                raise

    def get_setting(self, key: str, default: str = "") -> str:
        return self.get_settings({key: default})[key]

    def set_setting(self, key: str, value: str) -> None:
        self.set_settings({key: value})
