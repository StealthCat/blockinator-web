from __future__ import annotations

import ipaddress
import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .mysql_backend import MySQLBackend


class Database:
    def __init__(self, path: str | None = None) -> None:
        configured_backend = os.getenv("DATABASE_BACKEND", "sqlite").strip().lower()
        self.backend = "sqlite" if path is not None else configured_backend
        if self.backend not in {"sqlite", "mysql"}:
            raise ValueError("DATABASE_BACKEND must be either 'sqlite' or 'mysql'")

        self._init_lock = threading.Lock()
        self._mysql: MySQLBackend | None = None

        if self.backend == "mysql":
            self.path = ""
            self._mysql = MySQLBackend()
        else:
            if path is not None:
                db_path = Path(path)
                db_path.parent.mkdir(parents=True, exist_ok=True)
            else:
                data_dir = Path(os.getenv("DATA_DIR", "/data"))
                data_dir.mkdir(parents=True, exist_ok=True)
                db_path = data_dir / "policy.db"
            self.path = str(db_path)
            self._enable_wal()

        self.initialize()

    def _enable_wal(self) -> None:
        # journal_mode is persistent database state. Set it once during startup
        # instead of reissuing PRAGMA journal_mode=WAL on every connection,
        # which can itself contend with active SQLite writers.
        con = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            con.execute("PRAGMA busy_timeout=30000")
            con.execute("PRAGMA journal_mode=WAL")
        finally:
            con.close()

    @contextmanager
    def connect(self) -> Iterator:
        if self.backend == "mysql":
            assert self._mysql is not None
            with self._mysql.connect() as con:
                yield con
            return

        con = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA synchronous=NORMAL")
        con.execute("PRAGMA busy_timeout=30000")
        try:
            yield con
        finally:
            con.close()

    def initialize(self) -> None:
        if self.backend == "mysql":
            assert self._mysql is not None
            bootstrap_timezone = os.getenv("TZ", "UTC").strip() or "UTC"
            with self._init_lock:
                self._mysql.initialize(bootstrap_timezone)
            return
        self._initialize_sqlite()

    def _initialize_sqlite(self) -> None:
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
                    list_type TEXT NOT NULL DEFAULT 'block' CHECK(list_type IN ('block','whitelist')),
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
                    source_etag TEXT,
                    source_last_modified TEXT,
                    source_hash TEXT,
                    entry_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE
                );
                CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain);

                CREATE TABLE IF NOT EXISTS blocklist_domain_memberships (
                    blocklist_id INTEGER NOT NULL,
                    domain_id INTEGER NOT NULL,
                    PRIMARY KEY (blocklist_id, domain_id),
                    FOREIGN KEY (blocklist_id) REFERENCES blocklists(id) ON DELETE CASCADE,
                    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
                ) WITHOUT ROWID;
                CREATE INDEX IF NOT EXISTS idx_blocklist_domain_memberships_domain
                    ON blocklist_domain_memberships(domain_id);

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
                    policy_scheme TEXT,
                    qname TEXT,
                    qtype TEXT,
                    qclass TEXT,
                    blocked INTEGER NOT NULL,
                    reason TEXT,
                    matched_scope TEXT,
                    matched_list TEXT,
                    matched_list_type TEXT,
                    response_time_ms REAL,
                    request_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_query_log_ts ON query_log(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_query_log_client ON query_log(client_ip, ts DESC);
                CREATE INDEX IF NOT EXISTS idx_query_log_qname ON query_log(qname, ts DESC);
                CREATE INDEX IF NOT EXISTS idx_query_log_matched_list ON query_log(matched_list, ts DESC);
                CREATE INDEX IF NOT EXISTS idx_query_log_server_id ON query_log(server_id, id DESC);
                CREATE INDEX IF NOT EXISTS idx_query_log_scope_id ON query_log(matched_scope, id DESC);
                CREATE INDEX IF NOT EXISTS idx_query_log_blocked_id ON query_log(blocked, id DESC);

                CREATE TABLE IF NOT EXISTS client_identities (
                    client_ip TEXT PRIMARY KEY,
                    client_name TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_client_identities_name
                    ON client_identities(client_name);

                CREATE TABLE IF NOT EXISTS client_ptr_status (
                    client_ip TEXT PRIMARY KEY,
                    status TEXT NOT NULL DEFAULT 'pending',
                    client_name TEXT,
                    first_seen_at INTEGER NOT NULL,
                    last_seen_at INTEGER NOT NULL,
                    last_attempt_at INTEGER,
                    last_success_at INTEGER,
                    next_attempt_at INTEGER NOT NULL DEFAULT 0,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_client_ptr_status_due
                    ON client_ptr_status(next_attempt_at, status);
                CREATE INDEX IF NOT EXISTS idx_client_ptr_status_state
                    ON client_ptr_status(status, last_seen_at DESC);

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
            # Normalize block-list domain storage. Older databases stored the domain
            # text once per list in block_entries. New databases keep one canonical
            # domain row and store only integer list memberships. A compatibility
            # view preserves the existing block_entries SQL surface for the rest of
            # the application and for upgrades.
            block_entries_object = con.execute(
                "SELECT type FROM sqlite_master WHERE name='block_entries'"
            ).fetchone()
            if block_entries_object is not None and block_entries_object["type"] == "table":
                con.execute("BEGIN IMMEDIATE")
                try:
                    con.execute(
                        """
                        INSERT OR IGNORE INTO domains(domain)
                        SELECT DISTINCT domain
                        FROM block_entries
                        """
                    )
                    con.execute(
                        """
                        INSERT OR IGNORE INTO blocklist_domain_memberships(blocklist_id,domain_id)
                        SELECT legacy.blocklist_id, domains.id
                        FROM block_entries AS legacy
                        JOIN domains ON domains.domain=legacy.domain
                        """
                    )
                    con.execute("DROP TABLE block_entries")
                    con.execute("COMMIT")
                except Exception:
                    con.execute("ROLLBACK")
                    raise

            con.executescript(
                """
                CREATE VIEW IF NOT EXISTS block_entries AS
                SELECT memberships.blocklist_id, domains.domain
                FROM blocklist_domain_memberships AS memberships
                JOIN domains ON domains.id=memberships.domain_id;

                CREATE TRIGGER IF NOT EXISTS block_entries_insert
                INSTEAD OF INSERT ON block_entries
                BEGIN
                    INSERT OR IGNORE INTO domains(domain) VALUES(NEW.domain);
                    INSERT OR IGNORE INTO blocklist_domain_memberships(blocklist_id,domain_id)
                    SELECT NEW.blocklist_id,id
                    FROM domains
                    WHERE domain=NEW.domain;
                END;

                CREATE TRIGGER IF NOT EXISTS block_entries_delete
                INSTEAD OF DELETE ON block_entries
                BEGIN
                    DELETE FROM blocklist_domain_memberships
                    WHERE blocklist_id=OLD.blocklist_id
                      AND domain_id=(
                          SELECT id FROM domains WHERE domain=OLD.domain
                      );
                END;

                CREATE TRIGGER IF NOT EXISTS blocklist_domain_membership_cleanup
                AFTER DELETE ON blocklist_domain_memberships
                BEGIN
                    DELETE FROM domains
                    WHERE id=OLD.domain_id
                      AND NOT EXISTS(
                          SELECT 1
                          FROM blocklist_domain_memberships
                          WHERE domain_id=OLD.domain_id
                      );
                END;
                """
            )

            # Keep cached per-list counts synchronized after migration.
            con.execute(
                """
                UPDATE blocklists
                SET entry_count=(
                    SELECT COUNT(*)
                    FROM blocklist_domain_memberships AS memberships
                    WHERE memberships.blocklist_id=blocklists.id
                )
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
            for metadata_column in (
                "source_etag",
                "source_last_modified",
                "source_hash",
            ):
                if metadata_column not in blocklist_columns:
                    con.execute(
                        f"ALTER TABLE blocklists ADD COLUMN {metadata_column} TEXT"
                    )

            if "list_type" not in blocklist_columns:
                con.execute(
                    "ALTER TABLE blocklists ADD COLUMN list_type TEXT NOT NULL DEFAULT 'block'"
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
            if "policy_scheme" not in query_log_columns:
                con.execute("ALTER TABLE query_log ADD COLUMN policy_scheme TEXT")
            if "matched_list_type" not in query_log_columns:
                con.execute("ALTER TABLE query_log ADD COLUMN matched_list_type TEXT")
            if "response_time_ms" not in query_log_columns:
                con.execute("ALTER TABLE query_log ADD COLUMN response_time_ms REAL")
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_query_log_client_name "
                "ON query_log(client_name, ts DESC)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_query_log_matched_list "
                "ON query_log(matched_list, ts DESC)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_query_log_matched_scope "
                "ON query_log(matched_scope, ts DESC)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_query_log_server "
                "ON query_log(server_id, ts DESC)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_query_log_server_id "
                "ON query_log(server_id, id DESC)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_query_log_scope_id "
                "ON query_log(matched_scope, id DESC)"
            )
            con.execute(
                "CREATE INDEX IF NOT EXISTS idx_query_log_blocked_id "
                "ON query_log(blocked, id DESC)"
            )

            # Older SQLite releases used CURRENT_TIMESTAMP's space-separated
            # representation while the asynchronous logger writes ISO-8601 UTC.
            # Normalize legacy rows once so direct indexed timestamp comparisons
            # remain chronologically correct across both formats.
            timestamp_migration = con.execute(
                "SELECT value FROM settings WHERE key='query_log_ts_normalized'"
            ).fetchone()
            if (
                timestamp_migration is None
                or str(timestamp_migration["value"]) != "1"
            ):
                con.execute(
                    """
                    UPDATE query_log
                    SET ts=replace(ts,' ','T') || '+00:00'
                    WHERE length(ts)=19
                      AND substr(ts,11,1)=' '
                    """
                )
                con.execute(
                    """
                    INSERT OR REPLACE INTO settings(key,value)
                    VALUES('query_log_ts_normalized','1')
                    """
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

            con.execute("INSERT OR IGNORE INTO settings(`key`,value) VALUES('global_blocking','1')")
            con.execute("INSERT OR IGNORE INTO settings(`key`,value) VALUES('block_response','nxdomain')")
            con.execute("INSERT OR IGNORE INTO settings(`key`,value) VALUES('unmatched_scope_action','allow')")
            con.execute("INSERT OR IGNORE INTO settings(`key`,value) VALUES('global_blocklist_scope_mode','all_clients')")
            con.execute("INSERT OR IGNORE INTO settings(`key`,value) VALUES('ui_theme','dark')")
            con.execute("INSERT OR IGNORE INTO settings(`key`,value) VALUES('max_query_logs','25000')")
            con.execute("INSERT OR IGNORE INTO settings(`key`,value) VALUES('max_query_log_age_days','0')")
            con.execute("INSERT OR IGNORE INTO settings(`key`,value) VALUES('log_request_json','0')")
            bootstrap_timezone = os.getenv("TZ", "UTC").strip() or "UTC"
            con.execute(
                "INSERT OR IGNORE INTO settings(`key`,value) VALUES('default_timezone',?)",
                (bootstrap_timezone,),
            )
            con.execute("INSERT OR IGNORE INTO settings(`key`,value) VALUES('tls_mode','http')")
            con.execute("INSERT OR IGNORE INTO settings(`key`,value) VALUES('tls_hostname','')")
            con.execute("INSERT OR IGNORE INTO settings(`key`,value) VALUES('tls_acme_email','')")
            con.execute(
                "INSERT OR IGNORE INTO settings(`key`,value) "
                "VALUES('tls_acme_directory','https://acme-v02.api.letsencrypt.org/directory')"
            )
            con.execute("INSERT OR IGNORE INTO settings(`key`,value) VALUES('tls_acme_eab_key_id','')")
            con.execute("INSERT OR IGNORE INTO settings(`key`,value) VALUES('tls_http_redirect','0')")
            con.execute("INSERT OR IGNORE INTO settings(`key`,value) VALUES('tls_last_applied','')")
            con.execute("INSERT OR IGNORE INTO settings(`key`,value) VALUES('tls_last_error','')")

    def is_retryable_write_error(self, exc: Exception) -> bool:
        if self.backend == "mysql":
            assert self._mysql is not None
            return self._mysql.is_retryable_write_error(exc)
        return isinstance(exc, sqlite3.OperationalError) and any(
            marker in str(exc).lower()
            for marker in ("database is locked", "database is busy")
        )

    def backend_summary(self) -> str:
        if self.backend == "mysql":
            assert self._mysql is not None
            cfg = self._mysql.config
            return f"MySQL · {cfg.host}:{cfg.port}/{cfg.database}"
        return f"SQLite · {self.path}"

    def due_url_list_ids(self) -> list[int]:
        if self.backend == "mysql":
            sql = """
                SELECT id
                FROM blocklists
                WHERE source_type='url'
                  AND source_url IS NOT NULL
                  AND TRIM(source_url) <> ''
                  AND TIMESTAMPDIFF(
                        MINUTE,
                        COALESCE(last_refresh_attempt,last_updated,created_at),
                        UTC_TIMESTAMP()
                      ) >= GREATEST(refresh_minutes,1)
                ORDER BY id
            """
        else:
            sql = """
                SELECT id
                FROM blocklists
                WHERE source_type='url'
                  AND source_url IS NOT NULL
                  AND TRIM(source_url) <> ''
                  AND julianday('now') >= julianday(
                        COALESCE(last_refresh_attempt,last_updated,created_at)
                      ) + (
                        CASE
                          WHEN refresh_minutes < 1 THEN 1
                          ELSE refresh_minutes
                        END / 1440.0
                      )
                ORDER BY id
            """
        with self.connect() as con:
            rows = con.execute(sql).fetchall()
        return [int(row["id"]) for row in rows]

    @staticmethod
    def _domain_chunks(values: list, size: int = 750):
        for offset in range(0, len(values), size):
            yield values[offset : offset + size]

    def _insert_domain_memberships(
        self,
        con,
        list_id: int,
        domains: list[str] | tuple[str, ...] | set[str],
    ) -> None:
        unique_domains = list(dict.fromkeys(str(domain) for domain in domains))
        if not unique_domains:
            return

        insert_domain_sql = (
            "INSERT IGNORE INTO domains(domain) VALUES(?)"
            if self.backend == "mysql"
            else "INSERT OR IGNORE INTO domains(domain) VALUES(?)"
        )
        con.executemany(insert_domain_sql, [(domain,) for domain in unique_domains])

        for chunk in self._domain_chunks(unique_domains):
            placeholders = ",".join("?" for _ in chunk)
            rows = con.execute(
                f"SELECT id,domain FROM domains WHERE domain IN ({placeholders})",
                chunk,
            ).fetchall()
            memberships = [(list_id, int(row["id"])) for row in rows]
            if not memberships:
                continue
            insert_membership_sql = (
                "INSERT IGNORE INTO blocklist_domain_memberships(blocklist_id,domain_id) VALUES(?,?)"
                if self.backend == "mysql"
                else "INSERT OR IGNORE INTO blocklist_domain_memberships(blocklist_id,domain_id) VALUES(?,?)"
            )
            con.executemany(insert_membership_sql, memberships)

    def _cleanup_domain_ids(self, con, domain_ids: list[int]) -> None:
        if not domain_ids:
            return
        for chunk in self._domain_chunks(list(dict.fromkeys(domain_ids))):
            placeholders = ",".join("?" for _ in chunk)
            if self.backend == "mysql":
                con.execute(
                    f"""
                    DELETE d
                    FROM domains AS d
                    LEFT JOIN blocklist_domain_memberships AS memberships
                      ON memberships.domain_id=d.id
                    WHERE d.id IN ({placeholders})
                      AND memberships.domain_id IS NULL
                    """,
                    chunk,
                )
            else:
                con.execute(
                    f"""
                    DELETE FROM domains
                    WHERE id IN ({placeholders})
                      AND NOT EXISTS(
                        SELECT 1
                        FROM blocklist_domain_memberships AS memberships
                        WHERE memberships.domain_id=domains.id
                      )
                    """,
                    chunk,
                )

    def replace_list_domains(self, con, list_id: int, domains) -> bool:
        """Synchronize list membership by applying only the changed rows.

        Returns True when membership changed. This avoids deleting/reinserting
        hundreds of thousands of unchanged memberships during routine refreshes.
        """
        incoming = domains if isinstance(domains, set) else set(domains)
        if any(not isinstance(domain, str) for domain in incoming):
            incoming = {str(domain) for domain in incoming}
        existing_rows = con.execute(
            """
            SELECT domains.id AS domain_id, domains.domain
            FROM blocklist_domain_memberships AS memberships
            JOIN domains ON domains.id=memberships.domain_id
            WHERE memberships.blocklist_id=?
            """,
            (list_id,),
        ).fetchall()
        existing = {
            str(row["domain"]): int(row["domain_id"])
            for row in existing_rows
        }

        remove_domains = set(existing) - incoming
        add_domains = incoming - set(existing)
        if not remove_domains and not add_domains:
            return False

        remove_ids = [existing[domain] for domain in remove_domains]
        for chunk in self._domain_chunks(remove_ids):
            placeholders = ",".join("?" for _ in chunk)
            con.execute(
                f"""
                DELETE FROM blocklist_domain_memberships
                WHERE blocklist_id=?
                  AND domain_id IN ({placeholders})
                """,
                [list_id, *chunk],
            )

        if add_domains:
            self._insert_domain_memberships(con, list_id, add_domains)
        self._cleanup_domain_ids(con, remove_ids)
        return True

    def add_list_domain(self, con, list_id: int, domain: str) -> bool:
        existing = con.execute(
            """
            SELECT 1 AS found
            FROM block_entries
            WHERE blocklist_id=? AND domain=?
            """,
            (list_id, domain),
        ).fetchone()
        if existing is not None:
            return False
        self._insert_domain_memberships(con, list_id, [domain])
        return True

    def remove_list_domain(self, con, list_id: int, domain: str) -> bool:
        row = con.execute(
            """
            SELECT domains.id AS domain_id
            FROM domains
            JOIN blocklist_domain_memberships AS memberships
              ON memberships.domain_id=domains.id
            WHERE memberships.blocklist_id=? AND domains.domain=?
            """,
            (list_id, domain),
        ).fetchone()
        if row is None:
            return False
        domain_id = int(row["domain_id"])
        con.execute(
            """
            DELETE FROM blocklist_domain_memberships
            WHERE blocklist_id=? AND domain_id=?
            """,
            (list_id, domain_id),
        )
        self._cleanup_domain_ids(con, [domain_id])
        return True

    def delete_blocklist(self, con, list_id: int) -> None:
        domain_ids = [
            int(row["domain_id"])
            for row in con.execute(
                "SELECT domain_id FROM blocklist_domain_memberships WHERE blocklist_id=?",
                (list_id,),
            ).fetchall()
        ]
        con.execute("DELETE FROM blocklists WHERE id=?", (list_id,))
        self._cleanup_domain_ids(con, domain_ids)

    def get_settings(self, defaults: dict[str, str]) -> dict[str, str]:
        if not defaults:
            return {}
        keys = tuple(defaults)
        placeholders = ",".join("?" for _ in keys)
        values = dict(defaults)
        with self.connect() as con:
            rows = con.execute(
                f"SELECT `key` AS `key`,value FROM settings WHERE `key` IN ({placeholders})",
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
                    INSERT INTO settings(`key`,value)
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
