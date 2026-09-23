from __future__ import annotations

import os
import re
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

import pymysql
from pymysql.cursors import DictCursor


@dataclass(frozen=True, slots=True)
class MySQLConfig:
    host: str
    port: int
    database: str
    user: str
    password: str
    connect_timeout: int
    ssl_ca: str | None
    ssl_cert: str | None
    ssl_key: str | None
    ssl_enabled: bool
    ssl_verify_cert: bool

    @classmethod
    def from_env(cls) -> "MySQLConfig":
        host = os.getenv("MYSQL_HOST", "").strip()
        database = os.getenv("MYSQL_DATABASE", "").strip()
        user = os.getenv("MYSQL_USER", "").strip()
        password = os.getenv("MYSQL_PASSWORD", "")
        if not host:
            raise ValueError("MYSQL_HOST is required when DATABASE_BACKEND=mysql")
        if not database:
            raise ValueError("MYSQL_DATABASE is required when DATABASE_BACKEND=mysql")
        if not user:
            raise ValueError("MYSQL_USER is required when DATABASE_BACKEND=mysql")
        try:
            port = int(os.getenv("MYSQL_PORT", "3306"))
        except ValueError as exc:
            raise ValueError("MYSQL_PORT must be an integer") from exc
        try:
            timeout = int(os.getenv("MYSQL_CONNECT_TIMEOUT", "10"))
        except ValueError as exc:
            raise ValueError("MYSQL_CONNECT_TIMEOUT must be an integer") from exc
        ssl_enabled = os.getenv("MYSQL_SSL_ENABLED", "0").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        verify = os.getenv("MYSQL_SSL_VERIFY_CERT", "1").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        return cls(
            host=host,
            port=max(1, min(port, 65535)),
            database=database,
            user=user,
            password=password,
            connect_timeout=max(1, min(timeout, 120)),
            ssl_ca=os.getenv("MYSQL_SSL_CA", "").strip() or None,
            ssl_cert=os.getenv("MYSQL_SSL_CERT", "").strip() or None,
            ssl_key=os.getenv("MYSQL_SSL_KEY", "").strip() or None,
            ssl_enabled=ssl_enabled,
            ssl_verify_cert=verify,
        )


class MySQLCursor:
    def __init__(self, cursor) -> None:
        self._cursor = cursor

    @property
    def lastrowid(self):
        return self._cursor.lastrowid

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    def __iter__(self):
        return iter(self._cursor.fetchall())


class MySQLConnection:
    def __init__(self, raw) -> None:
        self._raw = raw
        self._in_transaction = False

    @property
    def in_transaction(self) -> bool:
        return self._in_transaction

    @staticmethod
    def _translate(sql: str) -> str:
        translated = sql
        translated = re.sub(r"\bCOLLATE\s+NOCASE\b", "", translated, flags=re.I)
        translated = re.sub(r"\bINSERT\s+OR\s+IGNORE\b", "INSERT IGNORE", translated, flags=re.I)
        translated = re.sub(r"\bINSERT\s+OR\s+REPLACE\b", "REPLACE", translated, flags=re.I)
        translated = re.sub(
            r"datetime\(\s*ts\s*\)\s*<\s*datetime\(\s*\?\s*\)",
            "ts < ?",
            translated,
            flags=re.I,
        )

        conflict = re.search(
            r"\bON\s+CONFLICT\s*\([^)]*\)\s+DO\s+UPDATE\s+SET\s+(.+)$",
            translated,
            flags=re.I | re.S,
        )
        if conflict:
            assignments = conflict.group(1)
            assignments = re.sub(
                r"\bexcluded\.([A-Za-z_][A-Za-z0-9_]*)",
                r"VALUES(\1)",
                assignments,
                flags=re.I,
            )
            translated = translated[: conflict.start()] + "ON DUPLICATE KEY UPDATE " + assignments

        # The application uses DB-API qmark parameters. PyMySQL uses %s.
        translated = translated.replace("?", "%s")
        return translated

    def execute(self, sql: str, params: Any = ()):
        normalized = sql.strip().rstrip(";").upper()
        if normalized in {"BEGIN", "BEGIN IMMEDIATE", "START TRANSACTION"}:
            self._raw.begin()
            self._in_transaction = True
            cursor = self._raw.cursor()
            return MySQLCursor(cursor)
        if normalized == "COMMIT":
            self._raw.commit()
            self._in_transaction = False
            cursor = self._raw.cursor()
            return MySQLCursor(cursor)
        if normalized == "ROLLBACK":
            self._raw.rollback()
            self._in_transaction = False
            cursor = self._raw.cursor()
            return MySQLCursor(cursor)

        cursor = self._raw.cursor()
        cursor.execute(self._translate(sql), params or ())
        return MySQLCursor(cursor)

    def executemany(self, sql: str, seq_of_params):
        cursor = self._raw.cursor()
        cursor.executemany(self._translate(sql), seq_of_params)
        return MySQLCursor(cursor)

    def close(self) -> None:
        self._raw.close()


class MySQLBackend:
    def __init__(self, config: MySQLConfig | None = None) -> None:
        self.config = config or MySQLConfig.from_env()

    def _connect_raw(self):
        ssl: dict[str, Any] | None = None
        if (
            self.config.ssl_enabled
            or self.config.ssl_ca
            or self.config.ssl_cert
            or self.config.ssl_key
        ):
            ssl = {}
            if self.config.ssl_ca:
                ssl["ca"] = self.config.ssl_ca
            if self.config.ssl_cert:
                ssl["cert"] = self.config.ssl_cert
            if self.config.ssl_key:
                ssl["key"] = self.config.ssl_key
            ssl["check_hostname"] = self.config.ssl_verify_cert

        con = pymysql.connect(
            host=self.config.host,
            port=self.config.port,
            user=self.config.user,
            password=self.config.password,
            database=self.config.database,
            charset="utf8mb4",
            autocommit=True,
            connect_timeout=self.config.connect_timeout,
            read_timeout=30,
            write_timeout=30,
            cursorclass=DictCursor,
            ssl=ssl,
        )
        with con.cursor() as cursor:
            cursor.execute("SET time_zone = '+00:00'")
        return con

    @contextmanager
    def connect(self) -> Iterator[MySQLConnection]:
        raw = self._connect_raw()
        try:
            yield MySQLConnection(raw)
        finally:
            raw.close()

    @staticmethod
    def is_retryable_write_error(exc: Exception) -> bool:
        if not isinstance(exc, pymysql.MySQLError):
            return False
        code = exc.args[0] if exc.args else None
        return code in {1205, 1213}

    def initialize(self, bootstrap_timezone: str) -> None:
        statements = [
            """
            CREATE TABLE IF NOT EXISTS settings (
                `key` VARCHAR(191) NOT NULL PRIMARY KEY,
                value LONGTEXT NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            """
            CREATE TABLE IF NOT EXISTS blocklists (
                id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL UNIQUE,
                source_type VARCHAR(32) NOT NULL DEFAULT 'manual',
                source_url TEXT NULL,
                format VARCHAR(32) NOT NULL DEFAULT 'auto',
                list_type VARCHAR(16) NOT NULL DEFAULT 'block',
                enabled TINYINT(1) NOT NULL DEFAULT 1,
                use_globally TINYINT(1) NOT NULL DEFAULT 1,
                refresh_minutes INT NOT NULL DEFAULT 1440,
                schedule_enabled TINYINT(1) NOT NULL DEFAULT 0,
                schedule_days VARCHAR(32) NOT NULL DEFAULT '0,1,2,3,4,5,6',
                schedule_start VARCHAR(16) NOT NULL DEFAULT '00:00',
                schedule_end VARCHAR(16) NOT NULL DEFAULT '00:00',
                schedule_timezone VARCHAR(128) NOT NULL DEFAULT 'UTC',
                last_updated DATETIME NULL,
                last_refresh_attempt DATETIME NULL,
                last_error LONGTEXT NULL,
                entry_count BIGINT NOT NULL DEFAULT 0,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            """
            CREATE TABLE IF NOT EXISTS domains (
                id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                domain VARCHAR(253) NOT NULL UNIQUE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            """
            CREATE TABLE IF NOT EXISTS blocklist_domain_memberships (
                blocklist_id BIGINT NOT NULL,
                domain_id BIGINT NOT NULL,
                PRIMARY KEY (blocklist_id,domain_id),
                KEY idx_blocklist_domain_memberships_domain (domain_id),
                CONSTRAINT fk_bdm_blocklist FOREIGN KEY (blocklist_id)
                    REFERENCES blocklists(id) ON DELETE CASCADE,
                CONSTRAINT fk_bdm_domain FOREIGN KEY (domain_id)
                    REFERENCES domains(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            """
            CREATE TABLE IF NOT EXISTS scopes (
                id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL UNIQUE,
                kind VARCHAR(16) NOT NULL,
                target VARCHAR(1024) NOT NULL,
                state VARCHAR(16) NOT NULL DEFAULT 'active',
                schedule_enabled TINYINT(1) NOT NULL DEFAULT 0,
                schedule_days VARCHAR(32) NOT NULL DEFAULT '0,1,2,3,4,5,6',
                schedule_start VARCHAR(16) NOT NULL DEFAULT '00:00',
                schedule_end VARCHAR(16) NOT NULL DEFAULT '00:00',
                schedule_timezone VARCHAR(128) NOT NULL DEFAULT 'UTC',
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            """
            CREATE TABLE IF NOT EXISTS scope_blocklists (
                scope_id BIGINT NOT NULL,
                blocklist_id BIGINT NOT NULL,
                PRIMARY KEY (scope_id,blocklist_id),
                CONSTRAINT fk_scope_blocklists_scope FOREIGN KEY (scope_id)
                    REFERENCES scopes(id) ON DELETE CASCADE,
                CONSTRAINT fk_scope_blocklists_list FOREIGN KEY (blocklist_id)
                    REFERENCES blocklists(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            """
            CREATE TABLE IF NOT EXISTS scope_network_targets (
                scope_id BIGINT NOT NULL,
                family TINYINT NOT NULL,
                target VARCHAR(128) NOT NULL,
                PRIMARY KEY (scope_id,family),
                CONSTRAINT fk_scope_network_targets_scope FOREIGN KEY (scope_id)
                    REFERENCES scopes(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            """
            CREATE TABLE IF NOT EXISTS query_log (
                id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                ts VARCHAR(64) NOT NULL,
                server_id VARCHAR(255) NULL,
                client_ip VARCHAR(45) NOT NULL,
                client_name VARCHAR(253) NULL,
                client_port INT NULL,
                protocol VARCHAR(32) NULL,
                policy_scheme VARCHAR(16) NULL,
                qname VARCHAR(253) NULL,
                qtype VARCHAR(32) NULL,
                qclass VARCHAR(32) NULL,
                blocked TINYINT(1) NOT NULL,
                reason VARCHAR(255) NULL,
                matched_scope VARCHAR(255) NULL,
                matched_list VARCHAR(255) NULL,
                matched_list_type VARCHAR(16) NULL,
                request_json LONGTEXT NULL,
                KEY idx_query_log_ts (ts DESC),
                KEY idx_query_log_client (client_ip,ts DESC),
                KEY idx_query_log_client_name (client_name,ts DESC),
                KEY idx_query_log_qname (qname,ts DESC),
                KEY idx_query_log_matched_list (matched_list,ts DESC)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            """
            CREATE TABLE IF NOT EXISTS client_identities (
                client_ip VARCHAR(45) NOT NULL PRIMARY KEY,
                client_name VARCHAR(253) NOT NULL,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                KEY idx_client_identities_name (client_name)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            """
            CREATE TABLE IF NOT EXISTS admin_users (
                id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(191) NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            """
            CREATE TABLE IF NOT EXISTS admin_sessions (
                token_hash VARCHAR(128) NOT NULL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                csrf_token VARCHAR(255) NOT NULL,
                created_at BIGINT NOT NULL,
                expires_at BIGINT NOT NULL,
                last_seen_at BIGINT NOT NULL,
                KEY idx_admin_sessions_user (user_id),
                KEY idx_admin_sessions_expiry (expires_at),
                CONSTRAINT fk_admin_sessions_user FOREIGN KEY (user_id)
                    REFERENCES admin_users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(191) NOT NULL UNIQUE,
                key_hash VARCHAR(128) NOT NULL UNIQUE,
                key_prefix VARCHAR(64) NOT NULL,
                enabled TINYINT(1) NOT NULL DEFAULT 1,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_used_at DATETIME NULL,
                KEY idx_api_keys_enabled (enabled)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """,
        ]

        with self.connect() as con:
            for statement in statements:
                con.execute(statement)

            # MySQL views over joins are read-only for our purposes. Writes go
            # through Database domain-membership helpers.
            con.execute(
                """
                CREATE OR REPLACE VIEW block_entries AS
                SELECT memberships.blocklist_id, domains.domain
                FROM blocklist_domain_memberships AS memberships
                JOIN domains ON domains.id=memberships.domain_id
                """
            )

            # Forward-compatible column checks for MySQL databases created by
            # earlier development versions of this backend.
            self._ensure_column(
                con,
                "blocklists",
                "list_type",
                "VARCHAR(16) NOT NULL DEFAULT 'block'",
            )
            self._ensure_column(
                con,
                "query_log",
                "matched_list_type",
                "VARCHAR(16) NULL",
            )

            defaults = {
                "global_blocking": "1",
                "block_response": "nxdomain",
                "unmatched_scope_action": "allow",
                "global_blocklist_scope_mode": "all_clients",
                "max_query_logs": "25000",
                "max_query_log_age_days": "0",
                "default_timezone": bootstrap_timezone,
                "tls_mode": "http",
                "tls_hostname": "",
                "tls_acme_email": "",
                "tls_acme_directory": "https://acme-v02.api.letsencrypt.org/directory",
                "tls_acme_eab_key_id": "",
                "tls_http_redirect": "0",
                "tls_last_applied": "",
                "tls_last_error": "",
            }
            con.executemany(
                "INSERT IGNORE INTO settings(`key`,value) VALUES(?,?)",
                list(defaults.items()),
            )

    def _ensure_column(
        self,
        con: MySQLConnection,
        table: str,
        column: str,
        definition: str,
    ) -> None:
        row = con.execute(
            """
            SELECT COUNT(*) AS c
            FROM information_schema.columns
            WHERE table_schema=? AND table_name=? AND column_name=?
            """,
            (self.config.database, table, column),
        ).fetchone()
        if not row or int(row["c"]) == 0:
            con.execute(f"ALTER TABLE `{table}` ADD COLUMN `{column}` {definition}")
