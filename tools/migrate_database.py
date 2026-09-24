#!/usr/bin/env python3
"""Offline Blockinator database migration between SQLite and MySQL.

Blockinator must be stopped for the entire migration. The destination is
initialized with the current schema, cleared, populated in dependency order,
then verified against the source.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pymysql
from pymysql.cursors import DictCursor

from app.db import Database
from app.mysql_backend import MySQLBackend, MySQLConfig


TABLE_ORDER = (
    "settings",
    "blocklists",
    "domains",
    "blocklist_domain_memberships",
    "scopes",
    "scope_network_targets",
    "scope_blocklists",
    "query_log",
    "client_identities",
    "client_ptr_status",
    "admin_users",
    "admin_sessions",
    "api_keys",
)

PRIMARY_KEYS: dict[str, tuple[str, ...]] = {
    "settings": ("key",),
    "blocklists": ("id",),
    "domains": ("id",),
    "blocklist_domain_memberships": ("blocklist_id", "domain_id"),
    "scopes": ("id",),
    "scope_network_targets": ("scope_id", "family"),
    "scope_blocklists": ("scope_id", "blocklist_id"),
    "query_log": ("id",),
    "client_identities": ("client_ip",),
    "client_ptr_status": ("client_ip",),
    "admin_users": ("id",),
    "admin_sessions": ("token_hash",),
    "api_keys": ("id",),
}

AUTO_INCREMENT_TABLES = (
    "blocklists",
    "domains",
    "scopes",
    "query_log",
    "admin_users",
    "api_keys",
)

MYSQL_DATETIME_COLUMNS: dict[str, frozenset[str]] = {
    "blocklists": frozenset(
        {"last_updated", "last_refresh_attempt", "created_at"}
    ),
    "scopes": frozenset({"created_at"}),
    "client_identities": frozenset({"updated_at"}),
    "admin_users": frozenset({"created_at", "updated_at"}),
    "api_keys": frozenset({"created_at", "updated_at", "last_used_at"}),
}


@dataclass(frozen=True, slots=True)
class MigrationSummary:
    row_counts: dict[str, int]
    content_verified: bool


def quote_identifier(kind: str, value: str) -> str:
    if kind == "mysql":
        tick = chr(96)
        return tick + value.replace(tick, tick + tick) + tick
    return '"' + value.replace('"', '""') + '"'


def _mysql_connect(config: MySQLConfig):
    ssl: dict[str, Any] | None = None
    if config.ssl_enabled or config.ssl_ca or config.ssl_cert or config.ssl_key:
        ssl = {}
        if config.ssl_ca:
            ssl["ca"] = config.ssl_ca
        if config.ssl_cert:
            ssl["cert"] = config.ssl_cert
        if config.ssl_key:
            ssl["key"] = config.ssl_key
        ssl["check_hostname"] = config.ssl_verify_cert

    con = pymysql.connect(
        host=config.host,
        port=config.port,
        user=config.user,
        password=config.password,
        database=config.database,
        charset="utf8mb4",
        autocommit=False,
        connect_timeout=config.connect_timeout,
        read_timeout=60,
        write_timeout=60,
        cursorclass=DictCursor,
        ssl=ssl,
        ssl_verify_cert=config.ssl_verify_cert if ssl is not None else None,
        ssl_verify_identity=config.ssl_verify_cert if ssl is not None else None,
    )
    with con.cursor() as cursor:
        cursor.execute("SET time_zone = '+00:00'")
    return con


class Endpoint:
    def __init__(
        self,
        kind: str,
        *,
        sqlite_path: Path | None = None,
        mysql_config: MySQLConfig | None = None,
        readonly: bool = False,
    ) -> None:
        self.kind = kind
        self.sqlite_path = sqlite_path
        self.mysql_config = mysql_config
        self.readonly = readonly
        self.connection = None

    def open(self) -> "Endpoint":
        if self.kind == "sqlite":
            assert self.sqlite_path is not None
            if self.readonly:
                uri = self.sqlite_path.resolve().as_uri() + "?mode=ro"
                con = sqlite3.connect(
                    uri,
                    uri=True,
                    timeout=30,
                    isolation_level=None,
                )
                con.execute("PRAGMA query_only=ON")
            else:
                con = sqlite3.connect(
                    str(self.sqlite_path),
                    timeout=30,
                    isolation_level=None,
                )
                con.execute("PRAGMA foreign_keys=ON")
                con.execute("PRAGMA synchronous=NORMAL")
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA busy_timeout=30000")
            self.connection = con
        else:
            assert self.mysql_config is not None
            self.connection = _mysql_connect(self.mysql_config)
        return self

    def close(self) -> None:
        if self.connection is not None:
            try:
                if self.kind == "mysql":
                    self.connection.rollback()
            finally:
                self.connection.close()
            self.connection = None

    def __enter__(self) -> "Endpoint":
        return self.open()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def cursor(self):
        assert self.connection is not None
        return self.connection.cursor()

    def table_exists(self, table: str) -> bool:
        assert self.connection is not None
        if self.kind == "sqlite":
            row = self.connection.execute(
                """
                SELECT 1
                FROM sqlite_master
                WHERE type='table' AND name=?
                """,
                (table,),
            ).fetchone()
            return row is not None

        with self.cursor() as cursor:
            cursor.execute(
                """
                SELECT 1
                FROM information_schema.tables
                WHERE table_schema=%s AND table_name=%s
                """,
                (self.mysql_config.database, table),
            )
            return cursor.fetchone() is not None

    def columns(self, table: str) -> tuple[str, ...]:
        assert self.connection is not None
        if self.kind == "sqlite":
            rows = self.connection.execute(
                f"PRAGMA table_info({quote_identifier('sqlite', table)})"
            ).fetchall()
            return tuple(str(row["name"]) for row in rows)

        with self.cursor() as cursor:
            cursor.execute(
                """
                SELECT COLUMN_NAME
                FROM information_schema.columns
                WHERE table_schema=%s AND table_name=%s
                ORDER BY ORDINAL_POSITION
                """,
                (self.mysql_config.database, table),
            )
            return tuple(str(row["COLUMN_NAME"]) for row in cursor.fetchall())

    def count(self, table: str) -> int:
        assert self.connection is not None
        quoted = quote_identifier(self.kind, table)
        if self.kind == "sqlite":
            row = self.connection.execute(
                f"SELECT COUNT(*) AS c FROM {quoted}"
            ).fetchone()
        else:
            with self.cursor() as cursor:
                cursor.execute(f"SELECT COUNT(*) AS c FROM {quoted}")
                row = cursor.fetchone()
        return int(row["c"] or 0)

    def iter_batches(
        self,
        table: str,
        columns: Sequence[str],
        *,
        batch_size: int,
        ordered: bool = False,
    ) -> Iterator[list[tuple[Any, ...]]]:
        assert self.connection is not None
        quoted_table = quote_identifier(self.kind, table)
        quoted_columns = ", ".join(
            quote_identifier(self.kind, column) for column in columns
        )
        sql = f"SELECT {quoted_columns} FROM {quoted_table}"
        if ordered:
            keys = PRIMARY_KEYS[table]
            sql += " ORDER BY " + ", ".join(
                quote_identifier(self.kind, key) for key in keys
            )

        if self.kind == "sqlite":
            cursor = self.connection.execute(sql)
            while True:
                rows = cursor.fetchmany(batch_size)
                if not rows:
                    break
                yield [
                    tuple(row[column] for column in columns)
                    for row in rows
                ]
            return

        with self.cursor() as cursor:
            cursor.execute(sql)
            while True:
                rows = cursor.fetchmany(batch_size)
                if not rows:
                    break
                yield [
                    tuple(row[column] for column in columns)
                    for row in rows
                ]

    def begin_consistent_read(self) -> None:
        assert self.connection is not None
        if self.kind == "sqlite":
            self.connection.execute("BEGIN")
        else:
            with self.cursor() as cursor:
                cursor.execute(
                    "START TRANSACTION WITH CONSISTENT SNAPSHOT"
                )

    def rollback(self) -> None:
        assert self.connection is not None
        self.connection.rollback()

    def clear_all(self) -> None:
        assert self.connection is not None
        if self.kind == "sqlite":
            self.connection.execute("PRAGMA foreign_keys=OFF")
            self.connection.execute("BEGIN")
            try:
                for table in reversed(TABLE_ORDER):
                    self.connection.execute(
                        f"DELETE FROM {quote_identifier('sqlite', table)}"
                    )
                self.connection.execute("COMMIT")
            except Exception:
                self.connection.execute("ROLLBACK")
                raise
            finally:
                self.connection.execute("PRAGMA foreign_keys=ON")
            return

        with self.cursor() as cursor:
            cursor.execute("SET FOREIGN_KEY_CHECKS=0")
            try:
                self.connection.begin()
                for table in reversed(TABLE_ORDER):
                    cursor.execute(
                        f"DELETE FROM {quote_identifier('mysql', table)}"
                    )
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise
            finally:
                cursor.execute("SET FOREIGN_KEY_CHECKS=1")
                self.connection.commit()

    def insert_batches(
        self,
        table: str,
        columns: Sequence[str],
        batches: Iterator[list[tuple[Any, ...]]],
    ) -> int:
        assert self.connection is not None
        quoted_table = quote_identifier(self.kind, table)
        quoted_columns = ", ".join(
            quote_identifier(self.kind, column) for column in columns
        )
        marker = "?" if self.kind == "sqlite" else "%s"
        markers = ", ".join(marker for _ in columns)
        sql = (
            f"INSERT INTO {quoted_table} ({quoted_columns}) "
            f"VALUES ({markers})"
        )
        copied = 0

        if self.kind == "sqlite":
            self.connection.execute("BEGIN")
            try:
                for batch in batches:
                    if not batch:
                        continue
                    self.connection.executemany(sql, batch)
                    copied += len(batch)
                self.connection.execute("COMMIT")
            except Exception:
                self.connection.execute("ROLLBACK")
                raise
            return copied

        with self.cursor() as cursor:
            try:
                self.connection.begin()
                for batch in batches:
                    if not batch:
                        continue
                    cursor.executemany(sql, batch)
                    copied += len(batch)
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise
        return copied

    def reset_sequences(self) -> None:
        assert self.connection is not None
        if self.kind == "sqlite":
            for table in AUTO_INCREMENT_TABLES:
                quoted = quote_identifier("sqlite", table)
                row = self.connection.execute(
                    f"SELECT COALESCE(MAX(id),0) AS max_id FROM {quoted}"
                ).fetchone()
                maximum = int(row["max_id"] or 0)
                self.connection.execute(
                    "DELETE FROM sqlite_sequence WHERE name=?",
                    (table,),
                )
                self.connection.execute(
                    "INSERT INTO sqlite_sequence(name,seq) VALUES(?,?)",
                    (table, maximum),
                )
            return

        with self.cursor() as cursor:
            for table in AUTO_INCREMENT_TABLES:
                quoted = quote_identifier("mysql", table)
                cursor.execute(
                    f"SELECT COALESCE(MAX(id),0) AS max_id FROM {quoted}"
                )
                maximum = int(cursor.fetchone()["max_id"] or 0)
                cursor.execute(
                    f"ALTER TABLE {quoted} AUTO_INCREMENT = {maximum + 1}"
                )
        self.connection.commit()

    def foreign_key_check(self) -> None:
        assert self.connection is not None
        if self.kind == "sqlite":
            rows = self.connection.execute("PRAGMA foreign_key_check").fetchall()
            if rows:
                raise RuntimeError(
                    f"SQLite foreign-key verification failed: {rows[:5]}"
                )


def _parse_datetime(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        raw = str(value).strip()
        if not raw:
            return None
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError as exc:
            raise ValueError(f"invalid timestamp {value!r}") from exc

    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def transform_value(
    table: str,
    column: str,
    value: Any,
    destination_kind: str,
) -> Any:
    if column not in MYSQL_DATETIME_COLUMNS.get(table, frozenset()):
        return value
    if value is None:
        return None

    parsed = _parse_datetime(value)
    if parsed is None:
        return None
    if destination_kind == "mysql":
        return parsed
    return parsed.isoformat(sep=" ")


def transform_batch(
    table: str,
    columns: Sequence[str],
    batch: list[tuple[Any, ...]],
    destination_kind: str,
) -> list[tuple[Any, ...]]:
    return [
        tuple(
            transform_value(table, column, value, destination_kind)
            for column, value in zip(columns, row)
        )
        for row in batch
    ]


def _canonical_value(table: str, column: str, value: Any) -> Any:
    if value is None:
        return None
    if column in MYSQL_DATETIME_COLUMNS.get(table, frozenset()):
        parsed = _parse_datetime(value)
        if parsed is None:
            return None
        return parsed.replace(tzinfo=timezone.utc).isoformat()
    if isinstance(value, datetime):
        parsed = value
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed.isoformat()
    if isinstance(value, bytes):
        return {"__bytes__": value.hex()}
    return value


def table_digest(
    endpoint: Endpoint,
    table: str,
    columns: Sequence[str],
    *,
    batch_size: int,
) -> str:
    digest = hashlib.sha256()
    for batch in endpoint.iter_batches(
        table,
        columns,
        batch_size=batch_size,
        ordered=True,
    ):
        for row in batch:
            canonical = [
                _canonical_value(table, column, value)
                for column, value in zip(columns, row)
            ]
            payload = json.dumps(
                canonical,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
                default=str,
            ).encode("utf-8")
            digest.update(len(payload).to_bytes(8, "big"))
            digest.update(payload)
    return digest.hexdigest()


def validate_schema(source: Endpoint, destination: Endpoint) -> dict[str, tuple[str, ...]]:
    schema: dict[str, tuple[str, ...]] = {}
    for table in TABLE_ORDER:
        if not source.table_exists(table):
            raise RuntimeError(
                f"source database is missing required Blockinator table {table!r}"
            )
        if not destination.table_exists(table):
            raise RuntimeError(
                f"destination schema is missing required Blockinator table {table!r}"
            )

        source_columns = source.columns(table)
        destination_columns = destination.columns(table)
        if set(source_columns) != set(destination_columns):
            missing = sorted(set(source_columns) - set(destination_columns))
            extra = sorted(set(destination_columns) - set(source_columns))
            raise RuntimeError(
                f"schema mismatch for {table}: "
                f"destination missing={missing or 'none'}, "
                f"destination extra={extra or 'none'}"
            )
        schema[table] = source_columns
    return schema


def migrate_data(
    source: Endpoint,
    destination: Endpoint,
    *,
    batch_size: int = 2000,
    verify_content: bool = True,
    progress=print,
) -> MigrationSummary:
    schema = validate_schema(source, destination)
    source_counts = {table: source.count(table) for table in TABLE_ORDER}

    progress("Clearing destination Blockinator tables...")
    destination.clear_all()

    source.begin_consistent_read()
    try:
        for table in TABLE_ORDER:
            columns = schema[table]

            def batches():
                for batch in source.iter_batches(
                    table,
                    columns,
                    batch_size=batch_size,
                ):
                    yield transform_batch(
                        table,
                        columns,
                        batch,
                        destination.kind,
                    )

            copied = destination.insert_batches(
                table,
                columns,
                batches(),
            )
            expected = source_counts[table]
            if copied != expected:
                raise RuntimeError(
                    f"{table}: copied {copied:,} rows but expected {expected:,}"
                )
            progress(f"  {table}: {copied:,} rows")
    finally:
        source.rollback()

    destination.reset_sequences()
    destination.foreign_key_check()

    destination_counts = {
        table: destination.count(table)
        for table in TABLE_ORDER
    }
    mismatches = {
        table: (source_counts[table], destination_counts[table])
        for table in TABLE_ORDER
        if source_counts[table] != destination_counts[table]
    }
    if mismatches:
        raise RuntimeError(
            f"row-count verification failed: {mismatches}"
        )

    if verify_content:
        progress("Verifying table contents...")
        for table in TABLE_ORDER:
            columns = schema[table]
            source_digest = table_digest(
                source,
                table,
                columns,
                batch_size=batch_size,
            )
            destination_digest = table_digest(
                destination,
                table,
                columns,
                batch_size=batch_size,
            )
            if source_digest != destination_digest:
                raise RuntimeError(
                    f"content verification failed for {table}: "
                    f"{source_digest} != {destination_digest}"
                )
            progress(f"  {table}: verified {source_digest[:12]}…")

    return MigrationSummary(
        row_counts=source_counts,
        content_verified=verify_content,
    )


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def mysql_config_from_args(args) -> MySQLConfig:
    host = args.mysql_host or os.getenv("MYSQL_HOST", "").strip()
    database = args.mysql_database or os.getenv("MYSQL_DATABASE", "").strip()
    user = args.mysql_user or os.getenv("MYSQL_USER", "").strip()
    password = (
        args.mysql_password
        if args.mysql_password is not None
        else os.getenv("MYSQL_PASSWORD", "")
    )
    if not host:
        raise ValueError("MySQL host is required (--mysql-host or MYSQL_HOST)")
    if not database:
        raise ValueError(
            "MySQL database is required (--mysql-database or MYSQL_DATABASE)"
        )
    if not user:
        raise ValueError("MySQL user is required (--mysql-user or MYSQL_USER)")

    ssl_enabled = (
        args.mysql_ssl_enabled
        if args.mysql_ssl_enabled is not None
        else _env_bool("MYSQL_SSL_ENABLED", False)
    )
    verify = (
        not args.mysql_ssl_no_verify
        if args.mysql_ssl_no_verify
        else _env_bool("MYSQL_SSL_VERIFY_CERT", True)
    )
    return MySQLConfig(
        host=host,
        port=args.mysql_port,
        database=database,
        user=user,
        password=password,
        connect_timeout=args.mysql_connect_timeout,
        ssl_ca=args.mysql_ssl_ca or os.getenv("MYSQL_SSL_CA", "").strip() or None,
        ssl_cert=args.mysql_ssl_cert
        or os.getenv("MYSQL_SSL_CERT", "").strip()
        or None,
        ssl_key=args.mysql_ssl_key
        or os.getenv("MYSQL_SSL_KEY", "").strip()
        or None,
        ssl_enabled=ssl_enabled,
        ssl_verify_cert=verify,
    )


def initialize_destination(
    kind: str,
    *,
    sqlite_path: Path,
    mysql_config: MySQLConfig,
) -> None:
    if kind == "sqlite":
        Database(str(sqlite_path))
        return
    MySQLBackend(mysql_config).initialize(
        os.getenv("TZ", "UTC").strip() or "UTC"
    )


def _source_counts(source: Endpoint) -> dict[str, int]:
    counts: dict[str, int] = {}
    for table in TABLE_ORDER:
        if not source.table_exists(table):
            raise RuntimeError(
                f"source database is missing required Blockinator table {table!r}"
            )
        counts[table] = source.count(table)
    return counts


def _confirm() -> None:
    if not sys.stdin.isatty():
        raise RuntimeError(
            "interactive confirmation unavailable; rerun with --yes"
        )
    response = input(
        "\nThe destination Blockinator database will be REPLACED. "
        "Type MIGRATE to continue: "
    )
    if response.strip() != "MIGRATE":
        raise RuntimeError("migration cancelled")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Migrate all Blockinator database data between SQLite and MySQL. "
            "Blockinator must be offline for the entire operation."
        )
    )
    parser.add_argument(
        "--source",
        choices=("sqlite", "mysql"),
        required=True,
        help="source database type",
    )
    parser.add_argument(
        "--destination",
        choices=("sqlite", "mysql"),
        required=True,
        help="destination database type",
    )
    parser.add_argument(
        "--sqlite-path",
        default=os.getenv(
            "SQLITE_PATH",
            str(Path(os.getenv("DATA_DIR", "./data")) / "policy.db"),
        ),
        help=(
            "SQLite policy.db path; used as source or destination depending "
            "on migration direction"
        ),
    )
    parser.add_argument("--mysql-host")
    parser.add_argument(
        "--mysql-port",
        type=int,
        default=int(os.getenv("MYSQL_PORT", "3306")),
    )
    parser.add_argument("--mysql-database")
    parser.add_argument("--mysql-user")
    parser.add_argument("--mysql-password")
    parser.add_argument(
        "--mysql-connect-timeout",
        type=int,
        default=int(os.getenv("MYSQL_CONNECT_TIMEOUT", "10")),
    )
    parser.add_argument("--mysql-ssl-ca")
    parser.add_argument("--mysql-ssl-cert")
    parser.add_argument("--mysql-ssl-key")
    parser.add_argument(
        "--mysql-ssl-enabled",
        action=argparse.BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "--mysql-ssl-no-verify",
        action="store_true",
        help="disable MySQL server certificate/identity verification",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=2000,
        help="rows copied per batch (default: 2000)",
    )
    parser.add_argument(
        "--confirm-offline",
        action="store_true",
        help="confirm Blockinator has been stopped before migration",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="skip the destructive destination confirmation prompt",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate the source and print row counts without modifying destination",
    )
    parser.add_argument(
        "--skip-content-verification",
        action="store_true",
        help="verify row counts only instead of SHA-256 content digests",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.source == args.destination:
        parser.error("source and destination must be different database types")
    if args.batch_size < 1 or args.batch_size > 100_000:
        parser.error("--batch-size must be between 1 and 100000")

    sqlite_path = Path(args.sqlite_path).expanduser()
    mysql_config = mysql_config_from_args(args)

    if args.source == "sqlite" and not sqlite_path.is_file():
        parser.error(f"SQLite source does not exist: {sqlite_path}")

    source = Endpoint(
        args.source,
        sqlite_path=sqlite_path if args.source == "sqlite" else None,
        mysql_config=mysql_config if args.source == "mysql" else None,
        readonly=args.source == "sqlite",
    )

    try:
        with source:
            counts = _source_counts(source)
            total = sum(counts.values())
            print(
                f"Source: {args.source} · "
                f"{total:,} rows across {len(TABLE_ORDER)} tables"
            )
            for table in TABLE_ORDER:
                print(f"  {table}: {counts[table]:,}")

        if args.dry_run:
            print("\nDry run complete. Destination was not modified.")
            return 0

        if not args.confirm_offline:
            parser.error(
                "--confirm-offline is required; stop Blockinator before migration"
            )

        print(
            "\nIMPORTANT: this migration replaces the destination database. "
            "Filesystem TLS/Caddy data under data/tls and data/caddy is not "
            "stored in either database and is not copied by this script."
        )
        if not args.yes:
            _confirm()

        if args.destination == "sqlite":
            sqlite_path.parent.mkdir(parents=True, exist_ok=True)

        initialize_destination(
            args.destination,
            sqlite_path=sqlite_path,
            mysql_config=mysql_config,
        )

        with Endpoint(
            args.source,
            sqlite_path=sqlite_path if args.source == "sqlite" else None,
            mysql_config=mysql_config if args.source == "mysql" else None,
            readonly=args.source == "sqlite",
        ) as source, Endpoint(
            args.destination,
            sqlite_path=sqlite_path if args.destination == "sqlite" else None,
            mysql_config=mysql_config if args.destination == "mysql" else None,
            readonly=False,
        ) as destination:
            summary = migrate_data(
                source,
                destination,
                batch_size=args.batch_size,
                verify_content=not args.skip_content_verification,
            )

        print("\nMigration completed successfully.")
        print(
            f"Copied {sum(summary.row_counts.values()):,} rows across "
            f"{len(summary.row_counts)} tables."
        )
        print(
            "Verification: "
            + (
                "row counts + SHA-256 content digests"
                if summary.content_verified
                else "row counts"
            )
        )
        print(
            f"Set DATABASE_BACKEND={args.destination} before restarting Blockinator."
        )
        return 0
    except KeyboardInterrupt:
        print("\nMigration cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Migration failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
