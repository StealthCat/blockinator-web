#!/usr/bin/env python3
"""Offline, same-backend backup/restore. Run only through the host updater."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.mysql_backend import MySQLConfig
from tools.migrate_database import _mysql_connect, quote_identifier


def mysql_connection():
    # Configuration parsing does not initialize or migrate the database.
    return _mysql_connect(MySQLConfig.from_env())


def mysql_backup(destination):
    import pymysql
    con = mysql_connection()
    try:
        with con.cursor() as cur:
            cur.execute("SHOW FULL TABLES")
            objects = [(list(row.values())[0], list(row.values())[1]) for row in cur.fetchall()]
        with destination.open("w") as out:
            def emit(sql):
                out.write(json.dumps(sql) + "\n")
            for name, kind in objects:
                if kind != "BASE TABLE":
                    continue
                table = quote_identifier("mysql", name)
                with con.cursor() as cur:
                    cur.execute("SHOW CREATE TABLE " + table)
                    emit(cur.fetchone()["Create Table"])
                with con.cursor(pymysql.cursors.SSCursor) as cur:
                    cur.execute("SELECT * FROM " + table)
                    columns = ",".join(quote_identifier("mysql", c[0]) for c in cur.description)
                    for row in cur:
                        emit(f"INSERT INTO {table} ({columns}) VALUES ({','.join(con.escape(value) for value in row)})")
            for name, kind in objects:
                if kind == "VIEW":
                    with con.cursor() as cur:
                        cur.execute("SHOW CREATE VIEW " + quote_identifier("mysql", name))
                        sql = cur.fetchone()["Create View"]
                        # Restore with the configured application account as definer.
                        sql = re.sub(r"DEFINER=`(?:``|[^`])*`@`(?:``|[^`])*`", "", sql)
                        emit(sql)
            # The application currently has no triggers/routines; refuse to make
            # an incomplete backup if an administrator has installed extensions.
            with con.cursor() as cur:
                cur.execute("SHOW TRIGGERS")
                if cur.fetchone():
                    raise RuntimeError("Custom MySQL triggers require an external backup procedure")
                cur.execute("SELECT ROUTINE_NAME FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE()")
                if cur.fetchone():
                    raise RuntimeError("Custom MySQL routines require an external backup procedure")
    finally:
        con.close()


def mysql_restore(source):
    con = mysql_connection()
    try:
        with con.cursor() as cur:
            cur.execute("SET FOREIGN_KEY_CHECKS=0")
            cur.execute("SHOW FULL TABLES")
            objects = [(list(row.values())[0], list(row.values())[1]) for row in cur.fetchall()]
            for name, kind in sorted(objects, key=lambda item: item[1] != "VIEW"):
                cur.execute("DROP " + ("VIEW " if kind == "VIEW" else "TABLE ") + quote_identifier("mysql", name))
            with source.open() as inp:
                for line in inp:
                    cur.execute(json.loads(line))
            cur.execute("SET FOREIGN_KEY_CHECKS=1")
        con.commit()
    finally:
        con.close()


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(action, backup_dir, data_dir):
    backup_dir, data_dir = Path(backup_dir), Path(data_dir)
    kind = os.getenv("DATABASE_BACKEND", "sqlite")
    if kind not in {"sqlite", "mysql"}:
        raise ValueError("Unsupported database backend")
    database = backup_dir / ("database.sqlite" if kind == "sqlite" else "database.jsonl")
    if action == "backup":
        backup_dir.mkdir(parents=True, exist_ok=True)
        if kind == "sqlite":
            source = sqlite3.connect((data_dir / "policy.db").resolve().as_uri() + "?mode=ro", uri=True)
            target = sqlite3.connect(database)
            try:
                source.backup(target)
                if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise RuntimeError("SQLite backup integrity check failed")
            finally:
                target.close()
                source.close()
        else:
            mysql_backup(database)
        tls_source = data_dir / "tls"
        if tls_source.is_symlink() or any(p.is_symlink() for p in tls_source.rglob("*")):
            raise ValueError("TLS backups require regular files and directories")
        if tls_source.exists():
            shutil.copytree(data_dir / "tls", backup_dir / "tls", symlinks=False)
        hashes = {str(path.relative_to(backup_dir)): digest(path) for path in backup_dir.rglob("*") if path.is_file()}
        (backup_dir / "complete.json").write_text(json.dumps({"backend": kind, "hashes": hashes}))
    else:
        manifest = json.loads((backup_dir / "complete.json").read_text())
        if manifest["backend"] != kind:
            raise ValueError("Backup backend differs from deployment")
        for name, expected in manifest["hashes"].items():
            if digest(backup_dir / name) != expected:
                raise ValueError("Backup checksum mismatch")
        if kind == "sqlite":
            target = data_dir / "policy.db"
            shutil.copyfile(database, target.with_suffix(".restore"))
            os.replace(target.with_suffix(".restore"), target)
            for suffix in ("-wal", "-shm"):
                Path(str(target) + suffix).unlink(missing_ok=True)
        else:
            mysql_restore(database)
        tls = data_dir / "tls"
        tls.mkdir(exist_ok=True)
        # Preserve the directory inode: Caddy has this directory bind-mounted.
        for child in tls.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
        if (backup_dir / "tls").exists():
            shutil.copytree(backup_dir / "tls", tls, dirs_exist_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("backup", "restore"))
    parser.add_argument("--backup-dir", default="/backup")
    args = parser.parse_args()
    run(args.action, args.backup_dir, os.getenv("DATA_DIR", "/data"))
