"""Transactional statistics for retained log rows, including offline imports.

SQLite triggers and MySQL application writes maintain counters in the log
transaction. MySQL needs no server-level trigger privileges. Offline imports
rebuild derived counters; a one-time backfill supports existing installs.
"""
from collections import defaultdict
from contextlib import contextmanager

from .mysql_backend import MySQLConnection

TOTAL_BUCKET = "__total__"


def initialize_rollups(db):
    mysql = db.backend == "mysql"
    with db.connect() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS query_statistics (
            bucket VARCHAR(16) PRIMARY KEY,
            queries BIGINT NOT NULL DEFAULT 0,
            blocks BIGINT NOT NULL DEFAULT 0,
            response_total DOUBLE NOT NULL DEFAULT 0,
            response_samples BIGINT NOT NULL DEFAULT 0
        )""" + (" ENGINE=InnoDB" if mysql else ""))

        def delta(row, sign):
            statements = []
            for bucket in (f"SUBSTR({row}.ts,1,16)", "'__total__'"):
                statements.append(f"""INSERT INTO query_statistics
                    (bucket,queries,blocks,response_total,response_samples)
                    VALUES({bucket},{sign},{sign}*{row}.blocked,
                           {sign}*COALESCE({row}.response_time_ms,0),
                           {sign}*CASE WHEN {row}.response_time_ms IS NULL THEN 0 ELSE 1 END)
                    ON CONFLICT(bucket) DO UPDATE SET
                        queries=query_statistics.queries+excluded.queries,
                        blocks=query_statistics.blocks+excluded.blocks,
                        response_total=query_statistics.response_total+excluded.response_total,
                        response_samples=query_statistics.response_samples+excluded.response_samples;""")
            return "\n".join(statements)

        events = {
            "insert": delta("NEW", 1),
            "delete": delta("OLD", -1) + "DELETE FROM query_statistics WHERE bucket=SUBSTR(OLD.ts,1,16) AND queries=0;",
            "update": delta("OLD", -1) + delta("NEW", 1) + "DELETE FROM query_statistics WHERE bucket=SUBSTR(OLD.ts,1,16) AND queries=0;",
        }
        if mysql:
            # Remove triggers from the short-lived 1.20.0 implementation before
            # enabling application-side maintenance, preventing double counts.
            existing = {r["TRIGGER_NAME"] for r in con.execute(
                "SELECT TRIGGER_NAME FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE()"
            )}
            for event in events:
                name = "query_statistics_" + event
                if name in existing:
                    con.execute(f"DROP TRIGGER {name}")
        else:
            for event, body in events.items():
                event_sql = event.upper()
                if event == "update":
                    event_sql += " OF ts,blocked,response_time_ms"
                con.execute(f"CREATE TRIGGER IF NOT EXISTS query_statistics_{event} "
                            f"AFTER {event_sql} ON query_log FOR EACH ROW BEGIN {body} END")

        marker = con.execute("SELECT value FROM settings WHERE `key`='statistics_rollups_v1'").fetchone()
        if not marker:
            rebuild_rollups(con)


@contextmanager
def log_transaction(con):
    """Join the logger transaction, or own one for standalone maintenance."""
    own = not con.in_transaction
    if own:
        con.execute("BEGIN IMMEDIATE")
    try:
        yield
        if own:
            con.execute("COMMIT")
    except Exception:
        if own and con.in_transaction:
            con.execute("ROLLBACK")
        raise


def rebuild_rollups(con):
    """Recompute derived data after offline imports or manual history changes."""
    with log_transaction(con):
        con.execute("DELETE FROM query_statistics")
        con.execute("""INSERT INTO query_statistics
            SELECT SUBSTR(ts,1,16),COUNT(*),COALESCE(SUM(blocked),0),
                   COALESCE(SUM(response_time_ms),0),COUNT(response_time_ms)
            FROM query_log GROUP BY SUBSTR(ts,1,16)""")
        con.execute("""INSERT INTO query_statistics
            SELECT '__total__',COUNT(*),COALESCE(SUM(blocked),0),
                   COALESCE(SUM(response_time_ms),0),COUNT(response_time_ms)
            FROM query_log""")
        con.execute("""INSERT INTO settings(`key`,value) VALUES('statistics_rollups_v1','1')
            ON CONFLICT(key) DO UPDATE SET value=excluded.value""")


def _mysql_delta(con, rows, sign):
    buckets = defaultdict(lambda: [0, 0, 0.0, 0])
    for row in rows:
        for bucket in (str(row["ts"])[:16], TOTAL_BUCKET):
            values = buckets[bucket]
            values[0] += sign
            values[1] += sign * int(row["blocked"])
            timing = row.get("response_time_ms")
            if timing is not None:
                values[2] += sign * float(timing)
                values[3] += sign
    if not buckets:
        return
    con.executemany("""INSERT INTO query_statistics
        (bucket,queries,blocks,response_total,response_samples) VALUES(?,?,?,?,?)
        ON CONFLICT(bucket) DO UPDATE SET
            queries=query_statistics.queries+excluded.queries,
            blocks=query_statistics.blocks+excluded.blocks,
            response_total=query_statistics.response_total+excluded.response_total,
            response_samples=query_statistics.response_samples+excluded.response_samples""",
        [(bucket, *values) for bucket, values in sorted(buckets.items())])
    if sign < 0:
        con.executemany("DELETE FROM query_statistics WHERE bucket=? AND queries=0",
                        [(bucket,) for bucket in buckets if bucket != TOTAL_BUCKET])


LOG_COLUMNS = ("ts", "server_id", "client_ip", "client_name", "client_port",
               "protocol", "policy_scheme", "qname", "qtype", "qclass", "blocked",
               "reason", "matched_scope", "matched_list", "matched_list_type",
               "response_time_ms", "request_json")


def insert_query_logs(con, rows):
    """Insert a batch and its summaries atomically on either backend."""
    rows = list(rows)
    with log_transaction(con):
        result = con.executemany(
            "INSERT INTO query_log(" + ",".join(LOG_COLUMNS) + ") VALUES(" +
            ",".join("?" for _ in LOG_COLUMNS) + ")",
            [tuple(row.get(column) for column in LOG_COLUMNS) for row in rows])
        if isinstance(con, MySQLConnection):
            _mysql_delta(con, rows, 1)
        return result


def delete_query_logs(con, ids):
    """Delete bounded retained rows and summaries in the caller's transaction."""
    ids = list(ids)
    if not ids:
        return 0
    where = " WHERE id IN (" + ",".join("?" for _ in ids) + ")"
    with log_transaction(con):
        mysql = isinstance(con, MySQLConnection)
        if mysql:
            rows = con.execute("SELECT ts,blocked,response_time_ms FROM query_log" +
                               where + " FOR UPDATE", ids).fetchall()
        result = con.execute("DELETE FROM query_log" + where, ids)
        if mysql:
            _mysql_delta(con, rows, -1)
        return max(0, result.rowcount)


def retained_totals(con):
    row = con.execute("""SELECT queries,blocks,
        CASE WHEN response_samples>0 THEN response_total/response_samples ELSE NULL END
            AS average_response_time_ms
        FROM query_statistics WHERE bucket='__total__'""").fetchone()
    return dict(row) if row else {"queries": 0, "blocks": 0, "average_response_time_ms": None}
