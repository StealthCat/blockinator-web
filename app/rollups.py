"""Transactional statistics for retained log rows, including offline imports.

Database triggers keep inserts, deletes and timing corrections consistent with
the log in the same transaction. A one-time backfill supports existing installs.
PTR-only updates do not change aggregates. No raw request payload is duplicated.
"""
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
            existing = {r["TRIGGER_NAME"] for r in con.execute(
                "SELECT TRIGGER_NAME FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE()"
            )}
        for event, body in events.items():
            name = "query_statistics_" + event
            if mysql and name in existing:
                continue
            # MySQL fires UPDATE triggers for PTR backfill too. Guard them so
            # name-only updates do not contend on the summary counters.
            if mysql and event == "update":
                body = ("IF NOT (OLD.ts <=> NEW.ts) OR NOT (OLD.blocked <=> NEW.blocked) "
                        "OR NOT (OLD.response_time_ms <=> NEW.response_time_ms) THEN " + body + " END IF;")
            event_sql = event.upper()
            if not mysql and event == "update":
                event_sql += " OF ts,blocked,response_time_ms"
            statement = (f"CREATE TRIGGER {'IF NOT EXISTS ' if not mysql else ''}{name} "
                         f"AFTER {event_sql} ON query_log FOR EACH ROW BEGIN {body} END")
            if mysql:
                # Translate each upsert separately; the normal adapter accepts
                # a single statement, whereas a trigger contains multiple ones.
                from .mysql_backend import MySQLConnection
                parts = body.split(";")
                body = ";".join(MySQLConnection._translate(part) for part in parts)
                statement = f"CREATE TRIGGER {name} AFTER {event_sql} ON query_log FOR EACH ROW BEGIN {body} END"
            con.execute(statement)

        marker = con.execute("SELECT value FROM settings WHERE `key`='statistics_rollups_v1'").fetchone()
        if not marker:
            con.execute("BEGIN IMMEDIATE")
            try:
                con.execute("DELETE FROM query_statistics")
                con.execute("""INSERT INTO query_statistics
                    SELECT SUBSTR(ts,1,16),COUNT(*),COALESCE(SUM(blocked),0),
                           COALESCE(SUM(response_time_ms),0),COUNT(response_time_ms)
                    FROM query_log GROUP BY SUBSTR(ts,1,16)""")
                con.execute("""INSERT INTO query_statistics
                    SELECT '__total__',COUNT(*),COALESCE(SUM(blocked),0),
                           COALESCE(SUM(response_time_ms),0),COUNT(response_time_ms)
                    FROM query_log""")
                con.execute("INSERT INTO settings(`key`,value) VALUES('statistics_rollups_v1','1')")
                con.execute("COMMIT")
            except Exception:
                if con.in_transaction:
                    con.execute("ROLLBACK")
                raise


def retained_totals(con):
    row = con.execute("""SELECT queries,blocks,
        CASE WHEN response_samples>0 THEN response_total/response_samples ELSE NULL END
            AS average_response_time_ms
        FROM query_statistics WHERE bucket='__total__'""").fetchone()
    return dict(row) if row else {"queries": 0, "blocks": 0, "average_response_time_ms": None}
