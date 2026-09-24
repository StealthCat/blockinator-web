import os
import tempfile
from pathlib import Path

import pytest

from app.db import Database
from app.mysql_backend import MySQLBackend, MySQLConfig
from tools.migrate_database import Endpoint, TABLE_ORDER, migrate_data


def _populate_database(db: Database) -> None:
    with db.connect() as con:
        con.execute(
            "INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",
            ("migration_test_marker", "preserve-me"),
        )
        con.execute(
            """
            INSERT INTO blocklists(
                id,name,source_type,list_type,enabled,use_globally,entry_count
            ) VALUES(42,'migration-list','manual','block',1,1,1)
            """
        )
        con.execute(
            "INSERT INTO domains(id,domain) VALUES(77,'blocked.example.com')"
        )
        con.execute(
            """
            INSERT INTO blocklist_domain_memberships(blocklist_id,domain_id)
            VALUES(42,77)
            """
        )
        con.execute(
            """
            INSERT INTO scopes(id,name,kind,target,state)
            VALUES(11,'migration-network','network','192.0.2.0/24','active')
            """
        )
        con.execute(
            """
            INSERT INTO scope_network_targets(scope_id,family,target)
            VALUES(11,4,'192.0.2.0/24')
            """
        )
        con.execute(
            """
            INSERT INTO scope_blocklists(scope_id,blocklist_id)
            VALUES(11,42)
            """
        )
        con.execute(
            """
            INSERT INTO query_log(
                id,ts,server_id,client_ip,client_name,client_port,protocol,
                policy_scheme,qname,qtype,qclass,blocked,reason,matched_scope,
                matched_list,matched_list_type,response_time_ms,request_json
            ) VALUES(
                123,'2026-09-24T14:00:00+00:00','migration-dns',
                '192.0.2.44','client.example.test',53000,'Udp','https',
                'blocked.example.com','A','IN',1,'blocklist_match',
                'migration-network','migration-list','block',1.25,
                '{"migration":true}'
            )
            """
        )
        con.execute(
            """
            INSERT INTO client_identities(client_ip,client_name,updated_at)
            VALUES(
                '192.0.2.44','client.example.test','2026-09-24 14:00:01'
            )
            """
        )
        con.execute(
            """
            INSERT INTO client_ptr_status(
                client_ip,status,client_name,first_seen_at,last_seen_at,
                last_attempt_at,last_success_at,next_attempt_at,attempt_count,
                last_error
            ) VALUES(
                '192.0.2.44','resolved','client.example.test',
                100,200,190,190,500,0,NULL
            )
            """
        )
        con.execute(
            """
            INSERT INTO admin_users(
                id,username,password_hash,created_at,updated_at
            ) VALUES(
                5,'MigrationAdmin','hash-value',
                '2026-09-24 14:00:02','2026-09-24 14:00:03'
            )
            """
        )
        con.execute(
            """
            INSERT INTO admin_sessions(
                token_hash,user_id,csrf_token,created_at,expires_at,last_seen_at
            ) VALUES('session-hash',5,'csrf-value',1000,2000,1500)
            """
        )
        con.execute(
            """
            INSERT INTO api_keys(
                id,name,key_hash,key_prefix,enabled,created_at,updated_at,last_used_at
            ) VALUES(
                9,'Migration Key','api-hash','migrate',1,
                '2026-09-24 14:00:04','2026-09-24 14:00:05',
                '2026-09-24 14:00:06'
            )
            """
        )


def _assert_migrated_data(endpoint: Endpoint) -> None:
    assert endpoint.count("blocklists") == 1
    assert endpoint.count("domains") == 1
    assert endpoint.count("blocklist_domain_memberships") == 1
    assert endpoint.count("scopes") == 1
    assert endpoint.count("scope_network_targets") == 1
    assert endpoint.count("scope_blocklists") == 1
    assert endpoint.count("query_log") == 1
    assert endpoint.count("client_identities") == 1
    assert endpoint.count("client_ptr_status") == 1
    assert endpoint.count("admin_users") == 1
    assert endpoint.count("admin_sessions") == 1
    assert endpoint.count("api_keys") == 1

    assert endpoint.connection is not None
    if endpoint.kind == "sqlite":
        marker = endpoint.connection.execute(
            """
            SELECT value FROM settings
            WHERE value='preserve-me'
            """
        ).fetchone()
        query_row = endpoint.connection.execute(
            """
            SELECT id,matched_list,response_time_ms
            FROM query_log
            WHERE id=123
            """
        ).fetchone()
        session = endpoint.connection.execute(
            """
            SELECT user_id FROM admin_sessions WHERE token_hash='session-hash'
            """
        ).fetchone()
    else:
        with endpoint.cursor() as cursor:
            cursor.execute(
                """
                SELECT value FROM settings
                WHERE value='preserve-me'
                """
            )
            marker = cursor.fetchone()
            cursor.execute(
                """
                SELECT id,matched_list,response_time_ms
                FROM query_log
                WHERE id=123
                """
            )
            query_row = cursor.fetchone()
            cursor.execute(
                """
                SELECT user_id FROM admin_sessions
                WHERE token_hash='session-hash'
                """
            )
            session = cursor.fetchone()

    assert marker["value"] == "preserve-me"
    assert int(query_row["id"]) == 123
    assert query_row["matched_list"] == "migration-list"
    assert abs(float(query_row["response_time_ms"]) - 1.25) < 0.000001
    assert int(session["user_id"]) == 5


def test_migration_copies_all_current_tables_and_relationships():
    source_dir = tempfile.TemporaryDirectory()
    destination_dir = tempfile.TemporaryDirectory()
    source_path = Path(source_dir.name) / "source.db"
    destination_path = Path(destination_dir.name) / "destination.db"

    source_db = Database(str(source_path))
    Database(str(destination_path))
    _populate_database(source_db)

    messages = []
    with Endpoint(
        "sqlite",
        sqlite_path=source_path,
        readonly=True,
    ) as source, Endpoint(
        "sqlite",
        sqlite_path=destination_path,
    ) as destination:
        summary = migrate_data(
            source,
            destination,
            batch_size=3,
            verify_content=True,
            progress=messages.append,
        )
        _assert_migrated_data(destination)

    assert summary.content_verified is True
    assert set(summary.row_counts) == set(TABLE_ORDER)
    assert summary.row_counts["query_log"] == 1
    assert any("Verifying table contents" in message for message in messages)

    source_dir.cleanup()
    destination_dir.cleanup()


@pytest.mark.skipif(
    os.getenv("MYSQL_TEST") != "1",
    reason="requires the MySQL integration-test service",
)
def test_sqlite_to_mysql_migration_uses_real_backend():
    source_dir = tempfile.TemporaryDirectory()
    source_path = Path(source_dir.name) / "source.db"
    source_db = Database(str(source_path))
    _populate_database(source_db)

    config = MySQLConfig.from_env()
    MySQLBackend(config).initialize("UTC")

    with Endpoint(
        "sqlite",
        sqlite_path=source_path,
        readonly=True,
    ) as source, Endpoint(
        "mysql",
        mysql_config=config,
    ) as destination:
        summary = migrate_data(
            source,
            destination,
            batch_size=4,
            verify_content=True,
            progress=lambda _message: None,
        )
        _assert_migrated_data(destination)

    assert summary.content_verified is True
    assert summary.row_counts["admin_sessions"] == 1
    source_dir.cleanup()
