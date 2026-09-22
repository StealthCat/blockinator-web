from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.db import Database
from app.tls import TlsManager, TlsSettings


def certificate_pair(hostname: str) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, hostname)]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def write_json(path: Path, value: dict) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render representative Blockinator native Caddy JSON configs."
    )
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    output: Path = args.output
    output.mkdir(parents=True, exist_ok=True)
    tls_dir = output / "tls"
    tls_dir.mkdir(parents=True, exist_ok=True)

    db = Database(str(output / "fixtures.db"))
    manager = TlsManager(
        db,
        tls_dir=tls_dir,
        caddy_admin_url="http://caddy.invalid:2019",
        reconcile_seconds=3600,
    )

    write_json(
        output / "http.json",
        manager.render_caddy_json(TlsSettings(mode="http")),
    )

    cert_pem, key_pem = certificate_pair("blockinator.example.test")
    manager._write_atomic(manager.cert_path, cert_pem, 0o644)
    manager._write_atomic(manager.key_path, key_pem, 0o600)
    write_json(
        output / "upload.json",
        manager.render_caddy_json(
            TlsSettings(
                mode="upload",
                hostname="blockinator.example.test",
            )
        ),
    )

    ca_pem, _ = certificate_pair("private-ca.example.test")
    manager._write_atomic(manager.ca_root_path, ca_pem, 0o644)
    manager._write_atomic(
        manager.eab_hmac_path,
        b"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4\n",
        0o600,
    )
    write_json(
        output / "acme.json",
        manager.render_caddy_json(
            TlsSettings(
                mode="acme",
                hostname="blockinator.example.test",
                acme_email="admin@example.test",
                acme_directory="https://acme.example.test/directory",
                acme_eab_key_id="fixture-key-id",
            )
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
