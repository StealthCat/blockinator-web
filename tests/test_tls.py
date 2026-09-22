from __future__ import annotations

import os
import stat
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.db import Database
from app.tls import (
    DEFAULT_ACME_DIRECTORY,
    TlsManager,
    TlsSettings,
    normalize_tls_hostname,
    validate_ca_root,
    validate_certificate_and_key,
)


def _certificate_pair(hostname: str = "blockinator.example.com", wildcard: bool = False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, hostname)]
    )
    san_name = "*.example.com" if wildcard else hostname
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
            x509.SubjectAlternativeName([x509.DNSName(san_name)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _manager(tmp_path: Path):
    db = Database(str(tmp_path / "test.db"))
    manager = TlsManager(
        db,
        tls_dir=tmp_path / "tls",
        caddy_admin_url="http://caddy.invalid:2019",
        reconcile_seconds=5,
    )
    return db, manager


def test_hostname_normalization_accepts_idna_and_rejects_urls():
    assert normalize_tls_hostname("BÜCHER.Example.") == "xn--bcher-kva.example"
    with pytest.raises(ValueError):
        normalize_tls_hostname("https://blockinator.example.com")
    with pytest.raises(ValueError):
        normalize_tls_hostname("*.example.com")


def test_uploaded_certificate_and_key_validation():
    cert_pem, key_pem = _certificate_pair()
    info = validate_certificate_and_key(
        cert_pem,
        key_pem,
        "blockinator.example.com",
    )
    assert "blockinator.example.com" in info.dns_names
    assert info.not_after > datetime.now(timezone.utc)


def test_uploaded_certificate_rejects_wrong_key_and_wrong_hostname():
    cert_pem, _ = _certificate_pair()
    _, wrong_key = _certificate_pair("other.example.com")
    with pytest.raises(ValueError, match="does not match"):
        validate_certificate_and_key(
            cert_pem,
            wrong_key,
            "blockinator.example.com",
        )

    _, correct_key = _certificate_pair("unrelated.example.net")
    unrelated_cert, unrelated_key = _certificate_pair("unrelated.example.net")
    with pytest.raises(ValueError, match="does not cover"):
        validate_certificate_and_key(
            unrelated_cert,
            unrelated_key,
            "blockinator.example.com",
        )


def test_wildcard_certificate_matches_one_label():
    cert_pem, key_pem = _certificate_pair(wildcard=True)
    validate_certificate_and_key(cert_pem, key_pem, "blockinator.example.com")
    with pytest.raises(ValueError, match="does not cover"):
        validate_certificate_and_key(cert_pem, key_pem, "deep.blockinator.example.com")


def test_http_and_acme_caddyfile_rendering(tmp_path):
    _, manager = _manager(tmp_path)

    http_config = manager.render_caddyfile(TlsSettings(mode="http"))
    assert "persist_config off" in http_config
    assert "auto_https off" in http_config
    assert ":80 {" in http_config
    assert "reverse_proxy blockinator:8080" in http_config
    assert ":443" not in http_config

    manager._write_atomic(
        manager.ca_root_path,
        _certificate_pair("ca.example.com")[0],
        0o644,
    )
    manager._write_atomic(manager.eab_hmac_path, b"secret-hmac\n", 0o600)
    acme = manager.render_caddyfile(
        TlsSettings(
            mode="acme",
            hostname="blockinator.example.com",
            acme_email="admin@example.com",
            acme_directory="https://ca.example.com/acme/directory",
            acme_eab_key_id="kid-123",
        )
    )
    assert "auto_https disable_redirects" in acme
    assert 'acme_ca "https://ca.example.com/acme/directory"' in acme
    assert "acme_ca_root /blockinator-tls/acme-ca-root.pem" in acme
    assert 'key_id "kid-123"' in acme
    assert 'mac_key "secret-hmac"' in acme
    assert "blockinator.example.com {" in acme


def test_configure_uploaded_certificate_applies_and_persists(tmp_path, monkeypatch):
    db, manager = _manager(tmp_path)
    cert_pem, key_pem = _certificate_pair()
    adapted: list[str] = []
    loaded: list[str] = []

    monkeypatch.setattr(manager, "_adapt", lambda config: adapted.append(config))
    monkeypatch.setattr(manager, "_load", lambda config: loaded.append(config))

    info = manager.configure(
        TlsSettings(
            mode="upload",
            hostname="blockinator.example.com",
            http_redirect=True,
        ),
        certificate_pem=cert_pem,
        private_key_pem=key_pem,
    )

    assert info is not None
    assert db.get_setting("tls_mode") == "upload"
    assert db.get_setting("tls_hostname") == "blockinator.example.com"
    assert db.get_setting("tls_http_redirect") == "1"
    assert adapted and loaded
    assert "tls /blockinator-tls/uploaded-cert.pem /blockinator-tls/uploaded-key.pem" in loaded[-1]
    assert stat.S_IMODE(os.stat(manager.cert_path).st_mode) == 0o644
    assert stat.S_IMODE(os.stat(manager.key_path).st_mode) == 0o600


def test_configure_acme_custom_root_and_eab(tmp_path, monkeypatch):
    db, manager = _manager(tmp_path)
    ca_pem, _ = _certificate_pair("ca.example.com")
    loaded: list[str] = []
    monkeypatch.setattr(manager, "_adapt", lambda config: None)
    monkeypatch.setattr(manager, "_load", lambda config: loaded.append(config))

    manager.configure(
        TlsSettings(
            mode="acme",
            hostname="blockinator.example.com",
            acme_email="admin@example.com",
            acme_directory="https://ca.example.com/acme/directory",
            acme_eab_key_id="key-id",
        ),
        ca_root_pem=ca_pem,
        eab_hmac="hmac-secret",
    )

    assert db.get_setting("tls_mode") == "acme"
    assert db.get_setting("tls_acme_eab_key_id") == "key-id"
    assert manager.ca_root_path.exists()
    assert manager.eab_hmac_path.exists()
    assert stat.S_IMODE(os.stat(manager.eab_hmac_path).st_mode) == 0o600
    assert 'mac_key "hmac-secret"' in loaded[-1]


def test_failed_caddy_load_restores_previous_files_and_settings(tmp_path, monkeypatch):
    db, manager = _manager(tmp_path)
    old_cert, old_key = _certificate_pair("old.example.com")
    new_cert, new_key = _certificate_pair("new.example.com")

    manager._write_atomic(manager.cert_path, old_cert, 0o644)
    manager._write_atomic(manager.key_path, old_key, 0o600)
    db.set_setting("tls_mode", "upload")
    db.set_setting("tls_hostname", "old.example.com")

    monkeypatch.setattr(manager, "_adapt", lambda config: None)

    calls = {"count": 0}

    def fail_first_load(config: str):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("candidate rejected")

    monkeypatch.setattr(manager, "_load", fail_first_load)

    with pytest.raises(RuntimeError, match="candidate rejected"):
        manager.configure(
            TlsSettings(mode="upload", hostname="new.example.com"),
            certificate_pem=new_cert,
            private_key_pem=new_key,
        )

    assert manager.cert_path.read_bytes() == old_cert
    assert manager.key_path.read_bytes() == old_key
    assert db.get_setting("tls_mode") == "upload"
    assert db.get_setting("tls_hostname") == "old.example.com"


def test_ca_root_validation_rejects_non_certificate_data():
    with pytest.raises(ValueError):
        validate_ca_root(b"not a certificate")


def test_http_redirect_uses_configured_external_https_port(tmp_path, monkeypatch):
    _, manager = _manager(tmp_path)
    monkeypatch.setenv("HTTPS_PORT", "8443")

    config = manager.render_caddyfile(
        TlsSettings(
            mode="acme",
            hostname="blockinator.example.com",
            http_redirect=True,
        )
    )

    assert ":80 {" in config
    assert "redir https://blockinator.example.com:8443{uri} 308" in config
    assert ":80 {\n  reverse_proxy blockinator:8080" not in config


def test_http_redirect_omits_standard_https_port(tmp_path, monkeypatch):
    _, manager = _manager(tmp_path)
    monkeypatch.setenv("HTTPS_PORT", "443")

    config = manager.render_caddyfile(
        TlsSettings(
            mode="acme",
            hostname="blockinator.example.com",
            http_redirect=True,
        )
    )

    assert "redir https://blockinator.example.com{uri} 308" in config
    assert "https://blockinator.example.com:443{uri}" not in config


def test_http_only_mode_never_redirects(tmp_path, monkeypatch):
    _, manager = _manager(tmp_path)
    monkeypatch.setenv("HTTPS_PORT", "443")

    config = manager.render_caddyfile(
        TlsSettings(mode="http", http_redirect=True)
    )

    assert "redir https://" not in config
    assert ":80 {\n  reverse_proxy blockinator:8080\n}" in config
