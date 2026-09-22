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
    validate_http_redirect_change,
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


def test_http_and_acme_native_json_rendering(tmp_path):
    _, manager = _manager(tmp_path)

    http_config = manager.render_caddy_json(TlsSettings(mode="http"))
    assert http_config["admin"]["config"]["persist"] is False
    http_server = http_config["apps"]["http"]["servers"]["blockinator_http"]
    assert http_server["listen"] == [":80"]
    handler = http_server["routes"][0]["handle"][0]
    assert handler["handler"] == "reverse_proxy"
    assert handler["upstreams"] == [{"dial": "blockinator:8080"}]
    assert "tls" not in http_config["apps"]

    manager._write_atomic(
        manager.ca_root_path,
        _certificate_pair("ca.example.com")[0],
        0o644,
    )
    manager._write_atomic(manager.eab_hmac_path, b"secret-hmac\n", 0o600)
    acme = manager.render_caddy_json(
        TlsSettings(
            mode="acme",
            hostname="blockinator.example.com",
            acme_email="admin@example.com",
            acme_directory="https://ca.example.com/acme/directory",
            acme_eab_key_id="kid-123",
        )
    )
    https_server = acme["apps"]["http"]["servers"]["blockinator_https"]
    assert https_server["listen"] == [":443"]
    assert https_server["automatic_https"]["disable_redirects"] is True
    issuer = acme["apps"]["tls"]["automation"]["policies"][0]["issuers"][0]
    assert issuer["module"] == "acme"
    assert issuer["ca"] == "https://ca.example.com/acme/directory"
    assert issuer["trusted_roots_pem_files"] == ["/blockinator-tls/acme-ca-root.pem"]
    assert issuer["external_account"] == {
        "key_id": "kid-123",
        "mac_key": "secret-hmac",
    }


def test_configure_uploaded_certificate_applies_and_persists(tmp_path, monkeypatch):
    db, manager = _manager(tmp_path)
    cert_pem, key_pem = _certificate_pair()
    loaded: list[dict] = []

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
    assert loaded
    tls_loader = loaded[-1]["apps"]["tls"]["certificates"]["load_files"][0]
    assert tls_loader["certificate"] == "/blockinator-tls/uploaded-cert.pem"
    assert tls_loader["key"] == "/blockinator-tls/uploaded-key.pem"
    assert stat.S_IMODE(os.stat(manager.cert_path).st_mode) == 0o644
    assert stat.S_IMODE(os.stat(manager.key_path).st_mode) == 0o600


def test_configure_acme_custom_root_and_eab(tmp_path, monkeypatch):
    db, manager = _manager(tmp_path)
    ca_pem, _ = _certificate_pair("ca.example.com")
    loaded: list[dict] = []
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
    issuer = loaded[-1]["apps"]["tls"]["automation"]["policies"][0]["issuers"][0]
    assert issuer["external_account"]["mac_key"] == "hmac-secret"


def test_failed_caddy_load_restores_previous_files_and_settings(tmp_path, monkeypatch):
    db, manager = _manager(tmp_path)
    old_cert, old_key = _certificate_pair("old.example.com")
    new_cert, new_key = _certificate_pair("new.example.com")

    manager._write_atomic(manager.cert_path, old_cert, 0o644)
    manager._write_atomic(manager.key_path, old_key, 0o600)
    db.set_setting("tls_mode", "upload")
    db.set_setting("tls_hostname", "old.example.com")

    calls = {"count": 0}

    def fail_first_load(config: dict):
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

    config = manager.render_caddy_json(
        TlsSettings(
            mode="acme",
            hostname="blockinator.example.com",
            http_redirect=True,
        )
    )

    handler = config["apps"]["http"]["servers"]["blockinator_http"]["routes"][0]["handle"][0]
    assert handler["handler"] == "static_response"
    assert handler["status_code"] == 308
    assert handler["headers"]["Location"] == [
        "https://blockinator.example.com:8443{http.request.uri}"
    ]


def test_http_redirect_omits_standard_https_port(tmp_path, monkeypatch):
    _, manager = _manager(tmp_path)
    monkeypatch.setenv("HTTPS_PORT", "443")

    config = manager.render_caddy_json(
        TlsSettings(
            mode="acme",
            hostname="blockinator.example.com",
            http_redirect=True,
        )
    )

    handler = config["apps"]["http"]["servers"]["blockinator_http"]["routes"][0]["handle"][0]
    assert handler["headers"]["Location"] == [
        "https://blockinator.example.com{http.request.uri}"
    ]


def test_http_only_mode_never_redirects(tmp_path, monkeypatch):
    _, manager = _manager(tmp_path)
    monkeypatch.setenv("HTTPS_PORT", "443")

    config = manager.render_caddy_json(
        TlsSettings(mode="http", http_redirect=True)
    )

    handler = config["apps"]["http"]["servers"]["blockinator_http"]["routes"][0]["handle"][0]
    assert handler["handler"] == "reverse_proxy"
    assert handler["upstreams"] == [{"dial": "blockinator:8080"}]


def test_http_redirect_change_requires_https():
    validate_http_redirect_change(False, False, False)
    validate_http_redirect_change(True, True, False)
    validate_http_redirect_change(False, True, True)
    validate_http_redirect_change(True, False, True)

    with pytest.raises(ValueError, match="only be changed"):
        validate_http_redirect_change(False, True, False)

    with pytest.raises(ValueError, match="only be changed"):
        validate_http_redirect_change(True, False, False)



def test_reconcile_skips_load_when_config_is_unchanged(tmp_path, monkeypatch):
    _, manager = _manager(tmp_path)
    config = manager.render_caddy_json(TlsSettings(mode="http"))
    manager._last_applied_hash = __import__("hashlib").sha256(
        __import__("json").dumps(
            config,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    manager._caddy_reachable = True
    manager._managed_config_present = True

    loaded: list[dict] = []
    monkeypatch.setattr(manager, "_load", lambda candidate: loaded.append(candidate))

    applied = manager.apply_saved()

    assert applied is False
    assert loaded == []


def test_reconcile_restores_bootstrap_config_once(tmp_path, monkeypatch):
    _, manager = _manager(tmp_path)
    loaded: list[dict] = []
    monkeypatch.setattr(manager, "_load", lambda candidate: loaded.append(candidate))

    manager._caddy_reachable = True
    manager._managed_config_present = False

    applied = manager.apply_saved(force=True)

    assert applied is True
    assert len(loaded) == 1
    assert "blockinator_http" in loaded[0]["apps"]["http"]["servers"]

    applied_again = manager.apply_saved()

    assert applied_again is False
    assert len(loaded) == 1


def test_tls_error_write_is_deduplicated(tmp_path, monkeypatch):
    db, manager = _manager(tmp_path)
    writes: list[dict[str, str]] = []
    original = db.set_settings

    def capture(values: dict[str, str]):
        writes.append(dict(values))
        original(values)

    monkeypatch.setattr(db, "set_settings", capture)

    manager._set_last_error("same error")
    manager._set_last_error("same error")

    error_writes = [values for values in writes if "tls_last_error" in values]
    assert error_writes == [{"tls_last_error": "same error"}]
