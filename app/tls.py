from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable

if TYPE_CHECKING:
    from cryptography import x509

from .db import Database


DEFAULT_ACME_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
TLS_MODES = {"http", "upload", "acme"}

_TLS_SETTING_DEFAULTS = {
    "tls_mode": "http",
    "tls_hostname": "",
    "tls_acme_email": "",
    "tls_acme_directory": DEFAULT_ACME_DIRECTORY,
    "tls_acme_eab_key_id": "",
    "tls_http_redirect": "0",
    "tls_last_applied": "",
    "tls_last_error": "",
}


@dataclass(frozen=True, slots=True)
class TlsSettings:
    mode: str = "http"
    hostname: str = ""
    acme_email: str = ""
    acme_directory: str = DEFAULT_ACME_DIRECTORY
    acme_eab_key_id: str = ""
    http_redirect: bool = False


@dataclass(frozen=True, slots=True)
class CertificateInfo:
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    dns_names: tuple[str, ...]
    serial_hex: str


@dataclass(frozen=True, slots=True)
class TlsStatus:
    settings: TlsSettings
    caddy_reachable: bool
    uploaded_certificate: CertificateInfo | None
    uploaded_cert_present: bool
    uploaded_key_present: bool
    acme_ca_root_present: bool
    acme_eab_hmac_present: bool
    last_applied: str
    last_error: str


def normalize_tls_hostname(value: str) -> str:
    raw = str(value or "").strip().rstrip(".").lower()
    if not raw:
        raise ValueError("HTTPS hostname is required")
    if "://" in raw or "/" in raw or ":" in raw or "*" in raw:
        raise ValueError("HTTPS hostname must be a DNS name, not a URL, wildcard, or host:port")
    try:
        labels = [label.encode("idna").decode("ascii").lower() for label in raw.split(".")]
    except UnicodeError as exc:
        raise ValueError("HTTPS hostname is not a valid DNS name") from exc
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        raise ValueError("HTTPS hostname must be a fully qualified DNS name")
    hostname = ".".join(labels)
    if len(hostname) > 253:
        raise ValueError("HTTPS hostname is too long")
    return hostname


def validate_http_redirect_change(
    current: bool,
    requested: bool,
    request_is_https: bool,
) -> None:
    if current != requested and not request_is_https:
        raise ValueError(
            "HTTP redirect behavior can only be changed while System Settings is accessed over HTTPS"
        )


def validate_acme_directory(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return DEFAULT_ACME_DIRECTORY
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("ACME directory must be an http:// or https:// URL")
    if parsed.username or parsed.password:
        raise ValueError("ACME directory URL must not contain embedded credentials")
    if parsed.fragment:
        raise ValueError("ACME directory URL must not contain a fragment")
    return raw


def _public_key_bytes(key) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _dnsname_matches(hostname: str, pattern: str) -> bool:
    hostname = hostname.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[2:]
        if not hostname.endswith("." + suffix):
            return False
        return hostname.count(".") == suffix.count(".") + 1
    return hostname == pattern


def _certificate_info(cert: "x509.Certificate") -> CertificateInfo:
    from cryptography import x509

    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = tuple(sans.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        dns_names = ()
    return CertificateInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        dns_names=dns_names,
        serial_hex=f"{cert.serial_number:x}",
    )


def _load_leaf_certificate(pem: bytes) -> tuple["x509.Certificate", CertificateInfo]:
    from cryptography import x509

    try:
        certs = x509.load_pem_x509_certificates(pem)
    except ValueError as exc:
        raise ValueError("Certificate file does not contain valid PEM X.509 certificates") from exc
    if not certs:
        raise ValueError("Certificate file contains no X.509 certificates")
    cert = certs[0]
    return cert, _certificate_info(cert)


def parse_certificate(pem: bytes) -> CertificateInfo:
    return _load_leaf_certificate(pem)[1]


def validate_certificate_and_key(
    cert_pem: bytes,
    key_pem: bytes,
    hostname: str,
) -> CertificateInfo:
    from cryptography.hazmat.primitives import serialization

    cert, info = _load_leaf_certificate(cert_pem)
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("Private key must be a valid unencrypted PEM private key") from exc

    if _public_key_bytes(cert.public_key()) != _public_key_bytes(key.public_key()):
        raise ValueError("Uploaded private key does not match the certificate")

    now = datetime.now(timezone.utc)
    if now < info.not_before:
        raise ValueError("Uploaded certificate is not valid yet")
    if now >= info.not_after:
        raise ValueError("Uploaded certificate has expired")

    if not info.dns_names:
        raise ValueError("Uploaded certificate has no DNS Subject Alternative Names")
    if not any(_dnsname_matches(hostname, name) for name in info.dns_names):
        raise ValueError(
            f"Uploaded certificate does not cover {hostname}; certificate SANs: "
            + ", ".join(info.dns_names)
        )
    return info


def validate_ca_root(pem: bytes) -> None:
    from cryptography import x509

    try:
        certs = x509.load_pem_x509_certificates(pem)
    except ValueError as exc:
        raise ValueError("ACME CA root file is not valid PEM certificate data") from exc
    if not certs:
        raise ValueError("ACME CA root file contains no certificates")


def _config_bytes(config: dict[str, Any]) -> bytes:
    return json.dumps(
        config,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _config_hash(config: dict[str, Any]) -> str:
    return hashlib.sha256(_config_bytes(config)).hexdigest()


def _reverse_proxy_handler() -> dict[str, Any]:
    return {
        "handler": "reverse_proxy",
        "upstreams": [{"dial": "blockinator:8080"}],
    }


class TlsManager:
    CERT_FILE = "uploaded-cert.pem"
    KEY_FILE = "uploaded-key.pem"
    CA_ROOT_FILE = "acme-ca-root.pem"
    EAB_HMAC_FILE = "acme-eab-hmac"
    HTTP_SERVER_NAME = "blockinator_http"
    HTTPS_SERVER_NAME = "blockinator_https"

    def __init__(
        self,
        db: Database,
        tls_dir: str | Path | None = None,
        caddy_admin_url: str | None = None,
        reconcile_seconds: float | None = None,
    ) -> None:
        self.db = db
        data_dir = Path(os.getenv("DATA_DIR", "/data"))
        self.tls_dir = Path(tls_dir) if tls_dir else data_dir / "tls"
        self.tls_dir.mkdir(parents=True, exist_ok=True)
        self.caddy_admin_url = (
            caddy_admin_url
            or os.getenv("CADDY_ADMIN_URL", "http://caddy:2019")
        ).rstrip("/")
        configured = (
            float(os.getenv("TLS_RECONCILE_SECONDS", "30"))
            if reconcile_seconds is None
            else float(reconcile_seconds)
        )
        self.reconcile_seconds = max(5.0, min(configured, 3600.0))
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        initial = self.db.get_settings(
            {
                "tls_last_error": "",
                "tls_last_applied": "",
            }
        )
        self._last_error_cache = initial["tls_last_error"]
        self._last_applied_hash: str | None = None
        self._caddy_reachable = False
        self._managed_config_present = False

    @property
    def cert_path(self) -> Path:
        return self.tls_dir / self.CERT_FILE

    @property
    def key_path(self) -> Path:
        return self.tls_dir / self.KEY_FILE

    @property
    def ca_root_path(self) -> Path:
        return self.tls_dir / self.CA_ROOT_FILE

    @property
    def eab_hmac_path(self) -> Path:
        return self.tls_dir / self.EAB_HMAC_FILE

    @staticmethod
    def _settings_from_values(values: dict[str, str]) -> TlsSettings:
        mode = values.get("tls_mode", "http")
        if mode not in TLS_MODES:
            mode = "http"
        return TlsSettings(
            mode=mode,
            hostname=values.get("tls_hostname", ""),
            acme_email=values.get("tls_acme_email", ""),
            acme_directory=values.get(
                "tls_acme_directory",
                DEFAULT_ACME_DIRECTORY,
            )
            or DEFAULT_ACME_DIRECTORY,
            acme_eab_key_id=values.get("tls_acme_eab_key_id", ""),
            http_redirect=values.get("tls_http_redirect", "0") == "1",
        )

    @staticmethod
    def _settings_values(settings: TlsSettings) -> dict[str, str]:
        return {
            "tls_mode": settings.mode,
            "tls_hostname": settings.hostname,
            "tls_acme_email": settings.acme_email,
            "tls_acme_directory": settings.acme_directory,
            "tls_acme_eab_key_id": settings.acme_eab_key_id,
            "tls_http_redirect": "1" if settings.http_redirect else "0",
        }

    def load_settings(self) -> TlsSettings:
        values = self.db.get_settings(
            {key: value for key, value in _TLS_SETTING_DEFAULTS.items() if not key.startswith("tls_last_")}
        )
        return self._settings_from_values(values)

    def _set_last_error(self, value: str) -> None:
        normalized = value[:4000]
        if normalized == self._last_error_cache:
            return
        self.db.set_settings({"tls_last_error": normalized})
        self._last_error_cache = normalized

    def _record_success(
        self,
        settings: TlsSettings,
        config_hash: str,
        *,
        save_settings: bool,
    ) -> None:
        values = {
            "tls_last_applied": datetime.now(timezone.utc).isoformat(),
            "tls_last_error": "",
        }
        if save_settings:
            values.update(self._settings_values(settings))
        self.db.set_settings(values)
        self._last_error_cache = ""
        self._last_applied_hash = config_hash
        self._caddy_reachable = True
        self._managed_config_present = True

    def _write_atomic(self, path: Path, data: bytes, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, mode)
            os.replace(tmp_name, path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def _backups(self, paths: Iterable[Path]) -> dict[Path, bytes | None]:
        return {path: path.read_bytes() if path.exists() else None for path in paths}

    def _restore(self, backups: dict[Path, bytes | None]) -> None:
        for path, data in backups.items():
            if data is None:
                path.unlink(missing_ok=True)
            else:
                mode = 0o600 if path in {self.key_path, self.eab_hmac_path} else 0o644
                self._write_atomic(path, data, mode)

    def _redact_caddy_error(self, value: str) -> str:
        redacted = value
        try:
            if self.eab_hmac_path.exists():
                secret = self.eab_hmac_path.read_text(encoding="utf-8").strip()
                if secret:
                    redacted = redacted.replace(secret, "[redacted]")
        except OSError:
            pass
        return redacted

    def _request(
        self,
        path: str,
        *,
        method: str = "GET",
        body: bytes | None = None,
        content_type: str | None = None,
        timeout: float = 8.0,
    ) -> bytes:
        headers: dict[str, str] = {}
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(
            self.caddy_admin_url + path,
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace").strip()
            detail = self._redact_caddy_error(detail)
            raise RuntimeError(
                f"Caddy admin API returned HTTP {exc.code}: {detail or exc.reason}"
            ) from exc
        except OSError as exc:
            raise RuntimeError(f"Could not reach Caddy admin API: {exc}") from exc

    def _probe_caddy_state(self) -> tuple[bool, bool, str]:
        try:
            raw = self._request("/config/apps/http/servers", timeout=2.0)
            servers = json.loads(raw.decode("utf-8") or "{}")
            managed = isinstance(servers, dict) and self.HTTP_SERVER_NAME in servers
            return True, managed, ""
        except Exception as exc:
            return False, False, str(exc)

    def caddy_reachable(self) -> bool:
        return self._caddy_reachable

    def _validate_settings(self, settings: TlsSettings) -> TlsSettings:
        if settings.mode not in TLS_MODES:
            raise ValueError("TLS mode must be HTTP only, Uploaded certificate, or ACME")
        if settings.mode == "http":
            return TlsSettings(mode="http", http_redirect=False)

        hostname = normalize_tls_hostname(settings.hostname)
        email = settings.acme_email.strip()
        directory = validate_acme_directory(settings.acme_directory)
        key_id = settings.acme_eab_key_id.strip()

        if settings.mode == "upload":
            return TlsSettings(
                mode="upload",
                hostname=hostname,
                acme_directory=directory,
                http_redirect=bool(settings.http_redirect),
            )
        if email and ("@" not in email or any(ch.isspace() for ch in email)):
            raise ValueError("ACME account email is invalid")
        return TlsSettings(
            mode="acme",
            hostname=hostname,
            acme_email=email,
            acme_directory=directory,
            acme_eab_key_id=key_id,
            http_redirect=bool(settings.http_redirect),
        )

    def _http_handler(self, settings: TlsSettings) -> dict[str, Any]:
        if settings.mode != "http" and settings.http_redirect:
            try:
                https_port = int(os.getenv("HTTPS_PORT", "8443"))
            except ValueError:
                https_port = 8443
            port_suffix = "" if https_port == 443 else f":{https_port}"
            return {
                "handler": "static_response",
                "headers": {
                    "Location": [
                        f"https://{settings.hostname}{port_suffix}{{http.request.uri}}"
                    ]
                },
                "status_code": 308,
            }
        return _reverse_proxy_handler()

    def render_caddy_json(
        self,
        settings: TlsSettings | None = None,
    ) -> dict[str, Any]:
        settings = self._validate_settings(settings or self.load_settings())
        http_app: dict[str, Any] = {
            "servers": {
                self.HTTP_SERVER_NAME: {
                    "listen": [":80"],
                    "routes": [
                        {
                            "handle": [self._http_handler(settings)],
                        }
                    ],
                }
            }
        }
        config: dict[str, Any] = {
            "admin": {
                "listen": "0.0.0.0:2019",
                "config": {"persist": False},
            },
            "apps": {
                "http": http_app,
            },
        }

        if settings.mode == "http":
            return config

        https_server: dict[str, Any] = {
            "listen": [":443"],
            "routes": [
                {
                    "match": [{"host": [settings.hostname]}],
                    "handle": [_reverse_proxy_handler()],
                    "terminal": True,
                }
            ],
        }
        http_app["servers"][self.HTTPS_SERVER_NAME] = https_server

        if settings.mode == "upload":
            if not self.cert_path.exists() or not self.key_path.exists():
                raise ValueError("Uploaded certificate mode requires both certificate and private key")
            https_server["tls_connection_policies"] = [
                {
                    "match": {"sni": [settings.hostname]},
                    "certificate_selection": {"any_tag": ["blockinator-upload"]},
                }
            ]
            https_server["automatic_https"] = {"disable": True}
            config["apps"]["tls"] = {
                "certificates": {
                    "load_files": [
                        {
                            "certificate": "/blockinator-tls/uploaded-cert.pem",
                            "key": "/blockinator-tls/uploaded-key.pem",
                            "tags": ["blockinator-upload"],
                        }
                    ]
                }
            }
            return config

        https_server["tls_connection_policies"] = [
            {"match": {"sni": [settings.hostname]}}
        ]
        https_server["automatic_https"] = {"disable_redirects": True}

        issuer: dict[str, Any] = {
            "module": "acme",
            "ca": settings.acme_directory,
        }
        if settings.acme_email:
            issuer["email"] = settings.acme_email
        if self.ca_root_path.exists():
            issuer["trusted_roots_pem_files"] = [
                "/blockinator-tls/acme-ca-root.pem"
            ]
        if settings.acme_eab_key_id:
            if not self.eab_hmac_path.exists():
                raise ValueError("ACME EAB key ID is set but no EAB HMAC key is stored")
            mac_key = self.eab_hmac_path.read_text(encoding="utf-8").strip()
            if not mac_key:
                raise ValueError("Stored ACME EAB HMAC key is empty")
            issuer["external_account"] = {
                "key_id": settings.acme_eab_key_id,
                "mac_key": mac_key,
            }

        config["apps"]["tls"] = {
            "automation": {
                "policies": [
                    {
                        "subjects": [settings.hostname],
                        "issuers": [issuer],
                    }
                ]
            }
        }
        return config

    def _load(self, config: dict[str, Any]) -> None:
        self._request(
            "/load",
            method="POST",
            body=_config_bytes(config),
            content_type="application/json",
            timeout=20.0,
        )

    def apply_saved(self, *, force: bool = False) -> bool:
        with self._lock:
            settings = self.load_settings()
            config = self.render_caddy_json(settings)
            desired_hash = _config_hash(config)
            if (
                not force
                and self._caddy_reachable
                and self._managed_config_present
                and desired_hash == self._last_applied_hash
            ):
                return False
            try:
                self._load(config)
                self._record_success(
                    settings,
                    desired_hash,
                    save_settings=False,
                )
                return True
            except Exception as exc:
                self._set_last_error(str(exc))
                raise

    def configure(
        self,
        settings: TlsSettings,
        *,
        certificate_pem: bytes | None = None,
        private_key_pem: bytes | None = None,
        ca_root_pem: bytes | None = None,
        eab_hmac: str | None = None,
        remove_ca_root: bool = False,
        remove_eab_hmac: bool = False,
    ) -> CertificateInfo | None:
        candidate = self._validate_settings(settings)
        secret_paths = [
            self.cert_path,
            self.key_path,
            self.ca_root_path,
            self.eab_hmac_path,
        ]
        backups = self._backups(secret_paths)
        previous = self.load_settings()
        previous_config = self.render_caddy_json(previous)
        previous_hash = _config_hash(previous_config)

        with self._lock:
            try:
                if certificate_pem is not None:
                    self._write_atomic(self.cert_path, certificate_pem, 0o644)
                if private_key_pem is not None:
                    self._write_atomic(self.key_path, private_key_pem, 0o600)
                if remove_ca_root:
                    self.ca_root_path.unlink(missing_ok=True)
                elif ca_root_pem is not None:
                    validate_ca_root(ca_root_pem)
                    self._write_atomic(self.ca_root_path, ca_root_pem, 0o644)
                if remove_eab_hmac:
                    self.eab_hmac_path.unlink(missing_ok=True)
                elif eab_hmac is not None and eab_hmac.strip():
                    self._write_atomic(
                        self.eab_hmac_path,
                        eab_hmac.strip().encode("utf-8") + b"\n",
                        0o600,
                    )

                cert_info: CertificateInfo | None = None
                if candidate.mode == "upload":
                    if not self.cert_path.exists() or not self.key_path.exists():
                        raise ValueError(
                            "Upload both a PEM certificate/full chain and an unencrypted PEM private key"
                        )
                    cert_info = validate_certificate_and_key(
                        self.cert_path.read_bytes(),
                        self.key_path.read_bytes(),
                        candidate.hostname,
                    )

                if candidate.mode == "acme":
                    if self.ca_root_path.exists():
                        validate_ca_root(self.ca_root_path.read_bytes())
                    has_key_id = bool(candidate.acme_eab_key_id)
                    has_hmac = self.eab_hmac_path.exists() and bool(
                        self.eab_hmac_path.read_text(encoding="utf-8").strip()
                    )
                    if has_key_id != has_hmac:
                        raise ValueError(
                            "ACME EAB requires both a key ID and an HMAC key, or neither"
                        )

                config = self.render_caddy_json(candidate)
                config_hash = _config_hash(config)
                self._load(config)
                self._record_success(
                    candidate,
                    config_hash,
                    save_settings=True,
                )
                return cert_info
            except Exception as exc:
                self._restore(backups)
                self._set_last_error(str(exc))
                try:
                    self._load(previous_config)
                    self._last_applied_hash = previous_hash
                    self._caddy_reachable = True
                    self._managed_config_present = True
                except Exception:
                    pass
                raise

    def status(self) -> TlsStatus:
        values = self.db.get_settings(_TLS_SETTING_DEFAULTS)
        settings = self._settings_from_values(values)
        cert_info: CertificateInfo | None = None
        if self.cert_path.exists():
            try:
                cert_info = parse_certificate(self.cert_path.read_bytes())
            except Exception:
                cert_info = None
        return TlsStatus(
            settings=settings,
            caddy_reachable=self._caddy_reachable,
            uploaded_certificate=cert_info,
            uploaded_cert_present=self.cert_path.exists(),
            uploaded_key_present=self.key_path.exists(),
            acme_ca_root_present=self.ca_root_path.exists(),
            acme_eab_hmac_present=self.eab_hmac_path.exists(),
            last_applied=values["tls_last_applied"],
            last_error=values["tls_last_error"],
        )

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="blockinator-tls-reconciler",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
        self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            was_reachable = self._caddy_reachable
            reachable, managed, probe_error = self._probe_caddy_state()
            self._caddy_reachable = reachable
            self._managed_config_present = managed

            if not reachable:
                self._set_last_error(probe_error)
            else:
                try:
                    settings = self.load_settings()
                    config = self.render_caddy_json(settings)
                    desired_hash = _config_hash(config)
                    should_apply = (
                        not was_reachable
                        or not managed
                        or desired_hash != self._last_applied_hash
                    )
                    if should_apply:
                        self._load(config)
                        self._record_success(
                            settings,
                            desired_hash,
                            save_settings=False,
                        )
                except Exception as exc:
                    self._set_last_error(str(exc))

            self._stop.wait(self.reconcile_seconds)
