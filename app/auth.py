from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any

from .db import Database

SESSION_COOKIE = "trpb_session"
SESSION_TTL_SECONDS = int(os.getenv("ADMIN_SESSION_TTL_SECONDS", str(12 * 60 * 60)))


def _b64_token(n: int = 32) -> str:
    return secrets.token_urlsafe(n)


def hash_password(password: str) -> str:
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    salt = secrets.token_bytes(16)
    n, r, p = 2**14, 8, 1
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, n_s, r_s, p_s, salt_hex, digest_hex = encoded.split("$", 5)
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n_s), r=int(r_s), p=int(p_s), dklen=32,
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def key_prefix(raw: str) -> str:
    if len(raw) <= 12:
        return raw[:4] + "…"
    return raw[:8] + "…" + raw[-4:]


@dataclass(frozen=True, slots=True)
class AdminSession:
    token: str
    token_hash: str
    user_id: int
    username: str
    csrf_token: str
    expires_at: int


class AuthManager:
    def __init__(self, db: Database, bootstrap: bool = True) -> None:
        self.db = db
        self._api_lock = threading.RLock()
        self._api_keys: dict[str, dict[str, Any]] = {}
        self._last_used_write: dict[int, float] = {}
        if bootstrap:
            self.bootstrap_from_environment()
        self.reload_api_keys()
        self.cleanup_sessions()

    def bootstrap_from_environment(self) -> None:
        """One-time migration/bootstrap from legacy environment variables.

        Existing database credentials always win. This keeps v1.2 upgrades working,
        while all subsequent credential changes live exclusively in the configured database.
        """
        with self.db.connect() as con:
            user_count = int(con.execute("SELECT COUNT(*) c FROM admin_users").fetchone()["c"])
            if user_count == 0:
                username = os.getenv("ADMIN_USERNAME", "admin").strip() or "admin"
                password = os.getenv("ADMIN_PASSWORD", "change-this-admin-password")
                con.execute(
                    "INSERT INTO admin_users(username,password_hash) VALUES(?,?)",
                    (username, hash_password(password)),
                )

            key_count = int(con.execute("SELECT COUNT(*) c FROM api_keys").fetchone()["c"])
            if key_count == 0:
                raw = os.getenv("POLICY_API_KEY", "change-this-long-random-api-key")
                con.execute(
                    "INSERT INTO api_keys(name,key_hash,key_prefix) VALUES(?,?,?)",
                    ("Primary", hash_api_key(raw), key_prefix(raw)),
                )

    # ---- administrator authentication ----
    def authenticate(self, username: str, password: str) -> tuple[int, str] | None:
        with self.db.connect() as con:
            row = con.execute(
                "SELECT id,username,password_hash FROM admin_users WHERE username=? COLLATE NOCASE",
                (username.strip(),),
            ).fetchone()
        if row and verify_password(password, row["password_hash"]):
            return int(row["id"]), str(row["username"])
        return None

    def create_session(self, user_id: int, username: str) -> AdminSession:
        raw = _b64_token(36)
        token_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        csrf = _b64_token(24)
        now = int(time.time())
        expires = now + SESSION_TTL_SECONDS
        with self.db.connect() as con:
            con.execute(
                "INSERT INTO admin_sessions(token_hash,user_id,csrf_token,created_at,expires_at,last_seen_at) VALUES(?,?,?,?,?,?)",
                (token_hash, user_id, csrf, now, expires, now),
            )
        return AdminSession(raw, token_hash, user_id, username, csrf, expires)

    def get_session(self, raw_token: str | None) -> AdminSession | None:
        if not raw_token:
            return None
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        now = int(time.time())
        with self.db.connect() as con:
            row = con.execute(
                """
                SELECT s.token_hash,s.user_id,s.csrf_token,s.expires_at,u.username
                FROM admin_sessions s JOIN admin_users u ON u.id=s.user_id
                WHERE s.token_hash=?
                """,
                (token_hash,),
            ).fetchone()
            if not row:
                return None
            if int(row["expires_at"]) <= now:
                con.execute("DELETE FROM admin_sessions WHERE token_hash=?", (token_hash,))
                return None
            # Touch at most once per minute to reduce writes.
            last = con.execute(
                "SELECT last_seen_at FROM admin_sessions WHERE token_hash=?", (token_hash,)
            ).fetchone()["last_seen_at"]
            if now - int(last) >= 60:
                con.execute("UPDATE admin_sessions SET last_seen_at=? WHERE token_hash=?", (now, token_hash))
        return AdminSession(
            raw_token, token_hash, int(row["user_id"]), str(row["username"]),
            str(row["csrf_token"]), int(row["expires_at"]),
        )

    def delete_session(self, raw_token: str | None) -> None:
        if not raw_token:
            return
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        with self.db.connect() as con:
            con.execute("DELETE FROM admin_sessions WHERE token_hash=?", (token_hash,))

    def cleanup_sessions(self) -> None:
        with self.db.connect() as con:
            con.execute("DELETE FROM admin_sessions WHERE expires_at <= ?", (int(time.time()),))

    def update_admin_credentials(
        self,
        user_id: int,
        current_password: str,
        new_username: str,
        new_password: str | None,
    ) -> str:
        new_username = new_username.strip()
        if not new_username:
            raise ValueError("username cannot be empty")
        with self.db.connect() as con:
            row = con.execute(
                "SELECT username,password_hash FROM admin_users WHERE id=?", (user_id,)
            ).fetchone()
            if not row or not verify_password(current_password, row["password_hash"]):
                raise ValueError("current password is incorrect")
            password_hash = row["password_hash"]
            if new_password:
                password_hash = hash_password(new_password)
            try:
                con.execute(
                    "UPDATE admin_users SET username=?,password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (new_username, password_hash, user_id),
                )
            except Exception as e:
                raise ValueError(f"could not update administrator: {e}") from e
            # Credential changes invalidate every browser session.
            con.execute("DELETE FROM admin_sessions WHERE user_id=?", (user_id,))
        return new_username

    # ---- API keys ----
    def reload_api_keys(self) -> None:
        with self.db.connect() as con:
            rows = con.execute(
                "SELECT id,name,key_hash,key_prefix FROM api_keys WHERE enabled=1"
            ).fetchall()
        with self._api_lock:
            self._api_keys = {
                str(r["key_hash"]): {
                    "id": int(r["id"]), "name": str(r["name"]), "prefix": str(r["key_prefix"])
                }
                for r in rows
            }

    def verify_api_key(self, raw: str | None) -> dict[str, Any] | None:
        if not raw:
            return None
        hashed = hash_api_key(raw)
        with self._api_lock:
            info = self._api_keys.get(hashed)
        if info is None:
            return None
        now = time.monotonic()
        key_id = int(info["id"])
        with self._api_lock:
            last = self._last_used_write.get(key_id, 0.0)
            should_write = now - last >= 60
            if should_write:
                self._last_used_write[key_id] = now
        if should_write:
            try:
                with self.db.connect() as con:
                    con.execute("UPDATE api_keys SET last_used_at=CURRENT_TIMESTAMP WHERE id=?", (key_id,))
            except Exception:
                pass
        return dict(info)

    @staticmethod
    def generate_api_key() -> str:
        return "trpb_" + secrets.token_urlsafe(36)

    def create_api_key(self, name: str, raw_key: str | None = None) -> tuple[int, str]:
        name = name.strip()
        if not name:
            raise ValueError("key name cannot be empty")
        raw = (raw_key or "").strip() or self.generate_api_key()
        if len(raw) < 24:
            raise ValueError("API key must be at least 24 characters")
        try:
            with self.db.connect() as con:
                cur = con.execute(
                    "INSERT INTO api_keys(name,key_hash,key_prefix) VALUES(?,?,?)",
                    (name, hash_api_key(raw), key_prefix(raw)),
                )
                key_id = int(cur.lastrowid)
        except Exception as e:
            raise ValueError(f"could not create API key: {e}") from e
        self.reload_api_keys()
        return key_id, raw

    def rotate_api_key(self, key_id: int, raw_key: str | None = None) -> str:
        raw = (raw_key or "").strip() or self.generate_api_key()
        if len(raw) < 24:
            raise ValueError("API key must be at least 24 characters")
        with self.db.connect() as con:
            cur = con.execute(
                "UPDATE api_keys SET key_hash=?,key_prefix=?,updated_at=CURRENT_TIMESTAMP,last_used_at=NULL WHERE id=?",
                (hash_api_key(raw), key_prefix(raw), key_id),
            )
            if cur.rowcount != 1:
                raise ValueError("API key not found")
        self.reload_api_keys()
        return raw

    def set_api_key_enabled(self, key_id: int, enabled: bool) -> None:
        with self.db.connect() as con:
            row = con.execute("SELECT enabled FROM api_keys WHERE id=?", (key_id,)).fetchone()
            if not row:
                raise ValueError("API key not found")
            if not enabled:
                active = int(con.execute("SELECT COUNT(*) c FROM api_keys WHERE enabled=1").fetchone()["c"])
                if active <= 1 and bool(row["enabled"]):
                    raise ValueError("at least one API key must remain enabled")
            con.execute(
                "UPDATE api_keys SET enabled=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (1 if enabled else 0, key_id),
            )
        self.reload_api_keys()

    def delete_api_key(self, key_id: int) -> None:
        with self.db.connect() as con:
            row = con.execute("SELECT enabled FROM api_keys WHERE id=?", (key_id,)).fetchone()
            if not row:
                return
            if bool(row["enabled"]):
                active = int(con.execute("SELECT COUNT(*) c FROM api_keys WHERE enabled=1").fetchone()["c"])
                if active <= 1:
                    raise ValueError("cannot delete the only enabled API key")
            con.execute("DELETE FROM api_keys WHERE id=?", (key_id,))
        self.reload_api_keys()

    def list_api_keys(self) -> list[dict[str, Any]]:
        with self.db.connect() as con:
            return [dict(r) for r in con.execute(
                "SELECT id,name,key_prefix,enabled,created_at,updated_at,last_used_at FROM api_keys ORDER BY name COLLATE NOCASE"
            )]
