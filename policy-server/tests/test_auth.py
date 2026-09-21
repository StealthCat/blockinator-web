from __future__ import annotations

from pathlib import Path

from app.auth import AuthManager
from app.db import Database


def test_bootstrap_admin_and_multiple_api_keys(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ADMIN_USERNAME", "rootadmin")
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse-battery")
    monkeypatch.setenv("POLICY_API_KEY", "legacy-api-key-that-is-long-enough")

    db = Database(str(tmp_path / "auth.db"))
    auth = AuthManager(db)

    user = auth.authenticate("rootadmin", "correct-horse-battery")
    assert user is not None
    assert auth.authenticate("rootadmin", "wrong-password") is None

    legacy = auth.verify_api_key("legacy-api-key-that-is-long-enough")
    assert legacy is not None
    assert legacy["name"] == "Primary"

    _, second_raw = auth.create_api_key("Secondary")
    assert auth.verify_api_key(second_raw) is not None
    assert auth.verify_api_key("not-a-real-key") is None
    assert len(auth.list_api_keys()) == 2


def test_rotate_disable_and_delete_api_keys(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "some-password-for-testing")
    monkeypatch.setenv("POLICY_API_KEY", "primary-api-key-that-is-long-enough")
    db = Database(str(tmp_path / "auth.db"))
    auth = AuthManager(db)

    second_id, second_raw = auth.create_api_key("Secondary")
    assert auth.verify_api_key(second_raw)

    rotated = auth.rotate_api_key(second_id)
    assert auth.verify_api_key(second_raw) is None
    assert auth.verify_api_key(rotated) is not None

    auth.set_api_key_enabled(second_id, False)
    assert auth.verify_api_key(rotated) is None
    auth.delete_api_key(second_id)
    assert len(auth.list_api_keys()) == 1


def test_admin_credential_update_invalidates_sessions(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "initial-password")
    monkeypatch.setenv("POLICY_API_KEY", "primary-api-key-that-is-long-enough")
    db = Database(str(tmp_path / "auth.db"))
    auth = AuthManager(db)

    user_id, username = auth.authenticate("admin", "initial-password")
    session = auth.create_session(user_id, username)
    assert auth.get_session(session.token) is not None

    new_username = auth.update_admin_credentials(user_id, "initial-password", "operator", "new-password-123")
    assert new_username == "operator"
    assert auth.get_session(session.token) is None
    assert auth.authenticate("admin", "initial-password") is None
    assert auth.authenticate("operator", "new-password-123") is not None
