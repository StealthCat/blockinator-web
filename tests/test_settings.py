import tempfile
from pathlib import Path

from app.db import Database


def test_default_timezone_bootstraps_from_environment(monkeypatch):
    td = tempfile.TemporaryDirectory()
    path = Path(td.name) / "settings.db"
    monkeypatch.setenv("TZ", "America/Chicago")

    db = Database(str(path))

    assert db.get_setting("default_timezone") == "America/Chicago"
    td.cleanup()


def test_default_timezone_setting_persists_across_reinitialization(monkeypatch):
    td = tempfile.TemporaryDirectory()
    path = Path(td.name) / "settings.db"
    monkeypatch.setenv("TZ", "UTC")

    db = Database(str(path))
    db.set_setting("default_timezone", "America/New_York")

    monkeypatch.setenv("TZ", "America/Los_Angeles")
    db_again = Database(str(path))

    assert db_again.get_setting("default_timezone") == "America/New_York"
    td.cleanup()



def test_batch_settings_round_trip(tmp_path):
    db = Database(str(tmp_path / "settings.db"))
    db.set_settings(
        {
            "alpha": "1",
            "beta": "2",
            "gamma": "3",
        }
    )

    values = db.get_settings(
        {
            "alpha": "default-a",
            "beta": "default-b",
            "missing": "fallback",
        }
    )

    assert values == {
        "alpha": "1",
        "beta": "2",
        "missing": "fallback",
    }


def test_unmatched_scope_action_defaults_to_allow(tmp_path):
    db = Database(str(tmp_path / "settings.db"))

    assert db.get_setting("unmatched_scope_action") == "allow"


def test_global_blocklist_scope_mode_defaults_to_all_clients(tmp_path):
    db = Database(str(tmp_path / "settings.db"))

    assert db.get_setting("global_blocklist_scope_mode") == "all_clients"


def test_ui_theme_defaults_to_dark(tmp_path):
    db = Database(str(tmp_path / "settings.db"))

    assert db.get_setting("ui_theme") == "dark"


def test_ui_theme_setting_persists(tmp_path):
    db = Database(str(tmp_path / "settings.db"))
    db.set_setting("ui_theme", "light")

    db_again = Database(str(tmp_path / "settings.db"))
    assert db_again.get_setting("ui_theme") == "light"
