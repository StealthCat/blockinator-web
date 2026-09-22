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
