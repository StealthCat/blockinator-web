from pathlib import Path
import pytest
from tools import check_version


def test_current_version_metadata():
    check_version.check()


def test_missing_bump_is_rejected(tmp_path, monkeypatch):
    (tmp_path / 'app').mkdir()
    (tmp_path / 'app/main.py').write_text('APP_VERSION = "1.19.13"\n')
    (tmp_path / 'CHANGELOG.md').write_text('## 1.19.13 — Update\n')
    (tmp_path / 'README.md').write_text('Current source version: **1.19.13**')
    monkeypatch.setattr(check_version, 'ROOT', tmp_path)
    monkeypatch.setattr(check_version.subprocess, 'check_output',
                        lambda args, **kw: 'APP_VERSION = "1.19.13"' if args[1] == 'show' else 'app/main.py\n')
    with pytest.raises(ValueError, match='increment APP_VERSION'):
        check_version.check('abcdef1')
    for path in (tmp_path / 'app/main.py', tmp_path / 'CHANGELOG.md', tmp_path / 'README.md'):
        path.write_text(path.read_text().replace('1.19.13', '1.19.14'))
    check_version.check('abcdef1')


def test_stale_changelog_is_rejected(tmp_path, monkeypatch):
    (tmp_path / 'app').mkdir()
    (tmp_path / 'app/main.py').write_text('APP_VERSION = "1.19.14"\n')
    (tmp_path / 'CHANGELOG.md').write_text('## 1.19.13 — Previous\n')
    monkeypatch.setattr(check_version, 'ROOT', tmp_path)
    with pytest.raises(ValueError, match='changelog entry'):
        check_version.check()
