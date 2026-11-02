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


def test_broken_historical_source_does_not_block_repair(tmp_path, monkeypatch):
    (tmp_path / 'app').mkdir()
    (tmp_path / 'app/main.py').write_text('APP_VERSION = "1.20.15"\n', encoding='utf-8')
    (tmp_path / 'CHANGELOG.md').write_text('## 1.20.15 — Repair\n', encoding='utf-8')
    (tmp_path / 'README.md').write_text('Current source version: **1.20.15**', encoding='utf-8')
    monkeypatch.setattr(check_version, 'ROOT', tmp_path)
    broken = 'APP_VERSION = "1.20.14"\n…36812 tokens truncated…\n'
    monkeypatch.setattr(check_version.subprocess, 'check_output',
                        lambda args, **kw: broken if args[1] == 'show' else 'app/main.py\n')
    check_version.check('abcdef1')
    # The historical fallback must never accept a broken candidate source.
    (tmp_path / 'app/main.py').write_text(broken, encoding='utf-8')
    with pytest.raises(SyntaxError):
        check_version.check('abcdef1')


def test_broken_base_still_requires_version_increase(tmp_path, monkeypatch):
    (tmp_path / 'app').mkdir()
    (tmp_path / 'app/main.py').write_text('APP_VERSION = "1.20.14"\n', encoding='utf-8')
    (tmp_path / 'CHANGELOG.md').write_text('## 1.20.14 — Repair\n', encoding='utf-8')
    (tmp_path / 'README.md').write_text('Current source version: **1.20.14**', encoding='utf-8')
    monkeypatch.setattr(check_version, 'ROOT', tmp_path)
    monkeypatch.setattr(check_version.subprocess, 'check_output',
                        lambda args, **kw: 'APP_VERSION = "1.20.14"\nbroken syntax!' if args[1] == 'show' else 'app/main.py\n')
    with pytest.raises(ValueError, match='increment APP_VERSION'):
        check_version.check('abcdef1')


@pytest.mark.parametrize('source', [
    'APP_VERSION = str(1)\nbroken syntax!',
    'APP_VERSION = "1.20.14"\nAPP_VERSION = "1.20.15"\nbroken syntax!',
])
def test_broken_base_requires_unambiguous_literal_version(source):
    with pytest.raises(ValueError, match='Historical APP_VERSION'):
        check_version.version_from_source(source, historical=True)
