"""Validate source version history without importing or starting the application."""
import argparse
import ast
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def version_from_source(source):
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == 'APP_VERSION' for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            if isinstance(value, str) and re.fullmatch(r'\d+\.\d+\.\d+', value):
                return tuple(map(int, value.split('.')))
    raise ValueError('APP_VERSION must be a literal X.Y.Z string')


def check(base_ref=None):
    version = version_from_source((ROOT / 'app/main.py').read_text())
    text = '.'.join(map(str, version))
    headings = re.findall(r'^## (\d+\.\d+\.\d+) — ', (ROOT / 'CHANGELOG.md').read_text(), re.M)
    if not headings or headings[0] != text:
        raise ValueError('Newest numbered changelog entry must match APP_VERSION')
    # Enforce ordering from the version-history repair onward; older entries
    # retain their historical ordering.
    versions = [tuple(map(int, entry.split('.'))) for entry in headings]
    versions = [entry for entry in versions if entry >= (1, 19, 2)]
    if any(a <= b for a, b in zip(versions, versions[1:])):
        raise ValueError('Changelog versions must be unique and in descending order')
    if f'Current source version: **{text}**' not in (ROOT / 'README.md').read_text():
        raise ValueError('README current source version must match APP_VERSION')
    if base_ref and set(base_ref) != {'0'}:
        # CI supplies a commit SHA, never shell code or an arbitrary revision expression.
        if not re.fullmatch(r'[0-9a-fA-F]{7,40}', base_ref):
            raise ValueError('Base reference must be a commit SHA')
        old = subprocess.check_output(['git', 'show', f'{base_ref}:app/main.py'], cwd=ROOT, text=True)
        changed = subprocess.check_output(['git', 'diff', '--name-only', base_ref, 'HEAD'], cwd=ROOT, text=True).strip()
        if changed and version <= version_from_source(old):
            raise ValueError('Every changed revision must increment APP_VERSION and update its changelog')
    print(f'Version {text}: changelog and README are consistent')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-ref')
    args = parser.parse_args()
    try:
        check(args.base_ref)
    except ValueError as exc:
        parser.exit(1, f'Version check failed: {exc}\n')
