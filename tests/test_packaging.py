import shutil
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_remote_job_script_is_declared_as_package_data():
    # remote.py reads this file next to the module at runtime, so an installed
    # wheel without it would fail on the first remote job.
    config = tomllib.loads((ROOT / 'pyproject.toml').read_text())
    declared = config['tool']['setuptools']['package-data']['codex_worker']
    assert 'remote_job.sh' in declared
    assert (ROOT / 'codex_worker' / 'remote_job.sh').is_file()


def _builder():
    # The test interpreter may lack build tooling; fall back to any python3 on
    # PATH that has it. Nothing is ever downloaded.
    for candidate in (sys.executable, shutil.which('python3')):
        if candidate and subprocess.run(
                [candidate, '-c', 'import pip, setuptools, wheel'],
                capture_output=True).returncode == 0:
            return candidate
    return None


def test_built_wheel_contains_remote_job_script(tmp_path):
    builder = _builder()
    if builder is None:
        pytest.skip('no interpreter with pip, setuptools and wheel available offline')
    # Build from a copy so no build/ or *.egg-info directories land in the repo.
    source = tmp_path / 'src'
    shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns(
        '.git', '.venv', 'private', '__pycache__', '.pytest_cache', '*.egg-info', 'build', 'dist'))
    out = tmp_path / 'out'
    result = subprocess.run(
        [builder, '-m', 'pip', 'wheel', '--no-build-isolation', '--no-deps',
         '--disable-pip-version-check', '-q', '-w', str(out), str(source)],
        capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stderr[-2000:]
    wheels = list(out.glob('*.whl'))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        assert 'codex_worker/remote_job.sh' in archive.namelist()
