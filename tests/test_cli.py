import subprocess
import sys

import pytest


def run_cli(*args):
    return subprocess.run([sys.executable, '-m', 'codex_worker.cli', *args],
                          capture_output=True, text=True, timeout=60)


@pytest.mark.parametrize('mode', ['internal', 'check'])
def test_target_is_required_for_internal_and_check(tmp_path, mode):
    result = run_cli(mode, '--private-dir', str(tmp_path))
    assert result.returncode == 2
    assert '--target is required' in result.stderr


def test_filter_mode_does_not_need_a_target(tmp_path):
    # The failure here is the missing private configuration, not argument parsing.
    result = run_cli('filter', '--private-dir', str(tmp_path))
    assert result.returncode == 1
    assert 'worker_operation_failed' in result.stderr
