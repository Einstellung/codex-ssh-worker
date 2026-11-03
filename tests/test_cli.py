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


def test_serve_failure_reports_exception_type_and_traceback_on_stderr(tmp_path):
    # An empty private directory has none of the required configuration files.
    result = run_cli('serve', '--private-dir', str(tmp_path), '--socket', str(tmp_path / 's.sock'))
    assert result.returncode == 1
    assert 'Traceback' in result.stderr
    assert 'ValueError' in result.stderr
    assert 'worker_operation_failed' in result.stderr


@pytest.mark.parametrize('mode', ['mcp', 'internal', 'filter', 'check'])
def test_non_serve_modes_emit_only_the_fixed_error_code(tmp_path, monkeypatch, capsys, mode):
    from codex_worker import cli, mcp_api

    def boom(*args, **kwargs):
        raise RuntimeError('SENSITIVE-DETAIL')

    # mcp and internal fail inside these entry points; filter and check fail
    # while loading the (empty) private directory, whose error text must not leak.
    monkeypatch.setattr(mcp_api, 'public_mcp', boom)
    monkeypatch.setattr(mcp_api, 'internal_mcp', boom)
    monkeypatch.setattr(cli, 'load_settings', boom)
    argv = ['cli', mode, '--private-dir', str(tmp_path), '--socket', str(tmp_path / 's.sock'), '--target', 'example-server']
    monkeypatch.setattr(sys, 'argv', argv)
    assert cli.main() == 1
    err = capsys.readouterr().err
    assert err.strip() == '{"error_code":"worker_operation_failed"}'
    assert 'SENSITIVE-DETAIL' not in err and 'Traceback' not in err
