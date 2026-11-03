import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from codex_worker import push
from test_remote_jobs_push import HOST, PASSWORD, setup  # noqa: F401  (fixture)

pytestmark = pytest.mark.skipif(shutil.which('rsync') is None, reason='rsync is not installed')

# Stands in for OpenSSH: drops "-F <config> <alias>" and runs the command in a fake home.
WRAPPER = '''#!/bin/bash
echo "$*" >> {calls}
[[ $1 == -F && -f $2 && $3 == codex-push-target && ! -e {calls}.fail ]] || exit 255
shift 3
export HOME={home}
cd "$HOME" || exit 255
if [[ -e {corrupt} && $* == *"codex-job start verify-"* ]]; then
    printf 'X' >> "$HOME/dest/big.bin"
fi
exec bash -c "$*"
'''


@pytest.fixture
def pusher(setup, monkeypatch):  # noqa: F811
    instance, workspace, home, tmp_path = setup
    wrapper = tmp_path / 'fake-ssh'
    wrapper.write_text(WRAPPER.format(home=home, calls=tmp_path / 'calls', corrupt=tmp_path / 'corrupt'))
    wrapper.chmod(0o700)
    monkeypatch.setattr(push, 'SSH_PROGRAM', str(wrapper))
    monkeypatch.setattr(push, 'EXTRA_RSYNC_ARGS', [])
    root = tmp_path / 'pushes'
    (workspace / 'data/sub').mkdir(parents=True)
    (workspace / 'data/big.bin').write_bytes(os.urandom(3 * 1024 * 1024))
    (workspace / 'data/sub/secret-name-small.txt').write_text('hello\n')
    started = []
    yield instance, workspace, home, root, started
    for push_id in started:
        push.cancel_push(root, push_id)
    subprocess.run(['bash', '-c', 'for d in .codex-jobs/*/; do [ -d "$d" ] && .local/bin/codex-job kill "$(basename "$d")"; done'],
                   cwd=home, env={'HOME': str(home), 'PATH': os.environ['PATH'], 'CODEX_JOB_KILL_GRACE': '1'},
                   capture_output=True, timeout=60)


def wait(root, push_id, states, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = push.push_status(root, push_id)
        if status['state'] in states:
            return status
        time.sleep(0.1)
    raise AssertionError(push.push_status(root, push_id))


def private_text(root, push_id, calls):
    names = ('request.json', 'status.json', 'progress.json', 'runner.stderr', 'rsync.stderr', 'rsync.json', 'runner.json')
    text = ''.join((root / push_id / name).read_text() for name in names if (root / push_id / name).exists())
    return text + (calls.read_text() if calls.exists() else '')


def test_push_completes_verifies_and_keeps_secrets_off_disk(pusher):
    instance, workspace, home, root, started = pusher
    monkey_bw = ['--bwlimit=2000']
    push.EXTRA_RSYNC_ARGS[:] = monkey_bw
    result = push.start_push(instance, root, 'data', '~/dest', 'p1')
    started.append('p1')
    assert result == {'push_id': 'p1', 'state': 'started', 'file_count': 2}
    channel = root / 'p1' / 'ssh'
    # While running, the password exists only in 0600 files inside a 0700 directory.
    assert stat.S_IMODE(channel.stat().st_mode) == 0o700
    for name in ('secret', 'config', 'askpass'):
        assert stat.S_IMODE((channel / name).stat().st_mode) in (0o600, 0o700)
    assert stat.S_IMODE((channel / 'secret').stat().st_mode) == 0o600
    assert HOST in (channel / 'config').read_text()
    runner = json.loads((root / 'p1' / 'runner.json').read_text())
    cmdline = Path(f"/proc/{runner['pid']}/cmdline").read_bytes()
    assert PASSWORD.encode() not in cmdline and HOST.encode() not in cmdline
    environ = Path(f"/proc/{runner['pid']}/environ").read_bytes()
    assert PASSWORD.encode() not in environ and HOST.encode() not in environ
    status = wait(root, 'p1', push.TERMINAL)
    assert status['state'] == 'completed', status
    assert status['verify'] == {'verified': 2, 'failed': 0, 'failed_paths': []}
    assert status['progress']['bytes_done'] == status['bytes_total'] == 3 * 1024 * 1024 + 6
    assert status['progress']['percent'] == 100
    assert (home / 'dest/big.bin').read_bytes() == (workspace / 'data/big.bin').read_bytes()
    assert stat.S_IMODE((home / 'dest/big.bin').stat().st_mode) & 0o077 == 0
    assert not channel.exists()
    text = private_text(root, 'p1', home.parent / 'calls') + json.dumps(status)
    assert PASSWORD not in text and HOST not in text and 'remote-user' not in text
    progress = (root / 'p1' / 'progress.json').read_text()
    assert 'secret-name-small' not in progress and 'big.bin' not in progress
    assert 'secret-name-small' not in json.dumps(status)


def test_status_is_read_from_disk_without_the_service(pusher):
    instance, workspace, home, root, started = pusher
    push.start_push(instance, root, 'data/sub', 'dest2', 'p2')
    started.append('p2')
    final = wait(root, 'p2', push.TERMINAL)
    assert final['state'] == 'completed', (final, (root / 'p2' / 'rsync.stderr').read_text(), (root / 'p2' / 'runner.stderr').read_text())
    code = ("import json,sys; from codex_worker import push; "
            "print(json.dumps(push.push_status(sys.argv[1], 'p2')))")
    out = subprocess.run([sys.executable, '-c', code, str(root)], capture_output=True, text=True, check=True,
                         cwd=Path(push.__file__).resolve().parents[1]).stdout
    assert json.loads(out)['state'] == 'completed', out
    assert push.push_status(root, 'nope') == {'push_id': 'nope', 'state': 'unknown_id'}
    with pytest.raises(ValueError):
        push.push_status(root, '../p2')


def wait_progress(root, push_id, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if push.push_status(root, push_id)['progress'].get('bytes_done', 0) > 0:
            return
        time.sleep(0.05)
    raise AssertionError(push.push_status(root, push_id))


def test_cancel_keeps_partial_data_and_a_new_push_resumes(pusher):
    instance, workspace, home, root, started = pusher
    push.EXTRA_RSYNC_ARGS[:] = ['--bwlimit=300']
    push.start_push(instance, root, 'data', 'dest', 'slow')
    started.append('slow')
    wait_progress(root, 'slow')
    rsync = json.loads((root / 'slow' / 'rsync.json').read_text())
    status = push.cancel_push(root, 'slow')
    assert status['state'] == 'cancelled' and status['reason'] == 'cancelled'
    assert not push.alive(rsync)
    assert not (root / 'slow' / 'ssh').exists()
    assert list((home / 'dest').rglob('.rsync-partial/*')), 'partial file kept for resume'
    push.EXTRA_RSYNC_ARGS[:] = []
    push.start_push(instance, root, 'data', 'dest', 'resume')
    started.append('resume')
    status = wait(root, 'resume', push.TERMINAL)
    assert status['state'] == 'completed', status
    assert (home / 'dest/big.bin').read_bytes() == (workspace / 'data/big.bin').read_bytes()
    assert not list((home / 'dest').rglob('.rsync-partial'))
    assert push.cancel_push(root, 'resume')['state'] == 'completed'  # terminal: untouched


def test_runner_loss_is_reported_and_secrets_removed(pusher):
    instance, workspace, home, root, started = pusher
    push.EXTRA_RSYNC_ARGS[:] = ['--bwlimit=300']
    push.start_push(instance, root, 'data', 'dest', 'gone')
    started.append('gone')
    wait_progress(root, 'gone')
    runner = json.loads((root / 'gone' / 'runner.json').read_text())
    os.killpg(runner['pid'], signal.SIGKILL)
    status = wait(root, 'gone', {'lost'})
    assert status['reason'] == 'runner_lost'
    assert not (root / 'gone' / 'ssh').exists()


def test_verify_mismatch_reports_relative_paths(pusher):
    instance, workspace, home, root, started = pusher
    (home.parent / 'corrupt').write_text('')
    push.start_push(instance, root, 'data', 'dest', 'bad')
    started.append('bad')
    status = wait(root, 'bad', push.TERMINAL)
    assert status['state'] == 'failed' and status['reason'] == 'verify_mismatch'
    assert status['verify'] == {'verified': 1, 'failed': 1, 'failed_paths': ['big.bin']}
    assert str(home) not in json.dumps(status)
    assert not (root / 'bad' / 'ssh').exists()


def test_connection_failure_has_fixed_reason_and_cleans_channel(pusher):
    instance, workspace, home, root, started = pusher
    (home.parent / 'calls.fail').write_text('')
    push.start_push(instance, root, 'data', 'dest', 'down')
    started.append('down')
    status = wait(root, 'down', push.TERMINAL)
    assert status['state'] == 'failed' and status['reason'] == 'connection_failed', status
    assert not (root / 'down' / 'ssh').exists()
    assert PASSWORD not in private_text(root, 'down', home.parent / 'calls')


def test_start_rejects_escaping_or_linked_destinations(pusher, tmp_path):
    instance, workspace, home, root, started = pusher
    (tmp_path / 'outside').mkdir()
    (home / 'link').symlink_to(tmp_path / 'outside', target_is_directory=True)
    for bad in ('../x', '/abs', '~/../x', 'link/x', '-e', 'host:x', ''):
        with pytest.raises((ValueError, FileExistsError)):
            push.start_push(instance, root, 'data', bad, 'r' + str(abs(hash(bad)) % 10**6))
    for directory in root.iterdir():
        assert not (directory / 'ssh').exists()
        assert push.push_status(root, directory.name)['state'] in ('failed',)
    with pytest.raises(ValueError):
        push.start_push(instance, root, '../outside', 'dest', 'scope')
    assert not list((tmp_path / 'outside').iterdir())
