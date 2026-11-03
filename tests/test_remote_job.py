import json
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'codex_worker' / 'remote_job.sh'


@pytest.fixture
def job(tmp_path):
    home = tmp_path / 'home'
    home.mkdir()
    env = {'HOME': str(home), 'PATH': os.environ['PATH'], 'CODEX_JOB_KILL_GRACE': '1'}

    def run(*args, stdin=None, check_json=True):
        output = subprocess.run(['bash', str(SCRIPT), *args], input=stdin, env=env,
                                capture_output=True, text=True, timeout=30).stdout
        return json.loads(output) if check_json else output

    run.home = home
    run.env = env
    yield run
    # Clean up anything still running from a failed test.
    for line in run('ls', check_json=False).splitlines():
        state = json.loads(line)
        if state.get('state') == 'running':
            run('kill', state['id'])


def wait_state(run, identifier, states=('exited', 'lost'), timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = run('status', identifier)
        if state['state'] in states:
            return state
        time.sleep(0.05)
    raise AssertionError(state)


def test_argv_command_records_exit_code_and_merged_log(job, tmp_path):
    marker = tmp_path / 'injected'
    started = job('start', 'j1', '--', 'sh', '-c', 'echo out; echo err >&2; exit 3', f'; touch {marker}')
    assert started['state'] in ('running', 'exited')
    state = wait_state(job, 'j1')
    assert state['state'] == 'exited' and state['exit_code'] == 3 and state['killed'] is False
    assert job('tail', 'j1', '5', check_json=False).split() == ['out', 'err']
    assert not marker.exists()
    directory = job.home / '.codex-jobs' / 'j1'
    assert {p.name for p in directory.iterdir()} >= {'cmd', 'log', 'pid', 'exit', 'started_at', 'finished_at'}
    assert (directory / 'exit').read_text() == '3\n'
    assert oct(directory.stat().st_mode & 0o777) == '0o700'


def test_stdin_command_text_and_duplicate_ids(job):
    job('start', 'j.2', stdin='x="a b"\necho "$x"\n')
    assert wait_state(job, 'j.2')['exit_code'] == 0
    assert job('tail', 'j.2', check_json=False) == 'a b\n'
    assert job('start', 'j.2', '--', 'true') == {'error': 'id_exists'}
    assert job('start', 'empty', stdin='') == {'error': 'empty_command'}
    assert not (job.home / '.codex-jobs' / 'empty').exists()


@pytest.mark.parametrize('bad', ['', '../x', 'a/b', '.', '..', 'x' * 65, 'a b', '$(id)'])
def test_invalid_ids_are_rejected(job, bad):
    for command in ('start', 'status', 'tail', 'kill'):
        assert job(command, bad, '--', 'true')['error'] == 'invalid_id'
    assert not (job.home / '.codex-jobs').exists()


def test_read_only_commands_are_idempotent(job):
    assert job('status', 'missing') == {'id': 'missing', 'state': 'unknown_id'}
    assert job('ls', check_json=False) == ''
    assert job('tail', 'missing') == {'error': 'unknown_id'}
    assert not (job.home / '.codex-jobs').exists()
    job('start', 'j3', '--', 'true')
    wait_state(job, 'j3')
    before = {p.name: p.stat().st_mtime_ns for p in (job.home / '.codex-jobs' / 'j3').iterdir()}
    for _ in range(3):
        job('status', 'j3'); job('tail', 'j3', check_json=False); job('ls', check_json=False)
    after = {p.name: p.stat().st_mtime_ns for p in (job.home / '.codex-jobs' / 'j3').iterdir()}
    assert before == after


def test_job_survives_caller_session_and_kill_terminates_group(job, tmp_path):
    child_pid = tmp_path / 'child.pid'
    job('start', 'long', '--', 'bash', '-c', f'sleep 60 & echo $! > {child_pid}; wait')
    state = wait_state(job, 'long', states=('running',))
    assert os.getsid(state['pid']) == state['pid'] != os.getsid(0)
    deadline = time.monotonic() + 5
    while not child_pid.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    grandchild = int(child_pid.read_text())
    killed = job('kill', 'long')
    assert killed['state'] == 'exited' and killed['killed'] is True and killed['exit_code'] != 0
    time.sleep(0.2)
    with pytest.raises(ProcessLookupError):
        os.kill(grandchild, 0)
    assert job('kill', 'long')['state'] == 'exited'


def test_term_ignoring_job_is_force_killed(job):
    job('start', 'stubborn', stdin="trap '' TERM\nwhile :; do sleep 0.1; done\n")
    wait_state(job, 'stubborn', states=('running',))
    started = time.monotonic()
    state = job('kill', 'stubborn')
    assert state['state'] == 'exited' and state['killed'] is True
    assert time.monotonic() - started < 5


def test_lost_job_and_reused_pid_are_never_success(job):
    job('start', 'gone', '--', 'sleep', '60')
    state = wait_state(job, 'gone', states=('running',))
    directory = job.home / '.codex-jobs' / 'gone'
    # Simulate a crashed wrapper: kill the whole group with SIGKILL, no exit file.
    os.killpg(state['pid'], signal.SIGKILL)
    time.sleep(0.2)
    (directory / 'exit').unlink(missing_ok=True)
    assert job('status', 'gone')['state'] == 'lost'
    # A live, unrelated pid with a different start time must not count as the job.
    other = subprocess.Popen(['sleep', '30'])
    try:
        (directory / 'pid').write_text(f'{other.pid} 1\n')
        assert job('status', 'gone')['state'] == 'lost'
        assert job('kill', 'gone')['state'] == 'lost'
        assert other.poll() is None
    finally:
        other.kill(); other.wait()
    assert job('prune', '0') == {'removed': 0}


def test_log_rotation_and_prune(job):
    job.env.update(CODEX_JOB_LOG_MAX='4096', CODEX_JOB_ROTATE_INTERVAL='0.1')
    job('start', 'noisy', stdin='for i in $(seq 1 40); do head -c 1000 /dev/zero | tr "\\0" x; echo; sleep 0.02; done\n')
    assert wait_state(job, 'noisy')['exit_code'] == 0
    directory = job.home / '.codex-jobs' / 'noisy'
    assert (directory / 'log').stat().st_size < 40 * 1001
    assert (directory / 'log.1').exists()
    assert job('prune', '1') == {'removed': 0}
    assert job('prune', 'x') == {'error': 'invalid_days'}
    assert job('prune', '0') == {'removed': 1}
    assert not directory.exists()
