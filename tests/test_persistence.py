"""Task processes survive service exit and are adopted by the next instance."""
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from codex_worker.config import atomic_json, read_private
from codex_worker.processes import WRAPPER, proc_stat, terminate_group
from codex_worker.service import Worker

# The fake agent reads its prompt, optionally writes progress, sleeps, and then
# reports success with tool evidence. Behaviour is chosen by prompt keywords.
FAKE = '''import json, pathlib, re, sys, time
prompt = sys.stdin.read()
work = pathlib.Path.cwd()
work.parent.joinpath("agent.pid").write_text(str(__import__("os").getpid()))
match = re.search(r"progress:(\\S+)", prompt)
if match:
    work.joinpath("progress.txt").write_text(match.group(1).replace("_", " "))
match = re.search(r"sleep:([0-9.]+)", prompt)
if match:
    time.sleep(float(match.group(1)))
pathlib.Path(sys.argv[sys.argv.index("-o") + 1]).write_text(json.dumps({"task_status": "succeeded", "report": "done", "verification": "fake"}))
work.parent.joinpath("remote-audit.jsonl").write_text(json.dumps({"success": True}) + "\\n")
'''


def make_private(root):
    root.chmod(0o700)
    fake = root / 'fake-codex'
    fake.write_text('#!' + sys.executable + '\n' + FAKE)
    fake.chmod(0o700)
    atomic_json(root / 'resources.json', {'codex_binary': str(fake), 'max_parallel': 2,
                                          'monitor_interval_seconds': 0.05,
                                          'resources': {'example-server': {'host': '192.0.2.1'}}})
    atomic_json(root / 'credentials.json', {})
    atomic_json(root / 'policy.json', {'sensitive_literals': ['hidden-place']})
    return root


@pytest.fixture
def private(tmp_path):
    root = make_private(tmp_path)
    workers = []
    extra = []
    yield root, workers, extra
    for worker in workers:
        worker.close()
    # Never leave a task process behind, whichever instance started it.
    for record in root.glob('jobs/job_*/process.json'):
        try:
            os.killpg(json.loads(record.read_text())['pid'], signal.SIGKILL)
        except (ProcessLookupError, PermissionError, ValueError, KeyError):
            pass
    for process in extra:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)


def start(root, workers):
    worker = Worker(root)
    workers.append(worker)
    return worker


def until(predicate, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    pytest.fail('condition not reached')


def state(root, identifier):
    return read_private(root / 'jobs' / identifier / 'state.json')


def alive(pid):
    info = proc_stat(pid)
    return info is not None and info['state'] not in ('Z', 'X')


def running_job(worker, instruction):
    identifier = worker.submit('example-server', instruction)['job_id']
    path = worker.jobs / identifier
    until(lambda: (path / 'process.json').exists() and (path / 'agent.pid').exists())
    return identifier, path, read_private(path / 'process.json')


def manual_job(root, record=None, exit_code=None, report=True):
    identifier = 'job_' + os.urandom(12).hex()
    path = root / 'jobs' / identifier
    (path / 'work').mkdir(parents=True, mode=0o700)
    atomic_json(path / 'state.json', {'job_id': identifier, 'target': 'example-server',
                                     'status': 'running', 'created_at': time.time()})
    if record is not None:
        atomic_json(path / 'process.json', record)
    if exit_code is not None:
        (path / 'exit').write_text(f'{exit_code}\n')
    if report:
        (path / 'final.txt').write_text(json.dumps({'task_status': 'succeeded', 'report': 'r', 'verification': 'v'}))
        (path / 'remote-audit.jsonl').write_text(json.dumps({'success': True}) + '\n')
    return identifier


def dead_record():
    process = subprocess.Popen(['true'])
    info = proc_stat(process.pid)
    process.wait()
    return {'pid': process.pid, 'starttime': info['starttime'] if info else 1}


def test_closing_service_keeps_task_and_next_instance_adopts_it(private):
    root, workers, _ = private
    first = start(root, workers)
    identifier, path, record = running_job(first, 'sleep:1.5')
    first.close()
    time.sleep(0.3)
    assert alive(record['pid'])
    assert state(root, identifier)['status'] == 'running'
    second = start(root, workers)
    assert state(root, identifier)['status'] == 'running'
    final = until(lambda: state(root, identifier)['status'] != 'running' and state(root, identifier))
    assert final['status'] == 'completed' and final['exit_code'] == 0
    assert (path / 'exit').read_text().strip() == '0'
    assert not alive(record['pid'])
    assert second.public({'method': 'get_result', 'arguments': {'task_id': identifier}})['status'] == 'completed'


def test_adopting_dead_process_uses_exit_file_or_reports_lost(private):
    root, workers, _ = private
    with_exit = manual_job(root, dead_record(), exit_code=0)
    failed_exit = manual_job(root, dead_record(), exit_code=3)
    unverified = manual_job(root, dead_record(), exit_code=0, report=False)
    lost = manual_job(root, dead_record())
    no_record = manual_job(root)
    start(root, workers)
    assert state(root, with_exit)['status'] == 'completed'
    assert state(root, failed_exit)['status'] == 'failed'
    assert state(root, unverified)['status'] == 'failed'
    for identifier in (lost, no_record):
        result = state(root, identifier)
        assert result['status'] == 'interrupted' and result['error_code'] == 'lost'


def test_reused_pid_is_not_adopted_or_signalled(private):
    root, workers, extra = private
    stranger = subprocess.Popen(['sleep', '30'], start_new_session=True)
    extra.append(stranger)
    real = proc_stat(stranger.pid)['starttime']
    record = {'pid': stranger.pid, 'starttime': real + 12345}
    identifier = manual_job(root, record)
    worker = start(root, workers)
    assert state(root, identifier)['status'] == 'interrupted'
    assert terminate_group(record, wait=True) is False
    worker.public({'method': 'cancel_task', 'arguments': {'task_id': identifier}})
    time.sleep(0.2)
    assert stranger.poll() is None


def test_cancel_stops_adopted_task_group(private):
    root, workers, _ = private
    first = start(root, workers)
    identifier, path, record = running_job(first, 'sleep:30')
    agent = int((path / 'agent.pid').read_text())
    first.close()
    second = start(root, workers)
    result = second.public({'method': 'cancel_task', 'arguments': {'task_id': identifier}})
    assert result['status'] == 'cancelled'
    until(lambda: not alive(record['pid']) and not alive(agent))
    time.sleep(0.2)
    assert state(root, identifier)['status'] == 'cancelled'


def test_cancel_escalates_to_sigkill_after_grace(private):
    root, workers, extra = private
    stubborn = subprocess.Popen([sys.executable, '-c', 'import signal, time\n'
                                 'signal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(60)'],
                                start_new_session=True)
    extra.append(stubborn)
    time.sleep(0.2)
    record = {'pid': stubborn.pid, 'starttime': proc_stat(stubborn.pid)['starttime']}
    started = time.monotonic()
    assert terminate_group(record, grace_seconds=0.5, wait=True)
    stubborn.wait(timeout=5)
    assert stubborn.returncode == -signal.SIGKILL
    assert time.monotonic() - started >= 0.5


def test_task_timeout_parameter_stops_task(private):
    root, workers, _ = private
    worker = start(root, workers)
    assert worker.submit('example-server', 'x', timeout_seconds=0)['error_code'] == 'invalid_task_timeout'
    assert worker.submit('example-server', 'x', timeout_seconds=604801)['error_code'] == 'invalid_task_timeout'
    assert worker.submit('example-server', 'x', timeout_seconds=True)['error_code'] == 'invalid_task_timeout'
    submitted = worker.public({'method': 'submit_task', 'arguments': {
        'target': 'example-server', 'instruction': 'sleep:30', 'timeout_seconds': 1}})
    identifier = submitted['job_id']
    path = worker.jobs / identifier
    until(lambda: (path / 'agent.pid').exists())
    agent = int((path / 'agent.pid').read_text())
    final = until(lambda: state(root, identifier)['status'] != 'running' and state(root, identifier))
    assert final['status'] == 'timed_out'
    assert read_private(path / 'request.json')['timeout_seconds'] == 1
    until(lambda: not alive(agent))


def test_adopted_task_deadline_is_enforced(private):
    root, workers, _ = private
    first = start(root, workers)
    identifier, path, record = running_job(first, 'sleep:30')
    first.close()
    record['deadline'] = time.time() - 1
    atomic_json(path / 'process.json', record)
    start(root, workers)
    until(lambda: state(root, identifier)['status'] == 'timed_out')
    until(lambda: not alive(record['pid']))


def test_progress_is_returned_filtered_and_bounded(private):
    root, workers, _ = private
    worker = start(root, workers)
    identifier, path, _ = running_job(worker, 'progress:step_2/5_on_192.0.2.1_hidden-place sleep:30')
    task = until(lambda: worker.public({'method': 'get_task', 'arguments': {'task_id': identifier}}).get('progress')
                 and worker.public({'method': 'get_task', 'arguments': {'task_id': identifier}}))
    assert task['progress'].startswith('step 2/5 on [redacted-')
    assert '192.0.2.1' not in json.dumps(task) and 'hidden-place' not in json.dumps(task)
    assert isinstance(task['progress_updated_at'], float)
    (path / 'work/progress.txt').write_text('x' * 5000)
    assert len(worker.public({'method': 'get_task', 'arguments': {'task_id': identifier}})['progress']) == 2048
    (path / 'work/progress.txt').unlink()
    (path / 'work/progress.txt').symlink_to(root / 'policy.json')
    assert 'progress' not in worker.public({'method': 'get_task', 'arguments': {'task_id': identifier}})
    worker.public({'method': 'cancel_task', 'arguments': {'task_id': identifier}})


def test_queued_jobs_are_started_by_next_instance(private):
    root, workers, _ = private
    identifier = manual_job(root, report=False)
    path = root / 'jobs' / identifier
    atomic_json(path / 'state.json', {**state(root, identifier), 'status': 'queued'})
    atomic_json(path / 'request.json', {'target': 'example-server', 'instruction': 'quick', 'parent': None})
    start(root, workers)
    until(lambda: state(root, identifier)['status'] == 'completed')


def test_wrapper_passes_prompt_without_shell_interpretation(tmp_path):
    prompt = tmp_path / 'prompt.txt'
    payload = '$(touch pwned) `touch pwned2` ; rm -rf / "\'\n'
    prompt.write_text(payload)
    received = tmp_path / 'received'
    subprocess.run(['/bin/sh', '-c', WRAPPER, 'codex-task', str(prompt), str(tmp_path / 'exit'),
                    sys.executable, '-c', 'import sys; open(sys.argv[1], "w").write(sys.stdin.read()); sys.exit(7)',
                    str(received)], cwd=tmp_path, check=True)
    assert received.read_text() == payload
    assert (tmp_path / 'exit').read_text() == '7\n'
    assert not (tmp_path / 'pwned').exists() and not (tmp_path / 'pwned2').exists()


def test_sigterm_to_real_service_leaves_task_running(private):
    root, workers, extra = private
    socket_path = root / 'test.sock'
    service = subprocess.Popen([sys.executable, '-m', 'codex_worker.cli', 'serve', '--private-dir', str(root),
                                '--socket', str(socket_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    extra.append(service)
    until(socket_path.exists)
    with socket.socket(socket.AF_UNIX) as connection:
        connection.connect(str(socket_path))
        connection.sendall(json.dumps({'method': 'submit_task', 'arguments': {
            'target': 'example-server', 'instruction': 'sleep:2'}}).encode() + b'\n')
        identifier = json.loads(connection.makefile().readline())['job_id']
    path = root / 'jobs' / identifier
    until(lambda: (path / 'agent.pid').exists())
    agent = int((path / 'agent.pid').read_text())
    service.send_signal(signal.SIGTERM)
    assert service.wait(timeout=10) == 0
    assert alive(agent)
    assert state(root, identifier)['status'] == 'running'
    until(lambda: (path / 'exit').exists())
    start(root, workers)
    assert state(root, identifier)['status'] == 'completed'


def test_second_service_instance_does_not_adopt(private, monkeypatch):
    from codex_worker import service
    root, workers, extra = private
    socket_path = root / 'test.sock'
    first = subprocess.Popen([sys.executable, '-m', 'codex_worker.cli', 'serve', '--private-dir', str(root),
                              '--socket', str(socket_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    extra.append(first)
    until(socket_path.exists)
    monkeypatch.setattr(service, 'Worker', lambda *args: pytest.fail('adopted while another instance serves'))
    with pytest.raises(RuntimeError):
        service.serve(root, socket_path)
