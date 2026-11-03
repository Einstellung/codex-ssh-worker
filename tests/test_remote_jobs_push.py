import asyncio
import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from codex_worker import mcp_api, push
from codex_worker.remote import BinaryFileError, Remote
from test_remote_files import LocalSFTP

PASSWORD = 'pw-' + 'Z9q' * 6
HOST = 'host.example.invalid'


class FakeClient:
    def __init__(self, sftp): self.sftp = sftp
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def open_sftp(self): return self.sftp


@pytest.fixture
def setup(tmp_path, monkeypatch):
    workspace, home = tmp_path / 'work', tmp_path / 'home'
    workspace.mkdir(); home.mkdir()
    (tmp_path / 'known_hosts').write_text('')
    settings = {'resources': {'example-server': {'credential_ref': 'login', 'host': HOST, 'port': 2222, 'user': 'remote-user'}}}
    instance = Remote(tmp_path, settings, {'login': {'password': PASSWORD}}, 'example-server', workspace, 'job_' + 'a' * 24)
    monkeypatch.setattr(instance, 'connect', lambda: FakeClient(LocalSFTP(home)))

    def execute(command, timeout=120, max_bytes=262144, stdin=None):
        # Stand-in for SSH: run the command text with the fake remote home.
        result = subprocess.run(['bash', '-c', command], input=stdin, cwd=home, capture_output=True, timeout=60,
                                env={'HOME': str(home), 'PATH': os.environ['PATH'], 'CODEX_JOB_KILL_GRACE': '1'})
        return {'exit_code': result.returncode, 'stdout': result.stdout.decode(), 'stderr': result.stderr.decode()}
    monkeypatch.setattr(instance, 'execute', execute)
    return instance, workspace, home, tmp_path


class Tools:
    def __init__(self):
        self.functions, self.audits = {}, []
    def tool(self):
        def register(function):
            self.functions[function.__name__] = function
            return function
        return register


@pytest.fixture
def tools(setup):
    instance, workspace, home, tmp_path = setup
    registry = Tools()
    mcp_api.register_remote_tools(registry, instance, tmp_path / 'pushes', lambda *a: registry.audits.append(a))
    yield registry
    for job in registry.functions['job_list']().get('jobs', []):
        if job['state'] == 'running':
            registry.functions['job_kill'](job['id'])


def test_ensure_remote_tools_installs_once_and_repairs(setup):
    instance, _, home, _ = setup
    installed = home / '.local/bin/codex-job'
    assert instance.ensure_remote_tools() is True
    assert installed.read_bytes() == (Path(push.__file__).with_name('remote_job.sh')).read_bytes()
    assert stat.S_IMODE(installed.stat().st_mode) == 0o700
    assert instance.ensure_remote_tools() is False  # cached within the process
    instance._tools_ready = False
    assert instance.ensure_remote_tools() is False  # same digest: untouched
    installed.write_text('tampered')
    instance._tools_ready = False
    assert instance.ensure_remote_tools() is True
    assert b'codex-job' in installed.read_bytes()


def test_write_and_read_remote_file(setup, tmp_path):
    instance, _, home, _ = setup
    result = instance.write_file('~/proj/run.sh', 'echo ok\n', 0o700)
    assert result['written'] and result['size_bytes'] == 8
    assert (home / 'proj/run.sh').read_text() == 'echo ok\n'
    assert stat.S_IMODE((home / 'proj/run.sh').stat().st_mode) == 0o700
    assert instance.read_file('proj/run.sh') == {'content': 'echo ok\n', 'size_bytes': 8, 'truncated': False}
    assert instance.read_file('proj/run.sh', 4)['truncated'] is True
    assert not list(home.rglob('*.worker-*'))
    (home / 'blob').write_bytes(b'\x00\x01')
    with pytest.raises(BinaryFileError):
        instance.read_file('blob')
    outside = tmp_path / 'outside'
    outside.mkdir()
    (home / 'link').symlink_to(outside, target_is_directory=True)
    (home / 'filelink').symlink_to(home / 'proj/run.sh')
    for bad in ('link/x', '../escape', '/etc/passwd', 'filelink', ''):
        with pytest.raises(ValueError):
            instance.write_file(bad, 'x')
    with pytest.raises(ValueError):
        instance.read_file('link/x')
    with pytest.raises(ValueError):
        instance.write_file('big', 'x' * (1024 * 1024 + 1))
    assert not list(outside.iterdir())


def test_file_tools_return_codes_and_audit(tools):
    write, read = tools.functions['write_remote_file'], tools.functions['read_remote_file']
    assert write('notes.txt', 'hello')['written'] is True
    assert read('notes.txt', 100)['content'] == 'hello'
    assert read('missing', 100) == {'error_code': 'remote_read_failed'}
    assert write('../x', 'y') == {'error_code': 'remote_write_failed'}
    assert ('write_remote_file', True) in tools.audits and ('read_remote_file', False) in tools.audits


def test_job_tools_round_trip(tools, setup):
    f = tools.functions
    started = f['job_start']('echo "$((6 * 7))"; echo "$HOME" | wc -c >/dev/null; exit 4', 'calc')
    assert started['id'] == 'calc' and started['state'] in ('running', 'exited')
    deadline = time.monotonic() + 10
    while f['job_status']('calc')['state'] == 'running' and time.monotonic() < deadline:
        time.sleep(0.05)
    assert f['job_status']('calc') == {**f['job_status']('calc'), 'state': 'exited', 'exit_code': 4}
    assert f['job_tail']('calc', 10) == {'id': 'calc', 'log': '42\n'}
    assert f['job_start']('true', 'calc') == {'error_code': 'id_exists'}
    assert f['job_start']('true', '../bad') == {'error_code': 'job_start_failed'}
    assert f['job_tail']('nope', 10) == {'error_code': 'unknown_id'}
    assert f['job_tail']('calc', 0) == {'error_code': 'invalid_lines'}
    assert f['job_status']('nope')['state'] == 'unknown_id'
    long = f['job_start']('sleep 60')
    assert long['state'] == 'running'
    assert {job['id'] for job in f['job_list']()['jobs']} == {'calc', long['id']}
    killed = f['job_kill'](long['id'])
    assert killed['state'] == 'exited' and killed['killed'] is True
    assert ('job_start', True) in tools.audits
    text = json.dumps([f['job_list'](), f['job_status']('calc')])
    assert HOST not in text and PASSWORD not in text and str(setup[2]) not in text
    assert 'nvidia-smi' in f['job_start'].__doc__ and 'remote_exec' in f['job_start'].__doc__


def test_home_path_edge_cases_and_permissions(setup, tmp_path):
    instance, _, home, _ = setup
    sftp = LocalSFTP(home)
    for bad in ('..', '~/..', 'a/../../x', '/tmp/x', '~', '.', 'a\0b', None):
        with pytest.raises(ValueError):
            Remote.home_path(sftp, bad)
    (home / 'real').mkdir()
    (home / 'real/inner').symlink_to(tmp_path)
    with pytest.raises(ValueError):
        Remote.home_path(sftp, 'real/inner/deeper/file')
    assert Remote.home_path(sftp, 'a/../real/new.txt')[1] == str(home / 'real/new.txt')
    for mode in (0o666, 0o620, 0o1777, -1):
        with pytest.raises(ValueError):
            instance.write_file('m.txt', 'x', mode)
    with pytest.raises(ValueError):
        instance.write_file('m.txt', ['not', 'text'])
    assert not (home / 'm.txt').exists()
    instance.write_file('m.txt', 'x', 0o755)


def test_temporary_file_is_private_before_content_is_written(setup, monkeypatch):
    instance, _, home, _ = setup
    seen = []
    original = LocalSFTP.open
    def spy(self, path, mode):
        stream = original(self, path, mode)
        if 'w' in mode:
            write = stream.write
            stream.write = lambda data: (seen.append(stat.S_IMODE(os.stat(path).st_mode)), write(data))[1]
        return stream
    monkeypatch.setattr(LocalSFTP, 'open', spy)
    instance.write_file('secret.cfg', 'token=placeholder', 0o600)
    assert seen == [0o600]


def test_truncated_read_drops_only_a_split_character(setup):
    instance, _, home, _ = setup
    (home / 'zh.txt').write_text('ab' + '中' * 4)
    result = instance.read_file('zh.txt', 4)
    assert result == {'content': 'ab', 'size_bytes': 14, 'truncated': True}
    (home / 'latin1.txt').write_bytes(b'caf\xe9 au lait')
    with pytest.raises(BinaryFileError):
        instance.read_file('latin1.txt', 100)


def test_mkdirs_tolerates_concurrent_creation(setup):
    _, _, home, _ = setup
    sftp = LocalSFTP(home)
    original = sftp.mkdir
    def racing(path, mode):
        original(path, mode)
        raise OSError('exists')  # another call created it between lstat and mkdir
    sftp.mkdir = racing
    Remote._mkdirs(sftp, str(home / 'x/y'))
    assert (home / 'x/y').is_dir()
    (home / 'file').write_text('')
    sftp.mkdir = lambda path, mode: (_ for _ in ()).throw(OSError('exists'))
    with pytest.raises((ValueError, OSError)):
        Remote._mkdirs(sftp, str(home / 'file/z'))


def test_job_command_reinstalls_a_removed_tool(setup):
    instance, _, home, _ = setup
    assert instance.job_command('ls')['exit_code'] == 0
    (home / '.local/bin/codex-job').unlink()
    assert instance.job_command('ls')['exit_code'] == 0
    assert (home / '.local/bin/codex-job').exists()


def test_ssh_channel_rejects_token_characters(setup, tmp_path):
    instance, _, _, _ = setup
    instance.resource = {**instance.resource, 'user': 'user%h'}
    with pytest.raises(ValueError):
        push.write_ssh_channel(instance, tmp_path / 'chan')
