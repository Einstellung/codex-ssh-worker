import io
import os
import posixpath
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from codex_worker.remote import Remote


class LocalSFTP:
    def __init__(self, root):
        self.root = root
        self.puts = []
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def get_channel(self): return self
    def settimeout(self, value): pass
    def normalize(self, value): return str(self.root)
    def lstat(self, path): return Path(path).lstat()
    def mkdir(self, path, mode): Path(path).mkdir(mode=mode)
    def chmod(self, path, mode): Path(path).chmod(mode)
    def remove(self, path): Path(path).unlink()
    def posix_rename(self, source, destination): os.replace(source, destination)
    def open(self, path, mode): return Path(path).open(mode)
    def putfo(self, stream, destination, file_size, confirm):
        self.puts.append(destination)
        with Path(destination).open('wb') as output:
            shutil.copyfileobj(stream, output)
        assert Path(destination).stat().st_size == file_size


class ProcessOutput:
    def __init__(self, process):
        self.process = process
        self.channel = self
    def read(self, size): return self.process.stdout.read(size)
    def shutdown_write(self): self.process.stdin.close()
    def recv_exit_status(self): return self.process.wait(timeout=10)


class LocalClient:
    def __init__(self, sftp): self.sftp = sftp
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def open_sftp(self): return self.sftp
    def exec_command(self, command, timeout):
        arguments = shlex.split(command)
        assert arguments[:2] == ['python3', '-c']
        # Execute the actual remote hash checker against a synthetic local tree.
        process = subprocess.Popen([sys.executable, '-c', arguments[2]], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return process.stdin, ProcessOutput(process), process.stderr


@pytest.fixture
def remote(tmp_path, monkeypatch):
    workspace = tmp_path / 'work'
    workspace.mkdir()
    target = tmp_path / 'target'
    target.mkdir()
    instance = Remote(tmp_path, {'resources': {'example-server': {'credential_ref': 'login'}}},
                      {'login': {}}, 'example-server', workspace, 'job_' + 'a' * 24)
    (tmp_path / 'jobs' / instance.job).mkdir(parents=True)
    sftp = LocalSFTP(target)
    monkeypatch.setattr(instance, 'connect', lambda: LocalClient(sftp))
    return instance, workspace, target, sftp


def test_directory_transfer_hashes_actual_bytes_and_resumes(remote):
    instance, workspace, target, sftp = remote
    (workspace / 'inputs/sub').mkdir(parents=True)
    expected = b'\x00\xffunchanged bytes' * 10000
    (workspace / 'inputs/sub/model.bin').write_bytes(expected)
    (workspace / 'inputs/code.py').write_text('print(1 + 2)\n')
    result = instance.upload('inputs', 'dataset')
    assert result == {'uploaded': True, 'file_count': 2, 'skipped_files': 0,
                      'size_bytes': len(expected) + len(b'print(1 + 2)\n'),
                      'sha256_verified': True, 'md5_verified': True}
    assert (target / 'dataset/sub/model.bin').read_bytes() == expected
    assert len(sftp.puts) == 2
    assert instance.upload('inputs', 'dataset')['skipped_files'] == 2
    assert len(sftp.puts) == 2
    # Same size corruption must not be treated as an already-transferred file.
    (target / 'dataset/sub/model.bin').write_bytes(b'x' * len(expected))
    assert instance.upload('inputs', 'dataset')['skipped_files'] == 1
    assert len(sftp.puts) == 3
    assert (target / 'dataset/sub/model.bin').read_bytes() == expected
    assert not list(target.rglob('*.worker-*'))


def test_transfer_detects_corruption_and_preserves_other_files(remote, monkeypatch):
    instance, workspace, target, sftp = remote
    (workspace / 'data.bin').write_bytes(b'abcdef')
    (target / 'unrelated').write_text('leave this alone')
    original = sftp.putfo
    def corrupt(stream, destination, file_size, confirm):
        original(stream, destination, file_size, confirm)
        Path(destination).write_bytes(b'fedcba')
    monkeypatch.setattr(sftp, 'putfo', corrupt)
    with pytest.raises(ValueError, match='remote digest mismatch'):
        instance.upload('data.bin', 'result.bin')
    assert (target / 'unrelated').read_text() == 'leave this alone'
    assert not list(target.rglob('*.worker-*'))


def test_remote_symlink_directory_and_local_scope_are_rejected(remote, tmp_path):
    instance, workspace, target, _ = remote
    (workspace / 'data.bin').write_bytes(b'data')
    outside = tmp_path / 'outside'
    outside.mkdir()
    (target / 'link').symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        instance.upload('data.bin', 'link/file')
    assert not list(outside.iterdir())
    (workspace / 'private-link').symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        instance.upload('private-link', 'output')


def test_fetch_no_longer_truncates_large_binary(remote):
    instance, workspace, target, _ = remote
    content = b'\x00\xfftest' * 1800000
    assert len(content) > 10 * 1024 * 1024
    source = target / 'big.bin'
    source.write_bytes(content)
    result = instance.fetch(str(source))
    output = instance.private / 'jobs' / instance.job / 'artifacts' / result['artifact_id']
    assert result['size_bytes'] == len(content)
    assert output.read_bytes() == content
    assert output.stat().st_mode & 0o777 == 0o600


def test_fetch_failure_removes_partial_artifact(remote, monkeypatch):
    instance, workspace, target, sftp = remote
    def broken(*args):
        raise OSError('synthetic private error')
    monkeypatch.setattr(sftp, 'open', broken)
    with pytest.raises(OSError):
        instance.fetch('unavailable')
    assert not list((instance.private / 'jobs' / instance.job / 'artifacts').iterdir())
