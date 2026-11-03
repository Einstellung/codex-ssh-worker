import asyncio
import gzip
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import pytest

from codex_worker.attachments import (CHUNK, collect_inputs, input_workspace,
    receive_inputs, save_artifact, stage_inputs)
from codex_worker.config import atomic_json
from codex_worker.exports import ExportBlocked, ExportGuard, export_snapshot
from codex_worker.privacy import Redactor
from codex_worker.remote import Remote
from test_worker import worker


@pytest.fixture
def running_service(worker, tmp_path):
    address = tmp_path / 'files.sock'
    process = subprocess.Popen([sys.executable, '-m', 'codex_worker.cli', 'serve',
        '--private-dir', str(worker.private), '--socket', str(address)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 5
    while not address.exists():
        if process.poll() is not None or time.monotonic() >= deadline:
            pytest.fail('test service did not start')
        time.sleep(0.02)
    yield worker, address
    process.terminate()
    process.wait(timeout=10)


def rpc(address, method, **arguments):
    from codex_worker.mcp_api import gateway_call
    return asyncio.run(gateway_call(address, method, **arguments))


def archive_bytes(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for name, content, kind, digest in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = len(content)
            info.pax_headers = {'worker.sha256': digest or hashlib.sha256(content).hexdigest()}
            if info.issym():
                info.linkname = '/outside'
            archive.addfile(info, io.BytesIO(content))
    stream.seek(0)
    return stream


def test_binary_directory_and_selected_files_cross_real_service(running_service, tmp_path):
    worker, address = running_service
    root = tmp_path / 'caller'
    root.mkdir()
    content = bytes(range(256)) * 5000
    (root / '模型.bin').write_bytes(content)
    (root / 'excluded.bin').write_bytes(b'must not be copied')
    listing = tmp_path / 'selected.txt'
    listing.write_text('模型.bin\n', encoding='utf-8')
    staged = stage_inputs(address, [{'source': str(root), 'path': 'materials', 'list_file': str(listing)}])
    assert staged['file_count'] == 1 and staged['size_bytes'] == len(content)
    submitted = rpc(address, 'submit_task', target='example-server', instruction='Process the supplied binary',
                    input_id=staged['input_id'])
    path = worker.job(submitted['job_id'])
    assert (path / 'work/materials/模型.bin').read_bytes() == content
    assert not (path / 'work/materials/excluded.bin').exists()
    assert (path / 'work/AGENTS.md').is_file()
    assert (path / 'work/materials/模型.bin').stat().st_mode & 0o777 == 0o600
    assert rpc(address, 'submit_task', target='example-server', instruction='Do not reuse',
               input_id=staged['input_id']) == {'error_code': 'request_failed'}
    assert (root / '模型.bin').read_bytes() == content


def test_more_than_100_files_are_inputs_not_inline_text(running_service, tmp_path):
    worker, address = running_service
    source = tmp_path / 'many'
    source.mkdir()
    for index in range(130):
        (source / f'{index}.dat').write_bytes(bytes([index]))
    staged = stage_inputs(address, [{'source': str(source), 'path': 'data'}])
    assert staged['file_count'] == 130
    submitted = rpc(address, 'submit_task', target='example-server', instruction='Analyze', input_id=staged['input_id'])
    assert len(list((worker.job(submitted['job_id']) / 'work/data').iterdir())) == 130


@pytest.mark.parametrize('name,kind,digest', [
    ('../escape', tarfile.REGTYPE, None),
    ('/absolute', tarfile.REGTYPE, None),
    ('a/../../escape', tarfile.REGTYPE, None),
    ('AGENTS.md', tarfile.REGTYPE, None),
    ('data/.codex/config.toml', tarfile.REGTYPE, None),
    ('link', tarfile.SYMTYPE, None),
    ('file', tarfile.REGTYPE, '0' * 64),
])
def test_archive_paths_links_and_digest_fail_closed(tmp_path, name, kind, digest):
    with pytest.raises((ValueError, tarfile.TarError)):
        receive_inputs(tmp_path, archive_bytes([(name, b'abc', kind, digest)]),
                       {'file_count': 1, 'size_bytes': 3})
    assert not list((tmp_path / 'inputs').iterdir())
    assert not (tmp_path / 'escape').exists()


def test_archive_duplicates_incomplete_and_size_mismatch(tmp_path):
    cases = [([('a', b'x', tarfile.REGTYPE, None)] * 2, 2, 2),
             ([('a', b'x', tarfile.REGTYPE, None)], 2, 2),
             ([('a', b'xx', tarfile.REGTYPE, None)], 1, 1)]
    for entries, count, total in cases:
        with pytest.raises(ValueError):
            receive_inputs(tmp_path, archive_bytes(entries), {'file_count': count, 'size_bytes': total})
        assert not list((tmp_path / 'inputs').iterdir())


def test_caller_symlinks_and_manifest_traversal_are_rejected(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    outside = tmp_path / 'outside'
    outside.write_text('private')
    (source / 'link').symlink_to(outside)
    with pytest.raises((ValueError, OSError)):
        collect_inputs([{'source': str(source), 'path': 'data'}])
    listing = tmp_path / 'list'
    listing.write_text('../outside\n')
    with pytest.raises(ValueError):
        collect_inputs([{'source': str(source), 'path': 'data', 'list_file': str(listing)}])
    (source / 'link').unlink()
    (source / 'link').symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises((ValueError, OSError)):
        collect_inputs([{'source': str(source / 'link/outside'), 'path': 'data'}])


def test_binary_larger_than_old_limit_returns_original_and_never_overwrites(running_service, tmp_path):
    worker, address = running_service
    task = rpc(address, 'submit_task', target='example-server', instruction='task')['job_id']
    remote = Remote(worker.private, worker.settings, worker.credentials, 'example-server',
                    worker.job(task) / 'work', task)
    original = b'\x00\xffbusiness payload\n' * 600000  # exceeds the old 10 MiB ceiling
    local = worker.job(task) / 'work/model.bin'
    local.write_bytes(original)
    artifact = remote.publish('model.bin')
    assert artifact['size_bytes'] > 10 * 1024 * 1024
    destination = tmp_path / 'returned.bin'
    result = save_artifact(address, task, artifact['artifact_id'], str(destination))
    assert result.get('saved') is True, result
    assert destination.read_bytes() == original
    assert result['sha256'] == hashlib.sha256(original).hexdigest()
    assert destination.stat().st_mode & 0o777 == 0o600
    assert save_artifact(address, task, artifact['artifact_id'], str(destination)) == {
        'error_code': 'invalid_artifact_destination'}
    assert destination.read_bytes() == original


@pytest.mark.parametrize('content', [
    b'connection: 192.0.2.10',
    b'connection: 2001:db8::10',
    b'private-password',
    b'hidden-place',
    b'password=do-not-export',
    b'-----BEGIN OPENSSH PRIVATE KEY-----',
    b'{"latitude": 12.345}',
    '192.0.2.10'.encode('utf-16-le'),
    b'\x25\x88\x04\x00\x01\x00\x00\x00',
])
def test_sensitive_binary_artifact_held_before_any_content_leaves(running_service, tmp_path, content):
    worker, address = running_service
    task = rpc(address, 'submit_task', target='example-server', instruction='task')['job_id']
    directory = worker.job(task) / 'artifacts'
    directory.mkdir(exist_ok=True)
    identifier = 'artifact_' + 'd' * 24
    artifact = directory / identifier
    artifact.write_bytes(b'\x00\xff' + content + b'\x00')
    destination = tmp_path / 'must-not-exist'
    result = save_artifact(address, task, identifier, str(destination))
    assert result['status'] == 'review_required'
    assert not destination.exists()
    assert artifact.read_bytes() == b'\x00\xff' + content + b'\x00'
    serialized = json.dumps(result)
    assert all(secret not in serialized for secret in ('192.0.2.', 'private-password', 'hidden-place'))


def test_archive_member_contents_and_names_are_inspected(tmp_path):
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.txt', gzip.compress(b'endpoint 192.0.2.9'))
    data.seek(0)
    with pytest.raises(ExportBlocked):
        ExportGuard(Redactor()).scan(data)
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as archive:
        archive.writestr('hidden-place/result', b'safe payload')
    data.seek(0)
    with pytest.raises(ExportBlocked):
        ExportGuard(Redactor(['hidden-place'])).scan(data)


def test_export_snapshot_is_immutable_and_scans_across_chunk_boundaries(tmp_path):
    original = io.BytesIO(b'x' * (CHUNK - 5) + b' 192.0.2.20')
    with pytest.raises(ExportBlocked):
        export_snapshot(original, tmp_path, Redactor())
    original = io.BytesIO(b'original business bytes')
    snapshot, result = export_snapshot(original, tmp_path, Redactor())
    original.seek(0)
    original.write(b'mutated')
    with snapshot:
        assert snapshot.read() == b'original business bytes'
    assert result['size_bytes'] == len(b'original business bytes')


def test_mcp_input_and_output_over_real_stdio(running_service, tmp_path):
    from datetime import timedelta
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    worker, address = running_service
    source = tmp_path / 'caller.dat'
    source.write_bytes(b'\x00\xffreal attachment')
    async def scenario():
        parameters = StdioServerParameters(command=sys.executable,
            args=['-m', 'codex_worker.cli', 'mcp', '--socket', str(address)])
        async with stdio_client(parameters) as (reader, writer):
            async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=20)) as session:
                await session.initialize()
                result = await session.call_tool('run_task', {
                    'target': 'example-server', 'instruction': 'Process supplied file',
                    'attachments': [{'source': str(source), 'path': 'input.dat'}]})
                assert not result.isError, result.model_dump_json()
                body = json.loads(result.content[0].text)
                assert body['status'] == 'completed'
                job = worker.job(body['job_id'])
                assert (job / 'work/input.dat').read_bytes() == source.read_bytes()
                remote = Remote(worker.private, worker.settings, worker.credentials,
                                'example-server', job / 'work', body['job_id'])
                artifact = remote.publish('input.dat')
                destination = tmp_path / 'returned.dat'
                returned = await session.call_tool('get_artifact', {
                    'task_id': body['job_id'], 'artifact_id': artifact['artifact_id'],
                    'destination': str(destination)})
                assert not returned.isError, returned.model_dump_json()
                assert json.loads(returned.content[0].text)['saved'] is True
                assert destination.read_bytes() == source.read_bytes()
    asyncio.run(scenario())
