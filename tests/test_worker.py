import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from codex_worker.config import atomic_json, scoped_path
from codex_worker.privacy import Redactor
from codex_worker.service import Worker


def test_nested_identity_filter_preserves_business_metrics():
    source = {"custom_result": {"loss": 0.123, "records": 12, "gpu_count": 4},
              "serverIP": "192.0.2.10", "deployment_location": "private place",
              "log": "https://192.0.2.10:443/ and [2001:db8::1] in Beijing",
              "trace": "private-machine", "odd_key": {"value": "worker.example.net"}}
    redactor = Redactor(['private-machine'])
    output = redactor.clean(source)
    serialized = json.dumps(output)
    for value in ('192.0.2.10', '2001:db8::1', 'Beijing', 'private-machine', 'worker.example.net', 'private place'):
        assert value not in serialized
    assert output['custom_result'] == source['custom_result']
    assert source['serverIP'] == '192.0.2.10'


def test_credentials_control_characters_and_embedded_json():
    redactor = Redactor(['highly-private-secret'])
    report = {'log': '\x1b[31mpassword=highly-private-secret\x1b[0m https://user:pass@worker.example.net',
              'nested_json': json.dumps({'longitude': 120.2, 'custom': '192.0.2.9'}),
              '2001:db8::2': 'payload', '192.0.2.1/24': 'payload'}
    output = json.dumps(redactor.clean(report))
    assert 'highly-private-secret' not in output
    assert 'user:pass' not in output
    assert '120.2' not in output
    assert '192.0.2.' not in output
    assert '2001:db8' not in output


def test_address_alias_consistency_and_versions():
    output = Redactor().clean('Python 3.12.3; 192.0.2.1 then 192.0.2.1; ::1 and ::ffff:192.0.2.2')
    assert 'Python 3.12.3' in output
    assert output.count('[redacted-address-3]') == 2
    assert '::1' not in output
    assert '192.0.2.2' not in output


def test_traversal_rejected(tmp_path):
    with pytest.raises(ValueError):
        scoped_path(tmp_path, '../escape')
    (tmp_path / 'link').symlink_to('/tmp')
    with pytest.raises(ValueError):
        scoped_path(tmp_path, 'link/file')


@pytest.fixture
def worker(tmp_path):
    tmp_path.chmod(0o700)
    fake = tmp_path / 'fake-codex'
    fake.write_text('#!' + sys.executable + '\nimport json, pathlib, sys\n'
                    'prompt = sys.stdin.read()\n'
                    'pathlib.Path(sys.argv[sys.argv.index("-o") + 1]).write_text(json.dumps({"task_status": "succeeded", "report": json.dumps({"result": "done on 192.0.2.1", "metrics": {"rows": 9}}), "verification": "fake tool evidence"}))\n'
                    'pathlib.Path.cwd().parent.joinpath("remote-audit.jsonl").write_text(json.dumps({"success": True}) + "\\n")\n'
                    'print("PRIVATE LOG 192.0.2.1", file=sys.stderr)\n')
    fake.chmod(0o700)
    atomic_json(tmp_path / 'resources.json', {'codex_binary': str(fake), 'max_parallel': 1, 'resources': {'gpu-server': {'host': '192.0.2.1', 'credential_ref': 'login'}}})
    atomic_json(tmp_path / 'credentials.json', {'login': {'password': 'private-password'}})
    atomic_json(tmp_path / 'policy.json', {'sensitive_literals': ['hidden-place']})
    instance = Worker(tmp_path)
    yield instance
    for process in list(instance.processes.values()):
        instance.stop(process)
    instance.pool.shutdown(wait=True, cancel_futures=True)


def await_terminal(worker, task):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        state = worker.public({'method': 'get_task', 'arguments': {'task_id': task}})
        if state['status'] not in ('queued', 'running'):
            return state
        time.sleep(0.02)
    pytest.fail('task did not finish')


def test_flexible_task_lifecycle_filters_all_public_results(worker):
    submitted = worker.public({'method': 'submit_task', 'arguments': {'target': 'gpu-server', 'instruction': 'Analyze and export data', 'files': {'data/input.txt': 'unchanged 192.0.2.1'}}})
    identifier = submitted['job_id']
    assert await_terminal(worker, identifier)['status'] == 'completed'
    output = worker.public({'method': 'get_result', 'arguments': {'task_id': identifier}})
    assert '192.0.2.1' not in json.dumps(output)
    assert json.loads(output['report']['report'])['metrics']['rows'] == 9
    path = worker.job(identifier)
    assert (path / 'work/data/input.txt').read_text() == 'unchanged 192.0.2.1'
    assert '192.0.2.1' in (path / 'stderr.log').read_text()
    continued = worker.public({'method': 'continue_task', 'arguments': {'task_id': identifier, 'instruction': 'Now validate the export'}})
    assert continued['job_id'] != identifier
    assert await_terminal(worker, continued['job_id'])['status'] == 'completed'


def test_private_methods_and_policy_override_rejected(worker):
    for method in ('read_config', 'remote_exec', 'read_logs'):
        assert worker.public({'method': method}) == {'error_code': 'unknown_method'}
    for filename in ('../secret', '/tmp/secret', 'AGENTS.md', '.codex/config.toml'):
        output = worker.public({'method': 'submit_task', 'arguments': {'target': 'gpu-server', 'instruction': 'task', 'files': {filename: 'override'}}})
        assert output['error_code'] == 'invalid_file_path'
    assert worker.public({'method': 'get_task', 'arguments': {'task_id': '../../credentials.json'}}) == {'error_code': 'request_failed'}


def test_artifact_export_preserves_raw_and_holds_binary(worker):
    task = worker.submit('gpu-server', 'task')['job_id']
    await_terminal(worker, task)
    root = worker.job(task) / 'artifacts'
    root.mkdir(mode=0o700)
    text_id = 'artifact_' + 'a' * 24
    binary_id = 'artifact_' + 'b' * 24
    (root / text_id).write_text('value,endpoint\n9,192.0.2.1\n')
    (root / binary_id).write_bytes(b'\x00\xff')
    exported = worker.public({'method': 'get_artifact', 'arguments': {'task_id': task, 'artifact_id': text_id}})
    assert '192.0.2.1' not in exported['content']
    assert '192.0.2.1' in (root / text_id).read_text()
    assert worker.public({'method': 'get_artifact', 'arguments': {'task_id': task, 'artifact_id': binary_id}})['status'] == 'review_required'


def test_exceptions_never_return_original_content(worker, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError('private-password at 192.0.2.1 in hidden-place')
    monkeypatch.setattr(worker, 'dispatch', broken)
    assert worker.public({'method': 'list_resources'}) == {'error_code': 'request_failed'}


def test_success_without_remote_evidence_is_blocked(worker):
    fake = Path(worker.settings['codex_binary'])
    fake.write_text('#!' + sys.executable + '\nimport json, pathlib, sys\n'
                    'sys.stdin.read()\n'
                    'pathlib.Path(sys.argv[sys.argv.index("-o") + 1]).write_text(json.dumps({"task_status": "succeeded", "report": "all done", "verification": "no actual execution"}))\n')
    task = worker.submit('gpu-server', 'Check environment')['job_id']
    assert await_terminal(worker, task)['status'] == 'blocked'


def test_remote_source_auto_resolves_current_interface(monkeypatch):
    from codex_worker.remote import Remote
    seen = []
    class FakeSocket:
        def settimeout(self, value):
            pass
        def bind(self, address):
            seen.append(address)
        def connect(self, address):
            raise ConnectionRefusedError()
        def close(self):
            pass
    def command(arguments, **kwargs):
        if 'route' in arguments:
            return json.dumps([{'dst': 'default', 'dev': 'wifi-test', 'metric': 100}]).encode()
        return json.dumps([{'addr_info': [{'scope': 'global', 'local': '192.0.2.99'}]}]).encode()
    monkeypatch.setattr('codex_worker.remote.socket.socket', lambda *args: FakeSocket())
    monkeypatch.setattr('codex_worker.remote.subprocess.check_output', command)
    remote = Remote('/tmp', {'resources': {'gpu-server': {'source_interface': 'auto', 'host': '192.0.2.1', 'port': 22, 'credential_ref': 'login'}}}, {'login': {}}, 'gpu-server')
    with pytest.raises(ConnectionRefusedError):
        remote.connect()
    assert seen == [('192.0.2.99', 0)]
import asyncio
import concurrent.futures


def manual_task(worker, status='running'):
    identifier = 'job_' + 'c' * 24
    path = worker.jobs / identifier
    path.mkdir(mode=0o700)
    atomic_json(path / 'state.json', {'job_id': identifier, 'target': 'gpu-server',
                                     'status': status, 'created_at': time.time()})
    return identifier, path


@pytest.mark.parametrize('status', ['completed', 'partial', 'failed', 'blocked', 'cancelled', 'timed_out', 'interrupted'])
def test_wait_delivers_each_terminal_outcome_and_filtered_report(worker, status):
    identifier, path = manual_task(worker)
    atomic_json(path / 'final.txt', {'metrics': {'rows': 42},
                                   'detail': '192.0.2.1 hidden-place private-password'})
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as listeners:
        waits = [listeners.submit(worker.public, {'method': 'wait_for_task', 'arguments': {
            'task_id': identifier, 'timeout_seconds': 2}}) for _ in range(2)]
        worker.save_state(path, status=status)
        results = [future.result(timeout=3) for future in waits]
    for result in results:
        assert result['status'] == status
        assert result['report']['metrics'] == {'rows': 42}
        assert all(secret not in json.dumps(result) for secret in ('192.0.2.1', 'hidden-place', 'private-password'))
    assert worker.public({'method': 'wait_for_task', 'arguments': {'task_id': identifier}}) == results[0]


def test_wait_does_not_occupy_execution_pool_or_respond_to_other_job(worker):
    identifier, path = manual_task(worker)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as listeners:
        waiting = listeners.submit(worker.public, {'method': 'wait_for_task', 'arguments': {
            'task_id': identifier, 'timeout_seconds': 2}})
        task = worker.submit('gpu-server', 'Run unrelated work')['job_id']
        assert await_terminal(worker, task)['status'] == 'completed'
        assert not waiting.done()
        worker.save_state(path, status='partial')
        assert waiting.result(timeout=3)['status'] == 'partial'


def test_wait_timeout_cancel_invalid_input_and_recovery(worker):
    identifier, path = manual_task(worker)
    request = {'method': 'wait_for_task', 'arguments': {'task_id': identifier, 'timeout_seconds': 0}}
    assert worker.public(request)['status'] == 'running'
    for timeout in (-1, 21, True, float('nan'), float('inf'), '20'):
        request['arguments']['timeout_seconds'] = timeout
        assert worker.public(request) == {'error_code': 'invalid_wait_timeout'}
    assert worker.public({'method': 'wait_for_task', 'arguments': {'task_id': '../credentials.json'}}) == {'error_code': 'request_failed'}
    worker.public({'method': 'cancel_task', 'arguments': {'task_id': identifier}})
    request['arguments']['timeout_seconds'] = 1
    assert worker.public(request)['status'] == 'cancelled'
    worker.save_state(path, status='running')
    recovered = Worker(worker.private)
    try:
        assert recovered.public(request)['status'] == 'interrupted'
    finally:
        recovered.pool.shutdown()


def test_completion_client_heartbeats_and_retains_flexible_partial_report():
    from codex_worker.mcp_api import wait_for_completion
    class Progress:
        def __init__(self):
            self.messages = []
        async def report_progress(self, **message):
            self.messages.append(message)
    context = Progress()
    calls = []
    final = {'job_id': 'job_test', 'status': 'partial', 'report': {'custom_metrics': {'loss': 0.1}}}
    async def call(method, **arguments):
        calls.append((method, arguments))
        return {'job_id': 'job_test', 'status': 'running'} if len(calls) == 1 else final
    assert asyncio.run(wait_for_completion(call, 'job_test', context, 60)) == final
    assert len(context.messages) == 2
    assert all(method == 'wait_for_task' and args['timeout_seconds'] <= 20 for method, args in calls)


def test_completion_client_timeout_is_detach_and_validates_replies():
    from codex_worker import mcp_api
    class Progress:
        async def report_progress(self, **message):
            pass
    async def call(method, **arguments):
        await asyncio.sleep(1.01)
        return {'job_id': 'job_test', 'status': 'running'}
    result = asyncio.run(mcp_api.wait_for_completion(call, 'job_test', Progress(), 1))
    assert result['wait_status'] == 'timeout'
    assert result['task_cancelled'] is False
    async def invalid(method, **arguments):
        return {'unrecognized': True}
    invalid_result = asyncio.run(mcp_api.wait_for_completion(invalid, 'job_test', Progress(), 1))
    assert invalid_result['error_code'] == 'invalid_worker_response'
    assert invalid_result['task_cancelled'] is False
    assert asyncio.run(mcp_api.wait_for_completion(call, 'job_test', Progress(), 0)) == {'error_code': 'invalid_wait_timeout'}


def test_async_gateway_error_does_not_expose_socket_or_exception(tmp_path):
    from codex_worker.mcp_api import gateway_call
    result = asyncio.run(gateway_call(tmp_path / 'private-password', 'wait_for_task'))
    assert result == {'error_code': 'worker_unavailable'}


def test_public_mcp_wait_schema_and_cancellation_are_safe(monkeypatch):
    from codex_worker import mcp_api
    async def scenario():
        calls = []
        entered = asyncio.Event()
        async def gateway(socket_path, method, **arguments):
            calls.append(method)
            if method == 'wait_for_task':
                entered.set()
                await asyncio.Event().wait()
            return {'resources': ['gpu-server']}
        class Progress:
            async def report_progress(self, **message):
                pass
        monkeypatch.setattr(mcp_api, 'gateway_call', gateway)
        server = mcp_api.create_public_mcp('unused')
        tools = {tool.name: tool for tool in await server.list_tools()}
        assert 'wait_for_task' in tools
        assert 'ctx' not in tools['wait_for_task'].inputSchema['properties']
        assert tools['wait_for_task'].inputSchema['properties']['timeout_seconds']['default'] == 86400
        pending = asyncio.create_task(mcp_api.wait_for_completion(
            lambda method, **arguments: gateway('unused', method, **arguments), 'job_test', Progress(), 60))
        await entered.wait()
        assert await server.call_tool('list_resources', {})
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert 'cancel_task' not in calls
    asyncio.run(scenario())


def test_completion_over_real_stdio_and_service_socket(worker, tmp_path):
    from datetime import timedelta
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    fake = Path(worker.settings['codex_binary'])
    fake.write_text(fake.read_text().replace('prompt = sys.stdin.read()',
                                            'prompt = sys.stdin.read()\nimport time\ntime.sleep(0.5)'))
    socket_path = tmp_path / 'test.sock'
    process = subprocess.Popen([sys.executable, '-m', 'codex_worker.cli', 'serve',
                                '--private-dir', str(worker.private), '--socket', str(socket_path)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    async def scenario():
        deadline = time.monotonic() + 5
        while not socket_path.exists():
            if process.poll() is not None or time.monotonic() >= deadline:
                pytest.fail('isolated test service failed to start')
            await asyncio.sleep(0.02)
        parameters = StdioServerParameters(command=sys.executable,
            args=['-m', 'codex_worker.cli', 'mcp', '--socket', str(socket_path)])
        async with stdio_client(parameters) as (reader, writer):
            async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=10)) as session:
                initialized = await session.initialize()
                assert 'wait_for_task' in initialized.instructions
                submitted = await session.call_tool('submit_task', {'target': 'gpu-server', 'instruction': 'Analyze data'})
                assert not submitted.isError, submitted.model_dump_json()
                identifier = json.loads(submitted.content[0].text)['job_id']
                progress_seen = asyncio.Event()
                messages = []
                async def progress(value, total, message):
                    messages.append(message)
                    progress_seen.set()
                waiting = asyncio.create_task(session.call_tool('wait_for_task', {'task_id': identifier},
                                                                 progress_callback=progress))
                await asyncio.wait_for(progress_seen.wait(), timeout=3)
                resources = await session.call_tool('list_resources')
                assert json.loads(resources.content[0].text) == {'resources': ['gpu-server']}
                result = await waiting
                output = json.loads(result.content[0].text)
                assert output['status'] == 'completed'
                assert json.loads(output['report']['report'])['metrics']['rows'] == 9
                assert '192.0.2.1' not in result.model_dump_json()
                assert all('192.0.2.1' not in message for message in messages)
                repeated = await session.call_tool('wait_for_task', {'task_id': identifier})
                assert json.loads(repeated.content[0].text) == output

                # Exercise run_task and cancellation through the actual MCP
                # protocol, then recover with the compatible existing-ID tool.
                run_progress = asyncio.Event()
                run_messages = []
                async def announced(value, total, message):
                    run_messages.append(message)
                    run_progress.set()
                running = asyncio.create_task(session.call_tool('run_task', {
                    'target': 'gpu-server', 'instruction': 'Analyze data',
                    'files': {'input.txt': 'business input'}}, progress_callback=announced))
                await asyncio.wait_for(run_progress.wait(), timeout=3)
                from codex_worker.config import JOB_ID
                handle = run_messages[0].split('job_id=', 1)[1].split(';', 1)[0]
                assert JOB_ID.fullmatch(handle)
                assert handle != identifier
                listing = await session.call_tool('list_tasks', {'target': 'gpu-server', 'limit': 2})
                summaries = json.loads(listing.content[0].text)['tasks']
                assert {item['job_id'] for item in summaries} == {identifier, handle}
                assert all(set(item) <= {'job_id', 'target', 'status', 'created_at',
                                        'updated_at', 'started_at', 'finished_at'} for item in summaries)
                running.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await running
                recovered = await session.call_tool('wait_for_task', {'task_id': handle})
                assert json.loads(recovered.content[0].text)['status'] == 'completed'
                assert len(list(worker.jobs.glob('job_*'))) == 2
                invalid_limit = await session.call_tool('list_tasks', {'limit': True})
                assert invalid_limit.isError
                invalid_limit_text = await session.call_tool('list_tasks', {'limit': 'private input value'})
                assert invalid_limit_text.isError
                assert 'private input value' not in invalid_limit_text.model_dump_json()
                missing_instruction = await session.call_tool('run_task', {
                    'target': 'gpu-server', 'files': {'private-filename': 'private attachment'}})
                assert missing_instruction.isError
                assert 'private-filename' not in missing_instruction.model_dump_json()
                assert 'private attachment' not in missing_instruction.model_dump_json()
                invalid_run = await session.call_tool('run_task', {
                    'target': 'gpu-server', 'instruction': 'Must not submit', 'timeout_seconds': 0})
                assert json.loads(invalid_run.content[0].text) == {'error_code': 'invalid_wait_timeout'}
                invalid_run_type = await session.call_tool('run_task', {
                    'target': 'gpu-server', 'instruction': 'Must not submit', 'timeout_seconds': True})
                assert invalid_run_type.isError
                assert len(list(worker.jobs.glob('job_*'))) == 2

                completed = await session.call_tool('run_task', {
                    'target': 'gpu-server', 'instruction': 'Analyze data'})
                assert not completed.isError
                final = json.loads(completed.content[0].text)
                assert final['status'] == 'completed'
                assert json.loads(final['report']['report'])['metrics'] == {'rows': 9}
                assert final['job_id'] not in {identifier, handle}
                assert '192.0.2.1' not in completed.model_dump_json()
                # A second authorized MCP session has the same task scope.
                async with stdio_client(parameters) as (peer_reader, peer_writer):
                    async with ClientSession(peer_reader, peer_writer,
                            read_timeout_seconds=timedelta(seconds=10)) as peer:
                        await peer.initialize()
                        shared = await peer.call_tool('list_tasks', {'limit': 3})
                        assert {item['job_id'] for item in json.loads(shared.content[0].text)['tasks']} == {
                            identifier, handle, final['job_id']}
    try:
        asyncio.run(scenario())
    finally:
        process.terminate()
        process.wait(timeout=10)


class RecordingProgress:
    def __init__(self):
        self.messages = []

    async def report_progress(self, **message):
        self.messages.append(message)


def test_run_cancellation_during_submission_preserves_handle_and_work(worker):
    from codex_worker.mcp_api import run_and_wait, wait_for_completion

    async def scenario():
        submitted = asyncio.Event()
        acknowledge = asyncio.Event()
        calls = []
        context = RecordingProgress()

        async def call(method, **arguments):
            calls.append(method)
            result = await asyncio.to_thread(worker.public, {'method': method, 'arguments': arguments})
            if method == 'submit_task':
                submitted.set()
                await acknowledge.wait()
            return result

        running = asyncio.create_task(run_and_wait(call, 'gpu-server', 'Flexible task',
            {'input.txt': 'unchanged business data'}, context, 60))
        await submitted.wait()
        running.cancel()
        await asyncio.sleep(0)
        acknowledge.set()
        with pytest.raises(asyncio.CancelledError):
            await running
        assert calls == ['submit_task']
        identifier = worker.public({'method': 'list_tasks'})['tasks'][0]['job_id']
        assert identifier in context.messages[0]['message']
        recovered = await wait_for_completion(call, identifier, context, 60)
        assert recovered['status'] == 'completed'
        assert json.loads(recovered['report']['report'])['metrics'] == {'rows': 9}
        assert '192.0.2.1' not in json.dumps(recovered)
        assert (worker.job(identifier) / 'work/input.txt').read_text() == 'unchanged business data'
        assert 'cancel_task' not in calls
        assert calls.count('submit_task') == 1
    asyncio.run(scenario())


@pytest.mark.parametrize('failure', ['gateway_error', 'exception', 'invalid', 'wrong_terminal', 'progress', 'timeout'])
def test_run_post_submission_failures_always_keep_handle(failure):
    from codex_worker.mcp_api import run_and_wait
    identifier = 'job_' + 'd' * 24
    calls = []

    class Progress(RecordingProgress):
        async def report_progress(self, **message):
            if failure == 'progress':
                raise RuntimeError('private exception must stay private')
            await super().report_progress(**message)

    async def call(method, **arguments):
        calls.append(method)
        if method == 'submit_task':
            return {'job_id': identifier, 'status': 'queued'}
        if failure == 'gateway_error':
            return {'error_code': 'worker_unavailable'}
        if failure == 'exception':
            raise RuntimeError('private exception must stay private')
        if failure == 'invalid':
            return ['invalid response']
        if failure == 'wrong_terminal':
            return {'job_id': 'job_' + 'e' * 24, 'status': 'completed', 'report': 'wrong job'}
        if failure == 'timeout':
            await asyncio.sleep(10)
        raise AssertionError('unexpected call')

    result = asyncio.run(run_and_wait(call, 'gpu-server', 'Execute once', None, Progress(), 1))
    assert result['job_id'] == identifier
    assert result['task_cancelled'] is False
    assert 'wait_for_task' in result['next_action']
    assert 'status' not in result
    assert 'private exception' not in json.dumps(result)
    assert calls.count('submit_task') == 1
    assert 'cancel_task' not in calls
    if failure == 'timeout':
        assert result['wait_status'] == 'timeout'


@pytest.mark.parametrize('timeout', [0, -1, 604801, True, 1.5, '60', None])
def test_run_invalid_wait_does_not_submit(timeout):
    from codex_worker.mcp_api import run_and_wait
    async def call(*args, **kwargs):
        pytest.fail('invalid timeout must not create work')
    result = asyncio.run(run_and_wait(call, 'gpu-server', 'task', None, RecordingProgress(), timeout))
    assert result == {'error_code': 'invalid_wait_timeout'}


def test_run_ambiguous_acknowledgement_never_resubmits():
    from codex_worker.mcp_api import run_and_wait
    calls = []
    async def call(method, **arguments):
        calls.append(method)
        return {'error_code': 'worker_unavailable'}
    result = asyncio.run(run_and_wait(call, 'gpu-server', 'task', None, RecordingProgress(), 60))
    assert calls == ['submit_task']
    assert result['error_code'] == 'submission_unconfirmed'
    assert 'list_tasks' in result['next_action']
    assert 'job_id' not in result


def test_lost_submission_acknowledgement_recovers_from_listing(worker):
    from codex_worker.mcp_api import run_and_wait, wait_for_completion
    calls = []
    async def call(method, **arguments):
        calls.append(method)
        result = await asyncio.to_thread(worker.public, {'method': method, 'arguments': arguments})
        return {'error_code': 'worker_unavailable'} if method == 'submit_task' else result
    result = asyncio.run(run_and_wait(call, 'gpu-server', 'Task with a lost acknowledgement',
                                      None, RecordingProgress(), 60))
    assert result['submission_status'] == 'unconfirmed'
    listing = worker.public({'method': 'list_tasks', 'arguments': {'target': 'gpu-server'}})['tasks']
    assert len(listing) == 1
    recovered = asyncio.run(wait_for_completion(call, listing[0]['job_id'], RecordingProgress(), 60))
    assert recovered['status'] == 'completed'
    assert calls == ['submit_task', 'wait_for_task']


@pytest.mark.parametrize('status', ['completed', 'partial', 'blocked', 'failed', 'timed_out', 'interrupted', 'cancelled'])
def test_run_uses_existing_filtered_terminal_report(worker, status):
    from codex_worker.mcp_api import run_and_wait
    identifier, path = manual_task(worker, status)
    atomic_json(path / 'final.txt', {'arbitrary': {'business': [1, 2], 'metric': 0.125},
                                   'detail': 'hidden-place private-password'})
    calls = []
    async def call(method, **arguments):
        calls.append(method)
        if method == 'submit_task':
            assert arguments['instruction'] == 'Anything the user needs'
            assert arguments['files'] == {'input.txt': 'original text'}
            return {'job_id': identifier, 'status': 'queued'}
        return await asyncio.to_thread(worker.public, {'method': method, 'arguments': arguments})
    result = asyncio.run(run_and_wait(call, 'gpu-server', 'Anything the user needs',
        {'input.txt': 'original text'}, RecordingProgress(), 60))
    assert result == worker.public({'method': 'get_result', 'arguments': {'task_id': identifier}})
    assert result['status'] == status
    assert result['report']['arbitrary'] == {'business': [1, 2], 'metric': 0.125}
    assert all(value not in json.dumps(result) for value in ('hidden-place', 'private-password'))
    assert calls == ['submit_task', 'wait_for_task']


def test_list_tasks_is_bounded_filtered_and_strictly_metadata_only(worker, monkeypatch):
    from codex_worker import service
    worker.settings['resources']['other'] = worker.settings['resources']['gpu-server']
    for index in range(105):
        identifier = f'job_{index:024x}'
        path = worker.jobs / identifier
        path.mkdir(mode=0o700)
        atomic_json(path / 'state.json', {'job_id': 'untrusted identifier',
            'target': 'other' if index % 2 else 'gpu-server',
            'status': 'completed' if index % 3 else 'running', 'created_at': index,
            'updated_at': index + 1, 'finished_at': 'private timestamp', 'started_at': float('nan'),
            'instruction': 'private task text', 'report': 'private report',
            'raw_log': 'private log', 'credentials': 'private authentication',
            'config': {'internal': 'private config'}})
        atomic_json(path / 'request.json', {'instruction': 'private task text'})
    original_read = service.read_private
    def state_only(path):
        assert path.name == 'state.json'
        return original_read(path)
    monkeypatch.setattr(service, 'read_private', state_only)
    default = worker.public({'method': 'list_tasks'})['tasks']
    assert len(default) == 20
    assert [item['created_at'] for item in default] == list(range(104, 84, -1))
    assert len(worker.public({'method': 'list_tasks', 'arguments': {'limit': 100}})['tasks']) == 100
    filtered = worker.public({'method': 'list_tasks', 'arguments': {
        'target': 'gpu-server', 'status': 'running', 'limit': 3}})['tasks']
    assert [item['created_at'] for item in filtered] == [102, 96, 90]
    assert all(set(item) == {'job_id', 'target', 'status', 'created_at', 'updated_at'} for item in default)
    assert default[0]['job_id'] == f'job_{104:024x}'
    assert 'private' not in json.dumps(default)


@pytest.mark.parametrize('limit', [0, -1, 101, True, False, 1.0, '20', None, float('nan'), float('inf')])
def test_list_tasks_rejects_invalid_limits(worker, limit):
    assert worker.public({'method': 'list_tasks', 'arguments': {'limit': limit}}) == {'error_code': 'invalid_task_limit'}


def test_list_tasks_rejects_unsafe_filters_and_tolerates_damaged_history(worker):
    identifier, path = manual_task(worker, 'interrupted')
    damaged = worker.jobs / ('job_' + 'b' * 24)
    damaged.mkdir(mode=0o700)
    (damaged / 'state.json').write_text('not JSON')
    (damaged / 'state.json').chmod(0o600)
    for target in ('unknown private target', [], {}):
        assert worker.public({'method': 'list_tasks', 'arguments': {'target': target}}) == {'error_code': 'unknown_resource'}
    for status in ('unknown private status', [], {}):
        assert worker.public({'method': 'list_tasks', 'arguments': {'status': status}}) == {'error_code': 'invalid_task_status'}
    result = worker.public({'method': 'list_tasks', 'arguments': {'status': 'interrupted', 'limit': 1}})
    assert result['tasks'] == [{'job_id': identifier, 'target': 'gpu-server', 'status': 'interrupted',
                               'created_at': json.loads((path / 'state.json').read_text())['created_at']}]


def test_created_handle_survives_scheduling_and_public_filter_errors(worker, monkeypatch):
    from codex_worker import service
    def broken(*args, **kwargs):
        raise RuntimeError('private scheduling detail')
    with monkeypatch.context() as patch:
        patch.setattr(worker.pool, 'submit', broken)
        scheduled = worker.public({'method': 'submit_task', 'arguments': {
            'target': 'gpu-server', 'instruction': 'task'}})
    assert scheduled['status'] == 'failed'
    assert scheduled['error_code'] == 'execution_failed'
    assert worker.job(scheduled['job_id']).exists()
    with monkeypatch.context() as patch:
        patch.setattr(service, 'make_redactor', broken)
        filtered = worker.public({'method': 'submit_task', 'arguments': {
            'target': 'gpu-server', 'instruction': 'another task'}})
    assert set(filtered) == {'job_id', 'error_code'}
    assert filtered['error_code'] == 'request_failed'
    assert await_terminal(worker, filtered['job_id'])['status'] == 'completed'


def test_run_attaches_after_acknowledged_submission_error():
    from codex_worker.mcp_api import run_and_wait
    identifier = 'job_' + 'f' * 24
    calls = []
    final = {'job_id': identifier, 'status': 'failed', 'error_code': 'report_unavailable', 'artifacts': []}
    async def call(method, **arguments):
        calls.append(method)
        if method == 'submit_task':
            return {'job_id': identifier, 'error_code': 'request_failed'}
        return final
    assert asyncio.run(run_and_wait(call, 'gpu-server', 'task', None, RecordingProgress(), 60)) == final
    assert calls == ['submit_task', 'wait_for_task']


@pytest.mark.parametrize('status', ['queued', 'running', 'completed', 'partial', 'blocked',
                                   'failed', 'timed_out', 'interrupted', 'cancelled', 'unknown', None])
def test_admin_update_idle_check_refuses_active_or_unknown_state(tmp_path, status):
    # Run only the script's actual read-only preflight, against synthetic local
    # history. Do not execute the privileged deployment script or service calls.
    script = Path('scripts/update-isolated.sh').read_text()
    check = script.split('check_idle() {', 1)[1].split("<<'PY'\n", 1)[1].split('\nPY', 1)[0]
    history = tmp_path / 'jobs'
    job = history / ('job_' + 'a' * 24)
    job.mkdir(parents=True)
    atomic_json(job / 'state.json', {'status': status})
    result = subprocess.run([sys.executable, '-c', check, str(history)], capture_output=True, text=True)
    terminal = {'completed', 'partial', 'blocked', 'failed', 'timed_out', 'interrupted', 'cancelled'}
    assert (result.returncode == 0) == (status in terminal)
    assert str(history) not in result.stdout + result.stderr
    assert json.loads((job / 'state.json').read_text()) == {'status': status}


def test_admin_update_idle_check_fails_closed_without_raw_errors(tmp_path):
    script = Path('scripts/update-isolated.sh').read_text()
    check = script.split('check_idle() {', 1)[1].split("<<'PY'\n", 1)[1].split('\nPY', 1)[0]
    job = tmp_path / ('job_' + 'a' * 24)
    job.mkdir()
    (job / 'state.json').write_text('private invalid history')
    result = subprocess.run([sys.executable, '-c', check, str(tmp_path)], capture_output=True, text=True)
    assert result.returncode != 0
    assert result.stderr.strip() == 'Task history could not be checked; refusing the update.'
    assert not result.stdout


def test_new_public_schemas_preserve_compatible_tools_and_hide_context():
    from codex_worker.mcp_api import create_public_mcp
    async def scenario():
        server = create_public_mcp('unused')
        tools = {tool.name: tool for tool in await server.list_tools()}
        assert set(tools) == {'run_task', 'list_tasks', 'list_resources', 'submit_task',
                             'get_task', 'get_result', 'wait_for_task', 'continue_task',
                             'cancel_task', 'get_artifact'}
        assert 'ctx' not in tools['run_task'].inputSchema['properties']
        assert tools['run_task'].inputSchema['required'] == ['target', 'instruction']
        assert tools['run_task'].inputSchema['properties']['timeout_seconds']['default'] == 86400
        assert tools['list_tasks'].inputSchema['properties']['limit']['default'] == 20
        assert tools['list_tasks'].inputSchema['properties']['limit']['minimum'] == 1
        assert tools['list_tasks'].inputSchema['properties']['limit']['maximum'] == 100
        assert 'Prefer run_task for new work' in server.instructions
        assert 'without session isolation' in server.instructions
    asyncio.run(scenario())
