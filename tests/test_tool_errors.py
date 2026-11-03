import asyncio
import json

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from codex_worker import mcp_api
from codex_worker.attachments import stage_inputs

SECRET = 'private-input-value'


def call(monkeypatch, tool, arguments):
    calls = []

    async def gateway(socket_path, method, **forwarded):
        calls.append((method, forwarded))
        return {'job_id': 'job_' + 'a' * 24, 'status': 'completed'}
    monkeypatch.setattr(mcp_api, 'gateway_call', gateway)
    monkeypatch.setattr(mcp_api, 'stage_inputs', lambda socket, attachments: {'input_id': 'input_' + 'b' * 24})
    server = mcp_api.create_public_mcp('unused')
    try:
        result = asyncio.run(server.call_tool(tool, arguments))
    except ToolError as error:
        return json.loads(str(error)), calls
    return result, calls


@pytest.mark.parametrize('tool, arguments, expected', [
    ('submit_task', {'target': 'example-server', 'instruction': 'x', 'attachments': [{'source': '/' + SECRET}]},
     {'field': 'attachments', 'index': 0, 'reason': 'item_must_have_source_and_path'}),
    ('submit_task', {'target': 'example-server', 'instruction': 'x', 'attachments': [{'source': '/a', 'path': 'b', SECRET: 'v'}]},
     {'field': 'attachments', 'index': 0, 'reason': 'item_keys_must_be_source_path_list_file'}),
    ('run_task', {'target': 'example-server', 'instruction': 'x', 'attachments': {'source': SECRET, 'path': 'b'}},
     {'field': 'attachments', 'reason': 'must_be_list'}),
    ('run_task', {'target': 'example-server', 'instruction': 'x', 'attachments': [SECRET]},
     {'field': 'attachments', 'index': 0, 'reason': 'item_must_be_object'}),
    ('run_task', {'target': 'example-server', 'files': {SECRET: SECRET}}, {'field': 'instruction', 'reason': 'required'}),
    ('list_tasks', {'limit': SECRET}, {'field': 'limit', 'reason': 'must_be_integer'}),
    ('submit_task', {'target': 'example-server', 'instruction': 'x', 'timeout_seconds': 604801},
     {'field': 'timeout_seconds', 'reason': 'above_maximum'}),
])
def test_validation_errors_name_field_and_reason_without_input(monkeypatch, tool, arguments, expected):
    error, calls = call(monkeypatch, tool, arguments)
    assert error == {'error_code': 'invalid_tool_request', **expected}
    assert SECRET not in json.dumps(error)
    assert not calls


def test_run_task_accepts_attachments_with_optional_list_file_and_task_timeout(monkeypatch):
    result, calls = call(monkeypatch, 'run_task', {
        'target': 'example-server', 'instruction': 'x', 'task_timeout_seconds': 120,
        'attachments': [{'source': '/a', 'path': 'b', 'list_file': None}]})
    # Outside a real session the progress context is absent; the call still
    # validated and submitted exactly once with the forwarded values.
    assert 'job_' + 'a' * 24 in result[0].text
    assert calls[0][0] == 'submit_task'
    assert calls[0][1]['timeout_seconds'] == 120
    assert calls[0][1]['input_id'] == 'input_' + 'b' * 24


def test_tool_schemas_document_attachment_shape():
    async def scenario():
        tools = {tool.name: tool for tool in await mcp_api.create_public_mcp('unused').list_tools()}
        for name in ('run_task', 'submit_task', 'continue_task'):
            assert 'list_file?' in tools[name].description or 'same format' in tools[name].description
            schema = json.dumps(tools[name].inputSchema)
            assert '"required": ["source", "path"]' in schema
    asyncio.run(scenario())


def test_caller_side_attachment_reasons_are_fixed(tmp_path):
    (tmp_path / SECRET).write_text('x')
    cases = [([], 'must_be_non_empty_list'),
             ([{'source': 'relative/' + SECRET, 'path': 'a'}], 'source_must_be_absolute'),
             ([{'source': str(tmp_path / 'missing'), 'path': 'a'}], 'source_not_found'),
             ([{'source': str(tmp_path / SECRET), 'path': '../' + SECRET}], 'path_must_be_workspace_relative_and_not_reserved'),
             ([{'source': str(tmp_path / SECRET), 'path': 'AGENTS.md'}], 'path_must_be_workspace_relative_and_not_reserved'),
             ([{'source': str(tmp_path / SECRET), 'path': 'a', 'list_file': str(tmp_path / SECRET)}], 'list_file_requires_directory_source')]
    for attachments, reason in cases:
        result = stage_inputs(tmp_path / 'no.sock', attachments)
        assert result['error_code'] == 'invalid_attachments'
        assert result['field'] == 'attachments' and result['reason'] == reason
        assert SECRET not in json.dumps(result)
    assert stage_inputs(tmp_path / 'no.sock', [{'source': str(tmp_path / SECRET), 'path': 'a'}]) == {
        'error_code': 'attachment_transfer_failed'}
