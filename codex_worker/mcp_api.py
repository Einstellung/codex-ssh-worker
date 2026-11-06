import asyncio
import json
import re
import time
import uuid
from typing import Annotated

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import ConfigDict, Field, ValidationError
from typing_extensions import NotRequired, TypedDict

from .attachments import save_artifact, stage_inputs
from .config import JOB_ID, load_settings
from .remote import BinaryFileError, Remote
from .questions import ask


TERMINAL = {"completed", "failed", "blocked", "partial", "cancelled", "timed_out", "interrupted"}
WAIT_SLICE_SECONDS = 20
RECOVER = "Call wait_for_task with the same task_id. Do not resubmit the work."


MAX_TASK_SECONDS = 604800
TaskTimeout = Annotated[int | None, Field(strict=True, ge=1, le=MAX_TASK_SECONDS)]


class Attachment(TypedDict):
    """One caller file or directory to copy into the task workspace."""
    __pydantic_config__ = ConfigDict(extra="forbid")
    source: Annotated[str, Field(description="Absolute caller-local path of a file or directory.")]
    path: Annotated[str, Field(description="Workspace-relative destination, e.g. data/input.bin.")]
    list_file: NotRequired[Annotated[str | None, Field(
        description="Optional absolute caller-local UTF-8 file listing relative members of a directory source.")]]


# Pydantic error types mapped to fixed reasons. Nothing from the input value,
# and no nested key name (which could be caller data), ever reaches the reply.
REASONS = {"missing": "required", "string_type": "must_be_string", "int_type": "must_be_integer",
           "int_parsing": "must_be_integer", "int_from_float": "must_be_integer",
           "bool_type": "must_be_boolean", "list_type": "must_be_list", "dict_type": "must_be_object",
           "greater_than_equal": "below_minimum", "less_than_equal": "above_maximum",
           "extra_forbidden": "unexpected_key", "json_invalid": "invalid_json"}


def validation_reason(tool, error):
    parameters = set(tool.parameters.get("properties", {})) if tool is not None else set()
    details = error.errors(include_url=False, include_input=False, include_context=False)
    if not details:
        return {"error_code": "invalid_tool_request", "reason": "invalid_arguments"}
    first = details[0]
    location = [part for part in first.get("loc", ()) if part != "arguments"]
    reason = REASONS.get(first.get("type"), "invalid_value")
    result = {"error_code": "invalid_tool_request", "reason": reason}
    if location and isinstance(location[0], str) and location[0] in parameters:
        result["field"] = location[0]
        if location[0] == "attachments" and len(location) > 1:
            if isinstance(location[1], int):
                result["index"] = location[1]
            if reason == "unexpected_key":
                result["reason"] = "item_keys_must_be_source_path_list_file"
            elif reason == "required":
                result["reason"] = "item_must_have_source_and_path"
            elif len(location) == 2:
                result["reason"] = "item_must_be_object"
            else:
                result["reason"] = "item_values_must_be_strings"
    return result


class PublicMCP(FastMCP):
    async def call_tool(self, name, arguments):
        tool = self._tool_manager.get_tool(name)
        if tool is None:
            raise ToolError(json.dumps({"error_code": "invalid_tool_request", "reason": "unknown_tool"}))
        try:
            return await super().call_tool(name, arguments)
        except Exception as error:
            # SDK validation errors can echo entire instructions or attachments,
            # so only fixed reason codes and declared parameter names leave here.
            cause = error.__cause__ if isinstance(error.__cause__, ValidationError) else None
            if cause is None and isinstance(error, ValidationError):
                cause = error
            detail = validation_reason(tool, cause) if cause is not None else {
                "error_code": "invalid_tool_request", "reason": "tool_failed"}
            raise ToolError(json.dumps(detail)) from None


def detached(task_id, **details):
    result = {**details, "task_cancelled": False, "next_action": RECOVER}
    if isinstance(task_id, str) and JOB_ID.fullmatch(task_id):
        result["job_id"] = task_id
    return result


def job_progress(task_id):
    # Only worker-generated opaque IDs may enter progress messages.
    if isinstance(task_id, str) and JOB_ID.fullmatch(task_id):
        return f"Delegated task job_id={task_id}; execution continues independently."
    return "Waiting for delegated task; execution continues independently."


async def gateway_call(socket_path, method, **arguments):
    writer = None
    try:
        async with asyncio.timeout(30):
            reader, writer = await asyncio.open_unix_connection(str(socket_path), limit=4 * 1024 * 1024 + 1)
            writer.write(json.dumps({"method": method, "arguments": arguments}).encode() + b"\n")
            await writer.drain()
            raw = await reader.readline()
            if len(raw) > 4 * 1024 * 1024:
                return {"error_code": "response_limit"}
            result = json.loads(raw)
            return result if isinstance(result, dict) else {"error_code": "invalid_worker_response"}
    except Exception:
        return {"error_code": "worker_unavailable"}
    finally:
        if writer is not None:
            writer.close()


async def wait_for_completion(call, task_id, context, timeout_seconds):
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 604800:
        return {"error_code": "invalid_wait_timeout"}
    started = time.monotonic()
    deadline = started + timeout_seconds
    try:
        await context.report_progress(progress=0, message=job_progress(task_id))
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return detached(task_id, wait_status="timeout")
            async with asyncio.timeout(remaining):
                result = await call("wait_for_task", task_id=task_id, timeout_seconds=min(WAIT_SLICE_SECONDS, remaining))
            if not isinstance(result, dict):
                return detached(task_id, error_code="invalid_worker_response")
            if result.get("job_id", task_id) != task_id:
                return detached(task_id, error_code="invalid_worker_response")
            if result.get("status") in TERMINAL and result.get("job_id") == task_id:
                return result
            if result.get("status") == "waiting_for_input" and result.get("job_id") == task_id:
                return result
            if "error_code" in result:
                return detached(task_id, error_code=result["error_code"])
            if result.get("job_id") != task_id or result.get("status") not in {"queued", "running"}:
                return detached(task_id, error_code="invalid_worker_response")
            await context.report_progress(progress=time.monotonic() - started,
                                          message=job_progress(task_id))
    except TimeoutError:
        return detached(task_id, wait_status="timeout")
    except Exception:
        # Cancellation propagates; a lost listener must never cancel execution.
        return detached(task_id, error_code="wait_failed")


async def run_and_wait(call, target, instruction, files, context, timeout_seconds, input_id=None,
                       task_timeout_seconds=None):
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 604800:
        return {"error_code": "invalid_wait_timeout"}

    async def submit_and_announce():
        arguments = {"target": target, "instruction": instruction, "files": files}
        if input_id is not None:
            arguments["input_id"] = input_id
        if task_timeout_seconds is not None:
            arguments["timeout_seconds"] = task_timeout_seconds
        result = await call("submit_task", **arguments)
        identifier = result.get("job_id") if isinstance(result, dict) else None
        if isinstance(identifier, str) and JOB_ID.fullmatch(identifier):
            try:
                await context.report_progress(progress=0, message=job_progress(identifier))
            except Exception:
                pass  # The final response can still carry the acknowledged handle.
        return result

    # Finish the one submission and attempt to publish its handle even if the
    # caller detaches during the acknowledgement. Never repeat the submission.
    submission = asyncio.create_task(submit_and_announce())
    try:
        result = await asyncio.shield(submission)
    except asyncio.CancelledError:
        try:
            await asyncio.shield(submission)
        except Exception:
            pass
        raise
    except Exception:
        result = {"error_code": "worker_unavailable"}
    identifier = result.get("job_id") if isinstance(result, dict) else None
    if isinstance(identifier, str) and JOB_ID.fullmatch(identifier):
        return await wait_for_completion(call, identifier, context, timeout_seconds)
    if isinstance(result, dict) and isinstance(result.get("error_code"), str) and result["error_code"] not in {
        None, "worker_unavailable", "invalid_worker_response", "response_limit", "request_failed"
    }:
        return result
    return {"error_code": "submission_unconfirmed", "submission_status": "unconfirmed",
            "next_action": "Use list_tasks to recover the job_id; submission may have succeeded. Do not automatically resubmit."}


async def file_operation(function, context, *arguments):
    """Keep progress alive while copying bytes outside the model context."""
    pending = asyncio.create_task(asyncio.to_thread(function, *arguments))
    try:
        while True:
            done, _ = await asyncio.wait({pending}, timeout=20)
            if done:
                return pending.result()
            if context is not None:
                await context.report_progress(progress=0, message="Transferring or checking task files.")
    finally:
        # A cancelled listener must not submit work. Its in-flight local copy
        # may finish and leave a private, unclaimed input bundle.
        if not pending.done():
            pending.add_done_callback(lambda task: task.exception() if not task.cancelled() else None)


def create_public_mcp(socket_path):
    mcp = PublicMCP("codex-worker", instructions="Delegate arbitrary execution tasks to a logical resource. Prefer run_task for new work: it submits once and waits for the filtered terminal report. For an existing job_id, call wait_for_task once with it as task_id; do not poll or resubmit. Use list_tasks to recover missing IDs; authorized clients of the same socket share tasks, without session isolation. After submit_task or continue_task, attach with wait_for_task. Call long waits from the main conversation so the host can background them when supported; this is not native MCP Tasks or unsolicited push. partial, blocked, failed, timed_out, interrupted, and cancelled are terminal outcomes, not successful completion. When run_task or wait_for_task returns waiting_for_input, present the filtered question to the user if their decision is needed, call answer_question with its job_id and question_id, then call wait_for_task on the same job. Do not invent approval. Never automatically retry side-effecting work or suppress intentional reruns. Do not request infrastructure identity, private worker configuration, or deployment locations. Resource environment and software capabilities may be queried. Raw logs are not exposed. Cancelling a wait only stops waiting; cancel_task stops the local agent, not necessarily remote background processes." + " This is a general-purpose Codex agent, not a catalogue of business-specific actions. Attach caller files using attachments=[{source: absolute local path, path: workspace-relative destination, list_file?: absolute local list file}] on run_task, submit_task or continue_task. Directories are recursive; optional list_file is a caller-local UTF-8 list of relative files to include. These bytes travel directly to the worker, outside the model context. Use existing run_task/submit_task/continue_task for any authorized coding, analysis or execution work. To retrieve an original binary or large deliverable, call get_artifact with an absolute caller-local destination; sensitive artifacts are held. Do not ask for private server addresses or attempt reverse connections to transfer files.")

    async def call(method, **arguments):
        return await gateway_call(socket_path, method, **arguments)

    async def inputs(attachments, context=None):
        if attachments is None:
            return {}
        return await file_operation(stage_inputs, context, socket_path, attachments)


    @mcp.tool()
    async def list_resources() -> dict:
        """List logical execution resources without connection information."""
        return await call("list_resources")

    @mcp.tool()
    async def run_task(target: str, instruction: str, ctx: Context, files: dict[str, str] | None = None,
                       timeout_seconds: Annotated[int, Field(strict=True)] = 86400,
                       attachments: list[Attachment] | None = None,
                       task_timeout_seconds: TaskTimeout = None) -> dict:
        """Preferred for new free-form work: submit once, publish the opaque job_id, then wait for its filtered report or waiting_for_input question. Parameters: target is a logical resource name from list_resources; instruction is free text; files is an optional object of workspace-relative path -> UTF-8 text; attachments is an optional list [{source: absolute caller-local path, path: workspace-relative destination, list_file?: absolute caller-local UTF-8 list of relative members (directory sources only)}], copied as real bytes outside the model context. timeout_seconds bounds only this wait (integer seconds, default 24 hours, maximum 7 days); task_timeout_seconds is the optional execution limit after which the task is stopped (integer 1-604800, default from worker settings). Timeout/cancellation of the wait only detaches; recover with wait_for_task or list_tasks, never automatic resubmission. Host call limits still apply. Validation errors return a fixed error_code, field and reason, never your input."""
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 604800:
            return {"error_code": "invalid_wait_timeout"}
        staged = await inputs(attachments, ctx)
        if "error_code" in staged:
            return staged
        return await run_and_wait(call, target, instruction, files, ctx, timeout_seconds, staged.get("input_id"),
                                  task_timeout_seconds)

    @mcp.tool()
    async def list_tasks(target: str | None = None, status: str | None = None,
                         limit: Annotated[int, Field(strict=True, ge=1, le=100)] = 20) -> dict:
        """Recover recent task IDs, newest first (limit 1–100). Optional exact logical target and status filters. Only IDs, logical targets, statuses and timestamps; no instructions or logs. All authorized clients of this socket share the same task scope, without session isolation."""
        return await call("list_tasks", target=target, status=status, limit=limit)

    @mcp.tool()
    async def submit_task(target: str, instruction: str, files: dict[str, str] | None = None,
                          attachments: list[Attachment] | None = None,
                          timeout_seconds: TaskTimeout = None) -> dict:
        """Submit arbitrary work, returning immediately. Next call wait_for_task with job_id; do not poll. Inputs are unchanged. Parameters: target is a logical resource name from list_resources; instruction is free text; files is an optional object of workspace-relative path -> UTF-8 text; attachments is an optional list [{source: absolute caller-local path, path: workspace-relative destination, list_file?: absolute caller-local UTF-8 list of relative members (directory sources only)}], copied as real bytes outside the model context. timeout_seconds is the optional execution limit (integer 1-604800, default from worker settings); the task is stopped and reported timed_out when it expires."""
        staged = await inputs(attachments)
        if "error_code" in staged:
            return staged
        arguments = {"target": target, "instruction": instruction, "files": files}
        if timeout_seconds is not None:
            arguments["timeout_seconds"] = timeout_seconds
        if "input_id" in staged:
            arguments["input_id"] = staged["input_id"]
        return await call("submit_task", **arguments)

    @mcp.tool()
    async def get_task(task_id: str) -> dict:
        """Get durable task state for a job_id: status, timestamps, and progress (the agent's own filtered short progress note, with progress_updated_at) when available. Raw logs remain private."""
        return await call("get_task", task_id=task_id)

    @mcp.tool()
    async def get_result(task_id: str) -> dict:
        """Get a filtered report and opaque artifact IDs. A completed agent is not proof of remote-job completion."""
        return await call("get_result", task_id=task_id)

    @mcp.tool()
    async def wait_for_task(task_id: str, ctx: Context, timeout_seconds: int = 86400) -> dict:
        """Attach to a submitted task until a filtered terminal report or waiting_for_input question. For a question call answer_question, then wait again on this task. Claude Code can background this main-conversation call. Sends safe heartbeats, not raw logs. Timeout/cancellation detaches only; reconnect with the same task_id, never resubmit automatically. Default wait 24 hours, maximum 7 days; client call limits still apply."""
        return await wait_for_completion(call, task_id, ctx, timeout_seconds)

    @mcp.tool()
    async def answer_question(task_id: str, question_id: str, answer: str) -> dict:
        """Answer the pending question in the same task, then call wait_for_task again. Do not assume user approval."""
        return await call("answer_question", task_id=task_id, question_id=question_id, answer=answer)

    @mcp.tool()
    async def continue_task(task_id: str, instruction: str, files: dict[str, str] | None = None,
                            attachments: list[Attachment] | None = None,
                            timeout_seconds: TaskTimeout = None) -> dict:
        """Create a follow-up of a finished task with its prior private report and a new workspace. Next call wait_for_task with its new job_id. task_id is a job_id; files, attachments and timeout_seconds have the same format as submit_task."""
        staged = await inputs(attachments)
        if "error_code" in staged:
            return staged
        arguments = {"task_id": task_id, "instruction": instruction, "files": files}
        if timeout_seconds is not None:
            arguments["timeout_seconds"] = timeout_seconds
        if "input_id" in staged:
            arguments["input_id"] = staged["input_id"]
        return await call("continue_task", **arguments)

    @mcp.tool()
    async def cancel_task(task_id: str) -> dict:
        """Stop the local agent. Remote durable jobs require a separate explicitly delegated stop operation."""
        return await call("cancel_task", task_id=task_id)

    @mcp.tool()
    async def get_artifact(task_id: str, artifact_id: str, destination: str | None = None,
                           ctx: Context = None) -> dict:
        """Preview filtered UTF-8 text, or save the original file to an absolute caller-local destination. Any file type/size is supported; sensitive files are held. Existing destinations are never overwritten. File bytes do not enter model context."""
        if destination is not None:
            return await file_operation(save_artifact, ctx, socket_path, task_id, artifact_id, destination)
        return await call("get_artifact", task_id=task_id, artifact_id=artifact_id)

    return mcp


def public_mcp(socket_path):
    create_public_mcp(socket_path).run(transport="stdio")


REMOTE_JOB_ID = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
JOB_STATES = {"running", "exited", "lost", "unknown_id"}
GPU_HINT = (" For GPU work first run remote_exec with `nvidia-smi --query-gpu=index,memory.used,memory.total,"
            "utilization.gpu --format=csv` and set CUDA_VISIBLE_DEVICES to idle cards inside the command; the server is shared.")


def _job_state(value):
    # Re-build from known keys so nothing unexpected from the remote side leaks through.
    if value.get("state") not in JOB_STATES:
        raise ValueError("invalid job state")
    keys = ("id", "state", "exit_code", "killed", "started_at", "finished_at", "log_bytes")
    return {key: value[key] for key in keys if key in value}


def register_remote_tools(mcp, remote, push_root, audit):
    """Tools that always return immediately: durable remote jobs, pushes and small file edits."""
    from .push import cancel_push, push_status as read_push, start_push

    def remote_job_id(job_id):
        job_id = job_id or "job-" + uuid.uuid4().hex[:12]
        if not isinstance(job_id, str) or not REMOTE_JOB_ID.fullmatch(job_id) or job_id in (".", ".."):
            raise ValueError("invalid job id")
        return job_id

    def guarded(name, error_code, function):
        try:
            result = function()
            audit(name, "error_code" not in result and result.get("state") not in ("lost", "unknown_id", "failed"))
            return result
        except Exception:
            audit(name, False)
            return {"error_code": error_code}

    def job_start(command: str, job_id: str | None = None) -> dict:
        """Start a long-running remote shell command as a durable background job and return at once with its job_id. Use this, not remote_exec, for anything that may run longer than a minute. The command text runs under bash in the remote home with stdout+stderr merged into the job log; it survives SSH disconnects and worker restarts. Poll with job_status, read output with job_tail, stop with job_kill. Write checkpoints for resumable work."""
        def run():
            identifier = remote_job_id(job_id)
            if not isinstance(command, str) or not command.strip():
                return {"error_code": "empty_command"}
            [state] = remote.job_json("start", identifier, stdin=command.encode())
            return {"error_code": state["error"]} if "error" in state else _job_state(state)
        return guarded("job_start", "job_start_failed", run)

    # FastMCP reads __doc__; a concatenated literal would not be a docstring.
    job_start.__doc__ += GPU_HINT
    mcp.tool()(job_start)

    @mcp.tool()
    def job_status(job_id: str) -> dict:
        """Return one job's state immediately: running, exited (with exit_code; killed=true after job_kill), lost (process gone without an exit code: treat as failure, never success) or unknown_id."""
        def run():
            [state] = remote.job_json("status", remote_job_id(job_id))
            return {"error_code": state["error"]} if "error" in state else _job_state(state)
        return guarded("job_status", "job_status_failed", run)

    @mcp.tool()
    def job_tail(job_id: str, lines: int = 100) -> dict:
        """Return the last 1-10000 lines (at most 256 KB) of a job's merged stdout/stderr log, immediately."""
        def run():
            if type(lines) is not int or not 1 <= lines <= 10000:
                return {"error_code": "invalid_lines"}
            result = remote.job_command("tail", remote_job_id(job_id), lines)
            if result["exit_code"] != 0:
                return {"error_code": "unknown_id"}
            return {"id": job_id, "log": result["stdout"]}
        return guarded("job_tail", "job_tail_failed", run)

    @mcp.tool()
    def job_kill(job_id: str) -> dict:
        """Stop a job: SIGTERM to its whole process group, SIGKILL after 5 s. Returns the final state (takes up to about 6 s)."""
        def run():
            [state] = remote.job_json("kill", remote_job_id(job_id))
            return {"error_code": state["error"]} if "error" in state else _job_state(state)
        return guarded("job_kill", "job_kill_failed", run)

    @mcp.tool()
    def job_list() -> dict:
        """List all durable jobs of this account with their states (no command text)."""
        def run():
            result = remote.job_command("ls")
            jobs = [_job_state(json.loads(line)) for line in result["stdout"].splitlines() if line.strip()]
            return {"jobs": jobs}
        return guarded("job_list", "job_list_failed", run)

    @mcp.tool()
    def push_start(local_path: str, remote_path: str, job_id: str | None = None) -> dict:
        """Start a background rsync push of a workspace-relative file or directory to a path inside the remote home, returning a push_id at once. Resumable: re-running with a new job_id after a failure resends only missing or changed data. Afterwards the remote copy is independently checked against a local SHA-256 manifest. Poll push_status (every 10-60 s); do not block on it. Use this instead of put_file for large directories or many files."""
        def run():
            return start_push(remote, push_root, local_path, remote_path, job_id)
        try:
            result = run()
            audit("push_start", True)
            return result
        except FileExistsError:
            audit("push_start", False)
            return {"error_code": "id_exists"}
        except Exception:
            audit("push_start", False)
            return {"error_code": "push_start_failed"}

    @mcp.tool()
    def push_status(job_id: str) -> dict:
        """Return push state immediately: starting, hashing, transferring, verifying, completed, failed (with a fixed reason code), cancelled, lost or unknown_id, plus byte/file progress and the verification summary (verified, failed, up to 5 failed relative paths). Only completed means the remote copy is verified."""
        return guarded("push_status", "push_status_failed", lambda: read_push(push_root, job_id))

    @mcp.tool()
    def push_cancel(job_id: str) -> dict:
        """Cancel a running push and its local rsync (takes up to about 5 s). Partial files are kept for a later resume."""
        return guarded("push_cancel", "push_cancel_failed", lambda: cancel_push(push_root, job_id))

    @mcp.tool()
    def write_remote_file(remote_path: str, content: str, mode: int = 0o600) -> dict:
        """Atomically create or replace a UTF-8 text file (at most 1 MB) inside the remote home: written to a temporary file, then renamed. Symbolic links and paths outside the home are refused. mode is numeric, e.g. 384 for 0600 or 448 for 0700. Use it for scripts and configs instead of shell heredocs."""
        return guarded("write_remote_file", "remote_write_failed", lambda: remote.write_file(remote_path, content, mode))

    @mcp.tool()
    def read_remote_file(remote_path: str, max_bytes: int = 65536) -> dict:
        """Read up to max_bytes (at most 1 MB) of a UTF-8 text file inside the remote home. Binary files are refused; use fetch_file for those. truncated=true when the file is longer."""
        def run():
            try:
                return remote.read_file(remote_path, max_bytes)
            except BinaryFileError:
                return {"error_code": "binary_file"}
        return guarded("read_remote_file", "remote_read_failed", run)


def internal_mcp(private, target, job):
    private, settings, credentials, policy = load_settings(private)
    from .config import JOB_ID
    if not JOB_ID.fullmatch(job):
        raise ValueError("invalid task")
    remote = Remote(private, settings, credentials, target, private / "jobs" / job / "work", job)
    mcp = FastMCP("private-remote", instructions="Private worker-only tools. Use the configured logical target; do not inspect connection configuration. Original data is unchanged. Outputs are private until the public report gateway filters them.")

    def audit(method, success):
        path = private / "jobs" / job / "remote-audit.jsonl"
        with path.open("a") as stream:
            stream.write(json.dumps({"method": method, "success": success, "time": time.time()}) + "\n")

    register_remote_tools(mcp, remote, private / "jobs" / job / "pushes", audit)

    @mcp.tool()
    def ask_caller(question: str, timeout_seconds: int = 900) -> dict:
        """Ask the caller a necessary question and wait in this task. On timeout report blocked or partial; do not assume approval."""
        try:
            return ask(private / "jobs" / job, question, timeout_seconds)
        except Exception:
            return {"error_code": "question_failed"}

    @mcp.tool()
    def remote_exec(command: str, timeout_seconds: int = 120) -> dict:
        """Execute a short remote shell command (default 120 s, max 1 h, 256 KB output). Anything long-running (training, data processing, installs) must use job_start instead; closing this channel does not guarantee termination. Use it for quick probes such as `nvidia-smi --query-gpu=index,memory.used,utilization.gpu --format=csv`."""
        try:
            result = remote.execute(command, timeout_seconds)
            audit("remote_exec", result.get("exit_code") == 0)
            return result
        except Exception:
            audit("remote_exec", False)
            return {"error_code": "remote_execution_failed"}

    @mcp.tool()
    def put_file(local_path: str, remote_path: str) -> dict:
        """Upload a small workspace-relative file or directory through the existing private connection, blocking until done. Preserves bytes and verifies hashes; already-matching files are skipped. For large directories or many files use push_start, which returns immediately and reports progress."""
        try:
            result = remote.upload(local_path, remote_path)
            audit("put_file", True)
            return result
        except Exception:
            return {"error_code": "upload_failed"}

    @mcp.tool()
    def fetch_file(remote_path: str) -> dict:
        """Store a remote file privately and return an artifact ID. Public exports are separately filtered."""
        try:
            result = remote.fetch(remote_path)
            audit("fetch_file", True)
            return result
        except Exception:
            return {"error_code": "download_failed"}

    @mcp.tool()
    def export_file(local_path: str) -> dict:
        """Publish a workspace-relative deliverable of any type or size as an opaque artifact. The caller can retrieve it with get_artifact(destination=...). Sensitive original files will be held at the export boundary."""
        try:
            result = remote.publish(local_path)
            audit("export_file", True)
            return result
        except Exception:
            return {"error_code": "artifact_publish_failed"}

    mcp.run(transport="stdio")
