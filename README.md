# codex-ssh-worker

Claude delegates unrestricted natural-language tasks to a configured logical
resource. A private Codex worker resolves that resource and uses SSH without
putting connection credentials in the task prompt. Public reports are sanitized
independently of the model. Software versions and hardware capabilities are
permitted.

Worker tasks explicitly select `gpt-6.1-terra` with `model_reasoning_effort` set
to `high`. The service account must have access to the requested model.

Worker tasks explicitly select `gpt-6.1-terra` with `model_reasoning_effort` set
to `high`. The service account must have access to the requested model.

## Important deployment status

The local development mode uses mode-0700 directories and mode-0600 files.
**Another unsandboxed process running as the same OS user can read them.**
It is not an isolation boundary against Claude running as that same user.
Do not register the development socket with Claude as a supposedly isolated
production service. Use the administrator installer for a separate service
identity. Administrators and users with Docker/root-equivalent privileges can
still bypass Unix identity separation. This is a mitigation against accidental
disclosure, not a guarantee against a malicious executor or covert channels.

The worker can execute remote commands with the configured account's rights.
Do not expose its socket to untrusted users. It does not provision a training
environment, reserve GPUs across other users' jobs, or configure a remote
supervisor. Remote job durability and checkpointing must be explicitly arranged
for the task. No remote configuration is changed by installing this application.

## Status and limitations

This is a prototype. Read these before relying on it.

- All tests run on one machine against a fake `codex` executable and a fake
  SSH layer. Nothing has been exercised against a real remote host.
- The systemd integration (`KillMode=process`, the update script) has **not**
  been verified under real systemd.
- It has **not** been tested end to end with a real Codex binary. In particular,
  it is unverified whether Codex's private MCP child process exits with the
  process group on cancellation or timeout.
- The rsync push path with password login has **not** been verified on a real
  host. It depends on OpenSSH 8.4 or newer (`SSH_ASKPASS_REQUIRE`).
- Redaction is best effort, not a guarantee. An IP address placed directly
  after words such as `driver`, `cuda` or `version` is not replaced, and some
  file names ending in `.in` or `.app` may be treated as domain names.
- Other processes running as the same OS user can read the mode-0600 files.
  Development mode is not an isolation boundary.

## Local development

```bash
uv venv .venv
uv pip install --python .venv/bin/python -e '.[dev]'
.venv/bin/python -m codex_worker.cli serve
```

Private state defaults to the operator's `.local/share/codex-worker-private`.
Required files: `resources.json`, `credentials.json`, `policy.json`, and a
`known_hosts` file containing independently enrolled SSH host keys.
Real configuration and secrets must never be committed to this repository.

Example `resources.json` (placeholders only):

```json
{
  "codex_binary": "/path/to/codex",
  "max_parallel": 2,
  "task_timeout_seconds": 3600,
  "client_uid": 1000,
  "resources": {
    "example-server": {
      "connector": "ssh",
      "host": "<private endpoint>",
      "port": 22,
      "user": "<private account>",
      "source_interface": "<optional local physical interface>",
      "credential_ref": "example-server-login",
      "private_hostname": "<private hostname>",
      "private_home": "<private home>"
    }
  }
}
```

`credentials.json` maps credential references to `{"password": "..."}` or
`{"key_file": "/private/key"}`. It is stored as plaintext protected by OS
permissions; it is not encrypted at rest. The administrator installer migrates
the state away from the original user's home. Private config, jobs, and raw logs
must be excluded from public backups and shared workspaces. A saved source
interface is resolved at connection time to tolerate DHCP address changes. Set
`source_interface` to `auto` to use the lowest-metric physical default route in
the main routing table, excluding the known Mihomo/Tailscale interfaces.

`policy.json` contains `{"sensitive_literals": ["private hostname", "location"]}`.
Use known private location names, alternative spellings, and infrastructure
identifiers. IPv4, IPv6, CIDR, DNS names, common credential assignments,
sensitive JSON keys, selected location names, ANSI escapes, and explicit private
values are filtered. Output keys remain flexible, including nested structures.
Unknown locations, arbitrary encodings/base64, semantic hints, and malicious
covert channels are not reliably detectable. Domain-like filenames can be
over-redacted. There is no promise that all location inference is prevented.

## Public interface

- `list_resources`: logical aliases only.
- `run_task(target, instruction, files?, timeout_seconds=86400)`: **preferred for
  new work**. Submit exactly once, publish a safe `job_id` progress message, and
  attach to the same filtered completion path as `wait_for_task`. Instructions,
  input files, and free-form business results retain their existing semantics.
  The timeout bounds waiting after submission, not task execution; maximum
  seven days. No automatic resubmission, retries, or content-hash deduplication:
  two intentional calls create two tasks, even with identical inputs.
- `list_tasks(target?, status?, limit=20)`: recover recent task IDs, newest
  `created_at` first (ties by ID). Limit must be an integer from 1 to 100;
  booleans are rejected. Filters match an exact configured logical target and
  one of `queued`, `running`, `waiting_for_input`, `completed`, `partial`, `blocked`, `failed`,
  `timed_out`, `interrupted`, or `cancelled`. Each summary contains only opaque
  `job_id`, logical `target`, `status`, and available numeric timestamps
  (`created_at`, `updated_at`, `started_at`, `finished_at`). Older history may
  have only `created_at`. No instruction text, filenames, reports, logs,
  authentication, or private configuration is included. The returned list is
  bounded; the worker scans saved state metadata to find the newest matches.
- `submit_task(target, instruction, files?)`: enqueue a free-form task. Optional
  files are UTF-8 text keyed by workspace-relative filename; they are unchanged.
  This immediate-return tool remains available for existing clients.
- `get_task(task_id)`: queued/running/terminal state plus the agent's filtered
  `progress` note when present; not raw execution logs.
- `get_result(task_id)`: filtered final report and opaque artifact IDs.
- `wait_for_task(task_id, timeout_seconds=86400)`: attach once and receive the
  same filtered terminal report as `get_result`, without repeated model tool
  calls. Maximum wait is seven days. Safe progress heartbeats contain no logs.
- A running agent can call its private `ask_caller` tool when it needs a
  decision or missing information. `run_task` and `wait_for_task` then return
  `status: waiting_for_input` with the filtered `question`, `question_id`, and
  original `job_id`. Ask the user when appropriate, call
  `answer_question(task_id, question_id, answer)`, then call `wait_for_task`
  again on the same job. The running session and workspace are preserved and
  no new job is submitted. Questions pass through the same redactor as reports.
  A question defaults to a 15-minute wait (maximum one hour); the task's
  execution timeout still applies. Timeout or cancellation is not approval;
  late and duplicate answers are rejected. This supports agent-initiated
  questions, not arbitrary mid-task steering.
- `continue_task(task_id, instruction, files?)`: new task with prior private
  report as context. New workspace; pass needed inputs again. Existing remote
  files remain available according to the task's permissions.
- `get_artifact(task_id, artifact_id)`: filtered UTF-8 preview up to 1 MiB;
  larger/binary previews remain private; provide a caller-local `destination` to save an inspected file or sanitized copy.
- `cancel_task(task_id)`: terminates the local Codex process group only, including
  tasks adopted after a service restart (SIGTERM, then SIGKILL after 5 seconds). It does
  **not** guarantee remote processes stopped; delegate a remote stop separately.

The MCP client forwards only gateway responses. Neither raw stdout/stderr nor
Codex event streams are forwarded. Exceptions and public MCP validation failures
use fixed codes, suppressing exception text that could otherwise echo instructions
or attachment contents. A validation failure names only the declared parameter
and a fixed reason, for example
`{"error_code": "invalid_tool_request", "field": "attachments", "index": 0, "reason": "item_must_have_source_and_path"}`;
caller-side attachment problems return `invalid_attachments` with the same
`field`/`reason` shape. Input values and nested key names are never echoed. The gateway has an explicit RPC method allowlist;
configuration and raw-log APIs do not exist.
Tasks require a structured outcome as well as a report. A claimed success without
successful private-tool evidence (remote operations or published local deliverables) becomes `blocked`, not `completed`.
Tool evidence confirms an operation ran, not that all business postconditions
were met; the worker must validate those explicitly. This is not tamper-proof
against a malicious worker that can modify its own audit file.
Every response passes through a new redactor, so aliases are consistent within
that response but not across separate requests. Original business data and
privately stored artifacts remain unchanged. Reports are generated on retrieval,
so current policy also applies to old jobs.

Agent tasks outlive the service. Each `codex exec` runs in its own session under
a small `sh` wrapper that feeds the prompt from a file and writes the exit
status to the job's `exit` file, so the status is recorded even while no service
is running. The job's `process.json` holds the wrapper pid and its kernel start
time from `/proc/<pid>/stat`. Stopping or restarting the service kills no task
(the systemd unit uses `KillMode=process`). On startup the service adopts every
unfinished job: if the recorded pid still runs with the same start time, the job
stays `running` and is watched to completion; if it has exited, the `exit` file
decides the outcome through the same report and evidence checks; with no `exit`
file the job becomes `interrupted` with `error_code: "lost"`, never `completed`.
Queued jobs that never started are started by the new instance. A reused pid
(different start time) is never adopted or signalled. Remote durable jobs are
unaffected either way. Never automatically retry a side-effecting task without
checking its prior effects.

`submit_task`/`continue_task` accept `timeout_seconds` and `run_task` accepts
`task_timeout_seconds`: the execution limit, integer 1 to 604800 seconds
(7 days), defaulting to `task_timeout_seconds` in `resources.json`. When it
expires the task's process group receives SIGTERM, then SIGKILL after 5 seconds,
and the task becomes `timed_out`. The limit is kept across service restarts.

While a task runs, the agent may keep a short status in `progress.txt` at the
workspace root. `get_task` returns its first 2 KB as `progress` (filtered by the
same redactor) with `progress_updated_at`; symlinks are ignored.

## General-purpose task files

The worker remains a general-purpose Codex agent. Coding, design, analysis,
execution and file processing use the same task tools; no per-business-action
API is needed. The service boundary provides real file input/output while
keeping connection identity private.

`run_task`, `submit_task` and `continue_task` accept optional `attachments`:

```json
{
  "target": "example-server",
  "instruction": "Process the attached materials and return the deliverables.",
  "attachments": [
    {"source": "/caller/materials", "path": "materials"},
    {"source": "/caller/model.bin", "path": "inputs/model.bin"}
  ]
}
```

`source` is an absolute path on the caller's machine. `path` is the destination
relative to the task workspace. A directory is recursive; optional `list_file`
is a caller-local UTF-8 file listing exactly the relative files to include.
Each item accepts only `source`, `path` and optional `list_file` (a string or
`null`); other keys are rejected with reason `item_keys_must_be_source_path_list_file`.
The caller opens local files using its own OS identity and streams the original
bytes over the existing authenticated Unix socket. The service never opens an
arbitrary caller-supplied local path. Inputs are checked with SHA256, privately
staged, and claimed once at submission. Bytes do not enter model prompts or MCP
JSON. Existing inline UTF-8 `files` remain compatible with their original limits;
attachments have no fixed per-file size or 100-file ceiling. Disk space and host
runtime limits still apply. Links, special files, path traversal, duplicate
paths and reserved instruction/configuration paths are rejected.

The agent can use its existing private `put_file` for a file or directory.
It reuses the enrolled SSH connection, skips files with matching SHA256 and MD5,
and verifies both hashes remotely after transfer. A server-to-caller connection,
new key, disclosed endpoint, network reconfiguration or third-party relay is
unnecessary. Failed transfers can be retried against existing remote files;
matching files are skipped, and unrelated files are not deleted.

### Long-running remote work

Codex MCP calls time out after one to five minutes, and progress notifications
do not extend that limit. These private tools therefore return at once and are
polled instead. Remote paths are relative to the remote home (`~/` is optional).
Absolute paths, `..` escapes and symbolic link components are refused.

- `job_start(command, job_id?)` installs `~/.local/bin/codex-job` on first use
  (it is replaced only when its SHA-256 differs) and starts the command text
  under bash in a new session. The job survives SSH disconnects and worker
  restarts. State and the merged stdout/stderr log are kept in `~/.codex-jobs/<id>/`.
- `job_status(job_id)` returns `running`, `exited` (with `exit_code`, and
  `killed=true` after `job_kill`), `lost` or `unknown_id`. A job is `lost` when
  its process is gone without an exit code, which means failure.
- `job_tail(job_id, lines)` returns the last 1-10000 log lines, at most 256 KB.
- `job_kill(job_id)` sends SIGTERM to the process group, then SIGKILL after 5 s.
  `job_list()` lists the jobs without their command text.
- `push_start(local_path, remote_path, job_id?)` starts a detached local
  `rsync` over OpenSSH and returns a `push_id`. Interrupted pushes keep partial
  files in `.rsync-partial`, so a new push to the same destination resends
  only the missing data. The connection settings and any password exist only
  in 0600 files in a 0700 private directory while the push runs. They are
  never passed in argv or environment values.
- `push_status(push_id)` reads from local disk, so it still works after a
  worker restart. It returns `starting`, `hashing`, `transferring`,
  `verifying`, `completed`, `failed`, `cancelled`, `lost` or `unknown_id`.
  `failed` and `lost` carry one fixed `reason`: `transfer_failed`,
  `connection_failed`, `partial_transfer`, `verify_mismatch`,
  `verify_unavailable`, `runner_lost`, `start_failed` or `internal_error`. Only
  `completed` means a remote SHA-256 check of every file passed. `verify`
  reports the passed and failed counts and up to five failed relative paths.
  `push_cancel(push_id)` stops the push.
- `write_remote_file(remote_path, content, mode)` atomically writes UTF-8 text
  of at most 1 MB (default mode 0600; group/other write is refused).
  `read_remote_file(remote_path, max_bytes)` reads text and refuses binary files.

`progress` in `push_status` contains only numbers and the transfer rate,
never file names:

```json
{"phase": "transfer", "bytes_done": 1048576, "bytes_total": 4194304,
 "files_transferred": 3, "files_total": 12, "entries_to_check": 9,
 "entries_total": 12, "percent": 25, "rate": "10.50MB/s", "updated_at": 1700000000.0}
```

During long work the agent also overwrites `progress.txt` in its workspace
with a single line of at most 2 KB.

Remote `fetch_file` streams a file into a private artifact without the old
10 MiB ceiling. Internal `export_file` publishes a locally generated file, or a
directory as an uncompressed tar, as an opaque artifact. To save a real file,
use the existing public tool:

```json
{
  "task_id": "job_<opaque-id>",
  "artifact_id": "artifact_<opaque-id>",
  "destination": "/caller/results/output.bin"
}
```

The caller saves the inspected bytes with mode 0600, verifies SHA256,
and atomically refuses to overwrite an existing destination. No file content,
private source path or exception is returned in the tool response. Without
`destination`, `get_artifact` retains its compatible filtered text preview.

Before bytes leave the service, an immutable private snapshot is inspected for
known private literals, IP addresses, geographic terms/coordinates, credential
assignments, private keys and common GPS metadata. ZIP, tar, gzip, bzip2 and xz
members are inspected recursively. When an original fails inspection, the
worker attempts to build a separate sanitized copy: it redacts private text and
fields, removes archive metadata, recursively rebuilds supported containers,
and then runs the inspection again. The source is never modified. A sanitized
export explicitly returns `sanitized: true`, both `source_sha256` and `sha256`,
and aggregate `redacted_files` and `redacted_fields` counts; consumers must
not treat this copy as byte-identical to the source. JSON numbers are parsed as
decimal values to preserve scientific numeric precision. Sensitive binary data
that cannot be safely rewritten, encrypted/unsupported archives, links,
malformed data, over 128 MiB of decompressed input, and files that still fail
inspection remain held. Progress messages contain no filenames or logs.
This is defense against accidental disclosure, not a complete content-security
system: arbitrary encodings, undocumented metadata formats, semantic location
hints and covert channels cannot be reliably detected. The agent must keep
private infrastructure information out of deliverables. Inspection defaults to
300 seconds (configurable via `export_inspection_seconds`); exceeding it holds
the file. Large deliveries need sufficient private temporary disk space.

If attachment staging is interrupted, no task is submitted. Completed but
unclaimed input bundles remain private. A lost task acknowledgement must still
be recovered using `list_tasks`; never resubmit automatically. Resending a large
input currently restarts local staging; remote file transfer skips verified
matches. Installation and upgrades preserve the isolated service identity and
home-directory protections.

## Completion delivery

Use `run_task` for new work and `wait_for_task` for an existing ID; do not poll.
`run_task` submits once and then waits. Record its safe `job_id` progress message
so a disconnected or interrupted caller can reattach. Once acknowledged, wait
timeouts and errors include that ID and recovery guidance; neither means the
task failed or was cancelled. Cancellation during submission lets that single
submission finish and attempts to publish its ID before detaching. Delivery of
progress still depends on the connection and host. If acknowledgement is lost,
`submission_unconfirmed` means work may already exist: use bounded `list_tasks`
filters to recover the ID and inspect candidates with `wait_for_task`. Listings
intentionally omit instruction text, so concurrent similar tasks may require
operator reconciliation. Never automatically submit again to recover feedback.

After `submit_task` or `continue_task`, call `wait_for_task` using the
returned `job_id` as `task_id`. It also attaches to jobs submitted before this
feature was installed. It returns on every terminal outcome: `completed` means
the agent reported success with execution evidence; `partial` means only part
was accomplished; `blocked`, `failed`, `timed_out`, `interrupted`, and `cancelled`
must not be described as successful completion. The free-form report and business
metrics remain available and pass through the existing redaction gateway.

The wait releases the worker lock while sleeping and never occupies a Codex
execution-pool slot. Short service-side condition waits stay below the existing
30-second socket timeout; the asynchronous MCP client chains them internally
and sends safe progress notifications. Other tools and task cancellations remain
usable while a wait is pending. No completion broadcasts or raw event streams
are sent to unrelated MCP sessions. Authorized clients of the same Unix socket
share task access and listings, as before; there is no session isolation or new
per-session authorization scheme.

Claude Code can move a long main-conversation MCP call into the background
(normally after two minutes) and deliver the result as a task notification. This
is a normal backgroundable tool call, **not native MCP Tasks and not an unsolicited
push channel**. The model must call `run_task` or attach with `wait_for_task`;
merely submitting does not subscribe it. Progress carries the safe job ID and
elapsed waiting activity, not a training percentage.
Client wall-clock limits still apply even with heartbeats. For longer waits,
an administrator may need to raise `MCP_TOOL_TIMEOUT` or the per-server timeout;
this project does not modify Claude settings. Calls from Claude subagents do not
automatically background. One-shot noninteractive runs do not keep a conversation
alive for completion delivery. Backgrounding must be enabled in the host.

Cancelling or timing out the wait detaches that listener only, without cancelling
the work. Use `cancel_task` explicitly to terminate the local agent; remote
processes may still need a separately delegated stop. If the MCP connection or
Claude session closes, no live notification can arrive, but execution remains in
the separate service. Reattach with the same ID after reconnecting; already-final
tasks return immediately. Multiple or repeated waits are safe and do not create
new jobs, but may deliver the same result more than once. Task IDs are the
deduplication key; never resubmit a task merely to recover its feedback.

Why this fallback: the pinned Python SDK negotiates protocol `2025-11-25`,
whereas Claude's current native MCP Tasks extension requires `2026-07-28` and
a different task contract. Advertising incompatible experimental SDK task support
would not provide reliable delivery. Custom Channels are gated research preview,
so the worker does not opt into them or require development-channel overrides.
See [automatic backgrounding](https://code.claude.com/docs/en/mcp#automatic-backgrounding-of-long-tool-calls),
[native task requirements](https://code.claude.com/docs/en/mcp#what-a-call-needs-to-become-an-mcp-task),
and [Channels requirements](https://code.claude.com/docs/en/channels-reference#what-you-need).

## Administrator installation

Review `scripts/install-isolated.sh` and run it with local administrator access.
It installs root-owned code, creates a `codex-worker` service user, migrates
private state, copies Codex authentication into that user's private home, and
starts a system service. The public client runs under the Claude user's identity
and can access only the service socket. It does not start the private worker.
The installer is for this Linux/systemd host and refuses to replace an existing
deployment. It does not alter server configuration or reuse the server password
as the local administrator password.

The native Codex executable requires its matching `codex-code-mode-host` sibling.
Both are installed together. For a deployment made before this fix, run
`sudo bash scripts/repair-isolated.sh`. The repair verifies the installed Codex
binary matches its source package before copying the helper. No credentials,
worker policy, service state, or remote configuration are changed.

For the run-and-wait and task-list source update, review `scripts/update-isolated.sh`.
Running tasks no longer need to finish first:

```bash
sudo bash scripts/update-isolated.sh --apply
```

It makes sure the unit uses `KillMode=process` (adding the drop-in
`/etc/systemd/system/codex-worker.service.d/killmode.conf` and running
`systemctl daemon-reload` if it does not), prints how many tasks are queued or
running, backs up the code, updates the worker code modules and this README in
the installed source (and the modules in the Python package), and restarts the
local service. Running tasks keep running and are adopted by the restarted
service. One exception: if the installed code predates task adoption, stopping
it would still kill its tasks, so the script refuses while any are active.
Submissions sent while the service is down fail with `worker_unavailable`.
On a command failure it attempts rollback and restart. It does not replace
private configuration, credentials, Codex authentication, saved jobs, dependencies,
or remote configuration. Reconnect the MCP server from Claude's `/mcp` afterward
to load the new tools and instructions. Do not run the original installer over an
existing installation.

```bash
sudo --preserve-env=HTTP_PROXY,HTTPS_PROXY,ALL_PROXY,NO_PROXY,http_proxy,https_proxy,all_proxy,no_proxy bash scripts/install-isolated.sh
claude mcp add --scope user --transport stdio codex-worker -- /opt/codex-worker/venv/bin/python -m codex_worker.cli mcp --socket /run/codex-worker/worker.sock
```

Restart Claude Code, then run `/mcp`. Ask it to list resources and submit a
read-only environment check first. Registration contains no server endpoints or
credentials. The installer prints the registration command after successful
installation. Do not share this conversation or earlier raw inspection logs with
Claude if they contain infrastructure information.

The dedicated user isolates Claude from worker files, but the worker itself can
read its own credentials. The model is instructed to use only logical tools;
this prototype does not enforce a separate credential-broker identity or worker
egress allowlist. Training code is arbitrary code: stronger adversarial isolation
would require those extra controls and artifact approval.

## Validation

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m codex_worker.cli check --target example-server
```

The `check` command executes only `python3 --version` remotely, verifies the
saved host key, and emits a sanitized result. It never installs dependencies or
changes remote files. Full task integration additionally uses the saved Codex
login and incurs normal model usage.

Reference: [Codex non-interactive execution](https://developers.openai.com/codex/noninteractive),
[MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk),
[Paramiko host-key checking](https://docs.paramiko.org/en/stable/api/client.html).
