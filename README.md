# Private Codex Worker

Claude delegates unrestricted natural-language tasks to `gpu-server`; a private
Codex worker resolves the resource and uses SSH without putting connection
credentials in the task prompt. Public reports are sanitized independently of
the model. Software versions and hardware capabilities are permitted.

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
    "gpu-server": {
      "connector": "ssh",
      "host": "<private endpoint>",
      "port": 22,
      "user": "<private account>",
      "source_interface": "<optional local physical interface>",
      "credential_ref": "gpu-server-login",
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
  one of `queued`, `running`, `completed`, `partial`, `blocked`, `failed`,
  `timed_out`, `interrupted`, or `cancelled`. Each summary contains only opaque
  `job_id`, logical `target`, `status`, and available numeric timestamps
  (`created_at`, `updated_at`, `started_at`, `finished_at`). Older history may
  have only `created_at`. No instruction text, filenames, reports, logs,
  authentication, or private configuration is included. The returned list is
  bounded; the worker scans saved state metadata to find the newest matches.
- `submit_task(target, instruction, files?)`: enqueue a free-form task. Optional
  files are UTF-8 text keyed by workspace-relative filename; they are unchanged.
  This immediate-return tool remains available for existing clients.
- `get_task(task_id)`: queued/running/terminal state, not raw execution logs.
- `get_result(task_id)`: filtered final report and opaque artifact IDs.
- `wait_for_task(task_id, timeout_seconds=86400)`: attach once and receive the
  same filtered terminal report as `get_result`, without repeated model tool
  calls. Maximum wait is seven days. Safe progress heartbeats contain no logs.
- `continue_task(task_id, instruction, files?)`: new task with prior private
  report as context. New workspace; pass needed inputs again. Existing remote
  files remain available according to the task's permissions.
- `get_artifact(task_id, artifact_id)`: filtered UTF-8 preview up to 1 MiB;
  larger/binary previews remain private; provide a caller-local `destination` to save an inspected original file.
- `cancel_task(task_id)`: terminates the local Codex process group only. It does
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
so current policy also applies to old jobs. On service restart, active agent
tasks become `interrupted`; remote durable jobs may still be running. Never
automatically retry a side-effecting task without checking its prior effects.

## General-purpose task files

The worker remains a general-purpose Codex agent. Coding, design, analysis,
execution and file processing use the same task tools; no per-business-action
API is needed. The service boundary provides real file input/output while
keeping connection identity private.

`run_task`, `submit_task` and `continue_task` accept optional `attachments`:

```json
{
  "target": "gpu-server",
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

The caller saves the approved original bytes with mode 0600, verifies SHA256,
and atomically refuses to overwrite an existing destination. No file content,
private source path or exception is returned in the tool response. Without
`destination`, `get_artifact` retains its compatible filtered text preview.

Before bytes leave the service, an immutable private snapshot is inspected for
known private literals, IP addresses, geographic terms/coordinates, credential
assignments, private keys and common GPS metadata. ZIP, tar, gzip, bzip2 and xz
members are inspected recursively. Sensitive, encrypted/unsupported archive,
malformed or uninspectable artifacts are held; original files are never silently
redacted or rewritten. Progress messages contain no filenames or logs.
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

After `submit_task` or `continue_task`, call `wait_for_task` once using the
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
Finish active tasks and pause new submissions before running:

```bash
sudo bash scripts/update-isolated.sh --apply
```

It checks for active tasks before and after staging and refuses if it sees any,
backs up the code, updates the worker code modules and this README in
the installed source (and the modules in the Python package), and restarts the
local service. Unreadable or malformed task state also causes refusal.
On a command failure it attempts rollback and restart. It does not replace
private configuration, credentials, Codex authentication, saved jobs, dependencies,
or remote configuration. Reconnect the MCP server from Claude's `/mcp` afterward
to load the new tools and instructions. Do not run the original installer over an
existing installation. Any service restart can interrupt work submitted during
an update, so these active-task checks are not a maintenance lock.

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
.venv/bin/python -m codex_worker.cli check
```

The `check` command executes only `python3 --version` remotely, verifies the
saved host key, and emits a sanitized result. It never installs dependencies or
changes remote files. Full task integration additionally uses the saved Codex
login and incurs normal model usage.

Reference: [Codex non-interactive execution](https://developers.openai.com/codex/noninteractive),
[MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk),
[Paramiko host-key checking](https://docs.paramiko.org/en/stable/api/client.html).
