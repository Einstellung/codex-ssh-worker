"""Detached local rsync pushes with on-disk progress and an independent remote check.

push_start() validates, writes the request and spawns ``python -m codex_worker.push``
in a new session, then returns at once. The runner owns rsync, writes progress.json
and status.json under the private task directory, and needs nothing from the caller
afterwards, so status survives Codex timeouts and service restarts.
"""
import base64
import hashlib
import json
import os
import posixpath
import re
import shlex
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .attachments import CHUNK, open_regular
from .config import atomic_json, scoped_path

PUSH_ID = re.compile(r"[A-Za-z0-9._-]{1,40}\Z")
SSH_PROGRAM = "ssh"
RSYNC_PROGRAM = "rsync"
EXTRA_RSYNC_ARGS = []
PROGRESS_INTERVAL = 1.0
CANCEL_GRACE = 5.0
VERIFY_POLL = 2.0
VERIFY_TIMEOUT = 6 * 3600
VERIFY_START_GRACE = 15.0
ALIAS = "codex-push-target"
PROGRESS = re.compile(rb"^\s*([\d,]+)\s+(\d+)%\s+(\S+)\s+\S+(?:\s+\(xfr#(\d+), (?:to|ir)-chk=(\d+)/(\d+)\))?")
RSYNC_REASONS = {20: "cancelled", 23: "partial_transfer", 24: "partial_transfer", 11: "remote_io_error",
                 12: "connection_failed", 30: "connection_failed", 35: "connection_failed", 255: "connection_failed"}


def starttime(pid):
    try:
        data = Path(f"/proc/{int(pid)}/stat").read_text()
    except (OSError, ValueError):
        return None
    fields = data.rsplit(")", 1)[1].split()
    # An unreaped child keeps its /proc entry; a zombie is not a live runner.
    if fields[0] in ("Z", "X", "x"):
        return None
    return fields[19]


def alive(record):
    return bool(record) and starttime(record.get("pid")) == record.get("starttime")


def _hash(path):
    digest, size = hashlib.sha256(), 0
    with open_regular(path) as stream:
        while chunk := stream.read(CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def build_manifest(files, workers=4):
    """[[relative, size, sha256], ...]; one digest only, computed in parallel."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        digests = list(pool.map(_hash, [path for path, _ in files]))
    return [[relative, size, sha] for (_, relative), (size, sha) in zip(files, digests)]


def _config_value(value):
    value = str(value)
    # "%" starts an ssh_config token expansion in several keywords.
    if not value or any(character in value for character in "\n\r\0\"%") or value != value.strip():
        raise ValueError("unsupported connection setting")
    return '"' + value + '"' if " " in value else value


def write_ssh_channel(remote, directory):
    """Write a private ssh_config (and askpass helper for passwords); return (-e, env).

    Connection identity and secrets live only in 0600 files inside a 0700 directory,
    never in argv, environment values or logs. The caller removes the directory.
    """
    directory.mkdir(mode=0o700)
    resource, credential = remote.resource, remote.credential
    lines = [f"Host {ALIAS}", f"  HostName {_config_value(resource['host'])}",
             f"  Port {int(resource.get('port', 22))}", f"  User {_config_value(resource['user'])}",
             f"  UserKnownHostsFile {_config_value(remote.private / 'known_hosts')}",
             "  GlobalKnownHostsFile /dev/null", "  StrictHostKeyChecking yes", "  CheckHostIP no",
             "  IdentityAgent none", "  ForwardAgent no", "  ForwardX11 no", "  ClearAllForwardings yes",
             "  ControlMaster no", "  ControlPath none", "  ConnectTimeout 15", "  ServerAliveInterval 30",
             "  ServerAliveCountMax 4", "  LogLevel QUIET", "  PermitLocalCommand no", "  UpdateHostKeys no"]
    address = remote.source_address()
    if address:
        lines.append(f"  BindAddress {_config_value(address)}")
    env = {key: value for key, value in os.environ.items() if not key.startswith(("SSH_", "DISPLAY"))}
    if credential.get("key_file"):
        lines += [f"  IdentityFile {_config_value(credential['key_file'])}", "  IdentitiesOnly yes",
                  "  PreferredAuthentications publickey", "  PasswordAuthentication no", "  BatchMode yes"]
    elif credential.get("password") is not None:
        secret = directory / "secret"
        descriptor = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(credential["password"])
        helper = directory / "askpass"
        helper.write_text("#!/bin/sh\nexec cat " + shlex.quote(str(secret)) + "\n")
        helper.chmod(0o700)
        # OpenSSH >= 8.4 reads the password from the helper without a terminal.
        env.update(SSH_ASKPASS=str(helper), SSH_ASKPASS_REQUIRE="force", DISPLAY="none")
        lines += ["  PubkeyAuthentication no", "  IdentityFile none",
                  "  PreferredAuthentications password,keyboard-interactive", "  NumberOfPasswordPrompts 1"]
    else:
        raise ValueError("no usable credential")
    config = directory / "config"
    descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write("\n".join(lines) + "\n")
    return f"{SSH_PROGRAM} -F {shlex.quote(str(config))}", env


# Runs on the remote host as a codex-job; the manifest is embedded as base64 data.
VERIFY_SCRIPT = r"""import base64,hashlib,json,os,stat,zlib
from concurrent.futures import ThreadPoolExecutor
home=os.path.expanduser('~');root=os.path.normpath(os.path.join(home,%(root)r))
items=json.loads(zlib.decompress(base64.b64decode(%(manifest)r)))
def check(item):
 rel,size,sha=item
 path=os.path.join(root,rel) if rel else root
 try:
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  with os.fdopen(fd,'rb') as f:
   if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):return False
   d=hashlib.sha256();n=0
   while True:
    b=f.read(1048576)
    if not b:break
    n+=len(b);d.update(b)
  return n==size and d.hexdigest()==sha
 except (OSError,ValueError):return False
with ThreadPoolExecutor(max_workers=min(8,os.cpu_count() or 2)) as pool:ok=list(pool.map(check,items))
bad=[i[0] for i,r in zip(items,ok) if not r]
print('CODEX_VERIFY '+json.dumps({'verified':len(items)-len(bad),'failed':len(bad),'failed_paths':bad[:5]}))
"""


def verify_command(remote_root, manifest):
    packed = base64.b64encode(__import__("zlib").compress(json.dumps(manifest).encode())).decode()
    script = VERIFY_SCRIPT % {"root": remote_root, "manifest": packed}
    return "python3 - <<'CODEX_VERIFY_EOF'\n" + script + "CODEX_VERIFY_EOF\n"


def remote_relative(remote_path):
    """Destination relative to the remote home, as rsync and the verifier expect."""
    if not isinstance(remote_path, str) or "\0" in remote_path or "\n" in remote_path:
        raise ValueError("remote path required")
    path = remote_path[2:] if remote_path.startswith("~/") else remote_path
    path = posixpath.normpath(path)
    if path.startswith(("/", "..", "-")) or path in (".", "") or ":" in path.split("/")[0]:
        raise ValueError("remote path must be inside the home directory")
    return path


def _read(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return default


class Runner:
    """Body of the detached process. Everything it needs is in the push directory."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.request = _read(self.directory / "request.json")
        self.cancelled = False
        self.child = None
        self.verify_job = None

    def save(self, **state):
        atomic_json(self.directory / "status.json", {"updated_at": time.time(), **state})

    def ssh(self, command, stdin=None, timeout=120):
        argv = shlex.split(self.request["ssh"]) + [ALIAS, command]
        result = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout,
                                env=self.request_env(), start_new_session=False)
        return result.returncode, result.stdout

    def request_env(self):
        env = {key: value for key, value in os.environ.items() if not key.startswith("SSH_")}
        env.update(self.request.get("ssh_env", {}))
        return env

    def on_term(self, *_):
        self.cancelled = True
        if self.child is not None and self.child.poll() is None:
            self.child.terminate()

    def transfer(self, totals):
        source = self.request["source"] + ("/" if self.request["is_dir"] else "")
        # --chmod: the server is shared, so pushed data is private to the account.
        argv = [RSYNC_PROGRAM, "-a", "--chmod=go-rwx", "--partial", "--partial-dir=.rsync-partial", "--info=progress2",
                "--no-inc-recursive", "--protect-args", "--mkpath", "-e", self.request["ssh"], *self.request["extra_args"],
                "--", source, f"{ALIAS}:{self.request['remote']}"]
        with open(self.directory / "rsync.stderr", "ab") as errors:
            self.child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=errors, stdin=subprocess.DEVNULL,
                                          env=self.request_env())
        atomic_json(self.directory / "rsync.json", {"pid": self.child.pid, "starttime": starttime(self.child.pid)})
        if self.cancelled:
            self.child.terminate()
        buffer, last = b"", 0.0
        progress = {"phase": "transfer", "bytes_done": 0, **totals, "files_transferred": 0, "percent": 0}
        while chunk := self.child.stdout.read1(65536):
            buffer += chunk
            *records, buffer = re.split(rb"[\r\n]", buffer)
            for record in records:
                match = PROGRESS.match(record)
                if not match:
                    continue  # names or messages never reach the progress file
                progress.update(bytes_done=int(match[1].replace(b",", b"")), percent=int(match[2]),
                                rate=match[3].decode("ascii", "replace")[:16])
                if match[4]:
                    progress.update(files_transferred=int(match[4]), entries_to_check=int(match[5]),
                                    entries_total=int(match[6]))
            if time.monotonic() - last >= PROGRESS_INTERVAL:
                atomic_json(self.directory / "progress.json", {**progress, "updated_at": time.time()})
                last = time.monotonic()
        code = self.child.wait()
        atomic_json(self.directory / "progress.json", {**progress, "updated_at": time.time()})
        return code

    def verify(self, manifest):
        try:
            return self._verify(manifest)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            # Unreachable or garbled verifier: never a success, never an internal error.
            return None

    def _verify(self, manifest):
        job = f"verify-{self.directory.name}-{uuid.uuid4().hex[:8]}"
        self.verify_job = job
        atomic_json(self.directory / "verify.json", {"remote_job": job})
        code, out = self.ssh(f"{JOB} start {shlex.quote(job)}", stdin=verify_command(self.request["remote"], manifest).encode())
        if code != 0:
            return None
        begun = time.monotonic()
        deadline = begun + VERIFY_TIMEOUT
        while time.monotonic() < deadline and not self.cancelled:
            code, out = self.ssh(f"{JOB} status {shlex.quote(job)}")
            state = _read_line(out)
            # On a loaded host the detached wrapper may not have recorded its pid yet.
            if state.get("state") == "lost" and time.monotonic() - begun < VERIFY_START_GRACE:
                time.sleep(0.5)
                continue
            if code != 0 or state.get("state") in ("lost", "unknown_id"):
                return None
            if state.get("state") == "exited":
                code, out = self.ssh(f"{JOB} tail {shlex.quote(job)} 20")
                lines = [line for line in out.decode(errors="replace").splitlines() if line.startswith("CODEX_VERIFY ")]
                if state.get("exit_code") != 0 or not lines:
                    return None
                result = json.loads(lines[-1].split(" ", 1)[1])
                return {"verified": int(result["verified"]), "failed": int(result["failed"]),
                        "failed_paths": [str(path) for path in result["failed_paths"][:5]]}
            time.sleep(VERIFY_POLL)
        if self.cancelled:
            self.ssh(f"{JOB} kill {shlex.quote(job)}")
        return None

    def run(self):
        signal.signal(signal.SIGTERM, self.on_term)
        started = time.time()
        try:
            self.save(state="hashing", started_at=started)
            files = [(Path(path), relative) for path, relative in self.request["files"]]
            manifest = build_manifest(files)
            totals = {"bytes_total": sum(item[1] for item in manifest), "files_total": len(manifest)}
            if self.cancelled:
                return self.save(state="cancelled", reason="cancelled", started_at=started, finished_at=time.time())
            self.save(state="transferring", started_at=started, **totals)
            code = self.transfer(totals)
            if self.cancelled:
                return self.save(state="cancelled", reason="cancelled", started_at=started, finished_at=time.time(), **totals)
            if code != 0:
                return self.save(state="failed", reason=RSYNC_REASONS.get(code, "transfer_failed"), rsync_exit=code,
                                 started_at=started, finished_at=time.time(), **totals)
            self.save(state="verifying", started_at=started, **totals)
            result = self.verify(manifest)
            if self.cancelled:
                return self.save(state="cancelled", reason="cancelled", started_at=started, finished_at=time.time(), **totals)
            if result is None:
                return self.save(state="failed", reason="verify_unavailable", started_at=started, finished_at=time.time(), **totals)
            state = "completed" if result["failed"] == 0 and result["verified"] == len(manifest) else "failed"
            extra = {} if state == "completed" else {"reason": "verify_mismatch"}
            return self.save(state=state, started_at=started, finished_at=time.time(), verify=result, **totals, **extra)
        except Exception:
            self.save(state="failed", reason="internal_error", started_at=started, finished_at=time.time())
        finally:
            # The channel secrets exist only for the lifetime of this process.
            _remove_channel(self.directory / "ssh")


JOB = "~/.local/bin/codex-job"


def _read_line(raw):
    try:
        value = json.loads(raw.decode().strip().splitlines()[-1])
        return value if isinstance(value, dict) else {}
    except (ValueError, IndexError, UnicodeDecodeError):
        return {}


def _remove_channel(directory):
    # Fixed file names only; never a recursive delete of a computed path.
    for name in ("secret", "askpass", "config"):
        try:
            (directory / name).unlink()
        except FileNotFoundError:
            pass
    try:
        directory.rmdir()
    except OSError:
        pass


TERMINAL = {"completed", "failed", "cancelled", "lost"}
START_GRACE = 10.0
PUBLIC_PROGRESS = ("phase", "bytes_done", "bytes_total", "files_transferred", "files_total",
                   "entries_to_check", "entries_total", "percent", "rate", "updated_at")


def _directory(root, push_id):
    if not isinstance(push_id, str) or not PUSH_ID.fullmatch(push_id) or push_id in (".", ".."):
        raise ValueError("invalid push id")
    return Path(root) / push_id


def start_push(remote, root, local_path, remote_path, push_id=None):
    from .remote import Remote
    push_id = push_id or "push_" + uuid.uuid4().hex[:16]
    directory = _directory(root, push_id)
    source = scoped_path(remote.workspace, local_path)
    files = Remote._local_files(source)
    destination = remote_relative(remote_path) + ("/" if source.is_dir() else "")
    Path(root).mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.mkdir(mode=0o700)  # raises FileExistsError for a duplicate id
    process = None
    try:
        # rsync follows symbolic links in the destination; refuse them up front.
        remote.check_home_path(destination)
        remote.ensure_remote_tools()  # the verifier runs as a codex-job
        ssh, env = write_ssh_channel(remote, directory / "ssh")
        extra = {key: value for key, value in env.items() if key in ("SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "DISPLAY")}
        atomic_json(directory / "request.json", {
            "source": str(source), "is_dir": source.is_dir(), "remote": destination, "ssh": ssh,
            "ssh_env": extra, "extra_args": list(EXTRA_RSYNC_ARGS),
            "files": [[str(path), relative] for path, relative in files]})
        atomic_json(directory / "status.json", {"state": "starting", "updated_at": time.time()})
        log = open(directory / "runner.stderr", "ab")
        with log:
            process = subprocess.Popen([sys.executable, "-m", "codex_worker.push", str(directory)],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log,
                                       start_new_session=True, close_fds=True,
                                       cwd=str(Path(__file__).resolve().parents[1]))
        atomic_json(directory / "runner.json", {"pid": process.pid, "starttime": starttime(process.pid)})
        # Reap the runner when it exits so a long-lived MCP process does not collect zombies.
        threading.Thread(target=process.wait, daemon=True).start()
    except BaseException:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        _remove_channel(directory / "ssh")
        atomic_json(directory / "status.json", {"state": "failed", "reason": "start_failed", "updated_at": time.time()})
        raise
    return {"push_id": push_id, "state": "started", "file_count": len(files)}


def push_status(root, push_id):
    directory = _directory(root, push_id)
    if not directory.is_dir():
        return {"push_id": push_id, "state": "unknown_id"}
    status = _read(directory / "status.json", {})
    state = status.get("state", "lost")
    result = {"push_id": push_id, "state": state}
    for key in ("reason", "rsync_exit", "bytes_total", "files_total", "started_at", "finished_at", "verify"):
        if key in status:
            result[key] = status[key]
    progress = _read(directory / "progress.json", {})
    result["progress"] = {key: progress[key] for key in PUBLIC_PROGRESS if key in progress}
    runner = _read(directory / "runner.json")
    starting = runner is None and state == "starting" and time.time() - status.get("updated_at", 0) < START_GRACE
    if state not in TERMINAL and not starting and not alive(runner):
        # The runner vanished before recording an outcome: never report success,
        # and do not leave its connection secrets behind.
        result.update(state="lost", reason="runner_lost")
        _remove_channel(directory / "ssh")
    return result


def cancel_push(root, push_id):
    directory = _directory(root, push_id)
    if not directory.is_dir():
        return {"push_id": push_id, "state": "unknown_id"}
    runner = _read(directory / "runner.json")
    if push_status(root, push_id)["state"] not in TERMINAL and alive(runner):
        os.kill(runner["pid"], signal.SIGTERM)
        deadline = time.monotonic() + CANCEL_GRACE
        while time.monotonic() < deadline and alive(runner):
            time.sleep(0.1)
        rsync = _read(directory / "rsync.json")
        if alive(runner):  # start time re-checked: a reused pid is never signalled
            # The runner leads its own session; this also reaches rsync and its ssh.
            os.killpg(runner["pid"], signal.SIGKILL)
        if alive(rsync):
            os.kill(rsync["pid"], signal.SIGKILL)
        if push_status(root, push_id)["state"] not in TERMINAL:
            atomic_json(directory / "status.json", {"state": "cancelled", "reason": "cancelled", "updated_at": time.time()})
        _remove_channel(directory / "ssh")
    return push_status(root, push_id)


if __name__ == "__main__":
    Runner(sys.argv[1]).run()
