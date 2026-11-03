"""Task processes that outlive the service, and identity checks for adopting them.

A pid alone is not an identity: after a restart the number may belong to an
unrelated process. Every check pairs it with the kernel start time from
/proc/<pid>/stat, and group signals are sent only to a group we can prove
is still the one we started.
"""
import os
import signal
import threading
import time
from pathlib import Path


# Runs codex with the prompt file on stdin and records its exit status even
# when no service is alive to wait for it. User data never enters the script:
# the prompt travels as a file and every value arrives as a positional argument.
WRAPPER = ('prompt=$1; exit_file=$2; shift 2; "$@" < "$prompt"; code=$?; '
           'printf "%s\\n" "$code" > "$exit_file.tmp" && mv -f "$exit_file.tmp" "$exit_file"')


def proc_stat(pid):
    try:
        raw = Path(f"/proc/{int(pid)}/stat").read_text()
        # The command name may contain spaces or parentheses; fields resume
        # after the last closing parenthesis (field 3 onwards).
        fields = raw[raw.rindex(")") + 2:].split()
        return {"state": fields[0], "pgrp": int(fields[2]), "starttime": int(fields[19])}
    except (OSError, ValueError, IndexError):
        return None


def same_process(record):
    """True while the recorded process runs (a zombie has already exited)."""
    info = proc_stat(record["pid"])
    return (info is not None and info["starttime"] == record.get("starttime")
            and info["state"] not in ("Z", "X"))


def group_exists(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return False  # Some other identity owns it; never ours.
    return True


def group_members(pgid):
    members = []
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            info = proc_stat(entry.name)
            if info is not None and info["pgrp"] == pgid and info["state"] not in ("Z", "X"):
                members.append(int(entry.name))
    return members


def owns_group(record):
    """Whether the recorded process group is provably still ours.

    The leader (pid == pgid) must match the recorded start time. If the leader
    has exited, surviving members keep the group id reserved, so the kernel
    cannot have handed that id to a new group; a live leader with another
    start time means the number was reused and we must not signal it.
    """
    pgid = record["pid"]
    leader = proc_stat(pgid)
    if leader is not None and leader["state"] not in ("Z", "X"):
        return leader["starttime"] == record.get("starttime") and leader["pgrp"] == pgid
    return bool(group_members(pgid))


def signal_group(record, signum):
    if not owns_group(record):
        return False
    try:
        os.killpg(record["pid"], signum)
    except (ProcessLookupError, PermissionError):
        return False
    return True


def terminate_group(record, grace_seconds=5.0, wait=False):
    """SIGTERM now, SIGKILL after the grace period if the group is still ours."""
    if not signal_group(record, signal.SIGTERM):
        return False

    def escalate():
        deadline = time.monotonic() + grace_seconds
        while time.monotonic() < deadline:
            if not owns_group(record):
                return
            time.sleep(0.05)
        signal_group(record, signal.SIGKILL)

    if wait:
        escalate()
    else:
        threading.Thread(target=escalate, daemon=True).start()
    return True


def read_exit_code(path):
    try:
        text = Path(path).read_text().strip()
    except OSError:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def read_progress(path, limit=2048):
    """Short agent-written progress line; never follows links."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        status = os.fstat(descriptor)
        if not (status.st_mode & 0o170000 == 0o100000):
            return None
        data = os.read(descriptor, limit)
        return data.decode("utf-8", errors="replace").strip(), status.st_mtime
    finally:
        os.close(descriptor)
