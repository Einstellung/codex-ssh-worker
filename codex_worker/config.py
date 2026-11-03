import json
import os
import re
import stat
import tempfile
from pathlib import Path


DEFAULT_PRIVATE = Path.home() / ".local/share/codex-worker-private"
JOB_ID = re.compile(r"job_[a-f0-9]{24}\Z")
ARTIFACT_ID = re.compile(r"artifact_[a-f0-9]{24}\Z")


def private_directory(path):
    path = Path(path).absolute()
    if path.is_symlink():
        raise ValueError("unsafe directory")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    mode = path.stat()
    if mode.st_uid != os.getuid() or stat.S_IMODE(mode.st_mode) & 0o077:
        raise ValueError("private directory permissions required")
    return path


def read_private(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("private file required")
    mode = path.stat()
    if mode.st_uid not in (0, os.getuid()) or stat.S_IMODE(mode.st_mode) & 0o077:
        raise ValueError("private file permissions required")
    return json.loads(path.read_text())


def atomic_json(path, value):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_settings(private):
    private = private_directory(private)
    settings = read_private(private / "resources.json")
    credentials = read_private(private / "credentials.json")
    policy = read_private(private / "policy.json")
    return private, settings, credentials, policy


def scoped_path(root, relative):
    root = Path(root).resolve()
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root) or candidate == root:
        raise ValueError("workspace-relative file required")
    return candidate
