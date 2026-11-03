"""Binary task input/output over the existing, authenticated local socket.

Local paths are opened by the caller, never by the privileged worker. Only
regular files are copied into a new private workspace; tar links are not used.
"""
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import tarfile
import tempfile
import uuid
from pathlib import Path, PurePosixPath

from .config import atomic_json, read_private


INPUT_ID = re.compile(r"input_[a-f0-9]{24}\Z")
CHUNK = 1024 * 1024
RESERVED = {"agents.md", "agents.override.md", ".codex"}


def relative_name(value):
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("invalid attachment name")
    path = PurePosixPath(value)
    if path.is_absolute() or any(p in ("", ".", "..") for p in value.split("/")):
        raise ValueError("invalid attachment name")
    if any(p.casefold() in RESERVED for p in path.parts):
        raise ValueError("reserved attachment name")
    return path.as_posix()


def open_regular(path):
    """Reject symlinks in every component, including a swapped parent."""
    path = Path(os.path.abspath(path))
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
        file_descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                  dir_fd=descriptor)
        if not stat.S_ISREG(os.fstat(file_descriptor).st_mode):
            os.close(file_descriptor)
            raise ValueError("regular file required")
        return os.fdopen(file_descriptor, "rb")
    finally:
        os.close(descriptor)


def collect_inputs(attachments):
    if not isinstance(attachments, list) or not attachments:
        raise ValueError("attachments required")
    entries = []
    names = set()
    for attachment in attachments:
        if not isinstance(attachment, dict) or set(attachment) - {"source", "path", "list_file"}:
            raise ValueError("invalid attachment")
        source = Path(attachment["source"])
        destination = relative_name(attachment["path"])
        if not source.is_absolute() or source.is_symlink():
            raise ValueError("absolute caller path required")
        if source.is_dir():
            if attachment.get("list_file"):
                with open_regular(attachment["list_file"]) as stream:
                    selected = stream.read().decode("utf-8-sig").splitlines()
                members = [relative_name(value) for value in selected]
            else:
                members = []
                for directory, directories, files in os.walk(source, followlinks=False):
                    for name in directories:
                        if (Path(directory) / name).is_symlink():
                            raise ValueError("attachment links are not supported")
                    members.extend((Path(directory) / name).relative_to(source).as_posix()
                                   for name in sorted(files))
            selected_entries = [(source / member, relative_name(destination + "/" + member))
                                for member in sorted(members)]
        else:
            if attachment.get("list_file"):
                raise ValueError("list_file requires a directory")
            selected_entries = [(source, destination)]
        for local, name in selected_entries:
            if name in names or any(parent.as_posix() in names for parent in PurePosixPath(name).parents):
                raise ValueError("duplicate attachment destination")
            if any(existing.startswith(name + "/") for existing in names):
                raise ValueError("conflicting attachment destination")
            with open_regular(local) as stream:
                size = os.fstat(stream.fileno()).st_size
            entries.append((local, name, size))
            names.add(name)
    if not entries:
        raise ValueError("no input files")
    return entries


def stage_inputs(socket_path, attachments):
    """Called as the caller's OS identity. File bytes never enter model output."""
    try:
        entries = collect_inputs(attachments)
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(60)
            connection.connect(str(socket_path))
            header = {"method": "stage_inputs", "arguments": {
                "file_count": len(entries), "size_bytes": sum(e[2] for e in entries)}}
            connection.sendall(json.dumps(header).encode() + b"\n")
            with connection.makefile("wb") as output:
                with tarfile.open(fileobj=output, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                    for local, name, expected_size in entries:
                        with open_regular(local) as stream:
                            before = os.fstat(stream.fileno())
                            if before.st_size != expected_size:
                                raise ValueError("input changed")
                            digest = hashlib.file_digest(stream, "sha256").hexdigest()
                            stream.seek(0)
                            info = tarfile.TarInfo(name)
                            info.size, info.mode, info.mtime = expected_size, 0o600, 0
                            info.pax_headers = {"worker.sha256": digest}
                            archive.addfile(info, stream)
                            after = os.fstat(stream.fileno())
                            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                                    after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                                raise ValueError("input changed")
            connection.shutdown(socket.SHUT_WR)
            with connection.makefile("rb") as incoming:
                result = json.loads(incoming.readline(65537))
            if not isinstance(result, dict):
                raise ValueError("invalid response")
            return result
    except Exception:
        return {"error_code": "attachment_transfer_failed"}


def receive_inputs(private, incoming, arguments):
    count, total = arguments.get("file_count"), arguments.get("size_bytes")
    if type(count) is not int or count < 1 or type(total) is not int or total < 0:
        return {"error_code": "invalid_attachments"}
    root = Path(private) / "inputs"
    root.mkdir(mode=0o700, exist_ok=True)
    if total > shutil.disk_usage(root).free:
        return {"error_code": "attachment_space_unavailable"}
    identifier = "input_" + uuid.uuid4().hex[:24]
    bundle = root / identifier
    work = bundle / "work"
    work.mkdir(mode=0o700, parents=True)
    names = set()
    received = 0
    complete = False
    try:
        with tarfile.open(fileobj=incoming, mode="r|") as archive:
            for member in archive:
                name = relative_name(member.name)
                expected = member.pax_headers.get("worker.sha256", "")
                if (not member.isfile() or member.issparse() or name in names or
                        not re.fullmatch(r"[a-f0-9]{64}", expected) or member.size < 0 or
                        len(names) >= count or received + member.size > total):
                    raise ValueError("invalid attachment archive")
                target = work / name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                digest = hashlib.sha256()
                with archive.extractfile(member) as source, target.open("xb") as destination:
                    target.chmod(0o600)
                    while chunk := source.read(CHUNK):
                        digest.update(chunk)
                        destination.write(chunk)
                if target.stat().st_size != member.size or digest.hexdigest() != expected:
                    raise ValueError("attachment digest mismatch")
                received += member.size
                names.add(name)
        # The client half-closes after the archive, allowing bounded idle reads.
        while incoming.read(CHUNK):
            pass
        if len(names) != count or received != total:
            raise ValueError("incomplete attachment bundle")
        atomic_json(bundle / "state.json", {"status": "ready", "file_count": count,
                                           "size_bytes": total})
        complete = True
        return {"input_id": identifier, "file_count": count, "size_bytes": total}
    finally:
        if not complete:
            shutil.rmtree(bundle)


def input_workspace(private, identifier):
    if not isinstance(identifier, str) or not INPUT_ID.fullmatch(identifier):
        raise ValueError("invalid input bundle")
    bundle = Path(private) / "inputs" / identifier
    if bundle.is_symlink() or (bundle / "work").is_symlink():
        raise ValueError("invalid input bundle")
    state = read_private(bundle / "state.json")
    if state.get("status") != "ready":
        raise ValueError("input bundle already consumed")
    return bundle / "work"


def save_artifact(socket_path, task_id, artifact_id, destination):
    """Save an approved original file without including its bytes in MCP JSON."""
    temporary = None
    try:
        destination = Path(destination)
        if not destination.is_absolute() or destination.exists() or destination.is_symlink():
            return {"error_code": "invalid_artifact_destination"}
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(86400)
            connection.connect(str(socket_path))
            connection.sendall(json.dumps({"method": "export_artifact", "arguments": {
                "task_id": task_id, "artifact_id": artifact_id}}).encode() + b"\n")
            with connection.makefile("rb") as incoming:
                response = json.loads(incoming.readline(65537))
                if response.get("status") != "ready":
                    return response
                descriptor, temporary = tempfile.mkstemp(prefix=".worker-artifact-", dir=destination.parent)
                digest = hashlib.sha256()
                remaining = response["size_bytes"]
                with os.fdopen(descriptor, "wb") as stream:
                    while remaining:
                        chunk = incoming.read(min(CHUNK, remaining))
                        if not chunk:
                            raise ValueError("incomplete artifact")
                        digest.update(chunk)
                        stream.write(chunk)
                        remaining -= len(chunk)
                if digest.hexdigest() != response["sha256"]:
                    raise ValueError("artifact digest mismatch")
                # Hard-link publication is atomic and refuses to overwrite.
                os.link(temporary, destination)
                return {"artifact_id": artifact_id, "saved": True,
                        "size_bytes": response["size_bytes"], "sha256": response["sha256"]}
    except Exception:
        return {"error_code": "artifact_transfer_failed"}
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)
