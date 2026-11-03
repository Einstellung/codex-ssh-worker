import json
import hashlib
import os
import posixpath
import shlex
import shutil
import stat
import tarfile
import socket
import subprocess
import time
import uuid
from pathlib import Path

import paramiko

from .attachments import CHUNK, open_regular
from .config import atomic_json, scoped_path


class Remote:
    def __init__(self, private, settings, credentials, target, workspace=None, job=None):
        self.private = Path(private)
        self.resource = settings["resources"][target]
        self.credential = credentials[self.resource["credential_ref"]]
        self.workspace = workspace
        self.job = job

    def source_address(self):
        """Local address to bind, shared by paramiko and the OpenSSH push channel."""
        resource = self.resource
        if resource.get("source_interface"):
            interface_name = resource["source_interface"]
            if interface_name == "auto":
                routes = json.loads(subprocess.check_output(["ip", "-j", "-4", "route", "show", "table", "main"], stderr=subprocess.DEVNULL))
                candidates = [route for route in routes if route.get("dst") == "default" and route.get("dev") not in ("Mihomo", "tailscale0", "lo")]
                if not candidates:
                    raise ValueError("physical default route unavailable")
                interface_name = min(candidates, key=lambda route: route.get("metric", 0))["dev"]
            interfaces = json.loads(subprocess.check_output(["ip", "-j", "-4", "addr", "show", "dev", interface_name], stderr=subprocess.DEVNULL))
            addresses = [address["local"] for interface in interfaces for address in interface.get("addr_info", []) if address.get("scope") == "global"]
            if not addresses:
                raise ValueError("source interface unavailable")
            return addresses[0]
        return resource.get("bind_address")

    def connect(self):
        resource = self.resource
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(15)
        try:
            address = self.source_address()
            if address:
                connection.bind((address, 0))
        except BaseException:
            connection.close()
            raise
        client = paramiko.SSHClient()
        try:
            connection.connect((resource["host"], resource["port"]))
            client.load_host_keys(str(self.private / "known_hosts"))
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            client.connect(resource["host"], port=resource["port"], username=resource["user"],
                           password=self.credential.get("password"), key_filename=self.credential.get("key_file"),
                           sock=connection, allow_agent=False, look_for_keys=False,
                           timeout=15, banner_timeout=15, auth_timeout=15)
            return client
        except BaseException:
            client.close()
            connection.close()
            raise

    def execute(self, command, timeout=120, max_bytes=262144, stdin=None):
        timeout = max(1, min(int(timeout), 3600))
        with self.connect() as client:
            channel = client.get_transport().open_session(timeout=15)
            channel.exec_command(command)
            if stdin is not None:
                # Untrusted text travels as data on stdin, never inside the command line.
                channel.sendall(stdin)
                channel.shutdown_write()
            output = bytearray()
            errors = bytearray()
            deadline = time.monotonic() + timeout
            try:
                while True:
                    for ready, receive, buffer in ((channel.recv_ready, channel.recv, output),
                                                    (channel.recv_stderr_ready, channel.recv_stderr, errors)):
                        if ready():
                            chunk = receive(65536)
                            buffer.extend(chunk)
                            if len(output) + len(errors) > max_bytes:
                                raise ValueError("output limit exceeded")
                    if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                        return {"exit_code": channel.recv_exit_status(), "stdout": output.decode(errors="replace"), "stderr": errors.decode(errors="replace")}
                    if time.monotonic() >= deadline:
                        raise TimeoutError("remote command timeout")
                    time.sleep(0.02)
            finally:
                channel.close()

    @staticmethod
    def _local_files(source):
        if source.is_file():
            return [(source, "")]
        entries = []
        for directory, directories, files in os.walk(source, followlinks=False):
            if any((Path(directory) / name).is_symlink() for name in directories):
                raise ValueError("source links are not supported")
            for name in sorted(files):
                path = Path(directory) / name
                with open_regular(path):
                    pass
                entries.append((path, path.relative_to(source).as_posix()))
        return entries

    @staticmethod
    def _mkdirs(sftp, directory, checked=None):
        checked = checked if checked is not None else set()
        missing = []
        while directory and directory != "/":
            if directory in checked:
                break
            try:
                mode = sftp.lstat(directory).st_mode
            except FileNotFoundError:
                missing.append(directory)
            else:
                if not stat.S_ISDIR(mode):
                    raise ValueError("remote directory is not a regular directory")
                checked.add(directory)
            directory = posixpath.dirname(directory)
        for directory in reversed(missing):
            try:
                sftp.mkdir(directory, mode=0o700)
            except OSError:
                # A concurrent call may have created it first; accept only a real directory.
                if not stat.S_ISDIR(sftp.lstat(directory).st_mode):
                    raise ValueError("remote directory is not a regular directory") from None
            checked.add(directory)

    @staticmethod
    def _verify(client, manifest):
        # JSON is sent on stdin, never interpolated into shell command text.
        script = """import hashlib,json,os,stat,sys
matches=[]
for i,(path,size,sha,md5) in enumerate(json.load(sys.stdin)):
 try:
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  with os.fdopen(fd,'rb') as f:
   if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):continue
   a=hashlib.sha256();b=hashlib.md5();n=0
   while True:
    chunk=f.read(1048576)
    if not chunk:break
    n+=len(chunk);a.update(chunk);b.update(chunk)
   if n==size and a.hexdigest()==sha and b.hexdigest()==md5:matches.append(i)
 except (OSError,ValueError):pass
print(json.dumps(matches))
"""
        stdin, stdout, stderr = client.exec_command("python3 -c " + shlex.quote(script), timeout=86400)
        stdin.write(json.dumps(manifest).encode())
        stdin.flush()
        stdout.channel.shutdown_write()
        result = stdout.read(1024 * 1024)
        if stdout.channel.recv_exit_status() != 0:
            raise ValueError("remote verification failed")
        matches = json.loads(result)
        if not isinstance(matches, list) or any(type(i) is not int or not 0 <= i < len(manifest) for i in matches):
            raise ValueError("invalid verification")
        return set(matches)

    def upload(self, local_path, remote_path):
        source = scoped_path(self.workspace, local_path)
        local_files = self._local_files(source)
        manifest = []
        with self.connect() as client, client.open_sftp() as sftp:
            sftp.get_channel().settimeout(86400)
            home = sftp.normalize(".")
            if remote_path.startswith("~/"):
                remote_path = remote_path[2:]
            target = posixpath.normpath(posixpath.join(home, remote_path))
            checked = set()
            if source.is_dir():
                self._mkdirs(sftp, target, checked)
            for local, relative in local_files:
                destination = posixpath.join(target, relative) if relative else target
                self._mkdirs(sftp, posixpath.dirname(destination), checked)
                sha, md5, size = hashlib.sha256(), hashlib.md5(), 0
                with open_regular(local) as stream:
                    while chunk := stream.read(CHUNK):
                        sha.update(chunk); md5.update(chunk); size += len(chunk)
                manifest.append([destination, size, sha.hexdigest(), md5.hexdigest()])
            matched = self._verify(client, manifest)
            for index, ((local, _), entry) in enumerate(zip(local_files, manifest)):
                if index in matched:
                    continue
                destination = entry[0]
                temporary = destination + ".worker-" + uuid.uuid4().hex
                try:
                    with open_regular(local) as stream:
                        sftp.putfo(stream, temporary, file_size=entry[1], confirm=True)
                    sftp.chmod(temporary, 0o600)
                    sftp.posix_rename(temporary, destination)
                finally:
                    try:
                        sftp.remove(temporary)
                    except FileNotFoundError:
                        pass
            if len(self._verify(client, manifest)) != len(manifest):
                raise ValueError("remote digest mismatch")
        return {"uploaded": True, "file_count": len(manifest), "skipped_files": len(matched),
                "size_bytes": sum(entry[1] for entry in manifest), "sha256_verified": True, "md5_verified": True}

    def _artifact(self):
        identifier = "artifact_" + uuid.uuid4().hex[:24]
        root = self.private / "jobs" / self.job / "artifacts"
        root.mkdir(mode=0o700, exist_ok=True)
        return identifier, root / identifier

    def fetch(self, remote_path):
        identifier, destination = self._artifact()
        complete = False
        try:
            with self.connect() as client, client.open_sftp() as sftp:
                sftp.get_channel().settimeout(86400)
                with sftp.open(remote_path, "rb") as stream, destination.open("xb") as output:
                    destination.chmod(0o600)
                    shutil.copyfileobj(stream, output, length=CHUNK)
            complete = True
            return {"artifact_id": identifier, "size_bytes": destination.stat().st_size}
        finally:
            if not complete:
                destination.unlink(missing_ok=True)

    def publish(self, local_path):
        source = scoped_path(self.workspace, local_path)
        identifier, destination = self._artifact()
        complete = False
        try:
            with destination.open("xb") as output:
                destination.chmod(0o600)
                if source.is_dir():
                    with tarfile.open(fileobj=output, mode="w") as archive:
                        for local, relative in self._local_files(source):
                            with open_regular(local) as stream:
                                info = tarfile.TarInfo(relative)
                                info.size = os.fstat(stream.fileno()).st_size
                                info.mode = 0o600
                                archive.addfile(info, stream)
                else:
                    with open_regular(source) as stream:
                        shutil.copyfileobj(stream, output, length=CHUNK)
            complete = True
            return {"artifact_id": identifier, "size_bytes": destination.stat().st_size}
        finally:
            if not complete:
                destination.unlink(missing_ok=True)

    # ---- remote tools, files and durable jobs -------------------------------

    JOB_TOOL = "~/.local/bin/codex-job"
    MAX_REMOTE_FILE = 1024 * 1024

    @staticmethod
    def home_path(sftp, remote_path, allow_missing=True):
        """Resolve a path inside the remote home and refuse symbolic link components."""
        if not isinstance(remote_path, str) or not remote_path or "\0" in remote_path:
            raise ValueError("remote path required")
        relative = remote_path[2:] if remote_path.startswith("~/") else remote_path
        if relative == "~":
            relative = "."  # the home itself, refused below; never a file named "~"
        home = sftp.normalize(".")
        target = posixpath.normpath(posixpath.join(home, relative))
        if not target.startswith(home.rstrip("/") + "/"):
            raise ValueError("remote path must stay inside the home directory")
        current = home
        for part in posixpath.relpath(target, home).split("/"):
            current = posixpath.join(current, part)
            try:
                mode = sftp.lstat(current).st_mode
            except FileNotFoundError:
                if not allow_missing:
                    raise
                break
            if stat.S_ISLNK(mode):
                raise ValueError("remote symbolic links are not followed")
        return home, target

    def check_home_path(self, remote_path):
        """Fail unless remote_path stays in the home without symbolic link components."""
        with self.connect() as client, client.open_sftp() as sftp:
            self.home_path(sftp, remote_path)

    def ensure_remote_tools(self):
        """Install codex-job into ~/.local/bin once; overwrite only when the digest differs."""
        if getattr(self, "_tools_ready", False):
            return False
        script = (Path(__file__).with_name("remote_job.sh")).read_bytes()
        wanted = hashlib.sha256(script).hexdigest()
        changed = False
        with self.connect() as client, client.open_sftp() as sftp:
            home, target = self.home_path(sftp, ".local/bin/codex-job")
            current = None
            try:
                if stat.S_ISREG(sftp.lstat(target).st_mode):
                    with sftp.open(target, "rb") as stream:
                        current = hashlib.sha256(stream.read(4 * 1024 * 1024)).hexdigest()
            except FileNotFoundError:
                pass
            if current != wanted:
                self._mkdirs(sftp, posixpath.dirname(target), {home})
                self._atomic_put(sftp, target, script, 0o700)
                changed = True
        self._tools_ready = True
        return changed

    @staticmethod
    def _atomic_put(sftp, target, data, mode):
        temporary = target + ".worker-" + uuid.uuid4().hex
        try:
            with sftp.open(temporary, "wb") as stream:
                # The server creates the file with its umask (often 0644) on a shared
                # host; restrict it before any byte is written.
                sftp.chmod(temporary, 0o600)
                stream.write(data)
            sftp.chmod(temporary, mode)
            sftp.posix_rename(temporary, target)
        finally:
            try:
                sftp.remove(temporary)
            except (FileNotFoundError, OSError):
                pass

    def write_file(self, remote_path, content, mode=0o600):
        if not isinstance(content, (str, bytes)):
            raise ValueError("text content required")
        data = content.encode() if isinstance(content, str) else content
        if len(data) > self.MAX_REMOTE_FILE:
            raise ValueError("content too large")
        # Group/other write on a shared host would let another account alter scripts.
        if type(mode) is not int or not 0 <= mode <= 0o777 or mode & 0o022:
            raise ValueError("invalid mode")
        with self.connect() as client, client.open_sftp() as sftp:
            home, target = self.home_path(sftp, remote_path)
            try:
                if not stat.S_ISREG(sftp.lstat(target).st_mode):
                    raise ValueError("remote target is not a regular file")
            except FileNotFoundError:
                pass
            self._mkdirs(sftp, posixpath.dirname(target), {home})
            self._atomic_put(sftp, target, data, mode)
        return {"written": True, "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def read_file(self, remote_path, max_bytes=65536):
        if type(max_bytes) is not int or not 1 <= max_bytes <= self.MAX_REMOTE_FILE:
            raise ValueError("invalid max_bytes")
        with self.connect() as client, client.open_sftp() as sftp:
            home, target = self.home_path(sftp, remote_path, allow_missing=False)
            info = sftp.lstat(target)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("remote target is not a regular file")
            with sftp.open(target, "rb") as stream:
                data = stream.read(max_bytes + 1)
        truncated = len(data) > max_bytes
        data = data[:max_bytes]
        if b"\0" in data:
            raise BinaryFileError("binary file")
        # A cut may split one multi-byte character; only those last 1-3 bytes may go.
        for drop in range(4 if truncated else 1):
            try:
                text = data[:len(data) - drop].decode()
                break
            except UnicodeDecodeError:
                continue
        else:
            raise BinaryFileError("binary file")
        return {"content": text, "size_bytes": info.st_size, "truncated": truncated}

    def job_command(self, *arguments, stdin=None, timeout=60):
        self.ensure_remote_tools()
        command = self.JOB_TOOL + " " + " ".join(shlex.quote(str(argument)) for argument in arguments)
        result = self.execute(command, timeout=timeout, max_bytes=1024 * 1024, stdin=stdin)
        if result["exit_code"] == 127 and not result["stdout"]:
            # The cached install was removed on the server: reinstall once and retry.
            self._tools_ready = False
            if self.ensure_remote_tools():
                result = self.execute(command, timeout=timeout, max_bytes=1024 * 1024, stdin=stdin)
        return result

    def job_json(self, *arguments, stdin=None, timeout=60):
        result = self.job_command(*arguments, stdin=stdin, timeout=timeout)
        lines = [json.loads(line) for line in result["stdout"].splitlines() if line.strip()]
        if not lines or not all(isinstance(line, dict) for line in lines):
            raise ValueError("invalid job response")
        return lines


class BinaryFileError(ValueError):
    pass
