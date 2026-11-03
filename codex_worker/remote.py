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

    def connect(self):
        resource = self.resource
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(15)
        if resource.get("source_interface"):
            interface_name = resource["source_interface"]
            if interface_name == "auto":
                routes = json.loads(subprocess.check_output(["ip", "-j", "-4", "route", "show", "table", "main"], stderr=subprocess.DEVNULL))
                candidates = [route for route in routes if route.get("dst") == "default" and route.get("dev") not in ("Mihomo", "tailscale0", "lo")]
                if not candidates:
                    connection.close()
                    raise ValueError("physical default route unavailable")
                interface_name = min(candidates, key=lambda route: route.get("metric", 0))["dev"]
            interfaces = json.loads(subprocess.check_output(["ip", "-j", "-4", "addr", "show", "dev", interface_name], stderr=subprocess.DEVNULL))
            addresses = [address["local"] for interface in interfaces for address in interface.get("addr_info", []) if address.get("scope") == "global"]
            if not addresses:
                connection.close()
                raise ValueError("source interface unavailable")
            connection.bind((addresses[0], 0))
        elif resource.get("bind_address"):
            connection.bind((resource["bind_address"], 0))
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

    def execute(self, command, timeout=120, max_bytes=262144):
        timeout = max(1, min(int(timeout), 3600))
        with self.connect() as client:
            channel = client.get_transport().open_session(timeout=15)
            channel.exec_command(command)
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
            sftp.mkdir(directory, mode=0o700)
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
