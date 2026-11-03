"""Inspect an immutable export snapshot; never rewrite original business files."""
import gzip
import bz2
import hashlib
import lzma
import re
import tarfile
import tempfile
import time
import unicodedata
import zipfile

from .attachments import CHUNK
from .privacy import GEO, IPV4, IPV6, SECRETS, URI_AUTH


class ExportBlocked(ValueError):
    pass


class ExportGuard:
    def __init__(self, redactor, timeout_seconds=300):
        self.literals = [value.casefold() for value in redactor.literals]
        self.deadline = time.monotonic() + timeout_seconds
        self.members = 0

    def check_text(self, text):
        text = unicodedata.normalize("NFKC", text)
        if any(value in text.casefold() for value in self.literals):
            raise ExportBlocked()
        if GEO.search(text) or SECRETS.search(text) or URI_AUTH.search(text):
            raise ExportBlocked()
        if "PRIVATE KEY-----" in text:
            raise ExportBlocked()
        if re.search(r'(?i)["\']?(?:latitude|longitude|coordinates|经纬度)["\']?\s*[:=]\s*[\[\d+.-]', text):
            raise ExportBlocked()
        # Use the same IP validation as report filtering, avoiding false
        # positives for software version numbers that are not IP addresses.
        from .privacy import Redactor
        checker = Redactor()
        for pattern in (IPV4, IPV6):
            for match in pattern.finditer(text):
                if checker.address(match) != match.group():
                    raise ExportBlocked()

    def scan(self, stream, depth=0):
        if depth > 8 or time.monotonic() > self.deadline:
            raise ExportBlocked()
        stream.seek(0)
        beginning = stream.read(512)
        stream.seek(0)
        tail = b""
        while chunk := stream.read(CHUNK):
            if time.monotonic() > self.deadline:
                raise ExportBlocked()
            data = tail + chunk
            if any(marker in data for marker in (b"GPSLatitude", b"GPSLongitude",
                    b"\x25\x88\x04\x00\x01\x00\x00\x00", b"\x88\x25\x00\x04\x00\x00\x00\x01")):
                raise ExportBlocked()
            self.check_text(data.decode("utf-8", errors="replace"))
            if b"\0" in data:
                self.check_text(data.decode("utf-16-le", errors="replace"))
                self.check_text(data.decode("utf-16-be", errors="replace"))
            tail = data[-65536:]
        stream.seek(0)
        if beginning.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            with zipfile.ZipFile(stream) as archive:
                for member in archive.infolist():
                    self.members += 1
                    if self.members > 100000 or member.flag_bits & 1:
                        raise ExportBlocked()
                    self.check_text(member.filename)
                    if not member.is_dir():
                        with archive.open(member) as source:
                            self.scan_nested(source, depth)
        elif beginning.startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=stream) as source:
                self.scan_nested(source, depth)
        elif beginning.startswith(b"BZh"):
            with bz2.BZ2File(stream) as source:
                self.scan_nested(source, depth)
        elif beginning.startswith(b"\xfd7zXZ\0"):
            with lzma.LZMAFile(stream) as source:
                self.scan_nested(source, depth)
        elif beginning.startswith((b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07")):
            raise ExportBlocked()
        elif beginning[257:262] == b"ustar":
            with tarfile.open(fileobj=stream, mode="r:") as archive:
                for member in archive:
                    self.members += 1
                    if self.members > 100000:
                        raise ExportBlocked()
                    self.check_text(member.name)
                    if member.isfile():
                        with archive.extractfile(member) as source:
                            self.scan_nested(source, depth)
                    elif not member.isdir():
                        raise ExportBlocked()
        stream.seek(0)

    def scan_nested(self, source, depth):
        # Spooling provides seekability for nested containers, without loading
        # large artifacts into RAM. All temporary files remain private.
        with tempfile.TemporaryFile() as snapshot:
            while chunk := source.read(CHUNK):
                if time.monotonic() > self.deadline:
                    raise ExportBlocked()
                snapshot.write(chunk)
            self.scan(snapshot, depth + 1)


def export_snapshot(source, private, redactor, timeout_seconds=300):
    """Caller owns the returned temporary file and must close it."""
    snapshot = tempfile.TemporaryFile(dir=private)
    try:
        digest = hashlib.sha256()
        size = 0
        while chunk := source.read(CHUNK):
            snapshot.write(chunk)
            digest.update(chunk)
            size += len(chunk)
        snapshot.flush()
        ExportGuard(redactor, timeout_seconds).scan(snapshot)
        return snapshot, {"status": "ready", "size_bytes": size, "sha256": digest.hexdigest()}
    except BaseException:
        snapshot.close()
        raise
