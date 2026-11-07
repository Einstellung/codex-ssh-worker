"""Create a bounded, redacted export copy; originals are never modified."""
import bz2
import gzip
import hashlib
import io
import json
import lzma
import re
import tarfile
import tempfile
import time
import unicodedata
import zipfile
import zlib
from decimal import Decimal
from pathlib import PurePosixPath

from .exports import ExportBlocked, ExportGuard
from .privacy import ANSI, GEO, HOST, IPV4, IPV6, SECRETS, SENSITIVE_KEY, URI_AUTH

# Bound decompression and memory usage, including recursive archives.
MAX_BYTES = 128 * 1024 * 1024
MAX_MEMBERS = 10000
MAX_DEPTH = 8
FILE_EXTENSIONS = frozenset('.json .jsonl .csv .tsv .txt .log .md .yaml .yml .toml .ini .cfg .py .sh .xml .html .tar .gz .zip .bz2 .xz .pt .pth .bin .npy .npz .safetensors'.split())


class Sanitizer:
    def __init__(self, redactor, timeout_seconds=300):
        self.redactor = redactor
        self.guard = ExportGuard(redactor, timeout_seconds)
        self.deadline = time.monotonic() + timeout_seconds
        self.bytes_seen = 0
        self.members = 0
        self.changed_files = 0
        self.changed_fields = 0

    def budget(self, amount, depth):
        self.bytes_seen += amount
        if depth > MAX_DEPTH or self.bytes_seen > MAX_BYTES or time.monotonic() > self.deadline:
            raise ExportBlocked()

    def text(self, value):
        # Detect against normalized text, but retain original punctuation when
        # no private value was found. Older report redactors also mistake every
        # dotted filename for a hostname, including filenames inside commands.
        clean = ANSI.sub('', value)
        clean = ''.join(c for c in clean if c in '\n\r\t' or not unicodedata.category(c).startswith('C'))
        normalized = unicodedata.normalize('NFKC', clean)
        safe = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----',
                      '[redacted-private-key]', normalized, flags=re.S)
        for literal in self.redactor.literals:
            safe = re.sub(re.escape(literal), lambda m: self.redactor.alias('private', m.group()), safe, flags=re.I)
        safe = URI_AUTH.sub(r'\1[redacted-credentials]@', safe)
        safe = SECRETS.sub('[redacted-secret]', safe)
        safe = IPV6.sub(self.redactor.address, safe)
        safe = IPV4.sub(self.redactor.address, safe)
        safe = GEO.sub(lambda m: self.redactor.alias('location', m.group()), safe)
        host_pattern = getattr(self.redactor, 'host', HOST)
        def hostname(match):
            name = match.group()
            if PurePosixPath(name).suffix.casefold() in FILE_EXTENSIONS:
                return name
            return self.redactor.alias('hostname', name)
        safe = host_pattern.sub(hostname, safe)
        if safe == normalized:
            safe = clean
        if safe != value:
            self.changed_fields += 1
        return safe

    def value(self, value, depth=0):
        if depth > 64:
            raise ExportBlocked()
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                normalized = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', key).replace('-', '_')
                safe_key = self.text(key)
                if safe_key in result:
                    raise ExportBlocked()
                if SENSITIVE_KEY.search(normalized):
                    result[safe_key] = '[redacted-field]'
                    self.changed_fields += 1
                else:
                    result[safe_key] = self.value(item, depth + 1)
            return result
        if isinstance(value, list):
            return [self.value(item, depth + 1) for item in value]
        if isinstance(value, str):
            return self.text(value)
        return value

    def json_text(self, text):
        def invalid_constant(_):
            raise ValueError('non-finite number')
        def unique_pairs(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ExportBlocked()
                result[key] = value
            return result
        value = json.loads(text, parse_float=Decimal, parse_constant=invalid_constant, object_pairs_hook=unique_pairs)
        value = self.value(value)
        def encode(v):
            if isinstance(v, Decimal):
                return str(v)
            if isinstance(v, dict):
                return '{' + ','.join(json.dumps(k, ensure_ascii=False) + ':' + encode(x) for k, x in v.items()) + '}'
            if isinstance(v, list):
                return '[' + ','.join(encode(x) for x in v) + ']'
            return json.dumps(v, ensure_ascii=False, allow_nan=False, separators=(',', ':'))
        return encode(value)

    def name(self, name):
        # Older redactors classify every dotted filename as a hostname. Keep
        # familiar file extensions only when the entire path also passes the
        # literal/IP/location checks; still inspect every directory component.
        try:
            self.guard.check_text(name)
        except ExportBlocked:
            safe = self.text(name)
        else:
            safe = '/'.join(self.text(part) for part in name.split('/'))
        path = PurePosixPath(safe)
        if not safe or path.is_absolute() or any(part in ('..', '.') for part in path.parts) or '\\' in safe:
            raise ExportBlocked()
        return safe

    def read_member(self, source, size):
        if size < 0 or size > MAX_BYTES - self.bytes_seen:
            raise ExportBlocked()
        data = source.read(size + 1)
        if len(data) != size:
            raise ExportBlocked()
        return data

    def transform(self, data, depth=0):
        self.budget(len(data), depth)
        if data.startswith((b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08')):
            return self.zip(data, depth)
        if data.startswith(b'\x1f\x8b'):
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as source:
                plain = source.read(MAX_BYTES - self.bytes_seen + 1)
            return gzip.compress(self.transform(plain, depth + 1), mtime=0)
        if data.startswith(b'BZh'):
            dec = bz2.BZ2Decompressor()
            plain = dec.decompress(data, max_length=MAX_BYTES - self.bytes_seen + 1)
            if not dec.eof or dec.unused_data:
                raise ExportBlocked()
            return bz2.compress(self.transform(plain, depth + 1))
        if data.startswith(b'\xfd7zXZ\0'):
            dec = lzma.LZMADecompressor()
            plain = dec.decompress(data, max_length=MAX_BYTES - self.bytes_seen + 1)
            if not dec.eof or dec.unused_data:
                raise ExportBlocked()
            return lzma.compress(self.transform(plain, depth + 1))
        if data.startswith((b'7z\xbc\xaf\x27\x1c', b'Rar!\x1a\x07')):
            raise ExportBlocked()
        if len(data) >= 262 and data[257:262] == b'ustar':
            return self.tar(data, depth)
        try:
            text = data.decode('utf-8')
            if any(ord(ch) < 32 and ch not in '\t\r\n' for ch in text):
                raise UnicodeError()
        except UnicodeError:
            # Unknown binary formats are never rewritten: preserve only if the
            # existing guard can inspect them without finding sensitive data.
            self.guard.scan(io.BytesIO(data))
            return data
        before = self.changed_fields
        try:
            result = self.json_text(text)
        except ExportBlocked:
            raise
        except (ValueError, RecursionError):
            # JSONL is common in evaluation outputs. Leave plain text plain.
            lines = text.splitlines(keepends=True)
            try:
                result = ''.join(self.json_text(line.rstrip('\r\n')) + line[len(line.rstrip('\r\n')):]
                                 if line.strip() else line for line in lines)
            except ExportBlocked:
                raise
            except (ValueError, RecursionError):
                if text.lstrip().startswith(('{', '[')):
                    raise ExportBlocked()
                result = self.text(text)
        if self.changed_fields == before:
            return data  # Preserve original bytes when there was no redaction.
        self.changed_files += 1
        return result.encode('utf-8')

    def tar(self, data, depth):
        output = io.BytesIO()
        names = set()
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as source, \
                tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as dest:
            for item in source:
                self.members += 1
                if self.members > MAX_MEMBERS or not (item.isfile() or item.isdir()):
                    raise ExportBlocked()
                name = self.name(item.name)
                if name in names:
                    raise ExportBlocked()
                names.add(name)
                new = tarfile.TarInfo(name)
                new.mode = item.mode & 0o777
                if item.isdir():
                    new.type = tarfile.DIRTYPE
                    dest.addfile(new)
                else:
                    with source.extractfile(item) as inp:
                        content = self.transform(self.read_member(inp, item.size), depth + 1)
                    new.size = len(content)
                    dest.addfile(new, io.BytesIO(content))
        return output.getvalue()

    def zip(self, data, depth):
        output = io.BytesIO()
        names = set()
        with zipfile.ZipFile(io.BytesIO(data)) as source, zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as dest:
            for item in source.infolist():
                self.members += 1
                if self.members > MAX_MEMBERS or item.flag_bits & 1 or (item.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ExportBlocked()
                name = self.name(item.filename)
                if name in names:
                    raise ExportBlocked()
                names.add(name)
                if item.is_dir():
                    dest.writestr(name, b'')
                else:
                    with source.open(item) as inp:
                        content = self.transform(self.read_member(inp, item.file_size), depth + 1)
                    dest.writestr(name, content)
        return output.getvalue()

    def verify(self, data, depth=0):
        """Inspect rebuilt containers by structure, not compressed binary noise."""
        self.budget(len(data), depth)
        if data.startswith((b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08')):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                if archive.comment:
                    raise ExportBlocked()
                for item in archive.infolist():
                    self.members += 1
                    if self.members > MAX_MEMBERS or item.flag_bits & 1 or item.extra or item.comment:
                        raise ExportBlocked()
                    self.guard.check_text(item.filename)
                    if not item.is_dir():
                        with archive.open(item) as source:
                            self.verify(self.read_member(source, item.file_size), depth + 1)
            return
        if data.startswith(b'\x1f\x8b'):
            # Our gzip writer emits zero flags and mtime: no filename/comment.
            if len(data) < 10 or data[3] != 0 or data[4:8] != b'\0\0\0\0':
                raise ExportBlocked()
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as source:
                plain = source.read(MAX_BYTES - self.bytes_seen + 1)
            self.verify(plain, depth + 1)
            return
        if data.startswith(b'BZh'):
            dec = bz2.BZ2Decompressor()
            plain = dec.decompress(data, max_length=MAX_BYTES - self.bytes_seen + 1)
            if not dec.eof or dec.unused_data:
                raise ExportBlocked()
            self.verify(plain, depth + 1)
            return
        if data.startswith(b'\xfd7zXZ\0'):
            dec = lzma.LZMADecompressor()
            plain = dec.decompress(data, max_length=MAX_BYTES - self.bytes_seen + 1)
            if not dec.eof or dec.unused_data:
                raise ExportBlocked()
            self.verify(plain, depth + 1)
            return
        if len(data) >= 262 and data[257:262] == b'ustar':
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
                for item in archive:
                    self.members += 1
                    if (self.members > MAX_MEMBERS or not (item.isfile() or item.isdir())
                            or item.pax_headers or item.uname or item.gname or item.uid or item.gid):
                        raise ExportBlocked()
                    self.guard.check_text(item.name)
                    if item.isfile():
                        with archive.extractfile(item) as source:
                            self.verify(self.read_member(source, item.size), depth + 1)
            return
        self.guard.scan(io.BytesIO(data))


def sanitized_snapshot(source, private, redactor, timeout_seconds=300):
    """Return a separately inspected copy and its original/output digests."""
    source.seek(0)
    original = source.read(MAX_BYTES + 1)
    if len(original) > MAX_BYTES:
        raise ExportBlocked()
    cleaner = Sanitizer(redactor, timeout_seconds)
    try:
        result = cleaner.transform(original)
        if len(result) > MAX_BYTES:
            raise ExportBlocked()
        # Reinspect decoded structure and all leaf bytes, not gzip/zip entropy.
        # A fresh budget is independent of the transform's accounting.
        Sanitizer(redactor, timeout_seconds).verify(result)
    except (OSError, EOFError, ValueError, tarfile.TarError, zipfile.BadZipFile,
            zipfile.LargeZipFile, lzma.LZMAError, zlib.error, RecursionError) as exc:
        raise ExportBlocked() from exc
    snapshot = tempfile.TemporaryFile(dir=private)
    try:
        snapshot.write(result)
        snapshot.flush()
        snapshot.seek(0)
        return snapshot, {'status': 'ready', 'sanitized': True,
                          'source_sha256': hashlib.sha256(original).hexdigest(),
                          'size_bytes': len(result), 'sha256': hashlib.sha256(result).hexdigest(),
                          'redacted_files': cleaner.changed_files,
                          'redacted_fields': cleaner.changed_fields}
    except BaseException:
        snapshot.close()
        raise
