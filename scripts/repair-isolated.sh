#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $(id -u) != 0 || -z ${SUDO_USER:-} || ${SUDO_USER} == root ]]; then
  echo 'Run using sudo from the original operator account.' >&2
  exit 1
fi

operator_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
test -x /opt/codex-worker/codex
test -f /etc/systemd/system/codex-worker.service
helper=$(python3 - "$operator_home" <<'PY'
import hashlib
import sys
from pathlib import Path

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').digest()

expected = digest(Path('/opt/codex-worker/codex'))
root = Path(sys.argv[1]) / '.local/share/pnpm/global/5/.pnpm'
for binary in root.glob('*codex*-linux-x64/node_modules/@openai/codex/vendor/*/bin/codex'):
    sibling = binary.with_name('codex-code-mode-host')
    if sibling.is_file() and digest(binary) == expected:
        with sibling.open('rb') as stream:
            if stream.read(4) != b'\x7fELF':
                continue
        print(sibling)
        break
else:
    raise SystemExit('No matching Codex tool host found; refusing to mix versions.')
PY
)

install -o root -g root -m 755 "$helper" /opt/codex-worker/codex-code-mode-host
systemctl is-active --quiet codex-worker.service
echo 'Installed the matching tool host. No service restart or remote changes were required.'
