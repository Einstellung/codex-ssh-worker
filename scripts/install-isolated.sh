#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $(id -u) != 0 || -z ${SUDO_USER:-} || ${SUDO_USER} == root ]]; then
  echo 'Run this installer using sudo from the intended Claude user account.' >&2
  exit 1
fi

operator_user=$SUDO_USER
operator_home=$(getent passwd "$operator_user" | cut -d: -f6)
operator_uid=$(id -u "$operator_user")
source_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
source_private=$operator_home/.local/share/codex-worker-private
install_root=/opt/codex-worker
service_home=/var/lib/codex-worker
uv_binary=$operator_home/.local/bin/uv

if [[ -e $install_root || -e $service_home ]] || id codex-worker >/dev/null 2>&1; then
  echo 'An installation already exists; refusing to replace it.' >&2
  exit 1
fi
for required_file in resources.json credentials.json policy.json known_hosts; do
  test -f "$source_private/$required_file"
done
test -f "$operator_home/.codex/auth.json"
test -x "$uv_binary"
native_codex=$(python3 - "$source_private/resources.json" <<'PY'
import json
import sys
from pathlib import Path
path = Path(json.loads(Path(sys.argv[1]).read_text())['codex_binary']).resolve()
if path.read_bytes()[:4] != b'\x7fELF':
    raise SystemExit('A standalone native Codex binary is required')
print(path)
PY
)
test -x "$(dirname -- "$native_codex")/codex-code-mode-host"

if python3 - "$source_private/worker.sock" <<'PY'
import socket
import sys
with socket.socket(socket.AF_UNIX) as connection:
    connection.settimeout(2)
    try:
        connection.connect(sys.argv[1])
    except OSError:
        raise SystemExit(1)
PY
then
  echo 'Stop the development worker before migrating private state.' >&2
  exit 1
fi

install -d -m 755 "$install_root"
cp -a "$source_root/codex_worker" "$source_root/pyproject.toml" "$source_root/requirements.lock" "$source_root/README.md" "$install_root/"
find "$install_root" -type d -name __pycache__ -prune -exec rm -rf -- {} +
install -m 755 "$native_codex" "$install_root/codex"
install -m 755 "$(dirname -- "$native_codex")/codex-code-mode-host" "$install_root/codex-code-mode-host"
"$uv_binary" venv --python /usr/bin/python3 "$install_root/venv"
"$uv_binary" pip install --python "$install_root/venv/bin/python" -r "$install_root/requirements.lock"
"$uv_binary" pip install --python "$install_root/venv/bin/python" --no-deps "$install_root"
chmod -R go+rX "$install_root"
chown -R root:root "$install_root"

useradd --system --user-group --home-dir "$service_home" --shell /usr/sbin/nologin codex-worker
mv -- "$source_private" "$service_home"
rm -f -- "$service_home/worker.sock"
install -d -m 700 "$service_home/.codex"
install -m 600 "$operator_home/.codex/auth.json" "$service_home/.codex/auth.json"
python3 - "$service_home/resources.json" "$operator_uid" <<'PY'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
settings = json.loads(path.read_text())
settings['codex_binary'] = '/opt/codex-worker/codex'
settings['client_uid'] = int(sys.argv[2])
path.write_text(json.dumps(settings, ensure_ascii=False, indent=2))
path.chmod(0o600)
PY
chown -R codex-worker:codex-worker "$service_home"
chmod 700 "$service_home"

operator_group=$(id -gn "$operator_user")
cat > /etc/systemd/system/codex-worker.service <<EOF
[Unit]
Description=Private Codex task worker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=codex-worker
Group=$operator_group
WorkingDirectory=/opt/codex-worker
RuntimeDirectory=codex-worker
RuntimeDirectoryMode=0750
UMask=0077
ExecStart=/opt/codex-worker/venv/bin/python -m codex_worker.cli serve --private-dir=/var/lib/codex-worker --socket=/run/codex-worker/worker.sock
Restart=on-failure
RestartSec=5
KillMode=control-group
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/codex-worker /run/codex-worker
EnvironmentFile=-/etc/codex-worker.env
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
EOF

python3 - /etc/codex-worker.env <<'PY'
import os
import sys
from pathlib import Path
names = ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')
lines = []
for name in names:
    value = os.environ.get(name)
    if value and '\n' not in value and '\r' not in value:
        escaped = value.replace('\\', '\\\\').replace('"', '\\"')
        lines.append(f'{name}="{escaped}"')
path = Path(sys.argv[1])
path.write_text('\n'.join(lines) + '\n')
path.chmod(0o600)
PY
systemctl daemon-reload
systemctl enable --now codex-worker.service
systemctl is-active --quiet codex-worker.service
echo 'Installed. Register the public client using:'
echo 'claude mcp add --scope user --transport stdio codex-worker -- /opt/codex-worker/venv/bin/python -m codex_worker.cli mcp --socket /run/codex-worker/worker.sock'
