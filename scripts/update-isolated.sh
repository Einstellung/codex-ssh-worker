#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $(id -u) != 0 || -z ${SUDO_USER:-} || ${SUDO_USER} == root ]]; then
  echo 'Run using sudo from the original operator account.' >&2
  exit 1
fi
if [[ ${1:-} != --apply || $# != 1 ]]; then
  echo 'Usage: sudo bash scripts/update-isolated.sh --apply' >&2
  echo 'This updates local worker code and restarts its service. Running tasks keep running and are adopted by the restarted service.' >&2
  exit 1
fi

source_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
install_root=/opt/codex-worker
test -d "$install_root/codex_worker"
test -f /etc/systemd/system/codex-worker.service
test -x "$install_root/venv/bin/python"
systemctl is-active --quiet codex-worker.service

# Running tasks no longer block an update: the service no longer kills them on
# exit and the restarted service adopts them. This only counts them so the
# operator knows a restart is happening underneath live work. It prints a
# number and never task details; an unreadable history is reported, not fatal.
count_active() {
python3 - /var/lib/codex-worker/jobs <<'PY'
import json
import sys
from pathlib import Path

terminal = {'completed', 'failed', 'blocked', 'partial', 'cancelled', 'timed_out', 'interrupted'}
try:
    active = sum(1 for path in Path(sys.argv[1]).glob('job_*/state.json')
                 if json.loads(path.read_text()).get('status') not in terminal)
except (OSError, ValueError, TypeError, AttributeError):
    print('Task history could not be counted; continuing, running tasks are adopted after restart.')
else:
    if active:
        print(f'{active} task(s) are queued or running. They keep running across this restart and are adopted by the new service.')
PY
}

# Older installs were written with KillMode=control-group, under which a
# restart kills every task process in the unit's cgroup. Fix that with a
# drop-in before the restart below; daemon-reload alone does not restart or
# stop the service, and the new KillMode applies to that next stop.
ensure_killmode() {
  local current
  current=$(systemctl show -p KillMode --value codex-worker.service)
  if [[ $current != process ]]; then
    install -d -o root -g root -m 755 /etc/systemd/system/codex-worker.service.d
    printf '[Service]\n# Let delegated tasks survive service stop/restart; see install-isolated.sh.\nKillMode=process\n' \
      > /etc/systemd/system/codex-worker.service.d/killmode.conf
    chmod 644 /etc/systemd/system/codex-worker.service.d/killmode.conf
    systemctl daemon-reload
    [[ $(systemctl show -p KillMode --value codex-worker.service) == process ]] || {
      echo 'Could not set KillMode=process; refusing a restart that would kill running tasks.' >&2
      exit 1
    }
    echo 'Set KillMode=process for codex-worker.service (drop-in killmode.conf; service not restarted by this step).'
  fi
}
ensure_killmode

# The service being stopped is the *installed* code. Versions before task
# adoption kill their own children on exit and leave no process record, so
# for that one transition running tasks would still die: keep refusing then.
if ! grep -q 'def adopt' "$install_root/codex_worker/service.py"; then
  if [[ -n $(count_active) ]]; then
    echo 'The installed worker predates task adoption and would kill running tasks on restart; finish them first.' >&2
    exit 1
  fi
fi

package_dir=$(cd / && "$install_root/venv/bin/python" - <<'PY'
import importlib.util
from pathlib import Path

path = Path(importlib.util.find_spec('codex_worker').origin).resolve().parent
if not path.is_relative_to('/opt/codex-worker/venv'):
    raise SystemExit('Unexpected installed package path; refusing to update.')
print(path)
PY
)

staging=$(mktemp -d "$install_root/update.XXXXXXXX")
service_stopped=0
update_finished=0
cleanup() {
  if [[ $service_stopped == 1 && $update_finished == 0 ]]; then
    for module in attachments.py exports.py processes.py push.py remote_job.sh; do
      if [[ ! -f $staging/source-backup/$module ]]; then rm -f -- "$install_root/codex_worker/$module"; fi
      if [[ ! -f $staging/package-backup/$module ]]; then rm -f -- "$package_dir/$module"; fi
    done
    cp -a -- "$staging/source-backup/." "$install_root/codex_worker/"
    cp -a -- "$staging/package-backup/." "$package_dir/"
    cp -a -- "$staging/README-backup.md" "$install_root/README.md"
    systemctl start codex-worker.service || true
  fi
  rm -rf -- "$staging"
}
trap cleanup EXIT
cp -a -- "$install_root/codex_worker" "$staging/source-backup"
cp -a -- "$package_dir" "$staging/package-backup"
cp -a -- "$install_root/README.md" "$staging/README-backup.md"
mkdir "$staging/new"
modules=(__init__.py cli.py config.py mcp_api.py privacy.py remote.py service.py attachments.py exports.py processes.py push.py remote_job.sh)
for module in "${modules[@]}"; do
  install -o root -g root -m 644 "$source_root/codex_worker/$module" "$staging/new/$module"
done
install -o root -g root -m 644 "$source_root/README.md" "$staging/new/README.md"
python3 - "$staging/new" <<'PY'
import ast
import sys
from pathlib import Path

for path in Path(sys.argv[1]).glob('*.py'):
    ast.parse(path.read_text())
PY

# Report right before the restart. Submissions that arrive while the service is
# down fail with worker_unavailable and are not queued; callers retry them.
count_active
echo 'Restarting codex-worker.service now.'
systemctl stop codex-worker.service
service_stopped=1
for destination in "$install_root/codex_worker" "$package_dir"; do
  for module in "${modules[@]}"; do
    install -o root -g root -m 644 "$staging/new/$module" "$destination/$module"
  done
  find "$destination" -type d -name __pycache__ -prune -exec rm -rf -- {} +
done
install -o root -g root -m 644 "$staging/new/README.md" "$install_root/README.md"
systemctl start codex-worker.service
systemctl is-active --quiet codex-worker.service
update_finished=1
echo 'Updated local worker code. Private config, authentication, jobs, and remote state were not migrated or replaced.'
echo 'Reconnect the MCP client. Existing task tools now accept binary attachments; get_artifact can save original files to a caller-local destination.'
