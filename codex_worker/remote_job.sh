#!/usr/bin/env bash
# codex-job: durable background jobs for an unprivileged remote shell account.
#
#   codex-job start <id> -- <cmd> [args...]   run argv (quoted with printf %q)
#   codex-job start <id> < script.sh          run command text read from stdin
#   codex-job status <id>                     one JSON line
#   codex-job tail <id> [lines]               last lines of the merged log
#   codex-job kill <id>                       SIGTERM process group, SIGKILL after 5 s
#   codex-job ls                              one status JSON line per job
#   codex-job prune <days>                    delete finished jobs older than <days>
#
# State lives in ${CODEX_JOB_ROOT:-~/.codex-jobs}/<id>/. Only bash, coreutils and
# util-linux setsid are needed. Read-only subcommands never create or modify files
# and never read anything outside the job root except /proc/<job pid>/stat.
set -u
umask 077

ROOT="${CODEX_JOB_ROOT:-$HOME/.codex-jobs}"
LOG_MAX="${CODEX_JOB_LOG_MAX:-67108864}"
ROTATE_INTERVAL="${CODEX_JOB_ROTATE_INTERVAL:-5}"
TAIL_MAX_BYTES=262144
ID_RE='^[A-Za-z0-9._-]{1,64}$'
SELF=$(readlink -f -- "${BASH_SOURCE[0]}")

fail() { printf '{"error":"%s"}\n' "$1"; exit "${2:-2}"; }

valid_id() { [[ ${1-} =~ $ID_RE && $1 != . && $1 != .. ]]; }

check_root() { if [[ -L $ROOT ]]; then fail unsafe_root; fi; }

# Prints an integer stored in a file, or null when absent/malformed.
num() {
    local value=""
    [[ -f $1 && ! -L $1 ]] && read -r value < "$1"
    if [[ $value =~ ^-?[0-9]+$ ]]; then printf '%s' "$value"; else printf 'null'; fi
}

# Field 22 of /proc/<pid>/stat; comm may contain spaces, so split after the last ")".
starttime_of() {
    local stat rest
    [[ ${1-} =~ ^[0-9]+$ ]] || return 1
    stat=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
    rest=${stat##*) }
    set -f; set -- $rest; set +f
    [[ -n ${20-} ]] || return 1
    printf '%s' "${20}"
}

# Atomic small-file write: tmp in the same directory, then rename.
put() { printf '%s\n' "$2" > "$1.tmp.$$" && mv -f -- "$1.tmp.$$" "$1"; }

alive() {
    # Prints the recorded pid when that exact process (pid + starttime) still exists.
    local dir=$1 pid="" start="" now
    [[ -f $dir/pid && ! -L $dir/pid ]] || return 1
    read -r pid start < "$dir/pid" || true
    now=$(starttime_of "$pid") || return 1
    [[ -n $start && $now == "$start" ]] || return 1
    printf '%s' "$pid"
}

status_json() {
    local id=$1 dir=$ROOT/$1 pid size=0
    if ! valid_id "$id" || [[ -L $dir || ! -d $dir ]]; then
        printf '{"id":%s,"state":"unknown_id"}\n' "$(valid_id "$id" && printf '"%s"' "$id" || printf null)"
        return
    fi
    [[ -f $dir/log && ! -L $dir/log ]] && size=$(stat -c %s -- "$dir/log" 2>/dev/null || echo 0)
    if [[ -f $dir/exit && ! -L $dir/exit ]]; then
        printf '{"id":"%s","state":"exited","exit_code":%s,"killed":%s,"started_at":%s,"finished_at":%s,"log_bytes":%s}\n' \
            "$id" "$(num "$dir/exit")" "$([[ -e $dir/killed ]] && echo true || echo false)" \
            "$(num "$dir/started_at")" "$(num "$dir/finished_at")" "$size"
    elif pid=$(alive "$dir"); then
        printf '{"id":"%s","state":"running","pid":%s,"started_at":%s,"log_bytes":%s}\n' \
            "$id" "$pid" "$(num "$dir/started_at")" "$size"
    else
        # No exit code and no live process: never report this as success.
        printf '{"id":"%s","state":"lost","started_at":%s,"log_bytes":%s}\n' \
            "$id" "$(num "$dir/started_at")" "$size"
    fi
}

rotate_loop() {
    # copytruncate: the log is opened with O_APPEND, so truncation is safe for the writer.
    local dir=$1 child=$2 size
    while kill -0 "$child" 2>/dev/null; do
        size=$(stat -c %s -- "$dir/log" 2>/dev/null || echo 0)
        if (( size > LOG_MAX )); then
            tail -c $((LOG_MAX / 2)) -- "$dir/log" > "$dir/log.1.tmp" && mv -f -- "$dir/log.1.tmp" "$dir/log.1"
            : > "$dir/log"
        fi
        sleep "$ROTATE_INTERVAL"
    done
}

run_wrapper() {
    local id=$1 dir=$ROOT/$1 child rotator rc second
    # A caught (not ignored) TERM interrupts wait without being inherited by the command.
    trap ':' TERM
    put "$dir/pid" "$$ $(starttime_of $$)"
    cd -- "$HOME" || cd /
    bash -- "$dir/cmd" < /dev/null >> "$dir/log" 2>&1 &
    child=$!
    rotate_loop "$dir" "$child" < /dev/null > /dev/null 2>&1 &
    rotator=$!
    while :; do
        wait "$child"; rc=$?
        kill -0 "$child" 2>/dev/null || break
    done
    # If the TERM trap interrupted wait, bash still holds the real status.
    wait "$child" 2>/dev/null; second=$?
    [[ $second != 127 ]] && rc=$second
    kill "$rotator" 2>/dev/null
    put "$dir/finished_at" "$(date +%s)"
    [[ -e $dir/exit ]] || put "$dir/exit" "$rc"
}

# Only ever removes "$ROOT/<validated id>".
remove_job() { valid_id "$1" && [[ -n $ROOT ]] && rm -rf -- "$ROOT/$1"; }

cmd_start() {
    local id=${1-} dir i
    valid_id "$id" || fail invalid_id
    shift
    check_root
    mkdir -p -m 700 -- "$ROOT" || fail state_unwritable
    # mkdir without -p is the lock: a second start with the same id is refused.
    mkdir -m 700 -- "$ROOT/$id" 2>/dev/null || fail id_exists
    dir=$ROOT/$id
    if [[ ${1-} == -- ]]; then
        shift
        (( $# > 0 )) || { remove_job "$id"; fail empty_command; }
        # argv is quoted, never re-split: no shell injection through arguments.
        printf '%q ' "$@" > "$dir/cmd"; printf '\n' >> "$dir/cmd"
    else
        cat > "$dir/cmd"
        [[ -s $dir/cmd ]] || { remove_job "$id"; fail empty_command; }
    fi
    : > "$dir/log"
    put "$dir/started_at" "$(date +%s)"
    setsid -f nohup bash -- "$SELF" __run "$id" < /dev/null > /dev/null 2>&1 \
        || { put "$dir/exit" 127; fail spawn_failed 1; }
    for ((i = 0; i < 100; i++)); do
        [[ -s $dir/pid || -e $dir/exit ]] && break
        sleep 0.02
    done
    status_json "$id"
}

cmd_tail() {
    local id=${1-} lines=${2:-100} dir
    valid_id "$id" || fail invalid_id
    [[ $lines =~ ^[0-9]{1,5}$ ]] && (( lines >= 1 && lines <= 10000 )) || fail invalid_lines
    dir=$ROOT/$id
    [[ -d $dir && ! -L $dir && -f $dir/log && ! -L $dir/log ]] || fail unknown_id 1
    tail -n "$lines" -- "$dir/log" | tail -c "$TAIL_MAX_BYTES"
}

cmd_kill() {
    local id=${1-} dir pid start i grace=${CODEX_JOB_KILL_GRACE:-5}
    valid_id "$id" || fail invalid_id
    [[ $grace =~ ^[0-9]{1,3}$ ]] || grace=5
    dir=$ROOT/$id
    [[ -d $dir && ! -L $dir ]] || { status_json "$id"; return; }
    if pid=$(alive "$dir"); then
        read -r _ start < "$dir/pid"
        : > "$dir/killed"
        kill -TERM -- "-$pid" 2>/dev/null
        for ((i = 0; i < grace * 10; i++)); do
            alive "$dir" > /dev/null || break
            sleep 0.1
        done
        # Re-check the start time right before SIGKILL so a reused pid is never hit.
        if [[ $(starttime_of "$pid") == "$start" ]]; then
            kill -KILL -- "-$pid" 2>/dev/null
            sleep 0.1
        fi
        # After SIGKILL no wrapper remains to record the code; record it here.
        for ((i = 0; i < 10; i++)); do [[ -e $dir/exit ]] && break; sleep 0.1; done
        [[ -e $dir/exit ]] || { put "$dir/finished_at" "$(date +%s)"; put "$dir/exit" 137; }
    fi
    status_json "$id"
}

cmd_ls() {
    local dir
    [[ -d $ROOT && ! -L $ROOT ]] || return 0
    for dir in "$ROOT"/*/; do
        [[ -d $dir ]] || continue
        dir=${dir%/}
        status_json "${dir##*/}"
    done
}

cmd_prune() {
    local days=${1-} dir id finished now removed=0
    [[ $days =~ ^[0-9]{1,5}$ ]] || fail invalid_days
    check_root
    [[ -d $ROOT ]] || { printf '{"removed":0}\n'; return; }
    now=$(date +%s)
    for dir in "$ROOT"/*/; do
        dir=${dir%/}; id=${dir##*/}
        valid_id "$id" && [[ ! -L $dir ]] || continue
        alive "$dir" > /dev/null && continue
        [[ -e $dir/exit ]] || continue   # lost jobs are kept for inspection
        finished=$(num "$dir/finished_at")
        [[ $finished == null ]] && continue
        if (( now - finished >= days * 86400 )); then
            remove_job "$id" && removed=$((removed + 1))
        fi
    done
    printf '{"removed":%s}\n' "$removed"
}

case ${1-} in
    start) shift; cmd_start "$@" ;;
    status) valid_id "${2-}" || fail invalid_id; status_json "$2" ;;
    tail) shift; cmd_tail "$@" ;;
    kill) shift; cmd_kill "$@" ;;
    ls) cmd_ls ;;
    prune) shift; cmd_prune "$@" ;;
    __run) valid_id "${2-}" || exit 2; run_wrapper "$2" ;;
    *) fail usage ;;
esac
