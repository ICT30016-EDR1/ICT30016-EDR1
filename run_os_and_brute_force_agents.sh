#!/usr/bin/env bash
#
# run_os_and_brute_force_agents.sh
# ==================================
# Launches the OS (SUID + cron) and "Brute force" components as
# independent background processes. Each stage (monitor/detection/
# response) reads its input from, and writes its output to, the
# shared on-disk files defined once in src/modules/common/events.py --
# there is no shell pipe between any of them. See that module's
# docstring for why: it used to be monitor | detection | response, but
# the GUI (core/GUI-Dashboard.py) only ever reads fixed files, same as
# the network/malware/injection modules already do, so these modules
# now write there directly instead of relying on stdout being piped
# somewhere.
#
# Because nothing here is chained with `|` any more, each process can
# be started, stopped and restarted on its own -- this script just
# starts all of them together for convenience.
#
# Layout this script expects (repo root):
#   core/GUI-Dashboard.py
#   src/modules/common/events.py
#   src/modules/OS/{suid,cron}_{monitor,detection,response}.py
#   src/modules/Brute force/{ssh_monitor,juice_shop_monitor,
#                             brute_force_detection,brute_force_response}.py
# Note "Brute force" has a space in it -- every path below is kept in
# its own array slot and always expanded in double quotes so that
# space is never word-split.
#
# Usage:
#   sudo ./run_os_and_brute_force_agents.sh start
#   ./run_os_and_brute_force_agents.sh status
#   sudo ./run_os_and_brute_force_agents.sh stop
#
# Needs sudo to start: OS/suid_monitor.py + suid_response.py,
# OS/cron_monitor.py + cron_response.py, and "Brute force"/ssh_monitor.py
# + brute_force_response.py all need root (each module's own usage
# comment explains why). The three detection stages (suid_detection.py,
# cron_detection.py, brute_force_detection.py) need neither.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RUN_DIR="/var/run/edr_pipelines"
LOG_DIR="/var/log/edr_pipeline_debug"

# Parallel arrays (NOT one whitespace-separated string per process) --
# "Brute force/..." paths contain a literal space, and splitting on
# whitespace would break those into the wrong number of fields. Every
# index below lines up across all three arrays.
PROC_NAMES=(
    os_monitor
    os_detection
    os_response
    cron_monitor
    cron_detection
    cron_response
    brute_ssh_monitor
    brute_web_monitor
    brute_detection
    brute_response
)
PROC_SCRIPTS=(
    "src/modules/OS/suid_monitor.py"
    "src/modules/OS/suid_detection.py"
    "src/modules/OS/suid_response.py"
    "src/modules/OS/cron_monitor.py"
    "src/modules/OS/cron_detection.py"
    "src/modules/OS/cron_response.py"
    "src/modules/Brute force/ssh_monitor.py"
    "src/modules/Brute force/juice_shop_monitor.py"
    "src/modules/Brute force/brute_force_detection.py"
    "src/modules/Brute force/brute_force_response.py"
)
PROC_NEEDS_SUDO=(1 0 1 1 0 1 1 1 0 1)

ensure_dirs() {
    sudo mkdir -p "$RUN_DIR" "$LOG_DIR" /var/log
    # The individual modules create/chmod the actual dashboard log
    # files themselves (via src/modules/common/events.py's
    # append_jsonl), the first time each one has something to write.
}

pid_file() { echo "$RUN_DIR/$1.pid"; }
debug_log() { echo "$LOG_DIR/$1.log"; }

is_running() {
    local pf
    pf="$(pid_file "$1")"
    [[ -f "$pf" ]] && kill -0 "$(cat "$pf")" 2>/dev/null
}

start_one() {
    local name="$1" script="$2" needs_sudo="$3"
    if is_running "$name"; then
        echo "[*] $name already running (pid $(cat "$(pid_file "$name")"))"
        return
    fi
    if [[ ! -f "$script" ]]; then
        echo "[!] $name: '$script' not found -- skipping. Check the repo layout matches what this script expects (see the comment at the top of this file)."
        return
    fi
    if [[ "$needs_sudo" == "1" ]]; then
        nohup sudo python3 "$script" >"$(debug_log "$name")" 2>&1 &
    else
        nohup python3 "$script" >"$(debug_log "$name")" 2>&1 &
    fi
    echo $! > "$(pid_file "$name")"
    echo "[*] started $name (pid $!, debug log: $(debug_log "$name"))"
}

start_all() {
    ensure_dirs
    for i in "${!PROC_NAMES[@]}"; do
        start_one "${PROC_NAMES[$i]}" "${PROC_SCRIPTS[$i]}" "${PROC_NEEDS_SUDO[$i]}"
    done
    echo
    echo "[*] Dashboard reads these files (paths defined in src/modules/common/events.py):"
    PYTHONPATH="src/modules" python3 - <<'PY'
from common.events import OS_ALERT_LOG, OS_RESPONSE_LOG, BRUTE_ALERT_LOG, BRUTE_RESPONSE_LOG
for p in (OS_ALERT_LOG, OS_RESPONSE_LOG, BRUTE_ALERT_LOG, BRUTE_RESPONSE_LOG):
    print(f"      {p}")
PY
}

stop_all() {
    for name in "${PROC_NAMES[@]}"; do
        pf="$(pid_file "$name")"
        if [[ -f "$pf" ]]; then
            pid="$(cat "$pf")"
            sudo kill -TERM "$pid" 2>/dev/null
            kill -TERM "$pid" 2>/dev/null
            rm -f "$pf"
            echo "[*] stopped $name"
        else
            echo "[*] $name was not running"
        fi
    done
}

status_all() {
    for i in "${!PROC_NAMES[@]}"; do
        name="${PROC_NAMES[$i]}"
        script="${PROC_SCRIPTS[$i]}"
        if is_running "$name"; then
            echo "[*] $name: RUNNING (pid $(cat "$(pid_file "$name")"))"
        elif [[ ! -f "$script" ]]; then
            echo "[*] $name: stopped (script not found: '$script')"
        else
            echo "[*] $name: stopped"
        fi
    done
}

case "${1:-}" in
    start)  start_all ;;
    stop)   stop_all ;;
    status) status_all ;;
    *)
        echo "Usage: $0 {start|stop|status}"
        exit 1
        ;;
esac
