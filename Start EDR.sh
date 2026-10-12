#!/usr/bin/env bash
#
# EDR1 - Launch All Modules
# =========================
#
# Repository layout:
#
#   ICT30016-EDR1/
#   ├── README.md
#   ├── docs/
#   ├── playbooks/
#   └── src/
#       ├── core/
#       ├── modules/
#       │   ├── injection/
#       │   ├── network/
#       │   ├── malware/
#       │   ├── os_agent/
#       │   ├── cron_agent/
#       │   └── brute_force_agent/
#       └── utils/
#
# This launcher belongs at the repository root and starts the existing
# modules from their own directories. It does NOT install/reinstall
# Juice Shop or Wazuh.
#
# Usage:
#   ./launch_all.sh
#   ./launch_all.sh start
#   ./launch_all.sh stop
#   ./launch_all.sh restart
#   ./launch_all.sh status
#   ./launch_all.sh logs
#   ./launch_all.sh dashboard
#
# Injection is Wazuh-driven, so there is no separate Python process for
# injection to launch. Starting Wazuh Manager enables the injection rules
# and Active Response already installed by the injection module.

set -u

# ---------------------------------------------------------------------------
# Repository paths
# ---------------------------------------------------------------------------

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="${PROJECT_ROOT}/src"
MODULE_ROOT="${SRC_ROOT}/modules"
CORE_ROOT="${SRC_ROOT}/core"

STATE_DIR="${PROJECT_ROOT}/.edr1-runtime"
LOG_DIR="${STATE_DIR}/logs"
PID_DIR="${STATE_DIR}/pids"

mkdir -p "$LOG_DIR" "$PID_DIR"

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

log() {
    echo "[$(timestamp)] $*"
}

error() {
    log "ERROR: $*" >&2
}

# ---------------------------------------------------------------------------
# Process helpers
# ---------------------------------------------------------------------------

pid_file() {
    echo "${PID_DIR}/$1.pid"
}

log_file() {
    echo "${LOG_DIR}/$1.log"
}

is_running() {
    kill -0 "$1" 2>/dev/null
}

# Return the first existing directory from a list.
find_dir() {
    local path
    for path in "$@"; do
        if [[ -d "$path" ]]; then
            echo "$path"
            return 0
        fi
    done
    return 1
}

# Find one exact file underneath src/modules.
# This keeps the launcher compatible with the repository layout without
# assuming that every module uses the same internal filename structure.
find_module_file() {
    local filename="$1"
    find "$MODULE_ROOT" -type f -name "$filename" -print -quit 2>/dev/null
}

# ---------------------------------------------------------------------------
# Start/stop helpers
# ---------------------------------------------------------------------------

start_process() {
    local name="$1"
    local workdir="$2"
    shift 2

    local pidfile logfile old_pid pid
    pidfile="$(pid_file "$name")"
    logfile="$(log_file "$name")"

    if [[ -f "$pidfile" ]]; then
        old_pid="$(cat "$pidfile" 2>/dev/null || true)"

        if [[ -n "$old_pid" ]] && is_running "$old_pid"; then
            log "$name is already running (PID $old_pid)"
            return 0
        fi

        rm -f "$pidfile"
    fi

    log "Starting $name..."

    (
        cd "$workdir" || exit 1
        exec "$@"
    ) >>"$logfile" 2>&1 &

    pid=$!
    echo "$pid" > "$pidfile"

    sleep 1

    if is_running "$pid"; then
        log "$name started (PID $pid)"
    else
        error "$name exited during startup. Check:"
        error "  $logfile"
        rm -f "$pidfile"
        return 1
    fi
}

start_pipeline() {
    local name="$1"
    local workdir="$2"
    local command="$3"

    local pidfile logfile old_pid pid
    pidfile="$(pid_file "$name")"
    logfile="$(log_file "$name")"

    if [[ -f "$pidfile" ]]; then
        old_pid="$(cat "$pidfile" 2>/dev/null || true)"

        if [[ -n "$old_pid" ]] && is_running "$old_pid"; then
            log "$name is already running (PID $old_pid)"
            return 0
        fi

        rm -f "$pidfile"
    fi

    log "Starting $name..."

    # A new process group is used so stop_all can terminate the complete
    # pipeline rather than leaving monitor/detection/response children behind.
    (
        cd "$workdir" || exit 1
        exec setsid bash -o pipefail -c "$command"
    ) >>"$logfile" 2>&1 &

    pid=$!
    echo "$pid" > "$pidfile"

    sleep 1

    if is_running "$pid"; then
        log "$name started (PID $pid)"
    else
        error "$name exited during startup. Check:"
        error "  $logfile"
        rm -f "$pidfile"
        return 1
    fi
}

stop_process() {
    local name="$1"
    local pidfile pid

    pidfile="$(pid_file "$name")"

    [[ -f "$pidfile" ]] || return 0

    pid="$(cat "$pidfile" 2>/dev/null || true)"

    if [[ -n "$pid" ]] && is_running "$pid"; then
        log "Stopping $name (PID $pid)..."

        # Kill the process group as well as the launcher process.
        kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true

        for _ in {1..10}; do
            if ! is_running "$pid"; then
                break
            fi
            sleep 0.2
        done

        if is_running "$pid"; then
            kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
        fi
    fi

    rm -f "$pidfile"
}

# ---------------------------------------------------------------------------
# Existing system services
# ---------------------------------------------------------------------------

start_services() {
    log "Checking existing system services..."

    # Juice Shop is already installed on the provided Ubuntu VM.
    if systemctl list-unit-files 2>/dev/null | grep -q '^juice-shop.service'; then
        if systemctl is-active --quiet juice-shop; then
            log "Juice Shop: already running."
        else
            log "Starting Juice Shop..."
            sudo systemctl start juice-shop
        fi
    else
        log "Juice Shop service not found; leaving it unchanged."
    fi

    # Wazuh provides the injection detection/response pipeline.
    if systemctl list-unit-files 2>/dev/null | grep -q '^wazuh-manager.service'; then
        if systemctl is-active --quiet wazuh-manager; then
            log "Wazuh Manager: already running."
        else
            log "Starting Wazuh Manager..."
            sudo systemctl start wazuh-manager
        fi
    else
        log "Wazuh Manager service not found; injection module cannot run."
    fi
}

# ---------------------------------------------------------------------------
# Network module
# ---------------------------------------------------------------------------

start_network() {
    local detection monitoring module_dir

    detection="$(find_module_file "detection_engine.py" || true)"
    monitoring="$(find_module_file "monitoring_engine.py" || true)"

    if [[ -z "$detection" || -z "$monitoring" ]]; then
        log "Network module: required files not found under src/modules; skipping."
        return 0
    fi

    module_dir="$(dirname "$detection")"

    # detection_engine.py captures packets and writes raw alerts. It also
    # calls response_engine.respond(), so response_engine.py is not started
    # as a separate process.
    start_process \
        "network-monitoring" \
        "$(dirname "$monitoring")" \
        sudo -n python3 "$(basename "$monitoring")"

    start_process \
        "network-detection" \
        "$module_dir" \
        sudo -n python3 "$(basename "$detection")"
}

# ---------------------------------------------------------------------------
# Injection module
# ---------------------------------------------------------------------------

start_injection() {
    # Injection is integrated with Wazuh:
    #
    # Juice Shop security/access logs
    #          -> Wazuh decoder
    #          -> custom injection rules
    #          -> Wazuh Active Response
    #
    # Therefore there is deliberately no second injection daemon here.
    log "Injection module: Wazuh Manager/rules/Active Response are active."
}

# ---------------------------------------------------------------------------
# Malware module
# ---------------------------------------------------------------------------

start_malware() {
    local collector module_dir

    collector="$(find_module_file "edr_alert_collector.py" || true)"

    if [[ -z "$collector" ]]; then
        log "Malware module: edr_alert_collector.py not found; skipping."
        return 0
    fi

    module_dir="$(dirname "$collector")"

    start_process \
        "malware-collector" \
        "$module_dir" \
        sudo -n python3 "$(basename "$collector")"
}

# ---------------------------------------------------------------------------
# OS SUID module
# ---------------------------------------------------------------------------

start_os_suid() {
    local monitor detection response module_dir

    monitor="$(find_module_file "os_agent/monitor.py" || true)"

    # find() does not normally match a path argument with this form on all
    # systems, so fall back to the directory lookup below.
    if [[ -z "$monitor" ]]; then
        monitor="$(find "$MODULE_ROOT" -type f -path "*/os_agent/monitor.py" -print -quit 2>/dev/null)"
    fi

    if [[ -z "$monitor" ]]; then
        log "OS SUID module: os_agent/monitor.py not found; skipping."
        return 0
    fi

    module_dir="$(dirname "$monitor")"
    detection="${module_dir}/detection.py"
    response="${module_dir}/response.py"

    if [[ ! -f "$detection" || ! -f "$response" ]]; then
        log "OS SUID module: monitor/detection/response files incomplete; skipping."
        return 0
    fi

    # monitor -> detection -> response
    #
    # The detection output is also written to the persistent OS evidence file
    # so the central GUI/CLI dashboard can display the event.
    start_pipeline \
        "os-suid" \
        "$module_dir" \
        'sudo -n python3 monitor.py \
         | python3 detection.py \
         | tee -a /var/log/edr_os_alerts.jsonl \
         | sudo -n python3 response.py \
         | sudo -n tee -a /var/log/edr_os_response_actions.jsonl >/dev/null'
}

# ---------------------------------------------------------------------------
# OS Cron module
# ---------------------------------------------------------------------------

start_os_cron() {
    local monitor module_dir detection response

    monitor="$(find "$MODULE_ROOT" -type f -path "*/cron_agent/monitor.py" -print -quit 2>/dev/null)"

    if [[ -z "$monitor" ]]; then
        log "OS Cron module: cron_agent/monitor.py not found; skipping."
        return 0
    fi

    module_dir="$(dirname "$monitor")"
    detection="${module_dir}/detection.py"
    response="${module_dir}/response.py"

    if [[ ! -f "$detection" || ! -f "$response" ]]; then
        log "OS Cron module: monitor/detection/response files incomplete; skipping."
        return 0
    fi

    # monitor -> detection -> response
    start_pipeline \
        "os-cron" \
        "$module_dir" \
        'sudo -n python3 monitor.py \
         | python3 detection.py \
         | tee -a /var/log/edr_os_alerts.jsonl \
         | sudo -n python3 response.py \
         | sudo -n tee -a /var/log/edr_os_response_actions.jsonl >/dev/null'
}

# ---------------------------------------------------------------------------
# Brute-force module
# ---------------------------------------------------------------------------

start_brute_force() {
    local monitor detection response juice_monitor module_dir

    monitor="$(find "$MODULE_ROOT" -type f -path "*/brute_force_agent/monitor.py" -print -quit 2>/dev/null)"

    if [[ -z "$monitor" ]]; then
        log "Brute Force module: brute_force_agent/monitor.py not found; skipping."
        return 0
    fi

    module_dir="$(dirname "$monitor")"
    detection="${module_dir}/detection.py"
    response="${module_dir}/response.py"
    juice_monitor="${module_dir}/juice_shop_monitor.py"

    if [[ ! -f "$detection" || ! -f "$response" || ! -f "$juice_monitor" ]]; then
        log "Brute Force module: required files are incomplete; skipping."
        return 0
    fi

    # Two monitoring sources feed one detector:
    #
    #   SSH monitor --------\
    #                         -> detection -> response
    #   Juice Shop monitor -/
    #
    # The response stage is responsible for the automated firewall action.
    start_pipeline \
        "brute-force" \
        "$module_dir" \
        '(sudo -n python3 monitor.py & \
          sudo -n python3 juice_shop_monitor.py & \
          wait) \
         | python3 detection.py \
         | tee -a /var/log/edr_bruteforce_alerts.jsonl \
         | sudo -n python3 response.py \
         | sudo -n tee -a /var/log/edr_bruteforce_response_actions.jsonl >/dev/null'
}

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

find_dashboard() {
    local candidate

    # Prefer the central dashboard in src/core, then look through src.
    for candidate in \
        "$CORE_ROOT/GUI-Dashboard.py" \
        "$CORE_ROOT/GUI-Dashboard-Brute-Force-OS-Fixed-Commented.py" \
        "$SRC_ROOT/GUI-Dashboard.py" \
        "$PROJECT_ROOT/GUI-Dashboard.py"
    do
        if [[ -f "$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done

    find "$SRC_ROOT" -type f \( \
        -name "GUI-Dashboard.py" \
        -o -name "GUI-Dashboard(3).py" \
        -o -name "GUI-Dashboard-Brute-Force-OS-Fixed-Commented.py" \
    \) -print -quit 2>/dev/null
}

start_dashboard() {
    local dashboard
    dashboard="$(find_dashboard || true)"

    if [[ -z "$dashboard" ]]; then
        log "GUI dashboard not found under src/; skipping dashboard."
        return 0
    fi

    # Tkinter should run as the logged-in desktop user, not as root.
    start_process \
        "dashboard" \
        "$(dirname "$dashboard")" \
        python3 "$(basename "$dashboard")"
}

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

status_all() {
    echo
    echo "============================================================"
    echo "EDR1 - MODULE STATUS"
    echo "============================================================"
    printf "%-24s %-12s %s\n" "MODULE" "STATUS" "PID"
    echo "------------------------------------------------------------"

    local names=(
        "network-monitoring"
        "network-detection"
        "malware-collector"
        "os-suid"
        "os-cron"
        "brute-force"
        "dashboard"
    )

    local name pidfile pid

    for name in "${names[@]}"; do
        pidfile="$(pid_file "$name")"

        if [[ -f "$pidfile" ]]; then
            pid="$(cat "$pidfile" 2>/dev/null || true)"

            if [[ -n "$pid" ]] && is_running "$pid"; then
                printf "%-24s %-12s %s\n" "$name" "RUNNING" "$pid"
                continue
            fi
        fi

        printf "%-24s %-12s %s\n" "$name" "STOPPED" "-"
    done

    echo "------------------------------------------------------------"

    if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
        echo "Wazuh Manager:           RUNNING"
    else
        echo "Wazuh Manager:           STOPPED"
    fi

    if systemctl is-active --quiet juice-shop 2>/dev/null; then
        echo "Juice Shop:               RUNNING"
    else
        echo "Juice Shop:               STOPPED / not found"
    fi

    echo "============================================================"
    echo
}

# ---------------------------------------------------------------------------
# Stop
# ---------------------------------------------------------------------------

stop_all() {
    log "Stopping EDR1 module processes..."

    stop_process "dashboard"
    stop_process "brute-force"
    stop_process "os-cron"
    stop_process "os-suid"
    stop_process "malware-collector"
    stop_process "network-detection"
    stop_process "network-monitoring"

    # Wazuh and Juice Shop deliberately remain running. They are existing
    # system services and are not owned by this launcher.
    log "EDR1 module processes stopped."
}

# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

show_logs() {
    echo
    echo "EDR1 launcher logs:"
    echo "$LOG_DIR"
    echo

    ls -lh "$LOG_DIR" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Start everything
# ---------------------------------------------------------------------------

start_all() {
    log "============================================================"
    log "EDR1 - Starting all modules"
    log "Repository: $PROJECT_ROOT"
    log "============================================================"

    if [[ ! -d "$SRC_ROOT" || ! -d "$MODULE_ROOT" ]]; then
        error "Expected repository layout not found."
        error "Expected:"
        error "  $PROJECT_ROOT/src/modules/"
        return 1
    fi

    # Authenticate once. The individual modules then use sudo -n so they
    # do not each prompt for a password.
    sudo -v || {
        error "sudo authentication failed."
        return 1
    }

    start_services
    start_network
    start_injection
    start_malware
    start_os_suid
    start_os_cron
    start_brute_force
    start_dashboard

    log "============================================================"
    log "EDR1 startup complete."
    log "Run: $0 status"
    log "Logs: $LOG_DIR"
    log "============================================================"
}

# ---------------------------------------------------------------------------
# Command dispatcher
# ---------------------------------------------------------------------------

case "${1:-start}" in
    start)
        start_all
        ;;

    stop)
        stop_all
        ;;

    restart)
        stop_all
        sleep 2
        start_all
        ;;

    status)
        status_all
        ;;

    logs)
        show_logs
        ;;

    dashboard)
        start_dashboard
        ;;

    *)
        echo "Usage: $0 {start|stop|restart|status|logs|dashboard}"
        exit 1
        ;;
esac
