
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
#       │   ├── os/
#       │   └── brute_force/
#       └── utils/
#
# This launcher belongs at the repository root and starts the existing
# modules from their own directories. It does NOT install/reinstall
# Juice Shop or Wazuh.
#
# Usage:
#   ./start.sh
#   ./start.sh start
#   ./start.sh stop
#   ./start.sh restart
#   ./start.sh status
#   ./start.sh logs
#   ./start.sh dashboard
#
# Injection is Wazuh-driven, so there is no separate Python process for
# injection to launch. Starting Wazuh Manager enables the injection rules
# and Active Response already installed by the injection module.

set -u

# ---------------------------------------------------------------------------
# Run the entire launcher with root privileges.
# ---------------------------------------------------------------------------
# The network, OS, brute-force response, Wazuh, and log files require root
# access. If the launcher is started normally, re-execute it through sudo so
# every child module runs with the required privileges.
if [[ "${EUID}" -ne 0 ]]; then
    echo "EDR1 launcher requires sudo. Requesting administrator privileges..."
    exec sudo -E bash "$0" "$@"
fi


# ---------------------------------------------------------------------------
# Repository paths
# ---------------------------------------------------------------------------

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="$PROJECT_ROOT/src"
MODULE_ROOT="$SRC_ROOT/modules"
CORE_ROOT="$PROJECT_ROOT/src/core"
# GUI location within the ICT30016-EDR1 repository.
DASHBOARD="$PROJECT_ROOT/src/core/GUI-Dashboard.py"

if [[ ! -f "$DASHBOARD" ]]; then
    echo "ERROR: GUI not found: $DASHBOARD" >&2
    exit 1
fi


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

    # Wazuh is deliberately started/restarted LAST, after all EDR helper
    # processes and the Stratum parser are ready.
    if systemctl list-unit-files 2>/dev/null | grep -q '^wazuh-manager.service'; then
        log "Wazuh Manager: deferred until all EDR modules are started."
    else
        log "Wazuh Manager service not found; injection module cannot run."
    fi
}

# ---------------------------------------------------------------------------
# Start Wazuh last
# ---------------------------------------------------------------------------

start_wazuh_last() {
    if ! systemctl list-unit-files 2>/dev/null | grep -q '^wazuh-manager.service'; then
        error "Wazuh Manager service not found."
        return 1
    fi

    log "Restarting Wazuh Manager after all EDR modules are ready..."
    sudo -n systemctl restart wazuh-manager

    sleep 3

    if systemctl is-active --quiet wazuh-manager; then
        log "Wazuh Manager restarted successfully."
    else
        error "Wazuh Manager failed to start after restart."
        sudo systemctl status wazuh-manager --no-pager || true
        return 1
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

    # Malware response consumes EDR alerts and performs verified automated
    # responses for correlated malware detections.
    local response_script="$MODULE_ROOT/malware/response/edr_response.py"

    if [[ ! -f "$response_script" ]]; then
        log "Malware module: edr_response.py not found; skipping response."
    else
        start_process \
            "malware-response" \
            "$(dirname "$response_script")" \
            sudo -n python3 "$(basename "$response_script")"
    fi

    # Capture Stratum traffic before Wazuh is restarted so the protocol
    # telemetry pipeline is already listening when the manager comes back.
    start_pipeline \
        "malware-stratum-parser" \
        "$PROJECT_ROOT" \
        "sudo -n bash -o pipefail -c 'tcpdump -l -nn -i ens33 -s 0 -A \"tcp port 3333\" 2>/dev/null | python3 -u /home/juice/ICT30016-EDR1/src/modules/malware/response/edr_stratum_parser.py | tee -a /var/log/mining-protocol.log'"
}

# ---------------------------------------------------------------------------
# OS SUID module
# ---------------------------------------------------------------------------

start_os_suid() {
    local module_dir

    module_dir="$MODULE_ROOT/os"

    if [[ ! -d "$module_dir" ]]; then
        log "OS module: $module_dir not found; skipping."
        return 0
    fi

    if [[ ! -f "$module_dir/suid_monitor.py" ||           ! -f "$module_dir/suid_detection.py" ||           ! -f "$module_dir/suid_response.py" ]]; then
        log "OS SUID module: required files are incomplete; skipping."
        return 0
    fi

    # suid_monitor -> suid_detection -> suid_response
    # Detection output is also persisted for the central dashboard.
    start_pipeline         "os-suid"         "$module_dir"         'sudo -n python3 suid_monitor.py          | python3 suid_detection.py          | tee -a /var/log/edr_os_alerts.jsonl          | sudo -n python3 suid_response.py          | sudo -n tee -a /var/log/edr_os_response_actions.jsonl >/dev/null'
}

# ---------------------------------------------------------------------------
# OS Cron module
# ---------------------------------------------------------------------------

start_os_cron() {
    local module_dir

    module_dir="$MODULE_ROOT/os"

    if [[ ! -d "$module_dir" ]]; then
        log "OS Cron module: $module_dir not found; skipping."
        return 0
    fi

    if [[ ! -f "$module_dir/cron_monitor.py" ||           ! -f "$module_dir/cron_detection.py" ||           ! -f "$module_dir/cron_response.py" ]]; then
        log "OS Cron module: required files are incomplete; skipping."
        return 0
    fi

    # cron_monitor -> cron_detection -> cron_response
    start_pipeline         "os-cron"         "$module_dir"         'sudo -n python3 cron_monitor.py          | python3 cron_detection.py          | tee -a /var/log/edr_os_alerts.jsonl          | sudo -n python3 cron_response.py          | sudo -n tee -a /var/log/edr_os_response_actions.jsonl >/dev/null'
}

# ---------------------------------------------------------------------------
# Brute-force module
# ---------------------------------------------------------------------------

start_brute_force() {
    local module_dir

    module_dir="$MODULE_ROOT/brute_force"

    if [[ ! -d "$module_dir" ]]; then
        log "Brute Force module: $module_dir not found; skipping."
        return 0
    fi

    if [[ ! -f "$module_dir/ssh_monitor.py" ||           ! -f "$module_dir/juice_shop_monitor.py" ||           ! -f "$module_dir/brute_force_detection.py" ||           ! -f "$module_dir/brute_force_response.py" ]]; then
        log "Brute Force module: required files are incomplete; skipping."
        return 0
    fi

    # Two monitoring sources feed the shared detector:
    #
    #   ssh_monitor -----------\
    #                             -> brute_force_detection -> response
    #   juice_shop_monitor ----/
    #
    # The response stage performs the automated firewall action.
    start_pipeline         "brute-force"         "$module_dir"         '(sudo -n python3 ssh_monitor.py &           sudo -n python3 juice_shop_monitor.py &           wait)          | python3 brute_force_detection.py          | tee -a /var/log/edr_bruteforce_alerts.jsonl          | sudo -n python3 brute_force_response.py          | sudo -n tee -a /var/log/edr_bruteforce_response_actions.jsonl >/dev/null'
}

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

start_dashboard() {
    # The GUI is located at exactly:
    # ICT30016-EDR1/src/core/GUI-Dashboard.py
    start_process         "dashboard"         "$CORE_ROOT"         python3 "GUI-Dashboard.py"
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
        "malware-response"
        "malware-stratum-parser"
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
    stop_process "malware-stratum-parser"
    stop_process "malware-response"
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

    # Configure auditd keyboard-input monitoring before starting the EDR
    # modules. The checks make these rules idempotent so repeated launches
    # do not create duplicate audit rules.
    log "Configuring auditd keylogger monitoring rules..."

    if ! sudo -n auditctl -l 2>/dev/null | grep -Fq -- "-w /dev/input -p r -k keylogger_input"; then
        sudo -n auditctl -w /dev/input -p r -k keylogger_input
        log "Added audit rule: /dev/input -> keylogger_input"
    else
        log "Audit rule already present: /dev/input -> keylogger_input"
    fi

    if ! sudo -n auditctl -l 2>/dev/null | grep -Fq -- "-w /dev/input/by-path/platform-i8042-serio-0-event-kbd -p r -k keylogger_keyboard"; then
        sudo -n auditctl -w /dev/input/by-path/platform-i8042-serio-0-event-kbd -p r -k keylogger_keyboard
        log "Added audit rule: event-kbd -> keylogger_keyboard"
    else
        log "Audit rule already present: event-kbd -> keylogger_keyboard"
    fi

    start_services
    start_network
    start_injection
    start_malware
    start_os_suid
    start_os_cron
    start_brute_force

    # Restart Wazuh only after every EDR helper and telemetry process is
    # running. This ensures Wazuh begins generating fresh alerts after the
    # collector, response handler, Stratum parser, and other modules exist.
    start_wazuh_last || return 1

    # Start the dashboard after Wazuh has successfully restarted.
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