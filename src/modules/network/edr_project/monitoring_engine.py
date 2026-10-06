import json
import logging
import os
import subprocess
import threading
import time
from collections import deque

import config

logging.basicConfig(
    filename=config.LOG_FILE,
    level=logging.WARNING,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# --- Correlation sources ---------------------------------------------------
# Tailed in the background into small rolling buffers; when a raw alert
# arrives from the detection engine, whatever's most recent gets bundled
# into the final evidence record alongside its packet stats.
_evidence_lock = threading.Lock()
kernel_lines = deque(maxlen=5)        # covers kernel warnings AND [UFW BLOCK] lines
apache_access_lines = deque(maxlen=5)
apache_error_lines = deque(maxlen=5)


def _tail_kernel_journal():
    """UFW logs through netfilter's LOG target, which lands in the kernel
    facility too, so this one source covers both kernel warnings and
    UFW block lines."""
    try:
        proc = subprocess.Popen(
            ['journalctl', '-k', '-f', '-n', '0'],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        for line in proc.stdout:
            with _evidence_lock:
                kernel_lines.append(line.rstrip('\n'))
    except FileNotFoundError:
        print("[EVIDENCE] journalctl not found -- kernel/UFW correlation disabled.")


def _tail_file(path, sink, label):
    try:
        with open(path, 'r') as f:
            f.seek(0, 2)  # start from end -- only new lines from here on
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                with _evidence_lock:
                    sink.append(line.rstrip('\n'))
    except FileNotFoundError:
        print(f"[EVIDENCE] {label} not found at {path} -- check the path, skipping.")
    except PermissionError:
        print(f"[EVIDENCE] No permission to read {label} at {path} -- run as root/sudo.")


def start_correlation_tails():
    threading.Thread(target=_tail_kernel_journal, daemon=True).start()
    threading.Thread(target=_tail_file, args=(config.APACHE_ACCESS_LOG, apache_access_lines, "Apache access log"), daemon=True).start()
    threading.Thread(target=_tail_file, args=(config.APACHE_ERROR_LOG, apache_error_lines, "Apache error log"), daemon=True).start()
# --------------------------------------------------------------------------


def handle_raw_alert(line):
    """Called for every new alert the detection engine hands off. Enriches
    it with whatever's currently buffered from the correlated log sources,
    then writes the evidence file and one combined plain-text log line."""
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        print(f"[MONITOR] Skipping malformed raw alert line: {line!r}")
        return

    with _evidence_lock:
        correlated = {'kernel_syslog': list(kernel_lines)}
        if raw.get('artifact_type') == 'HTTP Request':
            correlated['apache_access'] = list(apache_access_lines)
            correlated['apache_error'] = list(apache_error_lines)

    alert_msg = raw.pop('alert_msg', '')
    raw['correlated_logs'] = correlated

    with open(config.EVIDENCE_FILE, 'a') as f:
        f.write(json.dumps(raw) + '\n')

    # One combined line: sentence and full JSON record together.
    logging.warning(f"{alert_msg} | {json.dumps(raw)}")


def tail_raw_alerts():
    """Blocks the main thread, reacting to each detection event as it
    arrives -- same seek-to-end-then-follow pattern as _tail_file(), just
    pointed at the handoff file instead of an OS log."""
    if not os.path.exists(config.RAW_ALERTS_FILE):
        open(config.RAW_ALERTS_FILE, 'a').close()
    with open(config.RAW_ALERTS_FILE, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            handle_raw_alert(line.rstrip('\n'))


if __name__ == '__main__':
    print("Starting EDR Monitoring Engine...")
    print(f"Watching for alerts from: {config.RAW_ALERTS_FILE}")
    print(f"Writing alerts to: {config.LOG_FILE}")
    print(f"Writing evidence records to: {config.EVIDENCE_FILE}\n")

    start_correlation_tails()
    tail_raw_alerts()
