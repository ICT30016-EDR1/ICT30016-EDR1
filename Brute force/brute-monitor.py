"""
brute_force_agent/monitor.py
==============================
Monitoring layer for the brute force agent. Uses `watchdog` to detect
whenever /var/log/auth.log is modified, then reads only the newly
appended lines (never re-reading the whole file), parses out SSH
authentication attempts, and emits a structured MonitoringEvent for each
one.

This module ONLY collects telemetry — it does not decide whether an
attack is happening. That's the job of a detection engine that will
consume the events this produces (e.g. by reading them from stdout,
or later from a queue/log file once you wire that up).

Usage:
    sudo python3 monitor.py

(sudo is required to read /var/log/auth.log)
"""

import re
import sys
import time
import os

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from common.events import MonitoringEvent

AUTH_LOG_PATH = "/var/log/auth.log"

# Matches lines like:
#   Failed password for root from 192.168.1.20 port 54321 ssh2
#   Accepted password for labtarget from 192.168.1.20 port 54325 ssh2
SSH_AUTH_REGEX = re.compile(
    r"(?P<result>Failed password|Accepted password) for "
    r"(invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ssh2"
)


class AuthLogHandler(FileSystemEventHandler):
    """
    Watches auth.log for modifications and processes only the bytes
    appended since the last read, using a tracked file offset.
    """

    def __init__(self, path):
        self.path = path
        self._fh = open(path, "r")
        # Jump to the end of the file on startup so we only process
        # NEW events from this point forward, not the entire history.
        self._fh.seek(0, os.SEEK_END)

    def on_modified(self, event):
        # watchdog can report modifications to the containing directory
        # too; only act when it's actually our target file.
        if os.path.abspath(event.src_path) != os.path.abspath(self.path):
            return
        self._process_new_lines()

    def _process_new_lines(self):
        for line in self._fh:
            self._parse_line(line)

    def _parse_line(self, line: str):
        match = SSH_AUTH_REGEX.search(line)
        if not match:
            return  # not an SSH auth line we care about; ignore

        result = "accepted" if match.group("result") == "Accepted password" else "failed"

        event = MonitoringEvent(
            source="brute_force",
            event_type="ssh_auth_attempt",
            data={
                "result": result,
                "username": match.group("user"),
                "source_ip": match.group("ip"),
                "source_port": match.group("port"),
                "raw_line": line.strip(),
            },
        )
        event.emit()


def main():
    if not os.path.exists(AUTH_LOG_PATH):
        print(f"[!] {AUTH_LOG_PATH} not found. Are you running this on the Ubuntu victim VM?")
        sys.exit(1)

    handler = AuthLogHandler(AUTH_LOG_PATH)
    observer = Observer()
    # Watch the containing directory, not the file directly — this is
    # the standard watchdog pattern, since some editors/loggers replace
    # files rather than append in place, which a direct file watch can miss.
    observer.schedule(handler, path=os.path.dirname(AUTH_LOG_PATH), recursive=False)
    observer.start()

    print(f"[*] Brute force monitoring agent started. Watching {AUTH_LOG_PATH}")
    print("[*] Emitting events as JSON lines. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
