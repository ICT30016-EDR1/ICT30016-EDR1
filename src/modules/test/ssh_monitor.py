"""
ssh_monitor.py
==============================
Monitoring layer for the brute force agent. Polls /var/log/auth.log on a
fixed interval, reads only the newly appended bytes since the last check
(never re-reading the whole file), parses out SSH authentication
attempts, and emits a structured MonitoringEvent for each one.

This module ONLY collects telemetry — it does not decide whether an
attack is happening. That's the job of a detection engine that will
consume the events this produces (e.g. by reading them from stdout,
or later from a queue/log file once you wire that up).

Why polling instead of watchdog/inotify:
    The original version used watchdog's Observer to watch the
    containing directory (/var/log) for IN_MODIFY events. /var/log is a
    very high-churn directory — syslog, journald, cron, dpkg, and this
    project's own log files are all written to constantly — and under
    sustained load the kernel's inotify event queue for that watch can
    overflow (IN_Q_OVERFLOW), silently dropping further events. When
    that happens the watcher process stays alive, keeps its file handle
    open, and never raises a Python-catchable exception, but simply
    stops reacting to new writes forever. A fixed-interval poll sidesteps
    this entirely: no kernel event queue to overflow, and no external
    dependency (`watchdog`) required. The small latency this trades
    away (worst case ~POLL_INTERVAL_SECONDS before a new line is seen)
    is negligible against the detector's 60-second window.

Usage:
    sudo python3 ssh_monitor.py

(sudo is required to read /var/log/auth.log)
"""

import re
import sys
import time
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from common.events import MonitoringEvent

AUTH_LOG_PATH = "/var/log/auth.log"
POLL_INTERVAL_SECONDS = 1

# Matches lines like:
#   Failed password for root from 192.168.1.20 port 54321 ssh2
#   Accepted password for labtarget from 192.168.1.20 port 54325 ssh2
SSH_AUTH_REGEX = re.compile(
    r"(?P<result>Failed password|Accepted password) for "
    r"(invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ssh2"
)


class AuthLogPoller:
    """
    Polls auth.log on a fixed interval and processes only the bytes
    appended since the last check, using a tracked file offset.

    Also detects truncation/rotation: if the file's current size is
    SMALLER than our last-known offset (e.g. logrotate's copytruncate,
    or the file being replaced), we reset to the start rather than
    trying to seek past the new, shorter end of the file.
    """

    def __init__(self, path):
        self.path = path
        self._fh = open(path, "r")
        self._fh.seek(0, os.SEEK_END)
        self._offset = self._fh.tell()

    def poll_once(self):
        try:
            current_size = os.path.getsize(self.path)
        except OSError:
            return  # file momentarily missing (mid-rotation); try again next poll

        if current_size < self._offset:
            self._fh.close()
            self._fh = open(self.path, "r")
            self._offset = 0

        if current_size == self._offset:
            return  # nothing new

        self._fh.seek(self._offset)
        for line in self._fh:
            self._parse_line(line)
        self._offset = self._fh.tell()

    def _parse_line(self, line: str):
        match = SSH_AUTH_REGEX.search(line)
        if not match:
            return

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

    poller = AuthLogPoller(AUTH_LOG_PATH)

    print(f"[*] Brute force monitoring agent started (polling every "
          f"{POLL_INTERVAL_SECONDS}s). Watching {AUTH_LOG_PATH}")
    print("[*] Emitting events as JSON lines. Press Ctrl+C to stop.\n")

    try:
        while True:
            poller.poll_once()
            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[*] Stopping brute force monitoring agent.")


if __name__ == "__main__":
    main()