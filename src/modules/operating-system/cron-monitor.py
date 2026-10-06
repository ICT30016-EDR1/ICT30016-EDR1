"""
cron_agent/monitor.py
=======================
Monitoring layer for the cron job hijacking agent. Unlike the OS agent
(which looks at process UID/EUID at runtime), a hijacked cron job never
produces a uid mismatch -- cron launches the script directly as root, so
the malicious process has real_uid == effective_uid == 0 from the start.
The signature of this attack instead lives in the FILE: a script that
root's crontab trusts gets modified by a non-root user who found it
writable.

This module ONLY collects telemetry about those trusted scripts:
  - at startup, a one-off "here is what each cron-referenced script
    looks like right now" fact per script (hash, permissions, owner)
  - from then on, a fresh fact every time one of those files is modified

It makes NO judgment about whether a given hash, permission, or change
is suspicious. That is cron_agent/detection.py's job: comparing hashes
against a baseline, and separately flagging world/group-writable
scripts as a standing risk. This mirrors the split used by the other
two agents: monitor emits facts, detection emits judgments.

Usage:
    sudo python3 monitor.py

Limitation: cron-referenced scripts are enumerated once at startup. If
a new cron job referencing a different script is added after this
agent starts, that script won't be picked up until the agent is
restarted. This is an accepted limitation, not a bug -- a production
version would re-enumerate periodically or watch the cron config files
themselves too.
"""

import sys
import os
import re
import glob
import hashlib
import subprocess
import time

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from common.events import MonitoringEvent

CRON_SOURCES = ["/etc/crontab"] + glob.glob("/etc/cron.d/*")

# Matches script-like paths referenced inside a crontab line: a .sh
# file anywhere, or anything under /opt or /usr/local. Deliberately the
# same pattern used by the bash version of this detector, so both stay
# consistent.
SCRIPT_PATTERN = re.compile(r"(/\S+\.sh|/opt/\S+|/usr/local/\S+)")


def get_cron_referenced_scripts():
    """
    Parse root's crontab plus /etc/crontab and /etc/cron.d/* for script
    paths they invoke. Purely structural extraction -- no judgment
    about whether any of the referenced scripts are safe.
    """
    text_blobs = []

    try:
        result = subprocess.run(
            ["crontab", "-l", "-u", "root"],
            capture_output=True, text=True, check=False,
        )
        text_blobs.append(result.stdout)
    except FileNotFoundError:
        pass  # crontab command not installed; skip

    for path in CRON_SOURCES:
        try:
            with open(path, "r") as f:
                text_blobs.append(f.read())
        except (FileNotFoundError, PermissionError):
            continue

    scripts = set()
    for blob in text_blobs:
        for line in blob.splitlines():
            if line.strip().startswith("#"):
                continue
            for match in SCRIPT_PATTERN.findall(line):
                scripts.add(match)

    # Only report paths that actually exist as files right now.
    return sorted(p for p in scripts if os.path.isfile(p))


def describe_script(path):
    """
    Return the structural facts for one cron-referenced script: its
    hash, permissions, and owning UID. No judgment about whether any
    of these values are good or bad -- that's detection.py's job.
    """
    try:
        stat_info = os.stat(path)
        with open(path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
    except (FileNotFoundError, PermissionError):
        return None

    return {
        "path": path,
        "sha256": file_hash,
        "mode": oct(stat_info.st_mode & 0o777),
        "owner_uid": stat_info.st_uid,
        "size_bytes": stat_info.st_size,
    }


class CronScriptHandler(FileSystemEventHandler):
    """
    Watches the directories containing cron-referenced scripts, and
    emits a fresh fact whenever one of the tracked scripts is modified.
    """

    def __init__(self, tracked_paths):
        self.tracked_paths = set(tracked_paths)

    def on_modified(self, event):
        if event.is_directory:
            return
        if event.src_path not in self.tracked_paths:
            return

        facts = describe_script(event.src_path)
        if facts is None:
            return  # file disappeared between the event and reading it

        MonitoringEvent(
            source="cron",
            event_type="cron_script_state",
            data=facts,
        ).emit()


def main():
    scripts = get_cron_referenced_scripts()
    print(f"[*] Cron-based monitoring agent started. Tracking "
          f"{len(scripts)} cron-referenced script(s).")
    print("[*] Emitting events as JSON lines. Press Ctrl+C to stop.\n")

    if not scripts:
        print("[*] No cron-referenced scripts found to track. Exiting.")
        return

    # Emit one fact per script immediately, so a detection engine has
    # something to build its initial baseline from.
    for path in scripts:
        facts = describe_script(path)
        if facts:
            MonitoringEvent(source="cron", event_type="cron_script_state", data=facts).emit()

    handler = CronScriptHandler(scripts)
    observer = Observer()

    # watchdog watches directories, not individual files, so watch the
    # unique set of parent directories containing tracked scripts and
    # filter down to the exact paths inside the handler.
    watched_dirs = {os.path.dirname(p) for p in scripts}
    for directory in watched_dirs:
        observer.schedule(handler, directory, recursive=False)

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[*] Stopping cron-based monitoring agent.")
    observer.join()


if __name__ == "__main__":
    main()
