"""
os_agent/monitor.py
=====================
Monitoring layer for the OS-based agent. Uses `psutil` to periodically
poll running processes and extract real UID vs effective UID (EUID) for
each one — the raw fact that SUID binary exploitation shows up in.

This module ONLY collects telemetry. It does not decide what counts as
suspicious: it emits a structural fact ("this process's real UID and
effective UID differ") for every such process, with no judgment about
whether that's expected (e.g. `passwd`, `sudo` legitimately do this) or
an attack. That judgment belongs to os_agent/detection.py, which consumes
these events. This mirrors brute_force_agent/monitor.py, which likewise
only parses auth.log lines into structured fields and leaves "is this an
attack" to its own detection layer.

Usage:
    sudo python3 monitor.py

(sudo is required to see uid/euid info for processes you don't own)

Note on approach: this is a POLLING model, not an event-driven one —
see the project's own documentation/report for the discussion of this
trade-off versus auditd's event-driven syscall hooking. A short-lived
process that starts and exits between two polls will be missed here;
this is an accepted limitation of psutil-based monitoring, not a bug.
"""

import sys
import os
import time

import psutil

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from common.events import MonitoringEvent

POLL_INTERVAL_SECONDS = 2


def get_uid_mismatches():
    """
    Scan all running processes and return a list of dicts describing any
    process where the real UID and effective UID differ.

    This is a purely structural check — "do these two numbers differ" —
    not a security judgment. It deliberately does NOT single out
    effective_uid == 0, because that itself is a detection-layer
    decision about which mismatches matter. Monitoring just reports the
    fact; detection decides what's suspicious.
    """
    mismatches = []
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe"]):
        try:
            uids = proc.uids()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Process may have exited between listing and inspection,
            # or we may lack permission to inspect it — skip either way.
            continue

        real_uid, effective_uid = uids.real, uids.effective

        if real_uid != effective_uid:
            info = proc.info
            mismatches.append({
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name"),
                "exe": info.get("exe"),
                "real_uid": real_uid,
                "effective_uid": effective_uid,
            })
    return mismatches


def main():
    print("[*] OS-based monitoring agent started (psutil, polling every "
          f"{POLL_INTERVAL_SECONDS}s).")
    print("[*] Emitting events as JSON lines. Press Ctrl+C to stop.\n")

    # Track PIDs we've already reported so a long-running process with a
    # standing uid/euid mismatch doesn't generate a duplicate event on
    # every single poll. This is just event de-duplication, not a
    # judgment about suspiciousness, so it stays here in monitoring.
    already_reported_pids = set()

    try:
        while True:
            mismatches = get_uid_mismatches()
            current_pids = {m["pid"] for m in mismatches}

            for mismatch in mismatches:
                if mismatch["pid"] in already_reported_pids:
                    continue  # already reported this one; skip

                event = MonitoringEvent(
                    source="os",
                    event_type="uid_mismatch",
                    data=mismatch,
                )
                event.emit()

            # Forget PIDs that are no longer present, so if the same
            # binary is exploited again later under a new PID, it gets
            # reported again rather than being silently suppressed forever.
            already_reported_pids.intersection_update(current_pids)
            already_reported_pids.update(current_pids)

            time.sleep(POLL_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print("\n[*] Stopping OS-based monitoring agent.")


if __name__ == "__main__":
    main()
