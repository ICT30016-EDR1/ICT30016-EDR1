"""
cron_agent/detection.py
=========================
Detection layer for the cron job hijacking agent. Consumes the
`cron_script_state` facts produced by cron_agent/monitor.py and decides:

  1. Baseline tampering: has a cron-referenced script's content changed
     since the first time we observed it? (the actual "hijack in
     progress" signature)
  2. Standing risk: is a cron-referenced script writable by someone
     other than its owner right now? (the root cause that MAKES the
     hijack possible in the first place, independent of whether a
     change has happened yet)

monitor.py's job stops at "here is this script's hash/permissions right
now"; everything below is this module's job.

Usage:
    sudo python3 monitor.py | python3 detection.py

(monitor.py's stdout -- one MonitoringEvent JSON line per observed or
changed script -- is piped directly into this script's stdin.)
"""

import sys
import json


def is_group_or_other_writable(mode_str: str) -> bool:
    """mode_str looks like '0755'. Flag if group or other has the write
    bit set -- the root-cause misconfiguration behind this attack."""
    mode = int(mode_str, 8)
    group_write = bool(mode & 0o020)
    other_write = bool(mode & 0o002)
    return group_write or other_write


class Baseline:
    """Tracks the first-seen hash for each cron-referenced script, so
    later events can be compared against it."""

    def __init__(self):
        self._hashes = {}

    def check(self, path, sha256):
        """
        Returns ("baseline_set", None) the first time a path is seen,
        ("unchanged", None) if the hash matches what we last recorded,
        or ("modified", previous_hash) if it has changed.
        """
        if path not in self._hashes:
            self._hashes[path] = sha256
            return "baseline_set", None

        previous = self._hashes[path]
        if sha256 == previous:
            return "unchanged", None

        self._hashes[path] = sha256  # baseline moves forward to the new state
        return "modified", previous


def evaluate(event: dict, baseline: Baseline) -> dict | None:
    """
    Given one parsed MonitoringEvent dict from monitor.py, return a
    detection verdict dict, or None if this event isn't something
    detection.py handles.
    """
    if event.get("source") != "cron" or event.get("event_type") != "cron_script_state":
        return None

    data = event["data"]
    path = data.get("path")
    sha256 = data.get("sha256")
    mode = data.get("mode")

    status, previous_hash = baseline.check(path, sha256)
    writable_risk = is_group_or_other_writable(mode)

    return {
        "path": path,
        "status": status,
        "previous_hash": previous_hash,
        "current_hash": sha256,
        "mode": mode,
        "writable_risk": writable_risk,
    }


def main():
    print("[*] Cron-based detection engine started. Reading events from "
          "stdin (pipe monitor.py's output into this script).")
    print("[*] Press Ctrl+C to stop.\n")

    baseline = Baseline()

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue  # not a JSON line we understand; skip it

            verdict = evaluate(event, baseline)
            if verdict is None:
                continue

            if verdict["status"] == "baseline_set":
                print(f"[*] Baseline recorded for {verdict['path']} "
                      f"(hash={verdict['current_hash'][:12]}...)", flush=True)
            elif verdict["status"] == "modified":
                print(f"[!] ALERT: {verdict['path']} has been MODIFIED since baseline\n"
                      f"    Previous: {verdict['previous_hash']}\n"
                      f"    Current:  {verdict['current_hash']}", flush=True)
            # "unchanged" events are not printed -- nothing happened.

            if verdict["writable_risk"]:
                print(f"[!] ALERT: {verdict['path']} is writable by a non-owner "
                      f"(mode={verdict['mode']}) -- hijack is possible even "
                      f"without a modification yet", flush=True)

    except KeyboardInterrupt:
        print("\n[*] Stopping cron-based detection engine.")


if __name__ == "__main__":
    main()
