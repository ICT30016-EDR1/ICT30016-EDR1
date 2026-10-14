"""
cron_detection.py
=========================
Detection layer for the cron job hijacking agent. Consumes the
`cron_script_state` facts produced by cron_monitor.py and decides:

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
    sudo python3 monitor.py &      # writes facts to OS_FACTS_LOG
    python3 detection.py            # tails OS_FACTS_LOG, writes to OS_ALERT_LOG

Run standalone (no shell pipe needed): this reads monitor.py's facts
from the shared OS_FACTS_LOG file (common/events.py) -- the same file
suid_monitor.py also writes to -- instead of stdin, and writes its
verdicts to OS_ALERT_LOG instead of stdout. Both files are shared with
os since the GUI dashboard treats cron hijacking and SUID
privesc as one "OS Attacks" category; this script only ever acts on
records with source == "cron", so os's own facts and alerts
passing through the same files are simply ignored.
"""

import os
import sys
import json

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from common.events import OS_FACTS_LOG, OS_ALERT_LOG, append_jsonl, follow_jsonl


def is_group_or_other_writable(mode_str: str) -> bool:
    """mode_str looks like '0755'. Flag if group or other has the write
    bit set -- the root-cause misconfiguration behind this attack."""
    mode = int(mode_str, 8)
    group_write = bool(mode & 0o020)
    other_write = bool(mode & 0o002)
    return group_write or other_write

DEFAULT_BASELINE_FILE = "/var/lib/edr_cron_backups/baseline_hashes.json"

class Baseline:
    """Tracks the first-seen hash for each cron-referenced script.
    Persisted to disk so a restart doesn't treat 'whatever I see first'
    as automatically clean -- once a hash is on disk, only an explicit
    reset clears it."""

    def __init__(self, path: str = DEFAULT_BASELINE_FILE):
        self._path = path
        self._hashes = {}
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    self._hashes = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._hashes = {}

    def _save(self):
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        with open(self._path, "w") as f:
            json.dump(self._hashes, f)

    def check(self, path, sha256):
        if path not in self._hashes:
            self._hashes[path] = sha256
            self._save()
            return "baseline_set", None

        previous = self._hashes[path]
        if sha256 == previous:
            return "unchanged", None

        self._hashes[path] = sha256
        self._save()
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
        "source": "cron",  # tags this record for the shared OS_ALERT_LOG/
                            # OS_RESPONSE_LOG files, so the GUI dashboard
                            # and suid_response.py's "ignore anything
                            # not mine" filters can tell it apart from an
                            # os SUID verdict at a glance.
        "path": path,
        "status": status,
        "previous_hash": previous_hash,
        "current_hash": sha256,
        "mode": mode,
        "writable_risk": writable_risk,
    }


def main():
    print(f"[*] Cron-based detection engine started. Reading facts from "
          f"{OS_FACTS_LOG} (shared with os).")
    print(f"[*] Writing verdicts to {OS_ALERT_LOG}.")
    print("[*] Press Ctrl+C to stop.\n")

    baseline = Baseline()

    try:
        for event in follow_jsonl(OS_FACTS_LOG):
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

            # Emit a JSON line for anything response.py might need to act
            # on: a freshly-recorded baseline (so it can take a known-good
            # backup copy before any tampering happens), a confirmed
            # modification (so it can restore from that backup), or a
            # standing writable-permission risk (so it can lock the
            # permissions down) -- same dual-output pattern as the rest
            # of the project. A plain "unchanged" with no writable risk
            # means nothing happened and nothing to do, so it's the one
            # case left out of the JSON stream entirely.
            if verdict["status"] in ("baseline_set", "modified") or verdict["writable_risk"]:
                append_jsonl(OS_ALERT_LOG, verdict)

    except KeyboardInterrupt:
        print("\n[*] Stopping cron-based detection engine.")


if __name__ == "__main__":
    main()
