"""
os_agent/detection.py
=======================
Detection layer for the OS-based agent. Consumes the raw `uid_mismatch`
facts produced by os_agent/monitor.py and decides which ones are actually
worth flagging as suspected privilege escalation.

This is where the judgment calls that used to live in monitor.py belong:

  1. Not every real_uid != effective_uid process matters. We only care
     about escalation TO root (effective_uid == 0) FROM a non-root user
     (real_uid != 0) — that's the signature SUID exploitation produces.
  2. Some binaries legitimately do this on every normal system (passwd,
     sudo, su, mount, umount). Flagging those every time would just be
     noise, so this layer suppresses them via an allowlist — but still
     labels them in the output as "known_legitimate" rather than
     silently dropping them, so a future, more nuanced detection rule
     (e.g. "sudo running from an unexpected parent process") still has
     the raw event to work with instead of nothing.

monitor.py's job stops at "here is a process whose real and effective
UIDs differ"; everything below is this module's job.

Usage:
    sudo python3 monitor.py | python3 detection.py

(monitor.py's stdout — one MonitoringEvent JSON line per uid mismatch —
is piped directly into this script's stdin.)
"""

import sys
import json

# Processes that legitimately run with EUID 0 via SUID without necessarily
# being an attack. A real detection engine would want something more
# nuanced than a flat allowlist (e.g. checking the parent process or
# calling user), but this keeps the noise down for now.
KNOWN_LEGITIMATE_SUID_BINARIES = {"passwd", "sudo", "su", "mount", "umount"}


def is_root_escalation(data: dict) -> bool:
    """
    The actual detection judgment: does this mismatch represent a
    non-root process that is currently running with root's effective
    privileges? (As opposed to, say, a process dropping privileges the
    other way, which real_uid != effective_uid alone doesn't tell you.)
    """
    return data.get("effective_uid") == 0 and data.get("real_uid") != 0


def evaluate(event: dict) -> dict | None:
    """
    Given one parsed MonitoringEvent dict from monitor.py, return a
    detection verdict dict, or None if this event isn't something
    detection.py handles (e.g. a different source/event_type).
    """
    if event.get("source") != "os" or event.get("event_type") != "uid_mismatch":
        return None

    data = event["data"]

    if not is_root_escalation(data):
        # Some other kind of real/effective mismatch (e.g. privilege
        # drop) — not the pattern this detection rule is looking for.
        return None

    known_legitimate = data.get("name") in KNOWN_LEGITIMATE_SUID_BINARIES

    return {
        "verdict": "known_legitimate" if known_legitimate else "suspected_privesc",
        "pid": data.get("pid"),
        "ppid": data.get("ppid"),
        "name": data.get("name"),
        "exe": data.get("exe"),
        "real_uid": data.get("real_uid"),
        "effective_uid": data.get("effective_uid"),
    }


def main():
    print("[*] OS-based detection engine started. Reading events from "
          "stdin (pipe monitor.py's output into this script).")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue  # not a JSON line we understand; skip it

            verdict = evaluate(event)
            if verdict is None:
                continue

            if verdict["verdict"] == "suspected_privesc":
                print(f"[!] ALERT: suspected privilege escalation — "
                      f"pid={verdict['pid']} name={verdict['name']} "
                      f"exe={verdict['exe']} "
                      f"real_uid={verdict['real_uid']} -> effective_uid=0",
                      flush=True)
            else:
                print(f"[*] Suppressed (known legitimate SUID binary): "
                      f"pid={verdict['pid']} name={verdict['name']}",
                      flush=True)

    except KeyboardInterrupt:
        print("\n[*] Stopping OS-based detection engine.")


if __name__ == "__main__":
    main()
