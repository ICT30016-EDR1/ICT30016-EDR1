"""
suid_detection.py
=======================
Detection layer for the OS-based agent. Consumes the raw `uid_mismatch`
facts produced by suid_monitor.py and decides which ones are actually
worth flagging as suspected privilege escalation.

This is where the judgment calls that used to live in suid_monitor.py belong:

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

suid_monitor.py's job stops at "here is a process whose real and effective
UIDs differ"; everything below is this module's job.

Usage:
    sudo python3 suid_monitor.py &      # writes facts to OS_FACTS_LOG
    python3 suid_detection.py            # tails OS_FACTS_LOG, writes to OS_ALERT_LOG

Run standalone (no shell pipe needed): this reads suid_monitor.py's facts
from the shared OS_FACTS_LOG file (common/events.py) instead of stdin,
and writes its verdicts to OS_ALERT_LOG instead of stdout -- the same
file GUI-Dashboard.py's load_os_events() reads from.
"""

import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from common.events import OS_FACTS_LOG, OS_ALERT_LOG, append_jsonl, follow_jsonl

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
    Given one parsed MonitoringEvent dict from suid_monitor.py, return a
    detection verdict dict, or None if this event isn't something
    suid_detection.py handles (e.g. a different source/event_type).
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
    print(f"[*] OS-based detection engine started. Reading facts from "
          f"{OS_FACTS_LOG} (shared with the cron components).")
    print(f"[*] Writing verdicts to {OS_ALERT_LOG}.")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        for event in follow_jsonl(OS_FACTS_LOG):
            verdict = evaluate(event)
            if verdict is None:
                continue

            if verdict["verdict"] == "suspected_privesc":
                print(f"[!] ALERT: suspected privilege escalation — "
                      f"pid={verdict['pid']} name={verdict['name']} "
                      f"exe={verdict['exe']} "
                      f"real_uid={verdict['real_uid']} -> effective_uid=0",
                      flush=True)
                # Also append the verdict to OS_ALERT_LOG, same
                # dual-output idea the project always used: a
                # human-readable line for whoever's watching the
                # terminal, plus a structured record a downstream
                # consumer (suid_response.py, or the GUI dashboard) can
                # read. known_legitimate verdicts are NOT written here
                # — there's nothing for suid_response.py to act on for
                # those, and nothing for the dashboard to show.
                append_jsonl(OS_ALERT_LOG, verdict)
            else:
                print(f"[*] Suppressed (known legitimate SUID binary): "
                      f"pid={verdict['pid']} name={verdict['name']}",
                      flush=True)

    except KeyboardInterrupt:
        print("\n[*] Stopping OS-based detection engine.")


if __name__ == "__main__":
    main()
