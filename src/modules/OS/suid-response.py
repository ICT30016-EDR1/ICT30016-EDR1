"""
os_agent/response.py
======================
Response layer for the OS-based agent. Consumes the suspected_privesc
verdicts emitted by os_agent/detection.py and takes an automated action:
killing the offending process and stripping the SUID bit from the
executable it ran from, so the same binary can't be re-exploited the
same way after the process is gone.

Same three-layer separation used throughout the project:
    monitor   -> facts      ("here's what happened")
    detection -> judgments  ("this looks like an attack")
    response  -> actions    ("do something about it")

response.py doesn't re-derive any judgment itself -- it trusts whatever
detection.py decided (a "suspected_privesc" verdict) and acts on it. If
detection.py is flagging legitimate binaries, that's a detection.py
tuning problem (the KNOWN_LEGITIMATE_SUID_BINARIES allowlist), not
something response.py second-guesses -- which is also why
known_legitimate verdicts are never emitted as JSON in the first place
and never reach this script.

Two actions, taken together for every alert:
  1. Kill the offending process (SIGKILL by pid) -- stops whatever it's
     doing right now.
  2. Strip the SUID bit from its executable (chmod u-s) -- the exploit
     almost always depends on that bit being set, so removing it stops
     the SAME binary being abused again, without deleting the file or
     otherwise touching the rest of the system.

If the same exe path is flagged again later, the SUID-strip step is a
no-op (the bit's already gone) and is logged as such rather than
re-reported as a fresh action.

Usage (full chain):
    sudo python3 os_agent/monitor.py | \\
        python3 os_agent/detection.py | \\
        sudo python3 os_agent/response.py

(response.py needs sudo to kill another user's process and chmod a
system binary; monitor.py needs sudo to read every process's real/
effective UIDs; detection.py needs neither -- each sudo prompt is
independent, so you may be asked for your password twice.)

For testing without killing anything or touching file permissions:
    ... | python3 os_agent/response.py --dry-run
"""

import sys
import os
import json
import stat
import signal
import argparse
from datetime import datetime

# Binaries that are never touched, however an alert labels them -- a
# basic safety governor so a bad detection rule (or a bug) can't strip
# the SUID bit off something the lab VM itself depends on to boot or
# log in. This is deliberately a superset of detection.py's own
# KNOWN_LEGITIMATE_SUID_BINARIES allowlist, since those should already
# be filtered out before reaching this script, but a second
# independent check here costs nothing and catches a detection.py
# mistake before it does something irreversible.
NEVER_TOUCH_NAMES = {"passwd", "sudo", "su", "mount", "umount", "systemd", "init"}

# pids that are never killed, regardless of what's reported for them.
NEVER_KILL_PIDS = {1}


def log_action(action: str, pid, exe: str, reason: str, message: str):
    """
    Emit a response action both as a human-readable line and as a
    structured JSON line -- the same dual-output pattern response.py
    for the brute force agent uses, so a future log analyser or the
    team's shared dashboard could consume response actions from either
    agent the same way.
    """
    print(f"[>] RESPONSE: {message}", flush=True)
    print(json.dumps({
        "source": "os",
        "layer": "response",
        "action": action,
        "pid": pid,
        "exe": exe,
        "reason": reason,
        "timestamp": datetime.now().astimezone().isoformat(),
    }), flush=True)


class PrivescResponder:
    """
    Takes the two response actions for a suspected_privesc verdict:
    killing the process and stripping the SUID bit from its exe. Tracks
    which exe paths have already had their SUID bit stripped so a
    repeat alert for the same binary (e.g. a second launch before the
    first chmod's effect was confirmed) doesn't get re-logged as a new
    action.
    """

    def __init__(self, dry_run: bool):
        self.dry_run = dry_run
        self._stripped_exes: set[str] = set()

    def handle(self, verdict: dict):
        pid = verdict.get("pid")
        name = verdict.get("name")
        exe = verdict.get("exe")
        reason = "suspected_privesc"

        if name in NEVER_TOUCH_NAMES:
            log_action("skip_never_touch", pid, exe, reason,
                       f"{name} (pid={pid}) is on the never-touch list "
                       f"-- ignoring alert")
            return

        if pid in NEVER_KILL_PIDS:
            log_action("skip_never_touch", pid, exe, reason,
                       f"pid={pid} is on the never-kill list -- "
                       f"ignoring alert")
            return

        self._kill_process(pid, name, exe, reason)
        self._strip_suid(exe, pid, name, reason)

    # ---- actions -----------------------------------------------------

    def _kill_process(self, pid, name, exe, reason):
        if pid is None:
            log_action("kill_skipped", pid, exe, reason,
                       f"no pid in alert for {name} -- can't kill")
            return

        if self.dry_run:
            print(f"[DRY RUN] would run: sudo kill -9 {pid}", flush=True)
            log_action("kill", pid, exe, reason,
                       f"[DRY RUN] would kill pid={pid} ({name})")
            return

        try:
            os.kill(pid, signal.SIGKILL)
            log_action("kill", pid, exe, reason,
                       f"Killed pid={pid} ({name}) -- suspected privilege "
                       f"escalation")
        except ProcessLookupError:
            log_action("kill_skipped", pid, exe, reason,
                       f"pid={pid} ({name}) was already gone by the time "
                       f"we tried to kill it")
        except PermissionError:
            print(f"[!] kill failed: not permitted to kill pid={pid} "
                  f"(are we running as root?)", file=sys.stderr, flush=True)

    def _strip_suid(self, exe, pid, name, reason):
        if not exe:
            log_action("strip_suid_skipped", pid, exe, reason,
                       f"no exe path in alert for pid={pid} ({name}) -- "
                       f"can't strip SUID bit")
            return

        if exe in self._stripped_exes:
            log_action("strip_suid_skipped", pid, exe, reason,
                       f"{exe} already had its SUID bit stripped by an "
                       f"earlier alert -- nothing to do")
            return

        if self.dry_run:
            print(f"[DRY RUN] would run: sudo chmod u-s {exe}", flush=True)
            log_action("strip_suid", pid, exe, reason,
                       f"[DRY RUN] would strip SUID bit from {exe}")
            self._stripped_exes.add(exe)
            return

        try:
            current_mode = os.stat(exe).st_mode
            if not current_mode & stat.S_ISUID:
                log_action("strip_suid_skipped", pid, exe, reason,
                           f"{exe} has no SUID bit set -- nothing to strip "
                           f"(may have been stripped already, or the "
                           f"escalation didn't come from this binary)")
                self._stripped_exes.add(exe)
                return

            os.chmod(exe, current_mode & ~stat.S_ISUID)
            self._stripped_exes.add(exe)
            log_action("strip_suid", pid, exe, reason,
                       f"Stripped SUID bit from {exe} -- it can no longer "
                       f"run with elevated privileges")
        except FileNotFoundError:
            log_action("strip_suid_skipped", pid, exe, reason,
                       f"{exe} no longer exists -- nothing to strip")
        except PermissionError:
            print(f"[!] chmod failed: not permitted to modify {exe} "
                  f"(are we running as root?)", file=sys.stderr, flush=True)


def main():
    parser = argparse.ArgumentParser(
        description="Response engine for the OS-based agent.")
    parser.add_argument("--dry-run", action="store_true",
                         help="Log what would be done without killing "
                              "anything or touching file permissions.")
    args = parser.parse_args()

    responder = PrivescResponder(dry_run=args.dry_run)

    print("[*] OS-based response engine started. Reading alerts from "
          "stdin (pipe detection.py into this script).")
    if args.dry_run:
        print("[*] DRY RUN MODE -- no processes will be killed and no "
              "file permissions will change.")
    print("[*] Press Ctrl+C to stop.\n", flush=True)

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                verdict = json.loads(line)
            except json.JSONDecodeError:
                continue  # human-readable ALERT lines, banners, etc. - skip

            # Only react to things that look like a suspected_privesc
            # verdict from detection.py (have the fields we need) --
            # anything else that happens to be valid JSON is ignored
            # rather than risking a crash on an unexpected shape.
            if verdict.get("verdict") != "suspected_privesc":
                continue
            if "pid" not in verdict and "exe" not in verdict:
                continue

            responder.handle(verdict)

    except KeyboardInterrupt:
        print("\n[*] Stopping OS-based response engine.")


if __name__ == "__main__":
    main()
