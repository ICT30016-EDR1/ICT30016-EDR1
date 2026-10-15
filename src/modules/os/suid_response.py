"""
suid_response.py
======================
Response layer for the OS-based agent. Consumes the suspected_privesc
verdicts emitted by suid_detection.py and takes an automated action:
killing the offending process and stripping the SUID bit from the
executable it ran from, so the same binary can't be re-exploited the
same way after the process is gone.

Same three-layer separation used throughout the project:
    monitor   -> facts      ("here's what happened")
    detection -> judgments  ("this looks like an attack")
    response  -> actions    ("do something about it")

suid_response.py doesn't re-derive any judgment itself -- it trusts whatever
suid_detection.py decided (a "suspected_privesc" verdict) and acts on it. If
suid_detection.py is flagging legitimate binaries, that's a suid_detection.py
tuning problem (the KNOWN_LEGITIMATE_SUID_BINARIES allowlist), not
something suid_response.py second-guesses -- which is also why
known_legitimate verdicts are never emitted as JSON in the first place
and never reach this script.

PID reuse safety check: a verdict's `pid` is only a snapshot of which
process had the mismatch AT THE TIME suid_monitor.py polled it. Linux
recycles PID numbers once a process exits, and this project's exploit
labs produce exactly the kind of short-lived process chain (fork/exec/
exec/exit) where the real offending process can have already exited --
and its PID been reassigned to a completely unrelated, legitimate
process -- by the time this script gets around to acting on the
verdict. Acting on the PID alone in that situation means killing and
stripping the SUID bit off the WRONG, innocent binary (this was
observed in practice: a verdict for a short-lived privesc chain ended
up matching a legitimate `newgrp` invocation that happened to reuse
the same PID moments later, and `newgrp` had its SUID bit incorrectly
stripped as a result, breaking it for every user on the box).

To prevent this, every verdict also carries the process's start_time
(suid_monitor.py captures it via psutil's Process.create_time(), which
is unique per process instance, not just per PID number). Before
killing or stripping anything, this script re-reads the CURRENT
process at that PID and confirms its start_time still matches what was
recorded. If it doesn't match (or the PID no longer exists at all),
the PID has been reused since detection -- both actions are skipped
and logged as such, rather than risking acting on an unrelated
process.

Two actions, taken together for every alert (once the PID-reuse check
above passes):
  1. Kill the offending process (SIGKILL by pid) -- stops whatever it's
     doing right now.
  2. Strip the SUID bit from its executable (chmod u-s) -- the exploit
     almost always depends on that bit being set, so removing it stops
     the SAME binary being abused again, without deleting the file or
     otherwise touching the rest of the system.

If the same exe path is flagged again later, the SUID-strip step is a
no-op (the bit's already gone) and is logged as such rather than
re-reported as a fresh action.

Usage (run each stage independently -- no shell pipe needed):
    sudo python3 suid_monitor.py &     # writes facts to OS_FACTS_LOG
    python3 suid_detection.py &        # tails facts, writes to OS_ALERT_LOG
    sudo python3 suid_response.py      # tails OS_ALERT_LOG, acts, writes to OS_RESPONSE_LOG

(suid_response.py needs sudo to kill another user's process and chmod a
system binary; suid_monitor.py needs sudo to read every process's real/
effective UIDs; suid_detection.py needs neither.)

This reads verdicts from the shared OS_ALERT_LOG file (common/events.py)
instead of stdin, and writes its own actions to OS_RESPONSE_LOG instead
of stdout -- the same file GUI-Dashboard.py's
load_os_response_actions() reads from. cron_response.py writes
into that same file, tagging its own records "source": "cron" so the
two never get confused.

For testing without killing anything or touching file permissions:
    python3 suid_response.py --dry-run
"""

import sys
import os
import stat
import signal
import argparse
from datetime import datetime

import psutil

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from common.events import OS_ALERT_LOG, OS_RESPONSE_LOG, append_jsonl, follow_jsonl

# Binaries that are never touched, however an alert labels them -- a
# basic safety governor so a bad detection rule (or a bug) can't strip
# the SUID bit off something the lab VM itself depends on to boot or
# log in. This is deliberately a superset of suid_detection.py's own
# KNOWN_LEGITIMATE_SUID_BINARIES allowlist, since those should already
# be filtered out before reaching this script, but a second
# independent check here costs nothing and catches a suid_detection.py
# mistake before it does something irreversible.
NEVER_TOUCH_NAMES = {"passwd", "sudo", "su", "mount", "umount", "systemd", "init"}

# pids that are never killed, regardless of what's reported for them.
NEVER_KILL_PIDS = {1}

# How close two create_time() values need to be (in seconds) to count
# as "the same process". psutil reports this with sub-second precision;
# a small tolerance just absorbs float rounding, not genuine PID reuse
# (a reused PID's new process will have a start_time at least whole
# seconds away from the original in virtually every real scenario).
START_TIME_TOLERANCE_SECONDS = 0.01


def log_action(action: str, pid, exe: str, reason: str, message: str):
    """
    Print a human-readable line (handy when watching this run directly)
    AND append the structured record to OS_RESPONSE_LOG -- the same
    dual-output idea brute_force_response.py (in the "Brute force"
    module) uses, so the GUI dashboard's load_os_response_actions()
    can read actions from either module the same way.
    """
    print(f"[>] RESPONSE: {message}", flush=True)
    append_jsonl(OS_RESPONSE_LOG, {
        "source": "os",
        "layer": "response",
        "action": action,
        "pid": pid,
        "exe": exe,
        "reason": reason,
        "timestamp": datetime.now().astimezone().isoformat(),
    })


def pid_still_matches(pid, expected_start_time) -> bool:
    """
    True if the process CURRENTLY running at `pid` is the same process
    instance the verdict was raised for -- i.e. its start_time still
    matches what suid_monitor.py recorded at detection time.

    If expected_start_time is missing (e.g. a verdict from before this
    check existed), there's nothing to verify against, so this returns
    True and the old PID-only behaviour applies -- better to act on
    possibly-stale information than to never act at all.
    """
    if expected_start_time is None:
        return True

    try:
        current_start_time = psutil.Process(pid).create_time()
    except psutil.NoSuchProcess:
        return False

    return abs(current_start_time - expected_start_time) < START_TIME_TOLERANCE_SECONDS


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
        start_time = verdict.get("start_time")
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

        if pid is not None and not pid_still_matches(pid, start_time):
            log_action("skip_pid_reused", pid, exe, reason,
                       f"pid={pid} ({name}) no longer matches the process "
                       f"this alert was raised for -- the PID was likely "
                       f"recycled by a short-lived process (fork/exec/exit) "
                       f"and now belongs to something else. Skipping both "
                       f"the kill and the SUID strip to avoid acting on an "
                       f"unrelated process.")
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

    print(f"[*] OS-based response engine started. Reading verdicts from "
          f"{OS_ALERT_LOG}.")
    if args.dry_run:
        print("[*] DRY RUN MODE -- no processes will be killed and no "
              "file permissions will change.")
    print("[*] Press Ctrl+C to stop.\n", flush=True)

    try:
        for verdict in follow_jsonl(OS_ALERT_LOG):
            # Only react to things that look like a suspected_privesc
            # verdict from suid_detection.py (have the fields we need) --
            # anything else in the shared OS_ALERT_LOG (e.g. a cron
            # verdict) is ignored rather than risking a crash on an
            # unexpected shape.
            if verdict.get("verdict") != "suspected_privesc":
                continue
            if "pid" not in verdict and "exe" not in verdict:
                continue

            responder.handle(verdict)

    except KeyboardInterrupt:
        print("\n[*] Stopping OS-based response engine.")


if __name__ == "__main__":
    main()
