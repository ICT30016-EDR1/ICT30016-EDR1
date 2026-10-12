"""
cron_response.py
=========================
Response layer for the cron job hijacking agent. Consumes the verdicts
emitted by cron_detection.py and takes two independent automated
actions, matching the two things detection.py alerts on:

  1. Modified (tampering just happened) -> restore the script from a
     known-good backup. The backup itself is taken EARLIER, the moment
     detection.py tells us a baseline was recorded for that path --
     response.py reads the file straight off disk at that point (it
     runs on the same machine as the rest of the pipeline) and keeps a
     copy before anything has a chance to tamper with it. Without that
     earlier backup there is nothing uncorrupted to restore FROM, so a
     "modified" alert for a path we never backed up is logged as
     restore_skipped rather than guessed at.
  2. Writable risk (group/other can write to the script right now) ->
     lock the permissions down by stripping the group/other write bits,
     independent of whether a modification has happened yet. This is
     the root-cause fix: closing the hole, not just undoing one use of
     it.

Same three-layer separation used throughout the project:
    monitor   -> facts      ("here's what happened")
    detection -> judgments  ("this looks like an attack")
    response  -> actions    ("do something about it")

response.py doesn't re-derive any judgment -- it trusts whatever
detection.py decided (baseline_set / modified / writable_risk) and acts
on it.

Usage (run each stage independently -- no shell pipe needed):
    sudo python3 cron_monitor.py &     # writes facts to OS_FACTS_LOG
    python3 cron_detection.py &        # tails facts, writes to OS_ALERT_LOG
    sudo python3 cron_response.py      # tails OS_ALERT_LOG, acts, writes to OS_RESPONSE_LOG

(response.py needs sudo to overwrite a root-owned script and chmod it;
monitor.py needs sudo to read every cron-referenced script's owner/
permissions.)

This reads verdicts from the shared OS_ALERT_LOG file (common/events.py)
instead of stdin, and writes its own actions to OS_RESPONSE_LOG instead
of stdout -- the same pair of files suid_response.py uses, so the
GUI dashboard's load_os_response_actions() reads both agents' actions
the same way. Records are tagged "source": "cron" so os's own
verdicts passing through the same file are ignored (see the `if "path"
not in verdict` filter in main() below).

For testing without restoring or chmod'ing anything for real:
    python3 cron_response.py --dry-run
"""

import sys
import os
import shutil
import argparse
from datetime import datetime

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from common.events import OS_ALERT_LOG, OS_RESPONSE_LOG, append_jsonl, follow_jsonl

# Where known-good backups are kept, one file per tracked script. Kept
# on disk (rather than only in memory) so a backup taken in an earlier
# run is still there to restore from if this script gets restarted --
# the cron side's equivalent of the os/ SUID side's dedupe set, just
# persisted instead of in-memory, since a backup is exactly the kind
# of thing you don't want to lose on a restart.
DEFAULT_BACKUP_DIR = "/var/lib/edr_cron_backups"

# Cron-referenced scripts are already restricted by monitor.py's own
# extraction pattern to *.sh files, or paths under /opt or
# /usr/local -- but a second, independent check here costs nothing and
# means a bug or a bad detection verdict can't make this script
# overwrite or chmod something under a core system directory.
PROTECTED_PREFIXES = ("/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib")


def backup_file_for(path: str, backup_dir: str) -> str:
    """Map a tracked script's real path to its backup file's path,
    e.g. /opt/lab_backup.sh -> <backup_dir>/opt_lab_backup.sh.bak"""
    sanitized = path.strip("/").replace("/", "_")
    return os.path.join(backup_dir, f"{sanitized}.bak")


def log_action(action: str, path: str, reason: str, message: str):
    """
    Print a human-readable line (handy when watching this run directly)
    AND append the structured record to OS_RESPONSE_LOG -- the same
    dual-output idea the other two agents' response.py scripts use.
    """
    print(f"[>] RESPONSE: {message}", flush=True)
    append_jsonl(OS_RESPONSE_LOG, {
        "source": "cron",
        "layer": "response",
        "action": action,
        "path": path,
        "reason": reason,
        "timestamp": datetime.now().astimezone().isoformat(),
    })


class CronResponder:
    """
    Takes backup/restore and permission-lockdown actions for cron
    script verdicts. Keeps track of which paths have a backup on disk
    so a "modified" alert for a path with no known-good copy is logged
    as skipped rather than guessed at.
    """

    def __init__(self, dry_run: bool, backup_dir: str = DEFAULT_BACKUP_DIR):
        self.dry_run = dry_run
        self.backup_dir = backup_dir
        if not dry_run:
            os.makedirs(backup_dir, exist_ok=True)

    def handle(self, verdict: dict):
        path = verdict.get("path")
        status = verdict.get("status")
        mode = verdict.get("mode")
        writable_risk = verdict.get("writable_risk")

        if not path:
            return

        if path.startswith(PROTECTED_PREFIXES):
            log_action("skip_never_touch", path, "protected_path",
                       f"{path} is on a protected path -- ignoring alert")
            return

        if status == "baseline_set":
            self._backup(path)
        elif status == "modified":
            self._restore(path)

        if writable_risk:
            self._lock_down_permissions(path, mode)

    # ---- actions -----------------------------------------------------

    def _backup(self, path):
        dest = backup_file_for(path, self.backup_dir)

        if self.dry_run:
            print(f"[DRY RUN] would run: cp --preserve=mode,ownership "
                  f"{path} {dest}", flush=True)
            log_action("backup", path, "baseline_set",
                       f"[DRY RUN] would back up known-good copy of "
                       f"{path} to {dest}")
            return

        try:
            shutil.copy2(path, dest)
            log_action("backup", path, "baseline_set",
                       f"Backed up known-good copy of {path} to {dest}")
        except FileNotFoundError:
            log_action("backup_skipped", path, "baseline_set",
                       f"{path} no longer exists -- nothing to back up")
        except PermissionError:
            print(f"[!] backup failed: not permitted to read {path} or "
                  f"write {dest} (are we running as root?)",
                  file=sys.stderr, flush=True)

    def _restore(self, path):
        dest = backup_file_for(path, self.backup_dir)
        have_backup = os.path.exists(dest)

        if self.dry_run:
            if not have_backup:
                log_action("restore_skipped", path, "modified",
                           f"[DRY RUN] no known-good backup found for "
                           f"{path} at {dest} -- would need manual review")
                return
            print(f"[DRY RUN] would run: cp --preserve=mode,ownership "
                  f"{dest} {path}", flush=True)
            log_action("restore", path, "modified",
                       f"[DRY RUN] would restore {path} from known-good "
                       f"backup {dest}")
            return

        if not have_backup:
            log_action("restore_skipped", path, "modified",
                       f"No known-good backup exists for {path} -- can't "
                       f"auto-restore. This script was likely tampered "
                       f"with before this agent ever saw a clean baseline "
                       f"-- flag for manual review.")
            return

        try:
            # copy2 preserves the backup file's own mode -- but the
            # backup may have been taken back when the script still had
            # the writable misconfiguration (that's often exactly how
            # the attacker got in). Restoring content with copy2 alone
            # would silently bring that same insecure mode back too, so
            # every restore is immediately followed by stripping the
            # group/other write bits again, regardless of what mode the
            # backup carried. Content comes back, the hole does not.
            shutil.copy2(dest, path)
            restored_mode = os.stat(path).st_mode & 0o777
            safe_mode = restored_mode & ~0o022
            if safe_mode != restored_mode:
                os.chmod(path, safe_mode)
            log_action("restore", path, "modified",
                       f"Restored {path} from known-good backup and "
                       f"hardened its permissions to {oct(safe_mode)} -- "
                       f"tampering reverted")
        except PermissionError:
            print(f"[!] restore failed: not permitted to write {path} "
                  f"(are we running as root?)", file=sys.stderr, flush=True)

    def _lock_down_permissions(self, path, mode_str):
        try:
            current_mode = int(mode_str, 8)
        except (TypeError, ValueError):
            log_action("lock_down_skipped", path, "writable_risk",
                       f"couldn't parse mode {mode_str!r} for {path} -- "
                       f"skipping permission fix")
            return

        safe_mode = current_mode & ~0o022  # strip group + other write
        if safe_mode == current_mode:
            return  # nothing to fix (shouldn't happen if writable_risk fired)

        if self.dry_run:
            print(f"[DRY RUN] would run: sudo chmod {oct(safe_mode)} {path}",
                  flush=True)
            log_action("lock_down_permissions", path, "writable_risk",
                       f"[DRY RUN] would chmod {path} to {oct(safe_mode)} "
                       f"(removing group/other write)")
            return

        try:
            os.chmod(path, safe_mode)
            log_action("lock_down_permissions", path, "writable_risk",
                       f"Removed group/other write bit from {path} "
                       f"(mode now {oct(safe_mode)})")
        except FileNotFoundError:
            log_action("lock_down_skipped", path, "writable_risk",
                       f"{path} no longer exists -- nothing to chmod")
        except PermissionError:
            print(f"[!] chmod failed: not permitted to modify {path} "
                  f"(are we running as root?)", file=sys.stderr, flush=True)


def main():
    parser = argparse.ArgumentParser(
        description="Response engine for the cron job hijacking agent.")
    parser.add_argument("--dry-run", action="store_true",
                         help="Log what would be done without restoring "
                              "or chmod'ing anything for real.")
    parser.add_argument("--backup-dir", default=DEFAULT_BACKUP_DIR,
                         help=f"Where known-good script backups are kept "
                              f"(default: {DEFAULT_BACKUP_DIR})")
    args = parser.parse_args()

    responder = CronResponder(dry_run=args.dry_run, backup_dir=args.backup_dir)

    print(f"[*] Cron-based response engine started. Reading verdicts from "
          f"{OS_ALERT_LOG}.")
    if args.dry_run:
        print("[*] DRY RUN MODE -- no files will actually be restored or "
              "have their permissions changed.")
    print(f"[*] Backups kept in: {args.backup_dir}")
    print("[*] Press Ctrl+C to stop.\n", flush=True)

    try:
        for verdict in follow_jsonl(OS_ALERT_LOG):
            # Only react to things that look like a cron detection
            # verdict (have the fields we need) -- anything else in
            # the shared OS_ALERT_LOG (e.g. an os SUID verdict)
            # is ignored.
            if "path" not in verdict or "status" not in verdict:
                continue

            responder.handle(verdict)

    except KeyboardInterrupt:
        print("\n[*] Stopping cron-based response engine.")


if __name__ == "__main__":
    main()
