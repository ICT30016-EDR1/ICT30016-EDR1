"""
brute_force_response.py
===============================
Response layer for the brute force agent. Consumes the alert facts
emitted by brute_force_detection.py and takes an automated action:
temporarily firewalling off the offending source IP via ufw.

This keeps the same three-layer separation used throughout the project:
    monitor   -> facts      ("here's what happened")
    detection -> judgments  ("this looks like an attack")
    response  -> actions    ("do something about it")

brute_force_response.py doesn't re-derive any judgment itself -- it trusts whatever
brute_force_detection.py decided and acts on it. If the thresholds are wrong, that's
a brute_force_detection.py tuning problem, not something brute_force_response.py second-guesses.

Tiered response: the ban length depends on the alert's severity. A HIGH
alert (brute_force / password_spraying / credential_stuffing) gets a
short ban; a CRITICAL alert (success_after_failures -- meaning the
guessing likely WORKED) gets a longer one, since the risk is worse.

If a new alert arrives for an IP that's already banned, the ban is
extended (the un-ban timer is reset) rather than erroring out on a
duplicate firewall rule or stacking multiple rules for the same IP.

Usage (run each stage independently -- no shell pipe needed):
    sudo python3 ssh_monitor.py &              # writes facts to BRUTE_FACTS_LOG
    sudo python3 juice_shop_monitor.py &    # same file
    python3 brute_force_detection.py &                   # tails facts, writes to BRUTE_ALERT_LOG
    sudo python3 brute_force_response.py                 # tails BRUTE_ALERT_LOG, bans, writes to BRUTE_RESPONSE_LOG

(brute_force_response.py needs sudo to run ufw; ssh_monitor.py needs sudo to
read auth.log; brute_force_detection.py needs neither.)

This reads alerts from the shared BRUTE_ALERT_LOG file (common/events.py)
instead of stdin, and writes its own actions to BRUTE_RESPONSE_LOG
instead of stdout -- the same file GUI-Dashboard.py's
load_brute_response_actions() reads from.

For testing without touching the firewall at all:
    python3 brute_force_response.py --dry-run
"""

import sys
import os
import argparse
import subprocess
import threading
from datetime import datetime

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from common.events import BRUTE_ALERT_LOG, BRUTE_RESPONSE_LOG, append_jsonl, follow_jsonl

# Ban duration per alert severity, in seconds. These are short for
# lab/demo purposes so you can actually observe a ban expire during
# testing -- a real deployment would tune these, likely much longer.
BAN_DURATION_SECONDS = {
    "high": 600,       # 10 minutes
    "critical": 3600,  # 60 minutes
}
DEFAULT_BAN_SECONDS = 300

# IPs that are never blocked, however bad the alert -- a basic safety
# governor so a misconfigured rule (or testing against your own
# machine) can't lock you out of your own lab.
NEVER_BLOCK = {"127.0.0.1"}


def ban_duration_for(severity: str) -> int:
    return BAN_DURATION_SECONDS.get(severity, DEFAULT_BAN_SECONDS)


def log_action(action: str, ip: str, reason: str, message: str):
    """
    Print a human-readable line (handy when watching this run directly)
    AND append the structured record to BRUTE_RESPONSE_LOG -- the same
    dual-output idea brute_force_detection.py uses, so the GUI dashboard's
    load_brute_response_actions() can consume response actions the
    same way it consumes alerts.
    """
    print(f"[>] RESPONSE: {message}", flush=True)
    append_jsonl(BRUTE_RESPONSE_LOG, {
        "source": "brute_force",
        "layer": "response",
        "action": action,
        "ip": ip,
        "reason": reason,
        "timestamp": datetime.now().astimezone().isoformat(),
    })


class IPBanManager:
    """
    Tracks which IPs are currently banned and their un-ban timers, so a
    repeat alert for an already-banned IP extends the ban instead of
    issuing a duplicate firewall rule.
    """

    def __init__(self, dry_run: bool):
        self.dry_run = dry_run
        self._timers: dict[str, threading.Timer] = {}
        self._lock = threading.Lock()

    def ban(self, ip: str, duration_seconds: int, reason: str):
        if ip in NEVER_BLOCK:
            log_action("skip_never_block", ip, reason,
                       f"{ip} is on the never-block list -- ignoring alert")
            return

        with self._lock:
            already_banned = ip in self._timers
            if already_banned:
                self._timers[ip].cancel()
            else:
                self._run_ufw(["insert", "1", "deny", "from", ip, "to", "any"])

            timer = threading.Timer(duration_seconds, self._unban, args=[ip])
            timer.daemon = True
            timer.start()
            self._timers[ip] = timer

        action = "extend_ban" if already_banned else "ban"
        verb = "Extended ban on" if already_banned else "Banned"
        log_action(action, ip, reason,
                   f"{verb} {ip} for {duration_seconds}s (reason: {reason})")

    def _unban(self, ip: str):
        with self._lock:
            self._timers.pop(ip, None)
        self._run_ufw(["delete", "deny", "from", ip, "to", "any"])
        log_action("unban", ip, "ban_expired",
                   f"Ban on {ip} has expired, access restored")

    def _run_ufw(self, args: list):
        command = ["ufw"] + args
        if self.dry_run:
            print(f"[DRY RUN] would run: sudo {' '.join(command)}", flush=True)
            return
        try:
            subprocess.run(["sudo"] + command, check=True,
                            capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            print(f"[!] ufw command failed: {e.stderr.strip()}",
                  file=sys.stderr, flush=True)
        except FileNotFoundError:
            print("[!] ufw not found -- is it installed? "
                  "(sudo apt install ufw)", file=sys.stderr, flush=True)


def main():
    parser = argparse.ArgumentParser(
        description="Response engine for the brute force agent.")
    parser.add_argument("--dry-run", action="store_true",
                         help="Log what would be done without touching ufw.")
    args = parser.parse_args()

    manager = IPBanManager(dry_run=args.dry_run)

    print(f"[*] Brute force response engine started. Reading alerts from "
          f"{BRUTE_ALERT_LOG}.")
    if args.dry_run:
        print("[*] DRY RUN MODE -- no firewall rules will actually change.")
    print("[*] Press Ctrl+C to stop.\n", flush=True)

    try:
        for alert in follow_jsonl(BRUTE_ALERT_LOG):
            # Only react to things that look like an alert from
            # brute_force_detection.py (have the fields we need) -- anything else
            # in BRUTE_ALERT_LOG is ignored rather than risking a
            # crash on an unexpected shape.
            ip = alert.get("source_ip")
            severity = alert.get("severity")
            rule = alert.get("rule")
            if not ip or not severity or not rule:
                continue

            manager.ban(ip, ban_duration_for(severity), reason=rule)

    except KeyboardInterrupt:
        print("\n[*] Stopping brute force response engine.")


if __name__ == "__main__":
    main()
