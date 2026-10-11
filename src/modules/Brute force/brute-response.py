"""
brute_force_agent/response.py
===============================
Response layer for the brute force agent. Consumes the alert facts
emitted by brute_force_agent/detection.py and takes an automated action:
temporarily firewalling off the offending source IP via ufw.

This keeps the same three-layer separation used throughout the project:
    monitor   -> facts      ("here's what happened")
    detection -> judgments  ("this looks like an attack")
    response  -> actions    ("do something about it")

response.py doesn't re-derive any judgment itself -- it trusts whatever
detection.py decided and acts on it. If the thresholds are wrong, that's
a detection.py tuning problem, not something response.py second-guesses.

Tiered response: the ban length depends on the alert's severity. A HIGH
alert (brute_force / password_spraying / credential_stuffing) gets a
short ban; a CRITICAL alert (success_after_failures -- meaning the
guessing likely WORKED) gets a longer one, since the risk is worse.

If a new alert arrives for an IP that's already banned, the ban is
extended (the un-ban timer is reset) rather than erroring out on a
duplicate firewall rule or stacking multiple rules for the same IP.

Usage (full chain):
    sudo python3 brute_force_agent/monitor.py | \\
        python3 brute_force_agent/detection.py | \\
        sudo python3 brute_force_agent/response.py

(response.py needs sudo to run ufw; monitor.py needs sudo to read
auth.log; detection.py needs neither -- each sudo prompt is independent,
so you may be asked for your password twice when starting the chain.)

For testing without touching the firewall at all:
    ... | python3 brute_force_agent/response.py --dry-run
"""

import sys
import json
import argparse
import subprocess
import threading
from datetime import datetime

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
    Emit a response action both as a human-readable line and as a
    structured JSON line -- the same dual-output pattern detection.py
    uses, so a future log analyser or the team's shared dashboard could
    consume response actions the same way it consumes monitor/detection
    events.
    """
    print(f"[>] RESPONSE: {message}", flush=True)
    print(json.dumps({
        "source": "brute_force",
        "layer": "response",
        "action": action,
        "ip": ip,
        "reason": reason,
        "timestamp": datetime.now().astimezone().isoformat(),
    }), flush=True)


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

    print("[*] Brute force response engine started. Reading alerts from "
          "stdin (pipe detection.py into this script).")
    if args.dry_run:
        print("[*] DRY RUN MODE -- no firewall rules will actually change.")
    print("[*] Press Ctrl+C to stop.\n", flush=True)

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue  # human-readable ALERT lines, banners, etc. - skip

            # Only react to things that look like an alert from
            # detection.py (have the fields we need) -- anything else
            # that happens to be valid JSON is ignored rather than
            # risking a crash on an unexpected shape.
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
