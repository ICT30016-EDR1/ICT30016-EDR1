"""
brute_force_agent/detection.py
================================
Detection layer for the brute force agent. Consumes the structural facts
emitted by BOTH monitors:

  - brute_force_agent/monitor.py            -> ssh_auth_attempt
  - brute_force_agent/juice_shop_monitor.py -> web_login_attempt

and decides whether they add up to an attack. Neither monitor judges
anything; every threshold and rule lives here.

Approach: a per-source-IP sliding window (the same idea as the
sliding-window detection discussed in the project's literature review).
For each channel, the engine keeps the last N seconds of attempts per
source IP and re-evaluates a small set of rules every time a new event
arrives. Events are timed by the timestamp the monitor stamped on them,
not by when this script happens to read them, so a replayed or delayed
event stream is judged the same as a live one.

Rules, per channel (SSH identity = username, web identity = email):

  1. Targeted brute force   - many failures from one IP against ONE
                              identity within the window (Lab 1 / the
                              hydra -l <user> -P <list> pattern).
  2. Spraying / stuffing    - failures from one IP spread across MANY
                              distinct identities within the window.
                              Reported as "password_spraying" for SSH
                              and "credential_stuffing" for web, since
                              that is the form each takes in the labs.
  3. Success after failures - an accepted login from an IP that has just
                              racked up failures. This is the one that
                              says the guessing WORKED, so it is
                              reported at a higher severity.

An IP that keeps hammering after an alert fires is not re-alerted on
every event; the same (rule, ip, identity) is suppressed for COOLDOWN
seconds of event time, then allowed to alert again.

Usage (both monitors feeding one detector):
    (sudo python3 brute_force_agent/monitor.py & \\
     sudo python3 brute_force_agent/juice_shop_monitor.py & \\
     wait) | python3 brute_force_agent/detection.py

Or just one of them:
    sudo python3 brute_force_agent/monitor.py | python3 brute_force_agent/detection.py

The thresholds below are sized for the lab wordlists (a handful of
attempts), so the attacks in Labs 1 and 2 are visible. A real
deployment would raise them to cut false positives from people who
simply mistype a password.
"""

import sys
import json
from collections import deque
from datetime import datetime
from dataclasses import dataclass


@dataclass(frozen=True)
class ChannelConfig:
    name: str                  # "ssh" or "web"
    event_type: str            # which monitor event this channel consumes
    identity_field: str        # data field holding the account guessed at
    spread_rule_name: str      # what many-identities-from-one-IP is called here
    window_seconds: int = 60
    brute_force_threshold: int = 5          # failures vs ONE identity
    spread_threshold: int = 3               # distinct identities failed against
    success_after_failures_threshold: int = 3
    cooldown_seconds: int = 60


SSH = ChannelConfig(
    name="ssh",
    event_type="ssh_auth_attempt",
    identity_field="username",
    spread_rule_name="password_spraying",
)

WEB = ChannelConfig(
    name="web",
    event_type="web_login_attempt",
    identity_field="email",
    spread_rule_name="credential_stuffing",
)

CHANNELS_BY_EVENT_TYPE = {cfg.event_type: cfg for cfg in (SSH, WEB)}


class SlidingWindowDetector:
    """
    Detection state and rules for ONE channel (SSH or web). Keeping the
    two channels in separate instances means SSH failures never count
    towards a web alert or vice versa, even from the same IP.
    """

    def __init__(self, config: ChannelConfig):
        self.config = config
        # source_ip -> deque of (event_time: datetime, identity, result)
        self._attempts: dict[str, deque] = {}
        # (rule, ip, identity-or-None) -> event_time of the last alert
        self._last_alert: dict[tuple, datetime] = {}

    def observe(self, event_time: datetime, source_ip: str,
                identity, result: str) -> list[dict]:
        """Record one attempt and return any alerts it triggers."""
        window = self._attempts.setdefault(source_ip, deque())
        window.append((event_time, identity, result))
        self._prune(window, event_time)

        failures = [(t, who) for t, who, res in window if res == "failed"]
        alerts = []

        if result == "failed":
            alerts += self._check_targeted(event_time, source_ip, identity, failures)
            alerts += self._check_spread(event_time, source_ip, failures)
        elif result == "accepted":
            alerts += self._check_success_after_failures(
                event_time, source_ip, identity, failures)

        return alerts

    # ---- rules -----------------------------------------------------

    def _check_targeted(self, now, ip, identity, failures):
        count = sum(1 for _, who in failures if who == identity)
        if count < self.config.brute_force_threshold:
            return []
        return self._raise(
            now, "brute_force", "high", ip, identity,
            f"{count} failed logins against '{identity}' from {ip} "
            f"within {self.config.window_seconds}s",
            {"failures": count},
        )

    def _check_spread(self, now, ip, failures):
        identities = {who for _, who in failures if who is not None}
        if len(identities) < self.config.spread_threshold:
            return []
        return self._raise(
            now, self.config.spread_rule_name, "high", ip, None,
            f"{len(failures)} failed logins from {ip} spread across "
            f"{len(identities)} different accounts within "
            f"{self.config.window_seconds}s",
            {"failures": len(failures), "distinct_identities": len(identities)},
        )

    def _check_success_after_failures(self, now, ip, identity, failures):
        if len(failures) < self.config.success_after_failures_threshold:
            return []
        return self._raise(
            now, "success_after_failures", "critical", ip, identity,
            f"successful login as '{identity}' from {ip} right after "
            f"{len(failures)} failures within {self.config.window_seconds}s "
            f"- guessing likely succeeded",
            {"failures_before_success": len(failures)},
        )

    # ---- helpers ---------------------------------------------------

    def _prune(self, window: deque, now: datetime):
        """Drop attempts that have slid out of the window."""
        while window and (now - window[0][0]).total_seconds() > self.config.window_seconds:
            window.popleft()

    def _raise(self, now, rule, severity, ip, identity, message, detail):
        key = (rule, ip, identity)
        last = self._last_alert.get(key)
        if last is not None and (now - last).total_seconds() < self.config.cooldown_seconds:
            return []  # already told them about this one recently
        self._last_alert[key] = now
        return [{
            "channel": self.config.name,
            "rule": rule,
            "severity": severity,
            "source_ip": ip,
            "identity": identity,
            "message": message,
            "detail": detail,
            "event_time": now.isoformat(),
        }]


class BruteForceEngine:
    """Routes each incoming event to the detector for its channel."""

    def __init__(self):
        self.detectors = {
            cfg.event_type: SlidingWindowDetector(cfg)
            for cfg in (SSH, WEB)
        }

    def evaluate(self, event: dict) -> list[dict]:
        """
        Given one parsed MonitoringEvent dict, return the alerts it
        triggers (possibly none). Events from other agents or with
        missing fields are ignored rather than raising.
        """
        if event.get("source") != "brute_force":
            return []

        config = CHANNELS_BY_EVENT_TYPE.get(event.get("event_type"))
        if config is None:
            return []

        data = event.get("data") or {}
        ip = data.get("source_ip")
        result = data.get("result")
        if not ip or result not in ("failed", "accepted"):
            return []

        try:
            event_time = datetime.fromisoformat(event["timestamp"])
        except (KeyError, ValueError, TypeError):
            return []

        detector = self.detectors[config.event_type]
        return detector.observe(
            event_time, ip, data.get(config.identity_field), result)


def format_alert(alert: dict) -> str:
    tag = "!!" if alert["severity"] == "critical" else "!"
    return (f"[{tag}] ALERT [{alert['severity'].upper()}] "
            f"{alert['channel']}/{alert['rule']}: {alert['message']}")


def main():
    print("[*] Brute force detection engine started. Reading events from "
          "stdin (pipe the monitor(s) into this script).")
    print("[*] Press Ctrl+C to stop.\n")

    engine = BruteForceEngine()

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue  # monitor start-up banners etc. - not events

            for alert in engine.evaluate(event):
                print(format_alert(alert), flush=True)

    except KeyboardInterrupt:
        print("\n[*] Stopping brute force detection engine.")


if __name__ == "__main__":
    main()
