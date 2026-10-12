"""
common/events.py
================
A shared, structured event format used by every monitoring agent in the
project. Standardising on one event shape means your detection engines
consume telemetry from any agent the same way, rather than each agent
inventing its own ad-hoc output format.

This module lives in src/modules/common/, a sibling of every other
module directory under src/modules/ -- OS/, "Brute force/", plus
network/malware/injection, which already write straight to files of
their own. GUI-Dashboard.py (the GUI) lives one level further up, in
core/ at the repo root, and reaches this module by adding
src/modules/ to its import path (see the comment above its own import
of this module for why that's a slightly longer reach than every
module under src/modules/ needs). This module is the single source of
truth for WHERE each stage's output lands on disk: the dashboard reads
from a fixed set of file paths, this module defines that same set of
paths, and gives monitor/detection/response code a couple of small
helpers (`append_jsonl`, `follow_jsonl`) for writing to and reading
from them, so every stage talks to the GUI -- and to the next stage --
over a plain file instead of a shell pipe.

Why drop stdin/stdout:
    The original monitor | detection | response chaining was a
    deliberately simple way to prove the monitor/detect/response split
    worked before a real consumer existed (see the project README's
    "Why JSON-lines to stdout, for now" section). Now that
    GUI-Dashboard.py IS that consumer, and it -- like the
    network/malware/injection modules -- only ever reads fixed files
    from disk, keeping stdout as the inter-stage transport buys
    nothing and costs real things: every pipeline has to be started as
    one long `a | b | c` shell command (so one stage dying silently
    stops the ones after it), nothing can be restarted independently,
    and nothing lands anywhere the GUI can see until you remember to
    redirect it. Writing straight to the shared files fixes all three
    and matches how the rest of the team's modules already work.

Shared OS_* files:
    OS/ (both its SUID and cron components) report into the OS_FACTS_LOG /
    OS_ALERT_LOG / OS_RESPONSE_LOG trio, matching the dashboard's
    single "OS Attacks" category and its load_os_events() /
    load_os_response_actions() loaders, which already distinguish a
    SUID verdict from a cron verdict by field shape (`verdict` vs.
    `path`), not by file. Each stage's own filtering (e.g.
    suid_detection.py only acting on event_type == "uid_mismatch") means
    sharing one facts/alert file between the two modules is safe --
    each consumer already ignores records that aren't its own.
"""

import json
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

# ============================================================
# Shared on-disk log locations
# ============================================================
# These paths MUST match GUI-Dashboard.py's OS_ALERT_LOG /
# OS_RESPONSE_LOG / BRUTE_ALERT_LOG / BRUTE_RESPONSE_LOG constants --
# the dashboard imports them from here rather than redeclaring them, so
# the two sides can't drift apart.

OS_FACTS_LOG = "/var/log/edr_os_facts.jsonl"
OS_ALERT_LOG = "/var/log/edr_os_alerts.jsonl"
OS_RESPONSE_LOG = "/var/log/edr_os_response_actions.jsonl"

BRUTE_FACTS_LOG = "/var/log/edr_bruteforce_facts.jsonl"
BRUTE_ALERT_LOG = "/var/log/edr_bruteforce_alerts.jsonl"
BRUTE_RESPONSE_LOG = "/var/log/edr_bruteforce_response_actions.jsonl"

# Which facts/alert/response file each MonitoringEvent `source` reports
# into. Add an entry here (and update the dashboard) if a new agent
# joins this same file-based scheme later.
FACTS_LOG_BY_SOURCE = {
    "os": OS_FACTS_LOG,
    "cron": OS_FACTS_LOG,
    "brute_force": BRUTE_FACTS_LOG,
}
ALERT_LOG_BY_SOURCE = {
    "os": OS_ALERT_LOG,
    "cron": OS_ALERT_LOG,
    "brute_force": BRUTE_ALERT_LOG,
}
RESPONSE_LOG_BY_SOURCE = {
    "os": OS_RESPONSE_LOG,
    "cron": OS_RESPONSE_LOG,
    "brute_force": BRUTE_RESPONSE_LOG,
}


# ============================================================
# File-based transport helpers
# ============================================================

def append_jsonl(path: str, record: dict):
    """Append one JSON object to a shared log file as a line, creating
    the parent directory first if needed. This is the file-based
    replacement for "print a JSON line and let a shell pipe carry it
    to the next stage" -- every stage writes its output where the
    NEXT stage (or the GUI) can find it on disk, instead of only on
    whatever process happens to be reading its stdout right now."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
        f.flush()


def follow_jsonl(path: str, poll_seconds: float = 0.5, from_start: bool = False):
    """Generator that yields each JSON object appended to `path`,
    forever -- the file-based equivalent of `for line in sys.stdin`
    reading a live pipe.

    By default starts at the END of the file, so a freshly-started
    consumer only sees records written from this moment on (the same
    behaviour a shell pipe already had: you only see what's emitted
    after you start listening). Pass from_start=True to instead replay
    everything already on disk before following new appends -- useful
    for a response stage that wants to catch up on alerts it missed
    while it was down.

    A line that isn't valid JSON is skipped rather than raised on;
    there shouldn't be any since this file is only ever written to via
    append_jsonl(), but a stray blank line (or someone tailing the
    file by hand) shouldn't be able to crash a consumer.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "a").close()  # ensure the file exists before we open it to read

    with open(path, "r", encoding="utf-8") as f:
        if not from_start:
            f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_seconds)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


# ============================================================
# The shared event shape
# ============================================================

@dataclass
class MonitoringEvent:
    source: str          # which agent produced this, e.g. "brute_force" or "os"
    event_type: str       # short category, e.g. "ssh_auth_attempt", "euid_mismatch"
    data: dict            # the actual details specific to this event type
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_json(self) -> str:
        """Serialise this event to a JSON string, ready to print or log."""
        return json.dumps(asdict(self))

    def emit(self):
        """
        Print the event as a JSON line (handy for watching a monitor
        run directly in a terminal) AND append it to this source's
        shared facts file, so a detection engine no longer needs to be
        fed via a shell pipe -- it can tail the facts file itself with
        follow_jsonl() instead.

        Sources with no entry in FACTS_LOG_BY_SOURCE (none currently)
        just print, same as before this module wrote to disk at all.
        """
        print(self.to_json(), flush=True)
        path = FACTS_LOG_BY_SOURCE.get(self.source)
        if path:
            append_jsonl(path, asdict(self))
