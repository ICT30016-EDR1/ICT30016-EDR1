"""
juice_shop_monitor.py
=========================================
Monitoring layer for web-based brute force / credential stuffing against
OWASP Juice Shop's login endpoint (Lab 2).

Why this isn't just a file we can tail directly from Juice Shop: it
doesn't write individual login attempts to any log file by default --
Lab 2 itself has you fall back to tcpdump/Wireshark for evidence for
exactly this reason.

This version uses a plain nginx reverse proxy as a vantage point,
configured to log the request line, status code, and POST body, then
polls that access log file on a fixed interval the same way
ssh_monitor.py polls /var/log/auth.log.

Why polling instead of watchdog/inotify:
    The original version used watchdog's Observer to watch the
    containing directory (/var/log/nginx) for IN_MODIFY events.
    Directory-level inotify watches on a busy log directory can hit the
    kernel's per-watch event queue limit under sustained traffic,
    silently dropping further events (IN_Q_OVERFLOW) with no Python
    exception raised anywhere -- the process stays alive, the file
    handle stays open, but it just stops reacting to new writes. A
    fixed-interval poll removes that failure mode entirely and drops
    the `watchdog` dependency for this module. The latency this trades
    away (worst case ~POLL_INTERVAL_SECONDS) is negligible against the
    detector's 60-second window.

Required nginx configuration (see README for the full setup):

    # in /etc/nginx/nginx.conf, inside the http {} block:
    log_format juice_login '$remote_addr [$time_iso8601] "$request" '
                            '$status BODY:$request_body';

    # in /etc/nginx/sites-available/juiceshop-proxy:
    server {
        listen 8081;
        access_log /var/log/nginx/juiceshop_access.log juice_login;
        location / {
            proxy_pass http://127.0.0.1:3000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }

Point attackers at the proxy port (8081), not Juice Shop's real port
(3000) directly, so this access log actually sees the traffic -- same
principle as a WAF or reverse-proxy IDS sitting in front of a real app.

$request_body is populated because nginx buffers the whole request body
before proxying a POST -- this is how the attempted email survives into
the log line without needing to inspect traffic at the application
layer ourselves.

Like ssh_monitor.py, this module ONLY does structural
parsing of each access log line into fields -- no judgment about
whether a given attempt is part of an attack. It emits the SAME source
("brute_force") as the SSH monitor, just a different event_type, so a
future shared detection engine can threshold across both.

Usage:
    sudo python3 juice_shop_monitor.py
"""

import sys
import os
import re
import time
import json
from urllib.parse import parse_qs

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from common.events import MonitoringEvent

ACCESS_LOG_PATH = "/var/log/nginx/juiceshop_access.log"
LOGIN_PATH = "/rest/user/login"
POLL_INTERVAL_SECONDS = 1

# Matches: 192.168.1.20 [2026-10-05T10:12:00+00:00] "POST /rest/user/login HTTP/1.1" 401 BODY:email=a@b.com&password=x
LOG_LINE_PATTERN = re.compile(
    r'^(?P<ip>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" '
    r'(?P<status>\d+) BODY:(?P<body>.*)$'
)


def _extract_email(body: str):
    """
    Best-effort extraction of the submitted email address from the
    logged request body, whichever shape it arrives in: JSON (what
    Juice Shop's own frontend sends) or form-encoded (Hydra's
    http-post-form default). Purely structural -- just pulling a field
    out, no judgment about the value.
    """
    body = body.strip()
    if not body:
        return None
    try:
        if body.startswith("{"):
            return json.loads(body).get("email")
        values = parse_qs(body).get("email")
        return values[0] if values else None
    except Exception:
        return None


def _parse_line(line: str):
    """
    Parse one nginx access log line into a structured dict, or return
    None if it isn't a POST to the login endpoint (i.e. not relevant
    to this agent).
    """
    match = LOG_LINE_PATTERN.match(line)
    if not match:
        return None

    request_line = match.group("request")
    parts = request_line.split()
    if len(parts) < 2:
        return None
    method, path = parts[0], parts[1]

    if method != "POST" or path != LOGIN_PATH:
        return None  # not a login attempt -- not our concern here

    status = int(match.group("status"))
    email = _extract_email(match.group("body"))

    return {
        "result": "accepted" if status == 200 else "failed",
        "email": email,
        "source_ip": match.group("ip"),
        "status_code": status,
        "endpoint": LOGIN_PATH,
    }


class AccessLogPoller:
    """
    Polls nginx's access log on a fixed interval and processes only
    the bytes appended since the last check, using a tracked file
    offset. Mirrors ssh_monitor.py's AuthLogPoller.
    """

    def __init__(self, path):
        self.path = os.path.abspath(path)
        self._fh = open(self.path, "r")
        self._fh.seek(0, os.SEEK_END)
        self._offset = self._fh.tell()

    def poll_once(self):
        try:
            current_size = os.path.getsize(self.path)
        except OSError:
            return  # file momentarily missing (mid-rotation); try again next poll

        if current_size < self._offset:
            self._fh.close()
            self._fh = open(self.path, "r")
            self._offset = 0

        if current_size == self._offset:
            return  # nothing new

        self._fh.seek(self._offset)
        for line in self._fh:
            line = line.strip()
            if not line:
                continue
            data = _parse_line(line)
            if data is None:
                continue
            MonitoringEvent(
                source="brute_force",
                event_type="web_login_attempt",
                data=data,
            ).emit()
        self._offset = self._fh.tell()


def main():
    if not os.path.isfile(ACCESS_LOG_PATH):
        print(f"[!] {ACCESS_LOG_PATH} not found. Is the nginx reverse "
              "proxy configured and running? See README.", file=sys.stderr)
        sys.exit(1)

    poller = AccessLogPoller(ACCESS_LOG_PATH)

    print(f"[*] Web (Juice Shop) monitoring agent started (polling every "
          f"{POLL_INTERVAL_SECONDS}s), watching {ACCESS_LOG_PATH}.")
    print("[*] Emitting events as JSON lines. Press Ctrl+C to stop.\n")

    try:
        while True:
            poller.poll_once()
            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[*] Stopping web monitoring agent.")


if __name__ == "__main__":
    main()