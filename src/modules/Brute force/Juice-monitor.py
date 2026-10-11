"""
brute_force_agent/juice_shop_monitor.py
=========================================
Monitoring layer for web-based brute force / credential stuffing against
OWASP Juice Shop's login endpoint (Lab 2).

Why this isn't just a file we can tail directly from Juice Shop: it
doesn't write individual login attempts to any log file by default --
Lab 2 itself has you fall back to tcpdump/Wireshark for evidence for
exactly this reason.

An earlier version of this file used mitmproxy (a full Python-based,
TLS-capable interception framework) as a reverse proxy to get a vantage
point on this traffic. That worked, but is heavier than this needs to
be, and the team is already running Wazuh and watching system load. This
version uses a plain **nginx** reverse proxy instead -- negligible
overhead, industry-standard, nothing exotic -- configured to log the
one thing we need (the request line, status code, and POST body), and
then tails that access log file exactly the same way monitor.py already
tails /var/log/auth.log for SSH. Same architecture, same cost profile,
as the agent you've already got running.

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

Like brute_force_agent/monitor.py, this module ONLY does structural
parsing of each access log line into fields -- no judgment about
whether a given attempt is part of an attack. It emits the SAME source
("brute_force") as the SSH monitor, just a different event_type, so a
future shared detection engine can threshold across both.

Usage:
    sudo python3 brute_force_agent/juice_shop_monitor.py
"""

import sys
import os
import re
import time
import json
from urllib.parse import parse_qs

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from common.events import MonitoringEvent

ACCESS_LOG_PATH = "/var/log/nginx/juiceshop_access.log"
LOGIN_PATH = "/rest/user/login"

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


class AccessLogHandler(FileSystemEventHandler):
    """
    Tails nginx's access log the same way brute_force_agent/monitor.py's
    AuthLogHandler tails auth.log: track a byte offset into the file and
    only process lines appended since the agent started.
    """

    def __init__(self, path):
        self.path = os.path.abspath(path)
        self._fh = open(self.path, "r")
        self._fh.seek(0, os.SEEK_END)

    def on_modified(self, event):
        if os.path.abspath(event.src_path) != self.path:
            return
        self._process_new_lines()

    def _process_new_lines(self):
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


def main():
    if not os.path.isfile(ACCESS_LOG_PATH):
        print(f"[!] {ACCESS_LOG_PATH} not found. Is the nginx reverse "
              "proxy configured and running? See README.", file=sys.stderr)
        sys.exit(1)

    print("[*] Web (Juice Shop) monitoring agent started, watching "
          f"{ACCESS_LOG_PATH}.")
    print("[*] Emitting events as JSON lines. Press Ctrl+C to stop.\n")

    handler = AccessLogHandler(ACCESS_LOG_PATH)
    observer = Observer()
    observer.schedule(handler, os.path.dirname(ACCESS_LOG_PATH), recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[*] Stopping web monitoring agent.")
    observer.join()


if __name__ == "__main__":
    main()
