#!/usr/bin/env python3

# ============================================================
# EDR1 Central Dashboard
#
# This dashboard reads evidence produced by the separate EDR
# monitoring, detection and response modules. It normalises those
# records into one display format without duplicating the shared
# MonitoringEvent dataclass used by the project modules.
# ============================================================


import os
import sys
import json
import time
import select
import re
from datetime import datetime, timedelta

INJECTION_LOG = "/var/ossec/logs/injection-incidents.log"
NETWORK_LOG = "/var/log/edr_evidence.jsonl"
RESPONSE_LOG = "/var/log/edr_response_actions.log"
MALWARE_ALERT_LOG = "/var/ossec/logs/alerts/edr_alerts.json"
MALWARE_RESPONSE_LOG = "/var/ossec/logs/alerts/edr_responses.log"
OS_ALERT_LOG = "/var/log/edr_os_alerts.jsonl"
OS_RESPONSE_LOG = "/var/log/edr_os_response_actions.jsonl"
BRUTE_ALERT_LOG = "/var/log/edr_bruteforce_alerts.jsonl"
BRUTE_RESPONSE_LOG = "/var/log/edr_bruteforce_response_actions.jsonl"

MALWARE_RULES = {
    "100100": ("Keylogger", "T1056.001"),
    "100101": ("Keylogger", "T1056.001"),
    "100200": ("Rootkit", "T1014, T1547.006"),
    "100201": ("Rootkit", "T1547.006"),
    "100202": ("Rootkit", "T1014"),
    "100300": ("Cryptominer", "T1496"),
    "100301": ("Cryptominer", "T1496"),
}

REFRESH_SECONDS = 2
MAX_EVENTS = 1000

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
GREY = "\033[90m"


# Clear the terminal before drawing the next CLI dashboard screen.
def clear_screen():
    os.system("clear")


# Get the terminal width so the CLI layout can adapt to different screen sizes.
def terminal_width():
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 140


# Convert timestamps from all EDR modules into one comparable datetime format.
def parse_timestamp(value):
    if value is None or value == "":
        return None

    value = str(value).strip()
    iso_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(iso_value)
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone().replace(tzinfo=None)
        return parsed
    except ValueError:
        pass

    formats = [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
    ]

    for fmt in formats:
        try:
            parsed = datetime.strptime(value, fmt)
            if parsed.tzinfo:
                parsed = parsed.replace(tzinfo=None)
            return parsed
        except ValueError:
            pass

    return None


# Read the shared MonitoringEvent structure without recreating the common dataclass.
def unwrap_monitoring_event(item):
    """Unwrap the shared common.events.MonitoringEvent JSON shape."""
    if not isinstance(item, dict):
        return None, None, {}, ""
    # MonitoringEvent stores the producer and event type at the top level.
    source = item.get("source")
    event_type = item.get("event_type")
    data = item.get("data")
    timestamp = item.get("timestamp") or item.get("event_time") or item.get("time") or item.get("@timestamp")
    # Return the nested data when this is a shared MonitoringEvent record.
    if source and event_type and isinstance(data, dict):
        return source, event_type, data, timestamp
    return item.get("source", ""), item.get("event_type", ""), item, timestamp


# Read newline-delimited JSON evidence files and ignore malformed or non-JSON lines.
def load_json_lines(filename):
    events = []

    if not os.path.exists(filename):
        return events

    try:
        with open(filename, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if isinstance(data, dict):
                        events.append(data)
                except json.JSONDecodeError:
                    continue
    except PermissionError:
        return events

    return events


# Read network response actions so detected attacks can be matched with BLOCKED/UNBLOCKED actions.
def load_response_actions():
    """Read BLOCKED/UNBLOCKED entries written by response_engine.py."""
    actions = []
    if not os.path.exists(RESPONSE_LOG):
        return actions

    pattern = re.compile(
        r"^(?P<timestamp>\S+\s+\S+)\s+"
        r"(?P<action>BLOCKED|UNBLOCKED)\s+"
        r"(?P<ip>\S+).*?artifact_type=(?P<attack>[^,\)]+)"
    )
    try:
        with open(RESPONSE_LOG, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                match = pattern.search(line.strip())
                if not match:
                    continue
                timestamp = match.group("timestamp")
                actions.append({
                    "timestamp": timestamp,
                    "datetime": parse_timestamp(timestamp),
                    "action": match.group("action"),
                    "ip": match.group("ip"),
                    "attack": match.group("attack").strip()
                })
    except (PermissionError, OSError):
        return actions

    actions.sort(
        key=lambda item: item["datetime"] if item["datetime"] else datetime.min
    )
    return actions


# Find the response action associated with a network detection.
def network_response_action(source_ip, attack, event_datetime, response_actions):
    candidates = [
        action for action in response_actions
        if action["ip"] == source_ip
        and (
            action["attack"].lower() == attack.lower()
            or not action["attack"]
        )
    ]
    if not candidates:
        return None

    if event_datetime:
        prior = [
            action for action in candidates
            if action["datetime"] and action["datetime"] <= event_datetime
        ]
        if prior:
            return prior[-1]

    return candidates[-1]

    try:
        with open(RESPONSE_LOG, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                match = re.search(
                    r"^(?P<timestamp>\S+\s+\S+)\s+"
                    r"(?P<action>BLOCKED|UNBLOCKED)\s+"
                    r"(?P<ip>[^\s]+).*?"
                    r"artifact_type=(?P<attack>[^,\)]+)",
                    line.strip()
                )

                if match:
                    actions[match.group("ip")] = {
                        "action": match.group("action"),
                        "timestamp": match.group("timestamp"),
                        "attack": match.group("attack").strip()
                    }
    except (PermissionError, OSError):
        pass

    return actions


# Load malware response records generated by the Wazuh/EDR response component.
def load_malware_response_actions():
    """Read automatic malware response entries from edr_response.py."""
    actions = []
    if not os.path.exists(MALWARE_RESPONSE_LOG):
        return actions

    try:
        with open(MALWARE_RESPONSE_LOG, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                match = re.search(
                    r"(?P<action>AUTOMATIC_RESPONSE):\s*"
                    r"(?P<response>[^ ]+).*?"
                    r"PID=(?P<pid>\d+)",
                    line
                )
                if match:
                    actions.append({
                        "timestamp": line.split(" ", 2)[0] if line else "",
                        "action": match.group("response"),
                        "pid": match.group("pid"),
                        "raw": line
                    })
    except (PermissionError, OSError):
        pass

    return actions


# Convert malware Wazuh alerts into the common dashboard event representation.
def load_malware_events():
    """Load the malware alerts collected from Wazuh by edr_alert_collector.py."""
    events = []
    response_actions = load_malware_response_actions()

    for item in load_json_lines(MALWARE_ALERT_LOG):
        rule = item.get("rule", {})
        rule_id = str(rule.get("id", ""))

        if rule_id not in MALWARE_RULES:
            continue

        attack, default_mitre = MALWARE_RULES[rule_id]
        timestamp = (
            item.get("timestamp")
            or item.get("@timestamp")
            or item.get("time")
            or ""
        )

        try:
            level = int(rule.get("level", 0))
        except (TypeError, ValueError):
            level = 0

        if level >= 12:
            severity = "HIGH"
        elif level >= 7:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        mitre_value = rule.get("mitre", {}).get("id", default_mitre)
        if isinstance(mitre_value, list):
            mitre = ", ".join(str(x) for x in mitre_value)
        else:
            mitre = str(mitre_value or default_mitre)

        data = item.get("data", {})
        audit = data.get("audit", {}) if isinstance(data, dict) else {}

        pid = str(audit.get("pid", "-"))
        executable = audit.get("exe", "-")
        process_name = audit.get("comm", audit.get("process", "-"))

        response_info = None
        for response in reversed(response_actions):
            if response.get("pid") == pid:
                response_info = response
                break

        if response_info:
            action = response_info.get("action", "RESPONDED")
        elif attack == "Keylogger":
            action = "DETECTED / AWAITING CORRELATION"
        else:
            action = "MONITORING ONLY"

        description = rule.get(
            "description",
            "Malware event detected by Wazuh"
        )

        details = (
            f"Rule {rule_id} — {description} | "
            f"PID: {pid} | Executable: {executable} | "
            f"Process: {process_name} | MITRE: {mitre}"
        )

        if response_info:
            details += f" | Response: {response_info['raw']}"

        events.append({
            "timestamp": timestamp,
            "category": "Malware",
            "attack": attack,
            "source_ip": audit.get("srcip", item.get("agent", {}).get("ip", "-")),
            "destination_ip": "-",
            "severity": severity,
            "action": action,
            "details": details,
            "tool": "-",
            "interface": "-",
            "packets": "",
            "pps": "",
            "mitre": mitre,
            "rule_id": rule_id,
            "block_timeout": "",
            "response_timestamp": response_info.get("timestamp", "") if response_info else "",
            "pid": pid,
            "executable": executable,
            "process_name": process_name,
            "raw": item
        })

    return events


# Load structured OS and cron response records for response correlation.
def load_os_response_actions():
    """Load structured response JSON from the OS and cron response engines."""
    return [x for x in load_json_lines(OS_RESPONSE_LOG) if x.get("source") in ("os", "cron")]


# Convert SUID privilege-escalation and cron-hijacking detections into dashboard events.
def load_os_events():
    """Load OS events from either MonitoringEvent envelopes or legacy verdicts."""
    events = []
    responses = load_os_response_actions()

    for raw_item in load_json_lines(OS_ALERT_LOG):
        source, event_type, item, event_timestamp = unwrap_monitoring_event(raw_item)
        source = source or "os"

        suspected = item.get("verdict") == "suspected_privesc"
        suid_event = source == "os" and event_type in {
            "euid_mismatch", "suid_execution", "suspected_privesc",
            "privilege_escalation", "suid_privesc"
        }
        if suspected or suid_event:
            pid = item.get("pid", "-")
            exe = item.get("exe", item.get("executable", "-"))
            name = item.get("name", item.get("process_name", "-"))
            response_info = next((r for r in reversed(responses)
                                  if r.get("source") == "os" and str(r.get("pid", "")) == str(pid)), None)
            timestamp = event_timestamp or (response_info or {}).get("timestamp", "")
            if not timestamp:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            action = (response_info or {}).get("action", "DETECTED")
            details = (
                f"SUID privilege escalation suspected | PID: {pid} | Process: {name} | "
                f"Executable: {exe} | UID {item.get('real_uid', item.get('ruid', '-'))} -> "
                f"EUID {item.get('effective_uid', item.get('euid', '-'))} | MITRE: T1548.001"
            )
            if event_type:
                details += f" | Event: {event_type}"
            events.append({
                "timestamp": timestamp, "category": "OS Attacks",
                "attack": "Privilege Escalation / SUID", "source_ip": "localhost",
                "destination_ip": "-", "severity": "HIGH", "action": action,
                "details": details, "tool": "os_agent", "interface": "-",
                "packets": "", "pps": "", "mitre": "T1548.001", "rule_id": "",
                "block_timeout": "", "response_timestamp": (response_info or {}).get("timestamp", ""),
                "pid": pid, "executable": exe, "process_name": name,
                "real_uid": item.get("real_uid", item.get("ruid", "-")),
                "effective_uid": item.get("effective_uid", item.get("euid", "-")),
                "path": "", "mode": "", "writable_risk": "", "event_type": event_type,
                "raw": raw_item
            })
            continue

        path = item.get("path")
        status = item.get("status")
        writable = bool(item.get("writable_risk"))
        cron_event = source == "cron" and (event_type in {
            "cron_modified", "cron_hijack", "cron_job", "writable_cron", "cron_risk"
        } or path)
        if path and (status in ("modified", "changed") or writable or cron_event):
            response_info = next((r for r in reversed(responses)
                                  if r.get("source") == "cron" and r.get("path") == path), None)
            timestamp = event_timestamp or (response_info or {}).get("timestamp", "")
            if not timestamp:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            action = (response_info or {}).get("action", "DETECTED")
            reasons = []
            if status in ("modified", "changed"): reasons.append("SCRIPT MODIFIED")
            if writable: reasons.append("WRITABLE RISK")
            if not reasons: reasons.append(event_type.replace("_", " ").upper() if event_type else "CRON ACTIVITY")
            details = (
                f"Cron job hijacking risk | Path: {path} | Status: {', '.join(reasons)} | "
                f"Mode: {item.get('mode', '-')} | SHA256: {item.get('current_hash', '-')} | MITRE: T1053.003"
            )
            if event_type:
                details += f" | Event: {event_type}"
            events.append({
                "timestamp": timestamp, "category": "OS Attacks",
                "attack": "Cron Job Hijacking", "source_ip": "localhost", "destination_ip": "-",
                "severity": "HIGH", "action": action, "details": details,
                "tool": "cron_agent", "interface": "-", "packets": "", "pps": "",
                "mitre": "T1053.003", "rule_id": "", "block_timeout": "",
                "response_timestamp": (response_info or {}).get("timestamp", ""),
                "pid": "-", "executable": "", "process_name": "", "real_uid": "",
                "effective_uid": "", "path": path, "mode": item.get("mode", "-"),
                "writable_risk": writable, "event_type": event_type, "raw": raw_item
            })

    return events

# Load brute-force blocking/response records for correlation with detections.
def load_brute_response_actions():
    """Load structured response JSON from brute_force_agent/response.py."""
    return [
        x for x in load_json_lines(BRUTE_RESPONSE_LOG)
        if x.get("source") == "brute_force"
    ]


# Convert brute-force detector events into dashboard events.
def load_brute_force_events():
    """Load detector alerts and compatible MonitoringEvent detection records."""
    events = []
    responses = load_brute_response_actions()

    for raw_item in load_json_lines(BRUTE_ALERT_LOG):
        source, event_type, item, event_timestamp = unwrap_monitoring_event(raw_item)
        if source and source != "brute_force":
            continue

        rule = item.get("rule")
        source_ip = item.get("source_ip")
        if not rule and event_type in {
            "brute_force", "password_spraying", "credential_stuffing",
            "success_after_failures", "brute_force_alert"
        }:
            rule = event_type
        if not rule or not source_ip:
            continue

        timestamp = event_timestamp or item.get("event_time") or item.get("timestamp", "")
        event_time = parse_timestamp(timestamp)
        severity = str(item.get("severity", "high")).upper()
        identity = item.get("identity", item.get("username", item.get("email")))

        response_info = None
        candidates = []
        for response in responses:
            if response.get("ip") != source_ip or response.get("reason") != rule:
                continue
            response_time = parse_timestamp(response.get("timestamp", ""))
            if response_time is None:
                continue
            if event_time is not None:
                delta = (response_time - event_time).total_seconds()
                if -2 <= delta <= 10:
                    candidates.append((response_time, response))
            else:
                candidates.append((response_time, response))
        if candidates:
            candidates.sort(key=lambda x: x[0])
            response_info = candidates[0][1]

        action = (response_info or {}).get("action", item.get("action", "DETECTED"))
        identity_text = identity if identity not in (None, "") else "multiple accounts"
        detail_parts = [item.get("message", "")]
        detail_parts += [
            f"Channel: {str(item.get('channel', '-')).upper()}",
            f"Identity: {identity_text}", f"Rule: {rule}"
        ]
        detail = item.get("detail")
        if not isinstance(detail, dict):
            detail = item.get("details") if isinstance(item.get("details"), dict) else {}
        if isinstance(detail, dict):
            if "failures" in detail: detail_parts.append(f"Failures: {detail['failures']}")
            if "distinct_identities" in detail: detail_parts.append(f"Distinct identities: {detail['distinct_identities']}")
            if "failures_before_success" in detail: detail_parts.append(f"Failures before success: {detail['failures_before_success']}")
        if response_info:
            detail_parts.append(f"Response: {response_info.get('action', 'DETECTED')}")
            detail_parts.append(f"Response time: {response_info.get('timestamp', '-')}")

        events.append({
            "timestamp": timestamp, "category": "Brute Force",
            "attack": str(rule).replace("_", " ").title(), "source_ip": source_ip,
            "destination_ip": "-", "severity": severity, "action": action,
            "details": " | ".join(str(x) for x in detail_parts if x),
            "tool": "brute_force_agent", "interface": "-", "packets": "", "pps": "",
            "mitre": "", "rule_id": "", "block_timeout": "",
            "response_timestamp": (response_info or {}).get("timestamp", ""),
            "channel": item.get("channel", "-"), "identity": identity if identity is not None else "-",
            "brute_rule": rule, "event_type": event_type, "raw": raw_item
        })
    return events

# Collect events from every EDR module into one dashboard event list.
def load_events():
    events = []

    # Injection module
    for event in load_json_lines(INJECTION_LOG):
        timestamp = (
            event.get("timestamp")
            or event.get("time")
            or event.get("@timestamp")
        )
        events.append({
            "timestamp": timestamp,
            "category": "Injection",
            "attack": event.get("incident", "Injection"),
            "source_ip": event.get("source_ip", "Unknown"),
            "destination_ip": "-",
            "severity": event.get("severity", "HIGH"),
            "action": event.get("action", "DETECTED"),
            "details": event.get("description", ""),
            "tool": "-",
            "interface": "-",
            "packets": "",
            "pps": "",
            "mitre": "",
            "rule_id": event.get("rule_id", ""),
            "block_timeout": event.get("duration_seconds", ""),
            "response_timestamp": "",
            "raw": event
        })

    # Network module
    response_actions = load_response_actions()

    for event in load_json_lines(NETWORK_LOG):
        timestamp = (
            event.get("timestamp")
            or event.get("time")
            or event.get("@timestamp")
        )
        event_datetime = parse_timestamp(timestamp)

        attack = event.get("artifact_type", "Network Attack")
        source_ip = event.get("srcip", "Unknown")
        destination_ip = event.get("dstip", "-")

        action_info = network_response_action(
            source_ip, attack, event_datetime, response_actions
        )
        action = (
            action_info["action"]
            if action_info
            else event.get("action", "DETECTED")
        )

        severity = event.get("severity", "HIGH")
        rule_id = str(event.get("rule_id", "100051"))
        mitre = event.get("mitre", "T1498")
        tool = event.get("likely_source_tool", "Unknown")
        interface = event.get("interface", "-")
        packets = event.get("packet_count", "")
        pps = event.get("approx_pps", "")

        correlation = event.get("correlated_logs", {})
        if not isinstance(correlation, dict):
            correlation = {}

        details = event.get("alert_msg", "")
        extra = [
            f"Tool: {tool}",
            f"Dst: {destination_ip}",
            f"Iface: {interface}",
        ]
        if packets != "":
            extra.append(f"Packets: {packets}")
        if pps != "":
            extra.append(f"PPS: {pps}")
        extra += [
            f"Wazuh rule: {rule_id}",
            f"MITRE: {mitre}",
            "Block timeout: 600s",
        ]

        if correlation.get("kernel_syslog"):
            extra.append(f"Kernel correlation: {len(correlation['kernel_syslog'])}")
        if correlation.get("apache_access"):
            extra.append(f"Apache access correlation: {len(correlation['apache_access'])}")
        if correlation.get("apache_error"):
            extra.append(f"Apache error correlation: {len(correlation['apache_error'])}")
        if action_info:
            extra.append(f"Response timestamp: {action_info['timestamp']}")

        details = (details + " | " if details else "") + " | ".join(extra)

        events.append({
            "timestamp": timestamp,
            "category": "Network",
            "attack": attack,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "severity": severity,
            "action": action,
            "details": details,
            "tool": tool,
            "interface": interface,
            "packets": packets,
            "pps": pps,
            "mitre": mitre,
            "rule_id": rule_id,
            "block_timeout": 600,
            "correlation": correlation,
            "response_timestamp": action_info["timestamp"] if action_info else "",
            "raw": event
        })

    # Malware module
    events.extend(load_malware_events())

    # OS privilege-escalation / cron module
    events.extend(load_os_events())

    # Brute-force module
    events.extend(load_brute_force_events())

    events.sort(
        key=lambda x: parse_timestamp(x["timestamp"]) or datetime.min,
        reverse=True
    )
    return events[:MAX_EVENTS]


TIME_FILTERS = {
    "5m": timedelta(minutes=5),
    "15m": timedelta(minutes=15),
    "30m": timedelta(minutes=30),
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "12h": timedelta(hours=12),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "all": None
}


# Apply the selected time, category, severity and text-search filters.
def apply_filters(events, time_filter, category_filter, severity_filter, search):
    filtered = []
    now = datetime.now()
    duration = TIME_FILTERS.get(time_filter)
    cutoff = now - duration if duration is not None else None

    for event in events:
        event_time = parse_timestamp(event["timestamp"])

        if cutoff is not None:
            if event_time is None or event_time < cutoff:
                continue

        if category_filter != "All":
            if event["category"].lower() != category_filter.lower():
                continue

        if severity_filter != "All":
            if str(event["severity"]).upper() != severity_filter.upper():
                continue

        if search:
            searchable = " ".join([
                str(event.get("category", "")),
                str(event.get("attack", "")),
                str(event.get("source_ip", "")),
                str(event.get("destination_ip", "")),
                str(event.get("severity", "")),
                str(event.get("action", "")),
                str(event.get("details", "")),
                str(event.get("tool", "")),
                str(event.get("interface", "")),
                str(event.get("packets", "")),
                str(event.get("pps", "")),
                str(event.get("mitre", "")),
                str(event.get("rule_id", "")),
                str(event.get("pid", "")),
                str(event.get("executable", "")),
                str(event.get("process_name", "")),
            ]).lower()

            if search.lower() not in searchable:
                continue

        filtered.append(event)

    return filtered


# Return the ANSI colour used for a CLI severity level.
def severity_colour(severity):
    severity = str(severity).upper()

    if severity == "HIGH":
        return RED
    if severity == "MEDIUM":
        return YELLOW
    if severity == "LOW":
        return GREEN

    return WHITE


# Draw the CLI dashboard title and module information.
def print_header():
    width = terminal_width()
    clear_screen()

    print(BOLD + CYAN + "=" * width + RESET)
    print(
        BOLD + WHITE +
        "                 EDR1 - ENDPOINT DETECTION & RESPONSE" +
        RESET
    )
    print(
        GREY +
        "        Network flood detection | Wazuh evidence | Direct iptables response" +
        RESET
    )
    print(BOLD + CYAN + "=" * width + RESET)


# Display alert totals for Network, Injection, Malware, OS and Brute Force.
def print_summary(all_events, filtered_events):
    injection = sum(
        1 for e in all_events if e["category"] == "Injection"
    )

    network = sum(
        1 for e in all_events if e["category"] == "Network"
    )

    malware = sum(
        1 for e in all_events if e["category"] == "Malware"
    )

    os_attacks = sum(
        1 for e in all_events if e["category"] == "OS Attacks"
    )

    brute_force = sum(
        1 for e in all_events if e["category"] == "Brute Force"
    )

    blocked = sum(
        1 for e in all_events
        if str(e["action"]).upper() == "BLOCKED"
    )

    print()
    print(
        f"{BOLD}{WHITE}"
        f"Total: {len(all_events)}    "
        f"Network: {network}    "
        f"Injection: {injection}    "
        f"Malware: {malware}    "
        f"OS: {os_attacks}    "
        f"Brute Force: {brute_force}    "
        f"Blocked: {blocked}    "
        f"Showing: {len(filtered_events)}"
        f"{RESET}"
    )


# Show the filters currently applied to the dashboard.
def print_active_filters(time_filter, category_filter, severity_filter, search):
    print()
    print(
        f"{CYAN}Filters:{RESET} "
        f"Time={BOLD}{time_filter}{RESET} | "
        f"Category={BOLD}{category_filter}{RESET} | "
        f"Severity={BOLD}{severity_filter}{RESET} | "
        f"Search={BOLD}{search or 'None'}{RESET}"
    )
    print()


# Render the filtered events in a readable CLI table.
def print_events(events):
    width = terminal_width()

    if not events:
        print(
            YELLOW +
            "\nNo events match the current filters." +
            RESET
        )
        return

    time_width = 19
    attack_width = 17
    source_width = 16
    action_width = 11
    packets_width = 9
    pps_width = 9

    details_width = max(
        30,
        width
        - time_width
        - attack_width
        - source_width
        - action_width
        - packets_width
        - pps_width
        - 10
    )

    print(
        BOLD +
        f"{'TIME':<{time_width}} "
        f"{'ATTACK':<{attack_width}} "
        f"{'SOURCE IP':<{source_width}} "
        f"{'ACTION':<{action_width}} "
        f"{'PACKETS':<{packets_width}} "
        f"{'PPS':<{pps_width}} "
        f"DETAILS" +
        RESET
    )

    print("-" * width)

    for event in events[:100]:
        timestamp = str(event["timestamp"] or "Unknown")

        if "." in timestamp:
            timestamp = timestamp.split(".")[0]

        timestamp = timestamp[:time_width]

        attack = str(event["attack"])[:attack_width]
        source = str(event["source_ip"])[:source_width]
        action = str(event["action"])[:action_width]
        packets = str(event["packets"])[:packets_width]
        pps = str(event["pps"])[:pps_width]
        details = str(event["details"])

        if len(details) > details_width:
            details = details[:details_width - 3] + "..."

        colour = severity_colour(event["severity"])

        print(
            f"{timestamp:<{time_width}} "
            f"{attack:<{attack_width}} "
            f"{source:<{source_width}} "
            f"{colour}{action:<{action_width}}{RESET} "
            f"{packets:<{packets_width}} "
            f"{pps:<{pps_width}} "
            f"{details}"
        )


# Let the user select the time range used by the CLI dashboard.
def choose_time_filter(current):
    print()
    print(BOLD + CYAN + "TIME FILTER" + RESET)
    print()

    options = [
        ("1", "5m"),
        ("2", "15m"),
        ("3", "30m"),
        ("4", "1h"),
        ("5", "6h"),
        ("6", "12h"),
        ("7", "24h"),
        ("8", "7d"),
        ("9", "all"),
    ]

    for number, value in options:
        marker = " <-- current" if value == current else ""
        print(f"  {number}. {value}{marker}")

    print()
    choice = input("Select: ").strip()

    for number, value in options:
        if choice == number:
            return value

    return current


# Let the user select one EDR event category.
def choose_category_filter(current):
    print()
    print(BOLD + CYAN + "CATEGORY FILTER" + RESET)
    print()

    options = [
        ("1", "All"),
        ("2", "Injection"),
        ("3", "Network"),
        ("4", "Malware"),
    ]

    for number, value in options:
        marker = " <-- current" if value == current else ""
        print(f"  {number}. {value}{marker}")

    print()
    choice = input("Select: ").strip()

    for number, value in options:
        if choice == number:
            return value

    return current


# Let the user select a severity level.
def choose_severity_filter(current):
    print()
    print(BOLD + CYAN + "SEVERITY FILTER" + RESET)
    print()

    options = [
        ("1", "All"),
        ("2", "HIGH"),
        ("3", "MEDIUM"),
        ("4", "LOW"),
        ("5", "INFO"),
    ]

    for number, value in options:
        marker = " <-- current" if value == current else ""
        print(f"  {number}. {value}{marker}")

    print()
    choice = input("Select: ").strip()

    for number, value in options:
        if choice == number:
            return value

    return current


# Display the interactive filter menu.
def filter_menu(time_filter, category_filter, severity_filter):
    while True:
        clear_screen()

        print(BOLD + CYAN + "FILTER MENU" + RESET)
        print()
        print(f"1. Time       : {BOLD}{time_filter}{RESET}")
        print(f"2. Category   : {BOLD}{category_filter}{RESET}")
        print(f"3. Severity   : {BOLD}{severity_filter}{RESET}")
        print("4. Done")
        print()

        choice = input("Select: ").strip()

        if choice == "1":
            time_filter = choose_time_filter(time_filter)
        elif choice == "2":
            category_filter = choose_category_filter(category_filter)
        elif choice == "3":
            severity_filter = choose_severity_filter(severity_filter)
        elif choice == "4":
            break

    return time_filter, category_filter, severity_filter


# Set or clear the text search filter.
def search_menu(current):
    clear_screen()

    print(BOLD + CYAN + "SEARCH" + RESET)
    print()
    print(
        "Search attack type, source/destination IP, severity, "
        "action, tool, interface, packet count, PPS or MITRE ID."
    )
    print()

    return input(
        f"Search [{current or 'empty'}]: "
    ).strip()


# Display the full raw information for a selected event.
def details_menu(events):
    clear_screen()

    print(BOLD + CYAN + "EVENT DETAILS" + RESET)
    print()

    if not events:
        print("No matching events.")
        input("\nPress Enter...")
        return

    for index, event in enumerate(events[:50], 1):
        print(
            f"{index}. "
            f"{event['timestamp']} | "
            f"{event['attack']} | "
            f"{event['source_ip']} | "
            f"{event['action']}"
        )

    print()
    choice = input(
        "Enter event number or press Enter to return: "
    ).strip()

    if not choice:
        return

    try:
        index = int(choice) - 1
        if index < 0 or index >= len(events):
            raise ValueError
    except ValueError:
        print("Invalid event number.")
        input("Press Enter...")
        return

    clear_screen()

    event = events[index]

    print(BOLD + CYAN + "EDR1 EVENT DETAILS" + RESET)
    print()

    print(f"Timestamp        : {event['timestamp']}")
    print(f"Category         : {event['category']}")
    print(f"Attack           : {event['attack']}")
    print(f"Source IP        : {event['source_ip']}")
    print(f"Destination IP   : {event['destination_ip']}")
    print(f"Severity         : {event['severity']}")
    print(f"Action           : {event['action']}")
    print(f"Likely tool      : {event['tool']}")
    print(f"Interface        : {event['interface']}")
    print(f"Packet count     : {event['packets']}")
    print(f"Approx PPS       : {event['pps']}")
    print(f"MITRE            : {event['mitre'] or '-'}")
    print(f"Wazuh rule       : {event['rule_id'] or '-'}")
    print(f"Block timeout    : {event['block_timeout'] or '-'}")
    print(f"Response time    : {event['response_timestamp'] or '-'}")

    if event["category"] == "Malware":
        print(f"PID              : {event.get('pid', '-')}")
        print(f"Executable       : {event.get('executable', '-')}")
        print(f"Process          : {event.get('process_name', '-')}")

    if event["category"] == "Brute Force":
        print(f"Channel          : {event.get('channel', '-')}")
        print(f"Identity         : {event.get('identity', '-')}")
        print(f"Detection rule   : {event.get('brute_rule', '-')}")

    if event["category"] == "OS Attacks":
        print(f"PID              : {event.get('pid', '-')}")
        print(f"Executable       : {event.get('executable', '-')}")
        print(f"Process          : {event.get('process_name', '-')}")
        print(f"Real UID         : {event.get('real_uid', '-')}")
        print(f"Effective UID    : {event.get('effective_uid', '-')}")
        print(f"Cron Path        : {event.get('path', '-')}")
        print(f"Cron Mode        : {event.get('mode', '-')}")
        print(f"Writable Risk    : {event.get('writable_risk', '-')}")

    print()
    print(BOLD + "CORRELATION / DETAILS" + RESET)
    print(event["details"])

    print()
    print(BOLD + "RAW EVENT" + RESET)
    print(json.dumps(event["raw"], indent=4))

    input("\nPress Enter to return...")


# Display keyboard commands and dashboard usage information.
def show_help():
    clear_screen()

    print(BOLD + CYAN + "EDR1 CLI" + RESET)
    print()
    print("This dashboard combines the current Network, Injection, Malware, OS and Brute Force EDR modules.")
    print()
    print("Network detection:")
    print("  TCP SYN | ICMP | UDP | HTTP Request")
    print("  Evidence: /var/log/edr_evidence.jsonl")
    print("  Response: direct iptables block; 600-second timeout")
    print()
    print("Malware detection:")
    print("  Keylogger: rules 100100/100101 -> T1056.001")
    print("  Rootkit: rules 100200/100201/100202 -> T1014 / T1547.006")
    print("  Cryptominer: rules 100300/100301 -> T1496")
    print("  Evidence: /var/ossec/logs/alerts/edr_alerts.json")
    print("  Response log: /var/ossec/logs/alerts/edr_responses.log")
    print("  Keylogger: SIGTERM only after both keylogger rules match the same PID/executable")
    print("  Rootkit/Cryptominer: monitoring-only")
    print()
    print("OS detection:")
    print("  SUID privilege escalation: os_agent -> T1548.001")
    print("  Cron Job Hijacking: cron_agent -> T1053.003")
    print("  Evidence: /var/log/edr_os_alerts.jsonl")
    print("  Response: /var/log/edr_os_response_actions.jsonl")
    print("  SUID response: kill process + strip SUID bit")
    print("  Cron response: restore modified script + remove group/other write")
    print()
    print("Brute force detection:")
    print("  SSH targeted brute force | password spraying")
    print("  Juice Shop credential stuffing | success after failures")
    print("  Detection: /var/log/edr_bruteforce_alerts.jsonl")
    print("  Response: /var/log/edr_bruteforce_response_actions.jsonl")
    print("  HIGH alerts: 10-minute UFW ban")
    print("  CRITICAL success-after-failures: 60-minute UFW ban")
    print()
    print("Injection detection:")
    print("  SQL Injection | XSS | Command Injection | SSTI")
    print("  Evidence: /var/ossec/logs/injection-incidents.log")
    print()
    print("Commands:")
    print("  f   Change filters")
    print("  s   Search")
    print("  d   Show event details")
    print("  r   Reset filters")
    print("  h   Help")
    print("  q   Quit")
    print()

    input("Press Enter to continue...")


# Start the dashboard, load events and continuously refresh the display.
def main():
    time_filter = "24h"
    category_filter = "All"
    severity_filter = "All"
    search = ""

    while True:
        all_events = load_events()

        filtered_events = apply_filters(
            all_events,
            time_filter,
            category_filter,
            severity_filter,
            search
        )

        print_header()
        print_summary(all_events, filtered_events)
        print_active_filters(
            time_filter,
            category_filter,
            severity_filter,
            search
        )
        print_events(filtered_events)

        print()
        print(
            f"{GREY}"
            "Commands: f=filters | s=search | d=details | "
            "r=reset | h=help | q=quit"
            f"{RESET}"
        )
        print(
            f"{GREY}"
            f"Auto-refresh: {REFRESH_SECONDS}s"
            f"{RESET}"
        )

        ready, _, _ = select.select(
            [sys.stdin],
            [],
            [],
            REFRESH_SECONDS
        )

        if not ready:
            continue

        command = sys.stdin.readline().strip().lower()

        if command == "q":
            clear_screen()
            print("EDR CLI closed.")
            break

        if command == "f":
            (
                time_filter,
                category_filter,
                severity_filter
            ) = filter_menu(
                time_filter,
                category_filter,
                severity_filter
            )

        elif command == "s":
            search = search_menu(search)

        elif command == "d":
            details_menu(filtered_events)

        elif command == "r":
            time_filter = "24h"
            category_filter = "All"
            severity_filter = "All"
            search = ""

        elif command == "h":
            show_help()


if __name__ == "__main__":
    main()
