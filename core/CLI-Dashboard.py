#!/usr/bin/env python3

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


def clear_screen():
    os.system("clear")


def terminal_width():
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 140


def parse_timestamp(value):
    if not value:
        return None

    value = str(value)
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


def load_response_actions():
    actions = {}

    if not os.path.exists(RESPONSE_LOG):
        return actions

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


def load_events():
    events = []
    response_actions = load_response_actions()

    # --------------------------------------------------------
    # Injection events - retained for compatibility with the
    # existing Wazuh injection module.
    # --------------------------------------------------------

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
            "correlation": {},
            "raw": event
        })

    # --------------------------------------------------------
    # Network events - current EDR module schema.
    # --------------------------------------------------------

    for event in load_json_lines(NETWORK_LOG):
        timestamp = (
            event.get("timestamp")
            or event.get("time")
            or event.get("@timestamp")
        )

        attack = event.get("artifact_type", "Network Attack")
        source_ip = event.get("srcip", "Unknown")
        destination_ip = event.get("dstip", "-")

        action_info = response_actions.get(source_ip, {})

        action = action_info.get(
            "action",
            event.get("action", "DETECTED")
        )

        severity = event.get("severity", "HIGH")

        tool = event.get(
            "likely_source_tool",
            "Unknown"
        )

        interface = event.get(
            "interface",
            "-"
        )

        packets = event.get(
            "packet_count",
            ""
        )

        pps = event.get(
            "approx_pps",
            ""
        )

        correlation = event.get(
            "correlated_logs",
            {}
        )

        details = event.get(
            "alert_msg",
            ""
        )

        extra = [
            f"Tool: {tool}",
            f"Dst: {destination_ip}",
            f"Iface: {interface}",
        ]

        if packets != "":
            extra.append(f"Packets: {packets}")

        if pps != "":
            extra.append(f"PPS: {pps}")

        extra.append("MITRE: T1498")

        kernel_count = len(
            correlation.get("kernel_syslog", [])
        )

        apache_access_count = len(
            correlation.get("apache_access", [])
        )

        apache_error_count = len(
            correlation.get("apache_error", [])
        )

        if kernel_count:
            extra.append(f"Kernel logs: {kernel_count}")

        if apache_access_count:
            extra.append(f"Apache access: {apache_access_count}")

        if apache_error_count:
            extra.append(f"Apache error: {apache_error_count}")

        if details:
            details += " | "

        details += " | ".join(extra)

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
            "mitre": "T1498",
            "correlation": correlation,
            "raw": event
        })

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
            ]).lower()

            if search.lower() not in searchable:
                continue

        filtered.append(event)

    return filtered


def severity_colour(severity):
    severity = str(severity).upper()

    if severity == "HIGH":
        return RED
    if severity == "MEDIUM":
        return YELLOW
    if severity == "LOW":
        return GREEN

    return WHITE


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


def print_summary(all_events, filtered_events):
    injection = sum(
        1 for e in all_events if e["category"] == "Injection"
    )

    network = sum(
        1 for e in all_events if e["category"] == "Network"
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
        f"Blocked: {blocked}    "
        f"Showing: {len(filtered_events)}"
        f"{RESET}"
    )


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


def choose_category_filter(current):
    print()
    print(BOLD + CYAN + "CATEGORY FILTER" + RESET)
    print()

    options = [
        ("1", "All"),
        ("2", "Injection"),
        ("3", "Network"),
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

    print()
    print(BOLD + "CORRELATION / DETAILS" + RESET)
    print(event["details"])

    print()
    print(BOLD + "RAW EVENT" + RESET)
    print(json.dumps(event["raw"], indent=4))

    input("\nPress Enter to return...")


def show_help():
    clear_screen()

    print(BOLD + CYAN + "EDR1 CLI" + RESET)
    print()
    print("This dashboard follows the current network EDR module.")
    print()
    print("Detection types:")
    print("  TCP SYN      - threshold-based SYN flood detection")
    print("  ICMP         - ICMP echo flood detection")
    print("  UDP          - UDP flood detection")
    print("  HTTP Request - HTTP request flood detection")
    print()
    print("Evidence:")
    print("  /var/log/edr_evidence.jsonl")
    print()
    print("Response:")
    print("  /var/log/edr_response_actions.log")
    print()
    print("Wazuh:")
    print("  Custom artifact_type rule: 100051")
    print("  MITRE mapping: T1498")
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
