#!/usr/bin/env python3

import os
import sys
import json
import time
import select
from datetime import datetime, timedelta


INJECTION_LOG = "/var/ossec/logs/injection-incidents.log"
NETWORK_LOG = "/var/log/edr_evidence.jsonl"

REFRESH_SECONDS = 2
MAX_EVENTS = 1000


# ============================================================
# COLOURS
# ============================================================

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


# ============================================================
# TERMINAL
# ============================================================

def clear_screen():
    os.system("clear")


def terminal_width():
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 120


# ============================================================
# TIME PARSING
# ============================================================

def parse_timestamp(value):
    if not value:
        return None

    value = str(value)

    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass

    return None


# ============================================================
# LOAD EVENTS
# ============================================================

def load_json_lines(filename):
    events = []

    if not os.path.exists(filename):
        return events

    try:
        with open(filename, "r", errors="replace") as f:
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


def load_events():

    events = []

    # --------------------------------------------------------
    # Injection events
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
            "attack": event.get("incident", "Unknown"),
            "source_ip": event.get("source_ip", "Unknown"),
            "severity": event.get("severity", "HIGH"),
            "action": event.get("action", "DETECTED"),
            "details": event.get("description", ""),
            "rule_id": event.get("rule_id", ""),
            "raw": event
        })

    # --------------------------------------------------------
    # Network events
    # --------------------------------------------------------

    for event in load_json_lines(NETWORK_LOG):

        timestamp = (
            event.get("timestamp")
            or event.get("time")
            or event.get("@timestamp")
        )

        events.append({
            "timestamp": timestamp,
            "category": "Network",
            "attack": event.get(
                "artifact_type",
                "Network Attack"
            ),
            "source_ip": event.get(
                "srcip",
                event.get("source_ip", "Unknown")
            ),
            "severity": event.get("severity", "HIGH"),
            "action": event.get("action", "DETECTED"),
            "details": event.get(
                "alert_msg",
                event.get("description", "")
            ),
            "rule_id": event.get("rule_id", ""),
            "raw": event
        })

    # Sort newest first
    events.sort(
        key=lambda x: parse_timestamp(x["timestamp"])
        or datetime.min,
        reverse=True
    )

    return events[:MAX_EVENTS]


# ============================================================
# FILTERS
# ============================================================

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


def apply_filters(
    events,
    time_filter,
    category_filter,
    severity_filter,
    search
):

    filtered = []

    now = datetime.now()

    # --------------------------------------------------------
    # TIME
    # --------------------------------------------------------

    duration = TIME_FILTERS.get(time_filter)

    cutoff = None

    if duration is not None:
        cutoff = now - duration

    # --------------------------------------------------------
    # EVENTS
    # --------------------------------------------------------

    for event in events:

        # Timestamp
        event_time = parse_timestamp(event["timestamp"])

        if cutoff is not None:

            if event_time is None:
                continue

            if event_time < cutoff:
                continue

        # Category
        if category_filter != "All":

            if event["category"].lower() != category_filter.lower():
                continue

        # Severity
        if severity_filter != "All":

            if event["severity"].upper() != severity_filter.upper():
                continue

        # Search
        if search:

            searchable = " ".join([
                str(event.get("attack", "")),
                str(event.get("source_ip", "")),
                str(event.get("severity", "")),
                str(event.get("action", "")),
                str(event.get("details", "")),
                str(event.get("rule_id", "")),
                str(event.get("category", ""))
            ]).lower()

            if search.lower() not in searchable:
                continue

        filtered.append(event)

    return filtered


# ============================================================
# DISPLAY
# ============================================================

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

    print(
        BOLD
        + CYAN
        + "=" * width
        + RESET
    )

    print(
        BOLD
        + WHITE
        + "                 EDR1 - ENDPOINT DETECTION & RESPONSE"
        + RESET
    )

    print(
        BOLD
        + CYAN
        + "=" * width
        + RESET
    )


def print_summary(all_events, filtered_events):

    injection = sum(
        1 for e in all_events
        if e["category"] == "Injection"
    )

    network = sum(
        1 for e in all_events
        if e["category"] == "Network"
    )

    high = sum(
        1 for e in all_events
        if str(e["severity"]).upper() == "HIGH"
    )

    print()
    print(
        f"{BOLD}{WHITE}"
        f"Total: {len(all_events)}    "
        f"Injection: {injection}    "
        f"Network: {network}    "
        f"High: {high}    "
        f"Showing: {len(filtered_events)}"
        f"{RESET}"
    )


def print_active_filters(
    time_filter,
    category_filter,
    severity_filter,
    search
):

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
            YELLOW
            + "\nNo events match the current filters."
            + RESET
        )

        return

    # Fixed widths
    time_width = 19
    category_width = 10
    attack_width = 22
    ip_width = 16
    severity_width = 8
    action_width = 12

    details_width = max(
        20,
        width
        - time_width
        - category_width
        - attack_width
        - ip_width
        - severity_width
        - action_width
        - 10
    )

    print(
        BOLD
        + (
            f"{'TIME':<{time_width}} "
            f"{'CATEGORY':<{category_width}} "
            f"{'ATTACK':<{attack_width}} "
            f"{'SOURCE IP':<{ip_width}} "
            f"{'SEVERITY':<{severity_width}} "
            f"{'ACTION':<{action_width}} "
            f"DETAILS"
        )
        + RESET
    )

    print("-" * width)

    for event in events[:100]:

        timestamp = str(event["timestamp"] or "Unknown")

        # Remove milliseconds for cleaner display
        if "." in timestamp:
            timestamp = timestamp.split(".")[0]

        category = str(event["category"])[:category_width]

        attack = str(event["attack"])[:attack_width]

        source_ip = str(event["source_ip"])[:ip_width]

        severity = str(event["severity"]).upper()[:severity_width]

        action = str(event["action"])[:action_width]

        details = str(event["details"])

        if len(details) > details_width:
            details = details[:details_width - 3] + "..."

        colour = severity_colour(severity)

        print(
            f"{timestamp:<{time_width}} "
            f"{category:<{category_width}} "
            f"{attack:<{attack_width}} "
            f"{source_ip:<{ip_width}} "
            f"{colour}{severity:<{severity_width}}{RESET} "
            f"{action:<{action_width}} "
            f"{details}"
        )


# ============================================================
# FILTER MENUS
# ============================================================

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

        print(
            f"  {number}. {value}{marker}"
        )

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
        ("4", "Malware"),
        ("5", "OS Attacks"),
        ("6", "Brute Force"),
    ]

    for number, value in options:

        marker = " <-- current" if value == current else ""

        print(
            f"  {number}. {value}{marker}"
        )

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

        print(
            f"  {number}. {value}{marker}"
        )

    print()

    choice = input("Select: ").strip()

    for number, value in options:

        if choice == number:
            return value

    return current


# ============================================================
# COMMANDS
# ============================================================

def show_help():

    print()
    print(BOLD + CYAN + "COMMANDS" + RESET)
    print()

    print("  f   Change filters")
    print("  s   Search")
    print("  d   Show event details")
    print("  r   Reset filters")
    print("  h   Help")
    print("  q   Quit")
    print()

    input("Press Enter to continue...")


def filter_menu(
    time_filter,
    category_filter,
    severity_filter
):

    while True:

        clear_screen()

        print(BOLD + CYAN + "FILTER MENU" + RESET)
        print()

        print(
            f"1. Time       : {BOLD}{time_filter}{RESET}"
        )

        print(
            f"2. Category   : {BOLD}{category_filter}{RESET}"
        )

        print(
            f"3. Severity   : {BOLD}{severity_filter}{RESET}"
        )

        print("4. Done")

        print()

        choice = input("Select: ").strip()

        if choice == "1":

            time_filter = choose_time_filter(
                time_filter
            )

        elif choice == "2":

            category_filter = choose_category_filter(
                category_filter
            )

        elif choice == "3":

            severity_filter = choose_severity_filter(
                severity_filter
            )

        elif choice == "4":

            break

    return (
        time_filter,
        category_filter,
        severity_filter
    )


def search_menu(current):

    clear_screen()

    print(BOLD + CYAN + "SEARCH" + RESET)
    print()

    print(
        "Search attack type, IP, severity, action, "
        "category, rule ID or details."
    )

    print()

    value = input(
        f"Search [{current or 'empty'}]: "
    ).strip()

    return value


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
            f"{event['category']} | "
            f"{event['attack']} | "
            f"{event['source_ip']}"
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

    print(BOLD + CYAN + "RAW EVENT" + RESET)
    print()

    print(
        json.dumps(
            events[index]["raw"],
            indent=4
        )
    )

    print()
    input("Press Enter to return...")


# ============================================================
# MAIN
# ============================================================

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

        print_summary(
            all_events,
            filtered_events
        )

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
            "Commands: "
            "f=filters | "
            "s=search | "
            "d=details | "
            "r=reset | "
            "h=help | "
            "q=quit"
            f"{RESET}"
        )

        print(
            f"{GREY}"
            f"Auto-refresh: {REFRESH_SECONDS}s"
            f"{RESET}"
        )

        # ----------------------------------------------------
        # Wait for command OR timeout
        # ----------------------------------------------------

        ready, _, _ = select.select(
            [sys.stdin],
            [],
            [],
            REFRESH_SECONDS
        )

        # No keyboard input -> refresh
        if not ready:
            continue

        command = sys.stdin.readline().strip().lower()

        if command == "q":
            clear_screen()
            print("EDR CLI closed.")
            break

        elif command == "f":

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

            clear_screen()
            show_help()

        elif command == "":

            continue

        else:

            print(
                f"\n{YELLOW}"
                f"Unknown command: {command}"
                f"{RESET}"
            )

            time.sleep(1)


if __name__ == "__main__":
    main()