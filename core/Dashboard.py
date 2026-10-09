#!/usr/bin/env python3

import sys
import os
import json
from datetime import datetime


# ============================================================
# TKINTER CHECK
# ============================================================

try:
    import tkinter as tk
    from tkinter import ttk

except ModuleNotFoundError:
    print()
    print("=" * 60)
    print("ERROR: Tkinter is not installed.")
    print("=" * 60)
    print()
    print("The Central EDR Dashboard requires Python Tkinter.")
    print()
    print("Install it using the following commands:")
    print()
    print("    sudo apt update")
    print("    sudo apt install python3-tk -y")
    print()
    print("Then start the dashboard again with:")
    print()
    print("    python3 edr_central_dashboard.py")
    print()
    sys.exit(1)


# ============================================================
# CONFIGURATION
# ============================================================

INJECTION_LOG = "/var/ossec/logs/injection-incidents.log"
NETWORK_LOG = "/var/log/edr_evidence.jsonl"

REFRESH_INTERVAL = 1000
MAX_ALERTS = 500


# ============================================================
# EDR EVENT
# ============================================================

class EDREvent:

    def __init__(
        self,
        timestamp,
        category,
        attack,
        source_ip,
        severity,
        action,
        details,
        rule_id=""
    ):
        self.timestamp = timestamp
        self.category = category
        self.attack = attack
        self.source_ip = source_ip
        self.severity = severity
        self.action = action
        self.details = details
        self.rule_id = rule_id


# ============================================================
# CENTRAL EDR DASHBOARD
# ============================================================

class CentralEDRDashboard:

    def __init__(self, root):

        self.root = root

        self.root.title("Central EDR Dashboard")
        self.root.geometry("1250x720")
        self.root.minsize(1000, 600)

        self.events = []

        self.total_var = tk.StringVar(value="0")
        self.injection_var = tk.StringVar(value="0")
        self.network_var = tk.StringVar(value="0")
        self.malware_var = tk.StringVar(value="0")
        self.os_var = tk.StringVar(value="0")
        self.bruteforce_var = tk.StringVar(value="0")

        self.status_var = tk.StringVar(
            value="EDR monitoring active"
        )

        self.create_style()
        self.create_header()
        self.create_summary()
        self.create_tabs()

        self.refresh_data()


    # ========================================================
    # STYLE
    # ========================================================

    def create_style(self):

        style = ttk.Style()

        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "Treeview",
            rowheight=28,
            font=("Arial", 10)
        )

        style.configure(
            "Treeview.Heading",
            font=("Arial", 10, "bold")
        )

        style.configure(
            "TNotebook.Tab",
            padding=[15, 8],
            font=("Arial", 10, "bold")
        )


    # ========================================================
    # HEADER
    # ========================================================

    def create_header(self):

        header = tk.Frame(
            self.root,
            bg="#1f2937",
            height=80
        )

        header.pack(
            fill="x",
            side="top"
        )

        header.pack_propagate(False)

        title = tk.Label(
            header,
            text="CENTRAL EDR DASHBOARD",
            font=("Arial", 22, "bold"),
            fg="white",
            bg="#1f2937"
        )

        title.pack(
            side="left",
            padx=25
        )

        status = tk.Label(
            header,
            textvariable=self.status_var,
            font=("Arial", 10),
            fg="#d1d5db",
            bg="#1f2937"
        )

        status.pack(
            side="right",
            padx=25
        )


    # ========================================================
    # SUMMARY
    # ========================================================

    def create_summary(self):

        summary = tk.Frame(
            self.root,
            bg="#f3f4f6",
            height=110
        )

        summary.pack(
            fill="x"
        )

        summary.pack_propagate(False)

        self.create_summary_box(
            summary,
            "TOTAL ALERTS",
            self.total_var,
            0
        )

        self.create_summary_box(
            summary,
            "INJECTION",
            self.injection_var,
            1
        )

        self.create_summary_box(
            summary,
            "NETWORK",
            self.network_var,
            2
        )

        self.create_summary_box(
            summary,
            "MALWARE",
            self.malware_var,
            3
        )

        self.create_summary_box(
            summary,
            "OS ATTACKS",
            self.os_var,
            4
        )

        self.create_summary_box(
            summary,
            "BRUTE FORCE",
            self.bruteforce_var,
            5
        )


    def create_summary_box(
        self,
        parent,
        title,
        variable,
        column
    ):

        box = tk.Frame(
            parent,
            bg="white",
            relief="solid",
            borderwidth=1
        )

        box.grid(
            row=0,
            column=column,
            padx=8,
            pady=10,
            sticky="nsew"
        )

        parent.grid_columnconfigure(
            column,
            weight=1
        )

        title_label = tk.Label(
            box,
            text=title,
            font=("Arial", 9, "bold"),
            bg="white",
            fg="#6b7280"
        )

        title_label.pack(
            pady=(10, 2)
        )

        value_label = tk.Label(
            box,
            textvariable=variable,
            font=("Arial", 24, "bold"),
            bg="white",
            fg="#111827"
        )

        value_label.pack(
            pady=(0, 8)
        )


    # ========================================================
    # TABS
    # ========================================================

    def create_tabs(self):

        self.notebook = ttk.Notebook(
            self.root
        )

        self.notebook.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        self.all_tab = self.create_alert_tab(
            "All Alerts"
        )

        self.injection_tab = self.create_alert_tab(
            "Injection"
        )

        self.network_tab = self.create_alert_tab(
            "Network"
        )

        self.malware_tab = self.create_placeholder_tab(
            "Malware"
        )

        self.os_tab = self.create_placeholder_tab(
            "OS Attacks"
        )

        self.bruteforce_tab = self.create_placeholder_tab(
            "Brute Force"
        )


    # ========================================================
    # ALERT TABLE
    # ========================================================

    def create_alert_tab(self, name):

        frame = ttk.Frame(
            self.notebook
        )

        self.notebook.add(
            frame,
            text=name
        )

        columns = (
            "time",
            "category",
            "attack",
            "source",
            "severity",
            "action",
            "details"
        )

        tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings"
        )

        tree.heading(
            "time",
            text="Time"
        )

        tree.heading(
            "category",
            text="Category"
        )

        tree.heading(
            "attack",
            text="Attack"
        )

        tree.heading(
            "source",
            text="Source IP"
        )

        tree.heading(
            "severity",
            text="Severity"
        )

        tree.heading(
            "action",
            text="Action"
        )

        tree.heading(
            "details",
            text="Details"
        )

        tree.column(
            "time",
            width=160,
            anchor="center"
        )

        tree.column(
            "category",
            width=110,
            anchor="center"
        )

        tree.column(
            "attack",
            width=180,
            anchor="w"
        )

        tree.column(
            "source",
            width=140,
            anchor="center"
        )

        tree.column(
            "severity",
            width=90,
            anchor="center"
        )

        tree.column(
            "action",
            width=110,
            anchor="center"
        )

        tree.column(
            "details",
            width=420,
            anchor="w"
        )

        scrollbar = ttk.Scrollbar(
            frame,
            orient="vertical",
            command=tree.yview
        )

        tree.configure(
            yscrollcommand=scrollbar.set
        )

        tree.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

        return tree


    # ========================================================
    # PLACEHOLDER TABS
    # ========================================================

    def create_placeholder_tab(self, name):

        frame = ttk.Frame(
            self.notebook
        )

        self.notebook.add(
            frame,
            text=name
        )

        message = tk.Label(
            frame,
            text=(
                f"{name} monitoring is not currently enabled.\n\n"
                "This section is reserved for future EDR modules."
            ),
            font=("Arial", 14),
            fg="#6b7280"
        )

        message.pack(
            expand=True
        )

        return frame


    # ========================================================
    # READ JSONL FILE
    # ========================================================

    def read_json_lines(self, filename):

        records = []

        if not os.path.exists(filename):
            return records

        try:

            with open(
                filename,
                "r",
                encoding="utf-8",
                errors="replace"
            ) as file:

                lines = file.readlines()

                lines = lines[-MAX_ALERTS:]

                for line in lines:

                    line = line.strip()

                    if not line:
                        continue

                    try:

                        data = json.loads(line)

                        if isinstance(data, dict):
                            records.append(data)

                    except json.JSONDecodeError:
                        continue

        except PermissionError:

            self.status_var.set(
                "Permission denied reading EDR logs"
            )

        except Exception as error:

            self.status_var.set(
                f"Log error: {error}"
            )

        return records


    # ========================================================
    # LOAD INJECTION EVENTS
    # ========================================================

    def load_injection_events(self):

        records = self.read_json_lines(
            INJECTION_LOG
        )

        events = []

        for data in records:

            timestamp = data.get(
                "timestamp",
                ""
            )

            attack = data.get(
                "incident",
                "Injection"
            )

            source_ip = data.get(
                "source_ip",
                "Unknown"
            )

            severity = data.get(
                "severity",
                "UNKNOWN"
            )

            action = data.get(
                "action",
                "DETECTED"
            )

            rule_id = str(
                data.get(
                    "rule_id",
                    ""
                )
            )

            description = data.get(
                "description",
                ""
            )

            duration = data.get(
                "duration_seconds",
                ""
            )

            details = description

            if rule_id:

                if details:
                    details += " | "

                details += (
                    f"Rule: {rule_id}"
                )

            if duration:

                if details:
                    details += " | "

                details += (
                    f"Duration: {duration}s"
                )

            events.append(
                EDREvent(
                    timestamp=timestamp,
                    category="Injection",
                    attack=attack,
                    source_ip=source_ip,
                    severity=severity,
                    action=action,
                    details=details,
                    rule_id=rule_id
                )
            )

        return events


    # ========================================================
    # LOAD NETWORK EVENTS
    # ========================================================

    def load_network_events(self):

        records = self.read_json_lines(
            NETWORK_LOG
        )

        events = []

        for data in records:

            timestamp = data.get(
                "timestamp",
                ""
            )

            attack = data.get(
                "artifact_type",
                "Network Attack"
            )

            source_ip = data.get(
                "srcip",
                "Unknown"
            )

            severity = data.get(
                "severity",
                "HIGH"
            )

            action = data.get(
                "action",
                "DETECTED"
            )

            alert_msg = data.get(
                "alert_msg",
                ""
            )

            packet_count = data.get(
                "packet_count",
                ""
            )

            approx_pps = data.get(
                "approx_pps",
                ""
            )

            details_parts = []

            if alert_msg:

                details_parts.append(
                    str(alert_msg)
                )

            if packet_count:

                details_parts.append(
                    f"Packets: {packet_count}"
                )

            if approx_pps:

                details_parts.append(
                    f"Approx PPS: {approx_pps}"
                )

            details = " | ".join(
                details_parts
            )

            events.append(
                EDREvent(
                    timestamp=timestamp,
                    category="Network",
                    attack=attack,
                    source_ip=source_ip,
                    severity=severity,
                    action=action,
                    details=details
                )
            )

        return events


    # ========================================================
    # LOAD ALL EVENTS
    # ========================================================

    def load_events(self):

        injection_events = (
            self.load_injection_events()
        )

        network_events = (
            self.load_network_events()
        )

        events = (
            injection_events +
            network_events
        )

        def sort_key(event):

            try:

                return datetime.fromisoformat(
                    event.timestamp.replace(
                        "Z",
                        "+00:00"
                    )
                )

            except Exception:

                return datetime.min

        events.sort(
            key=sort_key,
            reverse=True
        )

        return events[:MAX_ALERTS]


    # ========================================================
    # REFRESH DATA
    # ========================================================

    def refresh_data(self):

        self.events = self.load_events()

        self.update_summary()
        self.update_tables()

        self.status_var.set(
            "Monitoring active | "
            "Last update: "
            + datetime.now().strftime("%H:%M:%S")
        )

        self.root.after(
            REFRESH_INTERVAL,
            self.refresh_data
        )


    # ========================================================
    # UPDATE SUMMARY
    # ========================================================

    def update_summary(self):

        total = len(
            self.events
        )

        injection = sum(
            1
            for event in self.events
            if event.category == "Injection"
        )

        network = sum(
            1
            for event in self.events
            if event.category == "Network"
        )

        malware = sum(
            1
            for event in self.events
            if event.category == "Malware"
        )

        os_attacks = sum(
            1
            for event in self.events
            if event.category == "OS Attacks"
        )

        brute_force = sum(
            1
            for event in self.events
            if event.category == "Brute Force"
        )

        self.total_var.set(
            str(total)
        )

        self.injection_var.set(
            str(injection)
        )

        self.network_var.set(
            str(network)
        )

        self.malware_var.set(
            str(malware)
        )

        self.os_var.set(
            str(os_attacks)
        )

        self.bruteforce_var.set(
            str(brute_force)
        )


    # ========================================================
    # UPDATE TABLES
    # ========================================================

    def update_tables(self):

        self.clear_tree(
            self.all_tab
        )

        self.clear_tree(
            self.injection_tab
        )

        self.clear_tree(
            self.network_tab
        )

        for event in self.events:

            values = (
                event.timestamp,
                event.category,
                event.attack,
                event.source_ip,
                event.severity,
                event.action,
                event.details
            )

            self.insert_event(
                self.all_tab,
                event,
                values
            )

            if event.category == "Injection":

                self.insert_event(
                    self.injection_tab,
                    event,
                    values
                )

            elif event.category == "Network":

                self.insert_event(
                    self.network_tab,
                    event,
                    values
                )


    def clear_tree(self, tree):

        for item in tree.get_children():

            tree.delete(
                item
            )


    def insert_event(
        self,
        tree,
        event,
        values
    ):

        item = tree.insert(
            "",
            "end",
            values=values
        )

        severity = str(
            event.severity
        ).upper()

        if severity == "HIGH":

            tree.item(
                item,
                tags=("high",)
            )

        elif severity == "MEDIUM":

            tree.item(
                item,
                tags=("medium",)
            )

        elif severity == "LOW":

            tree.item(
                item,
                tags=("low",)
            )

        tree.tag_configure(
            "high",
            background="#fee2e2"
        )

        tree.tag_configure(
            "medium",
            background="#fef3c7"
        )

        tree.tag_configure(
            "low",
            background="#dcfce7"
        )


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 60)
    print("Central EDR Dashboard")
    print("=" * 60)
    print()
    print("Injection log:")
    print(f"  {INJECTION_LOG}")
    print()
    print("Network log:")
    print(f"  {NETWORK_LOG}")
    print()
    print("Malware:     Reserved")
    print("OS Attacks:  Reserved")
    print("Brute Force: Reserved")
    print()
    print("Starting dashboard...")
    print()

    root = tk.Tk()

    CentralEDRDashboard(
        root
    )

    root.mainloop()


if __name__ == "__main__":
    main()