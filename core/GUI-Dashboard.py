#!/usr/bin/env python3

import sys
import os
import json
import re
from datetime import datetime, timedelta


# ============================================================
# Tkinter check
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
    print("The EDR1 Dashboard requires Python Tkinter.")
    print()
    print("Install it using:")
    print()
    print("    sudo apt update")
    print("    sudo apt install python3-tk -y")
    print()
    print("Then run:")
    print()
    print("    sudo python3 edr_central_dashboard.py")
    print()
    sys.exit(1)


# ============================================================
# Log configuration
# ============================================================

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

REFRESH_MS = 1000
MAX_ALERTS = 1000


# ============================================================
# Theme definitions
# ============================================================

DARK_THEME = {
    "bg": "#080d12",
    "panel": "#0e151d",
    "panel_light": "#151f2a",
    "panel_hover": "#1b2835",
    "border": "#253443",

    "text": "#f0f4f8",
    "text_secondary": "#b1bdc9",
    "text_muted": "#718096",

    "accent": "#3b82f6",
    "accent_light": "#60a5fa",

    "green": "#22c55e",
    "yellow": "#f59e0b",
    "red": "#ef4444",
    "purple": "#a855f7",
    "cyan": "#06b6d4",

    "selected": "#1d4ed8",
    "input": "#151f2a"
}


LIGHT_THEME = {
    "bg": "#eef2f6",
    "panel": "#ffffff",
    "panel_light": "#f1f5f9",
    "panel_hover": "#e2e8f0",
    "border": "#cbd5e1",

    "text": "#17202a",
    "text_secondary": "#334155",
    "text_muted": "#64748b",

    "accent": "#2563eb",
    "accent_light": "#3b82f6",

    "green": "#16a34a",
    "yellow": "#d97706",
    "red": "#dc2626",
    "purple": "#9333ea",
    "cyan": "#0891b2",

    "selected": "#2563eb",
    "input": "#f8fafc"
}


# ============================================================
# EDR Event
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
        raw,
        metadata=None
    ):

        self.timestamp = timestamp
        self.category = category
        self.attack = attack
        self.source_ip = source_ip
        self.severity = severity
        self.action = action
        self.details = details
        self.raw = raw
        self.metadata = metadata or {}

        self.datetime = self.parse_datetime(
            timestamp
        )

    # --------------------------------------------------------

    @staticmethod
    def parse_datetime(value):

        if not value:
            return None

        value = str(value)

        formats = [
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S.%f%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f"
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

    # --------------------------------------------------------

    def display_time(self):

        if self.datetime:

            return self.datetime.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        return str(
            self.timestamp
        )

    # --------------------------------------------------------

    def searchable_text(self):

        return " ".join([
            str(self.category),
            str(self.attack),
            str(self.source_ip),
            str(self.severity),
            str(self.action),
            str(self.details),
            json.dumps(self.metadata)
        ]).lower()


# ============================================================
# EDR1 Dashboard
# ============================================================

class EDR1Dashboard:

    def __init__(self, root):

        self.root = root

        # ----------------------------------------------------
        # Theme
        # ----------------------------------------------------

        self.dark_mode = True
        self.theme = DARK_THEME

        # ----------------------------------------------------
        # Window
        # ----------------------------------------------------

        self.root.title(
            "EDR1 — Endpoint Detection & Response • Network + Injection + Malware + OS + Brute Force Monitoring"
        )

        self.root.geometry(
            "1450x850"
        )

        self.root.minsize(
            1100,
            650
        )

        # ----------------------------------------------------
        # Data
        # ----------------------------------------------------

        self.events = []

        # ----------------------------------------------------
        # Filters
        # ----------------------------------------------------

        self.time_filter = tk.StringVar(
            value="Last 24 hours"
        )

        self.category_filter = tk.StringVar(
            value="All"
        )

        self.severity_filter = tk.StringVar(
            value="All"
        )

        self.search_filter = tk.StringVar()

        self.custom_start = tk.StringVar()

        self.custom_end = tk.StringVar()

        # ----------------------------------------------------
        # Status
        # ----------------------------------------------------

        self.status_text = tk.StringVar(
            value="Starting..."
        )

        self.last_update = tk.StringVar(
            value="Never"
        )

        # ----------------------------------------------------
        # Setup
        # ----------------------------------------------------

        self.configure_styles()

        self.build_ui()

        self.apply_theme()

        # ----------------------------------------------------
        # Initial data
        # ----------------------------------------------------

        self.load_events()

        self.refresh_table()

        # ----------------------------------------------------
        # Automatic refresh
        # ----------------------------------------------------

        self.root.after(
            REFRESH_MS,
            self.auto_refresh
        )

    # ========================================================
    # Configure ttk styles
    # ========================================================

    def configure_styles(self):

        self.style = ttk.Style()

        try:
            self.style.theme_use(
                "clam"
            )
        except Exception:
            pass

    # ========================================================
    # Create dark/light combobox
    # ========================================================

    def create_combobox(
        self,
        parent,
        variable,
        values,
        width
    ):

        combo = ttk.Combobox(
            parent,
            textvariable=variable,
            values=values,
            state="readonly",
            width=width,
            style="EDR.TCombobox"
        )

        combo.bind(
            "<Button-1>",
            lambda event: self.root.after(
                10,
                lambda: self.configure_combobox_dropdown(
                    combo
                )
            )
        )

        combo.bind(
            "<<ComboboxSelected>>",
            lambda event: self.root.after(
                10,
                lambda: self.configure_combobox_dropdown(
                    combo
                )
            )
        )

        return combo

    # ========================================================
    # Configure combobox dropdown
    # ========================================================

    def configure_combobox_dropdown(
        self,
        combobox
    ):

        try:

            popdown = self.root.tk.call(
                "ttk::combobox::PopdownWindow",
                str(combobox)
            )

            listbox = "{}.f.l".format(
                popdown
            )

            self.root.tk.call(
                listbox,
                "configure",
                "-background",
                self.theme["panel_light"],
                "-foreground",
                self.theme["text"],
                "-selectbackground",
                self.theme["selected"],
                "-selectforeground",
                "#ffffff",
                "-borderwidth",
                0,
                "-highlightthickness",
                0
            )

        except Exception:
            pass

    # ========================================================
    # Build interface
    # ========================================================

    def build_ui(self):

        # ----------------------------------------------------
        # Main
        # ----------------------------------------------------

        self.main = tk.Frame(
            self.root
        )

        self.main.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=18
        )

        # ----------------------------------------------------
        # Header
        # ----------------------------------------------------

        self.header = tk.Frame(
            self.main
        )

        self.header.pack(
            fill="x",
            pady=(0, 18)
        )

        # ----------------------------------------------------
        # Branding
        # ----------------------------------------------------

        self.title_frame = tk.Frame(
            self.header
        )

        self.title_frame.pack(
            side="left"
        )

        self.title_label = tk.Label(
            self.title_frame,
            text="EDR1",
            font=(
                "DejaVu Sans",
                28,
                "bold"
            )
        )

        self.title_label.pack(
            anchor="w"
        )

        self.subtitle_label = tk.Label(
            self.title_frame,
            text="Endpoint Detection & Response • Network + Injection + Malware + OS + Brute Force Monitoring",
            font=(
                "DejaVu Sans",
                10
            )
        )

        self.subtitle_label.pack(
            anchor="w"
        )

        # ----------------------------------------------------
        # Header right
        # ----------------------------------------------------

        self.header_right = tk.Frame(
            self.header
        )

        self.header_right.pack(
            side="right"
        )

        # ----------------------------------------------------
        # Theme button
        # ----------------------------------------------------

        self.theme_button = tk.Button(
            self.header_right,
            text="☀  LIGHT MODE",
            command=self.toggle_theme,
            relief="flat",
            bd=0,
            padx=14,
            pady=8,
            cursor="hand2",
            font=(
                "DejaVu Sans",
                9,
                "bold"
            )
        )

        self.theme_button.pack(
            side="left",
            padx=(0, 10)
        )

        # ----------------------------------------------------
        # Status
        # ----------------------------------------------------

        self.status_frame = tk.Frame(
            self.header_right
        )

        self.status_frame.pack(
            side="left"
        )

        self.status_indicator = tk.Label(
            self.status_frame,
            text="●",
            font=(
                "DejaVu Sans",
                13
            )
        )

        self.status_indicator.pack(
            side="left",
            padx=(12, 5),
            pady=8
        )

        self.status_label = tk.Label(
            self.status_frame,
            textvariable=self.status_text,
            font=(
                "DejaVu Sans",
                9,
                "bold"
            )
        )

        self.status_label.pack(
            side="left",
            padx=(0, 12)
        )

        # ----------------------------------------------------
        # Summary cards
        # ----------------------------------------------------

        self.cards = tk.Frame(
            self.main
        )

        self.cards.pack(
            fill="x",
            pady=(0, 15)
        )

        self.total_card = self.create_card(
            self.cards,
            "TOTAL ALERTS",
            "0",
            "accent"
        )

        self.injection_card = self.create_card(
            self.cards,
            "INJECTION",
            "0",
            "red"
        )

        self.network_card = self.create_card(
            self.cards,
            "NETWORK",
            "0",
            "cyan"
        )

        self.malware_card = self.create_card(
            self.cards,
            "MALWARE",
            "0",
            "purple"
        )

        self.os_card = self.create_card(
            self.cards,
            "OS ATTACKS",
            "0",
            "yellow"
        )

        self.brute_card = self.create_card(
            self.cards,
            "BRUTE FORCE",
            "0",
            "green"
        )

        # ----------------------------------------------------
        # Filter panel
        # ----------------------------------------------------

        self.filter_panel = tk.Frame(
            self.main,
            highlightthickness=1
        )

        self.filter_panel.pack(
            fill="x",
            pady=(0, 15)
        )

        self.filter_row = tk.Frame(
            self.filter_panel
        )

        self.filter_row.pack(
            fill="x",
            padx=15,
            pady=12
        )

        # ----------------------------------------------------
        # Time filter
        # ----------------------------------------------------

        self.time_label = tk.Label(
            self.filter_row,
            text="TIME RANGE",
            font=(
                "DejaVu Sans",
                8,
                "bold"
            )
        )

        self.time_label.pack(
            side="left",
            padx=(0, 8)
        )

        self.time_combo = self.create_combobox(
            self.filter_row,
            self.time_filter,
            [
                "Last 5 minutes",
                "Last 15 minutes",
                "Last 30 minutes",
                "Last hour",
                "Last 6 hours",
                "Last 12 hours",
                "Last 24 hours",
                "Last 7 days",
                "All time",
                "Custom"
            ],
            18
        )

        self.time_combo.pack(
            side="left",
            padx=(0, 20)
        )

        self.time_combo.bind(
            "<<ComboboxSelected>>",
            lambda event: self.time_filter_changed()
        )

        # ----------------------------------------------------
        # Category
        # ----------------------------------------------------

        self.category_label = tk.Label(
            self.filter_row,
            text="CATEGORY",
            font=(
                "DejaVu Sans",
                8,
                "bold"
            )
        )

        self.category_label.pack(
            side="left",
            padx=(0, 8)
        )

        self.category_combo = self.create_combobox(
            self.filter_row,
            self.category_filter,
            [
                "All",
                "Injection",
                "Network",
                "Malware",
                "OS Attacks",
                "Brute Force"
            ],
            16
        )

        self.category_combo.pack(
            side="left",
            padx=(0, 20)
        )

        self.category_combo.bind(
            "<<ComboboxSelected>>",
            lambda event: self.refresh_table()
        )

        # ----------------------------------------------------
        # Severity
        # ----------------------------------------------------

        self.severity_label = tk.Label(
            self.filter_row,
            text="SEVERITY",
            font=(
                "DejaVu Sans",
                8,
                "bold"
            )
        )

        self.severity_label.pack(
            side="left",
            padx=(0, 8)
        )

        self.severity_combo = self.create_combobox(
            self.filter_row,
            self.severity_filter,
            [
                "All",
                "HIGH",
                "MEDIUM",
                "LOW",
                "INFO"
            ],
            12
        )

        self.severity_combo.pack(
            side="left",
            padx=(0, 20)
        )

        self.severity_combo.bind(
            "<<ComboboxSelected>>",
            lambda event: self.refresh_table()
        )

        # ----------------------------------------------------
        # Search
        # ----------------------------------------------------

        self.search_label = tk.Label(
            self.filter_row,
            text="SEARCH",
            font=(
                "DejaVu Sans",
                8,
                "bold"
            )
        )

        self.search_label.pack(
            side="left",
            padx=(0, 8)
        )

        self.search_entry = tk.Entry(
            self.filter_row,
            textvariable=self.search_filter,
            relief="flat",
            width=28,
            font=(
                "DejaVu Sans",
                10
            )
        )

        self.search_entry.pack(
            side="left",
            padx=(0, 8),
            ipady=7
        )

        self.search_entry.bind(
            "<KeyRelease>",
            lambda event: self.refresh_table()
        )

        # ----------------------------------------------------
        # Clear button
        # ----------------------------------------------------

        self.clear_button = tk.Button(
            self.filter_row,
            text="CLEAR",
            command=self.clear_filters,
            relief="flat",
            bd=0,
            padx=14,
            pady=7,
            cursor="hand2",
            font=(
                "DejaVu Sans",
                8,
                "bold"
            )
        )

        self.clear_button.pack(
            side="right"
        )

        # ----------------------------------------------------
        # Custom date frame
        # ----------------------------------------------------

        self.custom_frame = tk.Frame(
            self.filter_panel
        )

        self.custom_start_label = tk.Label(
            self.custom_frame,
            text="START",
            font=(
                "DejaVu Sans",
                8,
                "bold"
            )
        )

        self.custom_start_label.pack(
            side="left",
            padx=(15, 8),
            pady=(0, 12)
        )

        self.custom_start_entry = tk.Entry(
            self.custom_frame,
            textvariable=self.custom_start,
            relief="flat",
            width=20
        )

        self.custom_start_entry.pack(
            side="left",
            padx=(0, 15),
            pady=(0, 12),
            ipady=6
        )

        self.custom_end_label = tk.Label(
            self.custom_frame,
            text="END",
            font=(
                "DejaVu Sans",
                8,
                "bold"
            )
        )

        self.custom_end_label.pack(
            side="left",
            padx=(0, 8),
            pady=(0, 12)
        )

        self.custom_end_entry = tk.Entry(
            self.custom_frame,
            textvariable=self.custom_end,
            relief="flat",
            width=20
        )

        self.custom_end_entry.pack(
            side="left",
            padx=(0, 15),
            pady=(0, 12),
            ipady=6
        )

        self.custom_format_label = tk.Label(
            self.custom_frame,
            text="YYYY-MM-DD HH:MM:SS",
            font=(
                "DejaVu Sans",
                8
            )
        )

        self.custom_format_label.pack(
            side="left",
            pady=(0, 12)
        )

        # ----------------------------------------------------
        # Table panel
        # ----------------------------------------------------

        self.table_panel = tk.Frame(
            self.main,
            highlightthickness=1
        )

        self.table_panel.pack(
            fill="both",
            expand=True
        )

        # ----------------------------------------------------
        # Table header
        # ----------------------------------------------------

        self.table_header = tk.Frame(
            self.table_panel
        )

        self.table_header.pack(
            fill="x",
            padx=15,
            pady=(12, 8)
        )

        self.events_title = tk.Label(
            self.table_header,
            text="NETWORK, INJECTION, MALWARE, OS & BRUTE FORCE EVENTS",
            font=(
                "DejaVu Sans",
                11,
                "bold"
            )
        )

        self.events_title.pack(
            side="left"
        )

        self.event_count_label = tk.Label(
            self.table_header,
            text="0 events",
            font=(
                "DejaVu Sans",
                9
            )
        )

        self.event_count_label.pack(
            side="right"
        )

        # ----------------------------------------------------
        # Tree
        # ----------------------------------------------------

        self.tree_frame = tk.Frame(
            self.table_panel
        )

        self.tree_frame.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=(0, 10)
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

        self.tree = ttk.Treeview(
            self.tree_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        headings = {
            "time": "TIME",
            "category": "CATEGORY",
            "attack": "ATTACK",
            "source": "SOURCE IP",
            "severity": "SEVERITY",
            "action": "ACTION",
            "details": "DETAILS"
        }

        for column, heading in headings.items():

            self.tree.heading(
                column,
                text=heading
            )

        self.tree.column(
            "time",
            width=155,
            minwidth=140
        )

        self.tree.column(
            "category",
            width=110,
            minwidth=90
        )

        self.tree.column(
            "attack",
            width=190,
            minwidth=150
        )

        self.tree.column(
            "source",
            width=135,
            minwidth=110
        )

        self.tree.column(
            "severity",
            width=95,
            minwidth=80,
            anchor="center"
        )

        self.tree.column(
            "action",
            width=120,
            minwidth=100
        )

        self.tree.column(
            "details",
            width=500,
            minwidth=250
        )

        self.scrollbar = ttk.Scrollbar(
            self.tree_frame,
            orient="vertical",
            command=self.tree.yview,
            style="EDR.Vertical.TScrollbar"
        )

        self.tree.configure(
            yscrollcommand=self.scrollbar.set
        )

        self.tree.pack(
            side="left",
            fill="both",
            expand=True
        )

        self.scrollbar.pack(
            side="right",
            fill="y"
        )

        # ----------------------------------------------------
        # Double click
        # ----------------------------------------------------

        self.tree.bind(
            "<Double-1>",
            self.show_event_details
        )

        # ----------------------------------------------------
        # Footer
        # ----------------------------------------------------

        self.footer = tk.Frame(
            self.main
        )

        self.footer.pack(
            fill="x",
            pady=(10, 0)
        )

        self.footer_left = tk.Label(
            self.footer,
            text=(
                "EDR1  •  Injection Monitoring  •  "
                "Network Monitoring"
            ),
            font=(
                "DejaVu Sans",
                8
            )
        )

        self.footer_left.pack(
            side="left"
        )

        self.footer_right = tk.Label(
            self.footer,
            textvariable=self.last_update,
            font=(
                "DejaVu Sans",
                8
            )
        )

        self.footer_right.pack(
            side="right"
        )

    # ========================================================
    # Create summary card
    # ========================================================

    def create_card(
        self,
        parent,
        title,
        value,
        accent_name
    ):

        accent = self.theme[
            accent_name
        ]

        card = tk.Frame(
            parent,
            highlightthickness=1
        )

        card.pack(
            side="left",
            fill="both",
            expand=True,
            padx=4
        )

        accent_bar = tk.Frame(
            card,
            bg=accent,
            width=4
        )

        accent_bar.pack(
            side="left",
            fill="y"
        )

        content = tk.Frame(
            card
        )

        content.pack(
            fill="both",
            expand=True,
            padx=13,
            pady=10
        )

        title_label = tk.Label(
            content,
            text=title,
            font=(
                "DejaVu Sans",
                8,
                "bold"
            )
        )

        title_label.pack(
            anchor="w"
        )

        value_label = tk.Label(
            content,
            text=value,
            font=(
                "DejaVu Sans",
                21,
                "bold"
            )
        )

        value_label.pack(
            anchor="w",
            pady=(2, 0)
        )

        # Store references

        card.title_label = title_label
        card.value_label = value_label
        card.accent_bar = accent_bar

        return value_label

    # ========================================================
    # Apply current theme
    # ========================================================

    def apply_theme(self):

        t = self.theme

        # ----------------------------------------------------
        # Root
        # ----------------------------------------------------

        self.root.configure(
            bg=t["bg"]
        )

        # ----------------------------------------------------
        # Main containers
        # ----------------------------------------------------

        for widget in [
            self.main,
            self.header,
            self.title_frame,
            self.header_right,
            self.cards,
            self.footer
        ]:

            widget.configure(
                bg=t["bg"]
            )

        # ----------------------------------------------------
        # Labels
        # ----------------------------------------------------

        self.title_label.configure(
            bg=t["bg"],
            fg=t["text"]
        )

        self.subtitle_label.configure(
            bg=t["bg"],
            fg=t["text_muted"]
        )

        self.status_frame.configure(
            bg=t["panel"],
            highlightbackground=t["border"]
        )

        self.status_label.configure(
            bg=t["panel"],
            fg=t["text"]
        )

        self.status_indicator.configure(
            bg=t["panel"],
            fg=t["green"]
        )

        # ----------------------------------------------------
        # Theme button
        # ----------------------------------------------------

        if self.dark_mode:

            self.theme_button.configure(
                text="☀  LIGHT MODE",
                bg=t["panel_light"],
                fg=t["text"],
                activebackground=t["panel_hover"],
                activeforeground=t["text"]
            )

        else:

            self.theme_button.configure(
                text="☾  DARK MODE",
                bg=t["panel_light"],
                fg=t["text"],
                activebackground=t["panel_hover"],
                activeforeground=t["text"]
            )

        # ----------------------------------------------------
        # Status frame
        # ----------------------------------------------------

        self.status_frame.configure(
            bg=t["panel"],
            highlightbackground=t["border"]
        )

        self.status_label.configure(
            bg=t["panel"],
            fg=t["text"]
        )

        self.status_indicator.configure(
            bg=t["panel"]
        )

        # ----------------------------------------------------
        # Filter panel
        # ----------------------------------------------------

        self.filter_panel.configure(
            bg=t["panel"],
            highlightbackground=t["border"]
        )

        self.filter_row.configure(
            bg=t["panel"]
        )

        # ----------------------------------------------------
        # Filter labels
        # ----------------------------------------------------

        for label in [
            self.time_label,
            self.category_label,
            self.severity_label,
            self.search_label,
            self.custom_start_label,
            self.custom_end_label
        ]:

            label.configure(
                bg=t["panel"],
                fg=t["text_muted"]
            )

        self.custom_format_label.configure(
            bg=t["panel"],
            fg=t["text_muted"]
        )

        self.custom_frame.configure(
            bg=t["panel"]
        )

        # ----------------------------------------------------
        # Entry
        # ----------------------------------------------------

        self.search_entry.configure(
            bg=t["input"],
            fg=t["text"],
            insertbackground=t["text"],
            selectbackground=t["selected"],
            selectforeground="#ffffff"
        )

        for entry in [
            self.custom_start_entry,
            self.custom_end_entry
        ]:

            entry.configure(
                bg=t["input"],
                fg=t["text"],
                insertbackground=t["text"],
                selectbackground=t["selected"],
                selectforeground="#ffffff"
            )

        # ----------------------------------------------------
        # Clear button
        # ----------------------------------------------------

        self.clear_button.configure(
            bg=t["panel_light"],
            fg=t["text"],
            activebackground=t["panel_hover"],
            activeforeground=t["text"]
        )

        # ----------------------------------------------------
        # Table panel
        # ----------------------------------------------------

        self.table_panel.configure(
            bg=t["panel"],
            highlightbackground=t["border"]
        )

        self.table_header.configure(
            bg=t["panel"]
        )

        self.tree_frame.configure(
            bg=t["panel"]
        )

        self.events_title.configure(
            bg=t["panel"],
            fg=t["text"]
        )

        self.event_count_label.configure(
            bg=t["panel"],
            fg=t["text_muted"]
        )

        # ----------------------------------------------------
        # Footer
        # ----------------------------------------------------

        self.footer_left.configure(
            bg=t["bg"],
            fg=t["text_muted"]
        )

        self.footer_right.configure(
            bg=t["bg"],
            fg=t["text_muted"]
        )

        # ----------------------------------------------------
        # ttk styles
        # ----------------------------------------------------

        self.style.configure(
            "EDR.TCombobox",
            foreground=t["text"],
            background=t["panel_light"],
            fieldbackground=t["panel_light"],
            selectforeground=t["text"],
            selectbackground=t["panel_hover"],
            bordercolor=t["border"],
            lightcolor=t["panel_light"],
            darkcolor=t["panel_light"],
            arrowcolor=t["text"],
            relief="flat",
            padding=6
        )

        self.style.map(
            "EDR.TCombobox",
            fieldbackground=[
                ("readonly", t["panel_light"]),
                ("active", t["panel_hover"])
            ],
            foreground=[
                ("readonly", t["text"]),
                ("active", t["text"])
            ],
            background=[
                ("readonly", t["panel_light"]),
                ("active", t["panel_hover"])
            ],
            selectbackground=[
                ("readonly", t["panel_hover"])
            ],
            selectforeground=[
                ("readonly", t["text"])
            ],
            arrowcolor=[
                ("readonly", t["text"])
            ]
        )

        # ----------------------------------------------------
        # Treeview
        # ----------------------------------------------------

        self.style.configure(
            "Treeview",
            background=t["panel"],
            foreground=t["text"],
            fieldbackground=t["panel"],
            borderwidth=0,
            relief="flat",
            rowheight=38
        )

        self.style.map(
            "Treeview",
            background=[
                ("selected", t["selected"])
            ],
            foreground=[
                ("selected", "#ffffff")
            ]
        )

        self.style.configure(
            "Treeview.Heading",
            background=t["panel_light"],
            foreground=t["text"],
            borderwidth=0,
            relief="flat"
        )

        self.style.map(
            "Treeview.Heading",
            background=[
                ("active", t["panel_hover"])
            ],
            foreground=[
                ("active", t["text"])
            ]
        )

        # ----------------------------------------------------
        # Scrollbar
        # ----------------------------------------------------

        self.style.configure(
            "EDR.Vertical.TScrollbar",
            background=t["panel_light"],
            troughcolor=t["bg"],
            bordercolor=t["bg"],
            arrowcolor=t["text"],
            relief="flat"
        )

        self.style.map(
            "EDR.Vertical.TScrollbar",
            background=[
                ("active", t["panel_hover"])
            ]
        )

        # ----------------------------------------------------
        # Cards
        # ----------------------------------------------------

        self.update_card_theme(
            self.total_card,
            "accent"
        )

        self.update_card_theme(
            self.injection_card,
            "red"
        )

        self.update_card_theme(
            self.network_card,
            "cyan"
        )

        self.update_card_theme(
            self.malware_card,
            "purple"
        )

        self.update_card_theme(
            self.os_card,
            "yellow"
        )

        self.update_card_theme(
            self.brute_card,
            "green"
        )

        # ----------------------------------------------------
        # Reconfigure dropdown if open
        # ----------------------------------------------------

        self.root.after(
            50,
            self.refresh_dropdowns
        )

        # ----------------------------------------------------
        # Update row colours
        # ----------------------------------------------------

        self.tree.tag_configure(
            "high",
            foreground=t["red"]
        )

        self.tree.tag_configure(
            "medium",
            foreground=t["yellow"]
        )

        self.tree.tag_configure(
            "low",
            foreground=t["green"]
        )

        self.tree.tag_configure(
            "normal",
            foreground=t["text"]
        )

    # ========================================================
    # Update card theme
    # ========================================================

    def update_card_theme(
        self,
        value_label,
        accent_name
    ):

        card = value_label.master.master

        content = value_label.master

        card.configure(
            bg=self.theme["panel"],
            highlightbackground=self.theme["border"]
        )

        content.configure(
            bg=self.theme["panel"]
        )

        card.title_label.configure(
            bg=self.theme["panel"],
            fg=self.theme["text_muted"]
        )

        card.value_label.configure(
            bg=self.theme["panel"],
            fg=self.theme["text"]
        )

        card.accent_bar.configure(
            bg=self.theme[accent_name]
        )

    # ========================================================
    # Refresh all dropdowns
    # ========================================================

    def refresh_dropdowns(self):

        for combo in [
            self.time_combo,
            self.category_combo,
            self.severity_combo
        ]:

            self.configure_combobox_dropdown(
                combo
            )

    # ========================================================
    # Toggle theme
    # ========================================================

    def toggle_theme(self):

        self.dark_mode = not self.dark_mode

        if self.dark_mode:

            self.theme = DARK_THEME

        else:

            self.theme = LIGHT_THEME

        self.apply_theme()

    # ========================================================
    # Read JSONL
    # ========================================================

    def read_jsonl(
        self,
        path
    ):

        events = []

        if not os.path.exists(path):

            return events

        try:

            with open(
                path,
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

                    events.append(
                        json.loads(line)
                    )

                except json.JSONDecodeError:

                    continue

        except PermissionError:

            self.status_text.set(
                "PERMISSION DENIED"
            )

            self.status_indicator.configure(
                fg=self.theme["red"]
            )

            return events

        except Exception:

            return events

        return events

    # ========================================================
    # Injection events
    # ========================================================

    def load_injection_events(self):

        raw_events = self.read_jsonl(
            INJECTION_LOG
        )

        events = []

        for item in raw_events:

            timestamp = item.get(
                "timestamp",
                ""
            )

            incident = item.get(
                "incident",
                "Injection"
            )

            source_ip = item.get(
                "source_ip",
                "-"
            )

            severity = item.get(
                "severity",
                "HIGH"
            )

            action = item.get(
                "action",
                "DETECTED"
            )

            description = item.get(
                "description",
                ""
            )

            rule_id = item.get(
                "rule_id",
                ""
            )

            details = description

            if rule_id:

                details = (
                    "Rule {} — {}"
                    .format(
                        rule_id,
                        description
                    )
                )

            events.append(
                EDREvent(
                    timestamp,
                    "Injection",
                    incident,
                    source_ip,
                    severity,
                    action,
                    details,
                    item
                )
            )

        return events

    # ========================================================
    # Response actions
    # ========================================================

    def load_response_actions(self):
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
            with open(RESPONSE_LOG, "r", encoding="utf-8", errors="replace") as file:
                for line in file:
                    match = pattern.search(line.strip())
                    if not match:
                        continue
                    timestamp = match.group("timestamp")
                    actions.append({
                        "timestamp": timestamp,
                        "datetime": self.parse_datetime(timestamp),
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

    def network_response_action(self, source_ip, attack, event_datetime, response_actions):
        """Match a response action to a network evidence record."""
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
            with open(RESPONSE_LOG, "r", encoding="utf-8", errors="replace") as file:
                for line in file:
                    match = re.search(
                        r"^(?P<timestamp>\\S+\\s+\\S+)\\s+(?P<action>BLOCKED|UNBLOCKED)\\s+(?P<ip>[^\\s]+).*?artifact_type=(?P<attack>[^,\\)]+)",
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

    # ========================================================
    # Network events
    # ========================================================

    def load_network_events(self):
        """Load final evidence from the current network EDR pipeline.

        detection_engine.py -> edr_raw_alerts.jsonl
        monitoring_engine.py -> edr_evidence.jsonl
        Wazuh also watches edr_evidence.jsonl.
        """
        raw_events = self.read_jsonl(NETWORK_LOG)
        response_actions = self.load_response_actions()
        events = []

        for item in raw_events:
            timestamp = item.get("timestamp", "")
            event_datetime = EDREvent.parse_datetime(timestamp)
            attack = item.get("artifact_type", "Network Attack")
            source_ip = item.get("srcip", "-")
            destination_ip = item.get("dstip", "-")

            # Wazuh local rule 100051 is level 10; evidence does not
            # carry a severity field, so show HIGH by default.
            severity = item.get("severity", "HIGH")
            rule_id = str(item.get("rule_id", "100051"))
            mitre = item.get("mitre", "T1498")

            tool = item.get("likely_source_tool", "Unknown")
            interface = item.get("interface", "-")
            packet_count = item.get("packet_count", "")
            approx_pps = item.get("approx_pps", "")
            alert_msg = item.get("alert_msg", "")

            correlated = item.get("correlated_logs", {})
            if not isinstance(correlated, dict):
                correlated = {}

            kernel = correlated.get("kernel_syslog", [])
            apache_access = correlated.get("apache_access", [])
            apache_error = correlated.get("apache_error", [])
            kernel = kernel if isinstance(kernel, list) else []
            apache_access = apache_access if isinstance(apache_access, list) else []
            apache_error = apache_error if isinstance(apache_error, list) else []

            action_info = self.network_response_action(
                source_ip, attack, event_datetime, response_actions
            )
            action = (
                action_info["action"]
                if action_info
                else item.get("action", "DETECTED")
            )

            details = []
            if alert_msg:
                details.append(alert_msg)
            details += [
                "Tool: {}".format(tool),
                "Dst: {}".format(destination_ip),
                "Iface: {}".format(interface),
            ]
            if packet_count != "":
                details.append("Packets: {}".format(packet_count))
            if approx_pps != "":
                details.append("PPS: {}".format(approx_pps))
            details += [
                "Wazuh rule: {}".format(rule_id),
                "MITRE: {}".format(mitre),
                "Block timeout: 600s",
            ]
            if kernel:
                details.append("Kernel correlation: {}".format(len(kernel)))
            if apache_access:
                details.append("Apache access correlation: {}".format(len(apache_access)))
            if apache_error:
                details.append("Apache error correlation: {}".format(len(apache_error)))
            if action_info:
                details.append("Response timestamp: {}".format(action_info["timestamp"]))

            events.append(
                EDREvent(
                    timestamp, "Network", attack, source_ip, severity, action,
                    " | ".join(details), item,
                    {
                        "destination_ip": destination_ip,
                        "likely_source_tool": tool,
                        "interface": interface,
                        "packet_count": packet_count,
                        "approx_pps": approx_pps,
                        "rule_id": rule_id,
                        "mitre": mitre,
                        "block_timeout": 600,
                        "response_timestamp": action_info["timestamp"] if action_info else "",
                        "correlated_kernel_logs": len(kernel),
                        "correlated_apache_access": len(apache_access),
                        "correlated_apache_error": len(apache_error)
                    }
                )
            )

        return events

    # ========================================================
    # Malware response actions
    # ========================================================

    def load_malware_response_actions(self):
        """Read malware response actions written by edr_response.py."""
        actions = []
        if not os.path.exists(MALWARE_RESPONSE_LOG):
            return actions

        try:
            with open(
                MALWARE_RESPONSE_LOG,
                "r",
                encoding="utf-8",
                errors="replace"
            ) as file:
                for line in file:
                    line = line.strip()
                    if not line:
                        continue

                    match = re.search(
                        r"(?P<action>AUTOMATIC_RESPONSE):\s*"
                        r"(?P<response>[^ ]+).*?"
                        r"PID=(?P<pid>\d+)",
                        line
                    )
                    if not match:
                        continue

                    actions.append({
                        "timestamp": line.split(" ", 2)[0] if line else "",
                        "action": match.group("response"),
                        "pid": match.group("pid"),
                        "raw": line
                    })
        except (PermissionError, OSError):
            return actions

        return actions

    # ========================================================
    # Malware events
    # ========================================================

    def load_malware_events(self):
        """
        Load Wazuh malware alerts collected by edr_alert_collector.py.

        Collector path:
            Wazuh alerts.json -> edr_alert_collector.py -> edr_alerts.json

        Current malware rules:
            100100/100101 = Keylogger
            100200/100201/100202 = Rootkit
            100300/100301 = Cryptominer
        """
        raw_events = self.read_jsonl(MALWARE_ALERT_LOG)
        response_actions = self.load_malware_response_actions()
        events = []

        for item in raw_events:
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

            level = rule.get("level", 0)
            try:
                level = int(level)
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
                # The response engine requires both keylogger rules before SIGTERM.
                action = "DETECTED / AWAITING CORRELATION"
            else:
                # Rootkit and cryptominer are explicitly monitoring-only.
                action = "MONITORING ONLY"

            description = rule.get(
                "description",
                "Malware event detected by Wazuh"
            )

            details = (
                "Rule {} — {} | PID: {} | Executable: {} | "
                "Process: {} | MITRE: {}"
            ).format(
                rule_id,
                description,
                pid,
                executable,
                process_name,
                mitre
            )

            if response_info:
                details += " | Response: {}".format(
                    response_info.get("raw", "")
                )

            events.append(
                EDREvent(
                    timestamp,
                    "Malware",
                    attack,
                    audit.get("srcip", item.get("agent", {}).get("ip", "-")),
                    severity,
                    action,
                    details,
                    item,
                    {
                        "rule_id": rule_id,
                        "wazuh_level": level,
                        "mitre": mitre,
                        "pid": pid,
                        "executable": executable,
                        "process_name": process_name,
                        "response": response_info.get("raw", "") if response_info else "",
                        "response_timestamp": response_info.get("timestamp", "") if response_info else ""
                    }
                )
            )

        return events

    # ========================================================
    # OS / privilege-escalation events
    # ========================================================

    def load_os_response_actions(self):
        """Load structured OS response JSON emitted by os_agent/response.py or cron_agent/response.py."""
        actions = []
        if not os.path.exists(OS_RESPONSE_LOG):
            return actions
        try:
            with open(OS_RESPONSE_LOG, "r", encoding="utf-8", errors="replace") as file:
                for line in file:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(item, dict) and item.get("source") in ("os", "cron"):
                        actions.append(item)
        except (PermissionError, OSError):
            return actions
        return actions

    def load_os_events(self):
        """Load OS-agent and cron-agent JSON verdicts captured with tee."""
        raw_events = self.read_jsonl(OS_ALERT_LOG)
        response_actions = self.load_os_response_actions()
        events = []

        for item in raw_events:
            # SUID / privilege escalation verdicts from os_agent/detection.py
            if item.get("verdict") == "suspected_privesc":
                pid = item.get("pid", "-")
                exe = item.get("exe", "-")
                name = item.get("name", "-")
                real_uid = item.get("real_uid", "-")
                effective_uid = item.get("effective_uid", "-")
                response_info = None
                for response in reversed(response_actions):
                    if response.get("source") == "os" and str(response.get("pid", "")) == str(pid):
                        response_info = response
                        break
                action = response_info.get("action", "RESPONDED") if response_info else "DETECTED"
                timestamp = response_info.get("timestamp", "") if response_info else ""
                if not timestamp:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                details = (
                    "SUID privilege escalation suspected | PID: {} | Process: {} | "
                    "Executable: {} | UID {} -> EUID {} | MITRE: T1548.001"
                ).format(pid, name, exe, real_uid, effective_uid)
                events.append(EDREvent(
                    timestamp, "OS Attacks", "Privilege Escalation / SUID", "localhost",
                    "HIGH", action, details, item,
                    {"pid": pid, "ppid": item.get("ppid", "-"), "process_name": name,
                     "executable": exe, "real_uid": real_uid, "effective_uid": effective_uid,
                     "mitre": "T1548.001", "response": response_info or {}}
                ))
                continue

            # Cron hijacking verdicts from cron_agent/detection.py
            if "path" in item and "status" in item and ("writable_risk" in item or "current_hash" in item):
                status = item.get("status")
                writable = bool(item.get("writable_risk"))
                if status == "modified" or writable:
                    path = item.get("path", "-")
                    response_info = None
                    for response in reversed(response_actions):
                        if response.get("source") == "cron" and response.get("path") == path:
                            response_info = response
                            break
                    actions = []
                    if status == "modified":
                        actions.append("SCRIPT MODIFIED")
                    if writable:
                        actions.append("WRITABLE RISK")
                    action = response_info.get("action", "DETECTED") if response_info else "DETECTED"
                    timestamp = response_info.get("timestamp", "") if response_info else ""
                    if not timestamp:
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    details = (
                        "Cron job hijacking risk | Path: {} | Status: {} | Mode: {} | "
                        "SHA256: {} | MITRE: T1053.003"
                    ).format(path, ", ".join(actions), item.get("mode", "-"),
                               item.get("current_hash", "-"),)
                    events.append(EDREvent(
                        timestamp, "OS Attacks", "Cron Job Hijacking", "localhost",
                        "HIGH", action, details, item,
                        {"path": path, "status": status, "mode": item.get("mode", "-"),
                         "writable_risk": writable, "current_hash": item.get("current_hash", "-"),
                         "previous_hash": item.get("previous_hash", "-"),
                         "mitre": "T1053.003", "response": response_info or {}}
                    ))

        return events

    # ========================================================
    # Brute force events
    # ========================================================

    def load_brute_response_actions(self):
        """Load structured response JSON emitted by brute_force_agent/response.py."""
        actions = []
        raw_events = self.read_jsonl(BRUTE_RESPONSE_LOG)
        for item in raw_events:
            if isinstance(item, dict) and item.get("source") == "brute_force":
                actions.append(item)
        return actions

    def load_brute_force_events(self):
        """
        Load brute-force detection alerts produced by detection.py.

        Expected pipeline:
          detection.py | tee -a /var/log/edr_bruteforce_alerts.jsonl
                      | response.py | tee -a /var/log/edr_bruteforce_response_actions.jsonl
        """
        raw_events = self.read_jsonl(BRUTE_ALERT_LOG)
        response_actions = self.load_brute_response_actions()
        events = []

        for item in raw_events:
            if not isinstance(item, dict):
                continue
            if not item.get("channel") or not item.get("rule"):
                continue

            timestamp = item.get("event_time") or item.get("timestamp", "")
            event_datetime = EDREvent.parse_datetime(timestamp)
            source_ip = item.get("source_ip", "Unknown")
            rule = item.get("rule", "brute_force")
            severity = str(item.get("severity", "high")).upper()
            identity = item.get("identity")

            # Find the response generated for this alert. Response.py emits
            # one structured record per ban/extension, with source_ip as ip
            # and the detector rule as reason.
            response_info = None
            candidates = []
            for response in response_actions:
                if response.get("ip") != source_ip:
                    continue
                if response.get("reason") != rule:
                    continue
                response_time = EDREvent.parse_datetime(response.get("timestamp", ""))
                if response_time is None:
                    continue
                if event_datetime is not None:
                    delta = (response_time - event_datetime).total_seconds()
                    if -2 <= delta <= 10:
                        candidates.append((response_time, response))
                else:
                    candidates.append((response_time, response))

            if candidates:
                candidates.sort(key=lambda x: x[0])
                response_info = candidates[0][1]

            action = response_info.get("action", "DETECTED") if response_info else "DETECTED"

            channel = item.get("channel", "unknown").upper()
            identity_text = identity if identity not in (None, "") else "multiple accounts"
            details = item.get("message", "")
            extra = [
                f"Channel: {channel}",
                f"Identity: {identity_text}",
                f"Rule: {rule}",
            ]

            detail = item.get("detail")
            if isinstance(detail, dict):
                if "failures" in detail:
                    extra.append(f"Failures: {detail['failures']}")
                if "distinct_identities" in detail:
                    extra.append(f"Distinct identities: {detail['distinct_identities']}")
                if "failures_before_success" in detail:
                    extra.append(f"Failures before success: {detail['failures_before_success']}")

            if response_info:
                extra.append(f"Response: {response_info.get('action', 'DETECTED')}")
                extra.append(f"Response time: {response_info.get('timestamp', '-')}")

            details = (details + " | " if details else "") + " | ".join(extra)

            events.append(EDREvent(
                timestamp,
                "Brute Force",
                rule.replace("_", " ").title(),
                source_ip,
                severity,
                action,
                details,
                item,
                {
                    "channel": item.get("channel", "-"),
                    "rule": rule,
                    "identity": identity if identity is not None else "-",
                    "detail": detail if isinstance(detail, dict) else {},
                    "response": response_info or {},
                    "response_timestamp": response_info.get("timestamp", "") if response_info else "",
                }
            ))

        return events

    # ========================================================
    # Load all events
    # ========================================================

    def load_events(self):

        injection = (
            self.load_injection_events()
        )

        network = (
            self.load_network_events()
        )

        malware = (
            self.load_malware_events()
        )

        os_attacks = (
            self.load_os_events()
        )

        brute_force = (
            self.load_brute_force_events()
        )

        self.events = (
            injection +
            network +
            malware +
            os_attacks +
            brute_force
        )

        self.events.sort(
            key=lambda event: (
                event.datetime
                if event.datetime
                else datetime.min
            ),
            reverse=True
        )

        self.events = self.events[
            :MAX_ALERTS
        ]

        self.status_text.set(
            "EDR1 ONLINE"
        )

        self.status_indicator.configure(
            fg=self.theme["green"]
        )

        self.last_update.set(
            "Last updated: {}".format(
                datetime.now().strftime(
                    "%H:%M:%S"
                )
            )
        )

    # ========================================================
    # Get time range
    # ========================================================

    def get_time_range(self):

        now = datetime.now()

        selection = (
            self.time_filter.get()
        )

        if selection == "Last 5 minutes":

            return (
                now - timedelta(minutes=5),
                now
            )

        if selection == "Last 15 minutes":

            return (
                now - timedelta(minutes=15),
                now
            )

        if selection == "Last 30 minutes":

            return (
                now - timedelta(minutes=30),
                now
            )

        if selection == "Last hour":

            return (
                now - timedelta(hours=1),
                now
            )

        if selection == "Last 6 hours":

            return (
                now - timedelta(hours=6),
                now
            )

        if selection == "Last 12 hours":

            return (
                now - timedelta(hours=12),
                now
            )

        if selection == "Last 24 hours":

            return (
                now - timedelta(hours=24),
                now
            )

        if selection == "Last 7 days":

            return (
                now - timedelta(days=7),
                now
            )

        if selection == "Custom":

            try:

                start = datetime.strptime(
                    self.custom_start
                    .get()
                    .strip(),
                    "%Y-%m-%d %H:%M:%S"
                )

                end = datetime.strptime(
                    self.custom_end
                    .get()
                    .strip(),
                    "%Y-%m-%d %H:%M:%S"
                )

                return (
                    start,
                    end
                )

            except ValueError:

                return (
                    None,
                    None
                )

        return (
            None,
            None
        )

    # ========================================================
    # Time filter changed
    # ========================================================

    def time_filter_changed(self):

        if (
            self.time_filter.get()
            == "Custom"
        ):

            self.custom_frame.pack(
                fill="x"
            )

        else:

            self.custom_frame.pack_forget()

        self.refresh_table()

    # ========================================================
    # Filter events
    # ========================================================

    def get_filtered_events(self):

        start, end = (
            self.get_time_range()
        )

        category = (
            self.category_filter.get()
        )

        severity = (
            self.severity_filter.get()
        )

        search = (
            self.search_filter
            .get()
            .strip()
            .lower()
        )

        filtered = []

        for event in self.events:

            # Time

            if start and end:

                if event.datetime is None:
                    continue

                if event.datetime < start:
                    continue

                if event.datetime > end:
                    continue

            # Category

            if category != "All":

                if event.category != category:
                    continue

            # Severity

            if severity != "All":

                if (
                    event.severity.upper()
                    != severity
                ):
                    continue

            # Search

            if search:

                if (
                    search
                    not in event.searchable_text()
                ):

                    continue

            filtered.append(
                event
            )

        return filtered

    # ========================================================
    # Refresh table
    # ========================================================

    def refresh_table(self):

        filtered = (
            self.get_filtered_events()
        )

        # Clear

        for item in (
            self.tree.get_children()
        ):

            self.tree.delete(
                item
            )

        # Insert

        for index, event in enumerate(
            filtered
        ):

            severity = (
                event.severity.upper()
            )

            tag = "normal"

            if severity == "HIGH":

                tag = "high"

            elif severity == "MEDIUM":

                tag = "medium"

            elif severity == "LOW":

                tag = "low"

            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    event.display_time(),
                    event.category,
                    event.attack,
                    event.source_ip,
                    severity,
                    event.action,
                    event.details
                ),
                tags=(tag,)
            )

        # ----------------------------------------------------
        # Counters
        # ----------------------------------------------------

        total = len(
            filtered
        )

        injection = sum(
            1
            for event in filtered
            if event.category == "Injection"
        )

        network = sum(
            1
            for event in filtered
            if event.category == "Network"
        )

        malware = sum(
            1
            for event in filtered
            if event.category == "Malware"
        )

        os_attacks = sum(
            1
            for event in filtered
            if event.category == "OS Attacks"
        )

        brute_force = sum(
            1
            for event in filtered
            if event.category == "Brute Force"
        )

        self.total_card.configure(
            text=str(total)
        )

        self.injection_card.configure(
            text=str(injection)
        )

        self.network_card.configure(
            text=str(network)
        )

        self.malware_card.configure(
            text=str(malware)
        )

        self.os_card.configure(
            text=str(os_attacks)
        )

        self.brute_card.configure(
            text=str(brute_force)
        )

        self.event_count_label.configure(
            text="{} events".format(
                total
            )
        )

    # ========================================================
    # Clear filters
    # ========================================================

    def clear_filters(self):

        self.time_filter.set(
            "Last 24 hours"
        )

        self.category_filter.set(
            "All"
        )

        self.severity_filter.set(
            "All"
        )

        self.search_filter.set(
            ""
        )

        self.custom_start.set(
            ""
        )

        self.custom_end.set(
            ""
        )

        self.custom_frame.pack_forget()

        self.refresh_table()

    # ========================================================
    # Show event details
    # ========================================================

    def show_event_details(
        self,
        event=None
    ):

        selected = (
            self.tree.selection()
        )

        if not selected:
            return

        try:

            index = int(
                selected[0]
            )

            filtered = (
                self.get_filtered_events()
            )

            selected_event = (
                filtered[index]
            )

        except Exception:

            return

        # ----------------------------------------------------
        # Popup
        # ----------------------------------------------------

        window = tk.Toplevel(
            self.root
        )

        window.title(
            "EDR1 — Alert Details"
        )

        window.geometry(
            "850x600"
        )

        window.configure(
            bg=self.theme["bg"]
        )

        window.transient(
            self.root
        )

        # ----------------------------------------------------
        # Header
        # ----------------------------------------------------

        header = tk.Frame(
            window,
            bg=self.theme["panel"]
        )

        header.pack(
            fill="x"
        )

        tk.Label(
            header,
            text="EDR1 ALERT DETAILS",
            bg=self.theme["panel"],
            fg=self.theme["text"],
            font=(
                "DejaVu Sans",
                16,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=20,
            pady=(18, 2)
        )

        attack_colour = (
            self.theme["text"]
        )

        if (
            selected_event
            .severity
            .upper()
            == "HIGH"
        ):

            attack_colour = (
                self.theme["red"]
            )

        tk.Label(
            header,
            text=selected_event.attack,
            bg=self.theme["panel"],
            fg=attack_colour,
            font=(
                "DejaVu Sans",
                11,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=20,
            pady=(0, 18)
        )

        # ----------------------------------------------------
        # Information
        # ----------------------------------------------------

        info = tk.Frame(
            window,
            bg=self.theme["bg"]
        )

        info.pack(
            fill="x",
            padx=20,
            pady=20
        )

        self.detail_row(
            info,
            "Timestamp",
            selected_event.display_time()
        )

        self.detail_row(
            info,
            "Category",
            selected_event.category
        )

        self.detail_row(
            info,
            "Attack",
            selected_event.attack
        )

        self.detail_row(
            info,
            "Source IP",
            selected_event.source_ip
        )

        self.detail_row(
            info,
            "Severity",
            selected_event.severity
        )

        self.detail_row(
            info,
            "Action",
            selected_event.action
        )

        self.detail_row(
            info,
            "Details",
            selected_event.details
        )
        if selected_event.category == "Network" and selected_event.metadata:
            self.detail_row(info, "Destination", selected_event.metadata.get("destination_ip", "-"))
            self.detail_row(info, "Likely Tool", selected_event.metadata.get("likely_source_tool", "-"))
            self.detail_row(info, "Interface", selected_event.metadata.get("interface", "-"))
            self.detail_row(info, "Packet Count", selected_event.metadata.get("packet_count", "-"))
            self.detail_row(info, "Approx. PPS", selected_event.metadata.get("approx_pps", "-"))
            self.detail_row(info, "Wazuh Rule", selected_event.metadata.get("rule_id", "100051"))
            self.detail_row(info, "MITRE", selected_event.metadata.get("mitre", "T1498"))
            self.detail_row(info, "Block Timeout", "{} seconds".format(selected_event.metadata.get("block_timeout", 600)))

        if selected_event.category == "Malware" and selected_event.metadata:
            self.detail_row(info, "Wazuh Rule", selected_event.metadata.get("rule_id", "-"))
            self.detail_row(info, "Wazuh Level", selected_event.metadata.get("wazuh_level", "-"))
            self.detail_row(info, "MITRE", selected_event.metadata.get("mitre", "-"))
            self.detail_row(info, "PID", selected_event.metadata.get("pid", "-"))
            self.detail_row(info, "Executable", selected_event.metadata.get("executable", "-"))
            self.detail_row(info, "Process", selected_event.metadata.get("process_name", "-"))
            self.detail_row(info, "Response", selected_event.metadata.get("response", "-") or "Monitoring only / awaiting correlation")
            self.detail_row(info, "Response Timestamp", selected_event.metadata.get("response_timestamp", "-"))

        if selected_event.category == "OS Attacks" and selected_event.metadata:
            self.detail_row(info, "MITRE", selected_event.metadata.get("mitre", "-"))
            self.detail_row(info, "PID", selected_event.metadata.get("pid", "-"))
            self.detail_row(info, "Process", selected_event.metadata.get("process_name", "-"))
            self.detail_row(info, "Executable", selected_event.metadata.get("executable", "-"))
            self.detail_row(info, "Real UID", selected_event.metadata.get("real_uid", "-"))
            self.detail_row(info, "Effective UID", selected_event.metadata.get("effective_uid", "-"))
            self.detail_row(info, "Cron Path", selected_event.metadata.get("path", "-"))
            self.detail_row(info, "Cron Mode", selected_event.metadata.get("mode", "-"))
            self.detail_row(info, "Writable Risk", selected_event.metadata.get("writable_risk", "-"))
            self.detail_row(info, "Response", json.dumps(selected_event.metadata.get("response", {})))

        # ----------------------------------------------------
        # Raw event
        # ----------------------------------------------------

        tk.Label(
            window,
            text="RAW EVENT",
            bg=self.theme["bg"],
            fg=self.theme["text_muted"],
            font=(
                "DejaVu Sans",
                9,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=20
        )

        raw_frame = tk.Frame(
            window,
            bg=self.theme["panel"]
        )

        raw_frame.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=(6, 20)
        )

        raw_text = tk.Text(
            raw_frame,
            bg=self.theme["panel_light"],
            fg=self.theme["text"],
            insertbackground=self.theme["text"],
            selectbackground=self.theme["selected"],
            selectforeground="#ffffff",
            relief="flat",
            font=(
                "DejaVu Sans Mono",
                9
            ),
            wrap="word"
        )

        raw_text.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        raw_text.insert(
            "1.0",
            json.dumps(
                selected_event.raw,
                indent=4
            )
        )

        raw_text.configure(
            state="disabled"
        )

    # ========================================================
    # Detail row
    # ========================================================

    def detail_row(
        self,
        parent,
        label,
        value
    ):

        row = tk.Frame(
            parent,
            bg=self.theme["bg"]
        )

        row.pack(
            fill="x",
            pady=3
        )

        tk.Label(
            row,
            text=label,
            bg=self.theme["bg"],
            fg=self.theme["text_muted"],
            width=15,
            anchor="w",
            font=(
                "DejaVu Sans",
                9,
                "bold"
            )
        ).pack(
            side="left"
        )

        tk.Label(
            row,
            text=str(value),
            bg=self.theme["bg"],
            fg=self.theme["text_secondary"],
            anchor="w",
            justify="left",
            font=(
                "DejaVu Sans",
                9
            )
        ).pack(
            side="left",
            fill="x",
            expand=True
        )

    # ========================================================
    # Automatic refresh
    # ========================================================

    def auto_refresh(self):

        try:

            self.load_events()

            self.refresh_table()

        except Exception as error:

            self.status_text.set(
                "DASHBOARD ERROR"
            )

            self.status_indicator.configure(
                fg=self.theme["red"]
            )

            print(
                "EDR1 dashboard error:",
                error
            )

        self.root.after(
            REFRESH_MS,
            self.auto_refresh
        )


# ============================================================
# Main
# ============================================================

def main():

    root = tk.Tk()

    EDR1Dashboard(
        root
    )

    root.mainloop()


if __name__ == "__main__":

    main()