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
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f"
        ]

        for fmt in formats:

            try:

                return datetime.strptime(
                    value,
                    fmt
                )

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
            "EDR1 — Endpoint Detection & Response"
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
            text="Endpoint Detection & Response",
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
            text="NETWORK & SECURITY EVENTS",
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
        actions = {}

        if not os.path.exists(RESPONSE_LOG):
            return actions

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

        raw_events = self.read_jsonl(
            NETWORK_LOG
        )

        response_actions = self.load_response_actions()
        events = []

        for item in raw_events:

            timestamp = item.get(
                "timestamp",
                ""
            )

            attack = item.get(
                "artifact_type",
                "Network Attack"
            )

            source_ip = item.get(
                "srcip",
                "-"
            )

            destination_ip = item.get(
                "dstip",
                "-"
            )

            severity = item.get(
                "severity",
                "HIGH"
            )

            # The current Wazuh custom rule is level 10 for
            # artifact_type events, so network detections are
            # represented as HIGH in the dashboard unless a future
            # evidence record supplies another severity.
            action_info = response_actions.get(source_ip, {})
            action = action_info.get(
                "action",
                item.get("action", "DETECTED")
            )

            alert_msg = item.get(
                "alert_msg",
                ""
            )

            packet_count = item.get(
                "packet_count",
                ""
            )

            approx_pps = item.get(
                "approx_pps",
                ""
            )

            likely_source_tool = item.get(
                "likely_source_tool",
                "Unknown"
            )

            interface = item.get(
                "interface",
                "-"
            )

            correlated = item.get(
                "correlated_logs",
                {}
            )

            kernel_count = len(
                correlated.get("kernel_syslog", [])
            )

            apache_access_count = len(
                correlated.get("apache_access", [])
            )

            apache_error_count = len(
                correlated.get("apache_error", [])
            )

            details_parts = []

            if alert_msg:
                details_parts.append(alert_msg)

            details_parts.append(
                "Tool: {}".format(likely_source_tool)
            )

            details_parts.append(
                "Dst: {}".format(destination_ip)
            )

            details_parts.append(
                "Iface: {}".format(interface)
            )

            if packet_count != "":
                details_parts.append(
                    "Packets: {}".format(packet_count)
                )

            if approx_pps != "":
                details_parts.append(
                    "PPS: {}".format(approx_pps)
                )

            details_parts.append(
                "MITRE: T1498"
            )

            if kernel_count:
                details_parts.append(
                    "Kernel logs: {}".format(kernel_count)
                )

            if apache_access_count:
                details_parts.append(
                    "Apache access: {}".format(apache_access_count)
                )

            if apache_error_count:
                details_parts.append(
                    "Apache error: {}".format(apache_error_count)
                )

            events.append(
                EDREvent(
                    timestamp,
                    "Network",
                    attack,
                    source_ip,
                    severity,
                    action,
                    " | ".join(details_parts),
                    item,
                    {
                        "destination_ip": destination_ip,
                        "likely_source_tool": likely_source_tool,
                        "interface": interface,
                        "packet_count": packet_count,
                        "approx_pps": approx_pps,
                        "mitre": "T1498",
                        "correlated_kernel_logs": kernel_count,
                        "correlated_apache_access": apache_access_count,
                        "correlated_apache_error": apache_error_count
                    }
                )
            )

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

        self.events = (
            injection +
            network
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