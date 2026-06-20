#!/usr/bin/env python3
"""
================================================================================
 VeriForge Red Scanner - Tkinter GUI Application
================================================================================
A user-friendly graphical interface for the VeriForge Red vulnerability scanner.
Features directory browsing, configurable scan depth, product selection,
progress tracking, results display, and report export.

Usage:
    pythonw veriforge-red-gui.pyw    # Run GUI (no console)
    python veriforge-red-gui.pyw     # Run with console output
================================================================================
"""

from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any


# ==============================================================================
# Application Configuration
# ==============================================================================

APP_TITLE = "VeriForge Red Scanner"
APP_VERSION = "1.0.0"
WINDOW_WIDTH = 800
WINDOW_HEIGHT = 700

# Color scheme
COLORS = {
    "bg_dark": "#1e1e2e",
    "bg_medium": "#2d2d44",
    "bg_light": "#3e3e5e",
    "accent_red": "#ff6b6b",
    "accent_orange": "#feca57",
    "accent_green": "#1dd1a1",
    "accent_blue": "#54a0ff",
    "text_primary": "#f1f2f6",
    "text_secondary": "#a4b0be",
    "border": "#575fcf",
    "success": "#1dd1a1",
    "warning": "#feca57",
    "danger": "#ff6b6b",
}

# Severity colors
SEVERITY_COLORS = {
    "critical": "#ff4757",
    "high": "#ff6b81",
    "medium": "#feca57",
    "low": "#1dd1a1",
    "info": "#54a0ff",
}

# ==============================================================================
# Demo Data for UI Preview
# ==============================================================================

DEMO_FINDINGS = [
    {"severity": "critical", "title": "Hardcoded API Key in config.py", "file": "src/config.py", "line": 42, "product": "Red"},
    {"severity": "high", "title": "SQL Injection in login handler", "file": "handlers/auth.py", "line": 128, "product": "Red"},
    {"severity": "high", "title": "Unvalidated file upload", "file": "api/upload.py", "line": 85, "product": "VeriClaw"},
    {"severity": "medium", "title": "Missing Content-Security-Policy header", "file": "middleware/security.py", "line": 15, "product": "Core"},
    {"severity": "medium", "title": "Weak password policy", "file": "models/user.py", "line": 200, "product": "Core"},
    {"severity": "low", "title": "Debug mode enabled in production", "file": "settings.py", "line": 8, "product": "Red"},
    {"severity": "info", "title": "Outdated dependency: requests 2.25.1", "file": "requirements.txt", "line": 3, "product": "VeriClaw"},
    {"severity": "critical", "title": "Remote Code Execution in parser", "file": "utils/parser.py", "line": 67, "product": "Red"},
    {"severity": "high", "title": "Insecure deserialization", "file": "cache/serializer.py", "line": 44, "product": "VeriClaw"},
    {"severity": "medium", "title": "Missing rate limiting", "file": "api/routes.py", "line": 312, "product": "Core"},
    {"severity": "low", "title": "Verbose error messages", "file": "handlers/error.py", "line": 22, "product": "Core"},
    {"severity": "info", "title": "Missing security.txt file", "file": "public/.well-known/", "line": 0, "product": "Red"},
]


# ==============================================================================
# Styled Tkinter Widgets
# ==============================================================================

class StyledFrame(ttk.Frame):
    """A frame with consistent styling."""
    def __init__(self, parent: tk.Widget, **kwargs: Any) -> None:
        super().__init__(parent, **kwargs)


class StyledLabel(ttk.Label):
    """A label with consistent styling."""
    def __init__(self, parent: tk.Widget, text: str = "", bold: bool = False, **kwargs: Any) -> None:
        font_size = kwargs.pop("font_size", 10)
        font_weight = "bold" if bold else "normal"
        super().__init__(
            parent,
            text=text,
            font=("Consolas", font_size, font_weight),
            foreground=COLORS["text_primary"],
            background=COLORS["bg_dark"],
            **kwargs,
        )


class StyledButton(tk.Button):
    """A styled button with hover effects."""
    def __init__(self, parent: tk.Widget, text: str, command: Any = None, variant: str = "primary", **kwargs: Any) -> None:
        self.variant = variant
        self.colors = {
            "primary": (COLORS["accent_red"], COLORS["accent_red"]),
            "secondary": (COLORS["bg_light"], COLORS["border"]),
            "success": (COLORS["accent_green"], COLORS["accent_green"]),
        }
        fg, bg = self.colors.get(variant, self.colors["primary"])

        super().__init__(
            parent,
            text=text,
            command=command,
            font=("Consolas", 10, "bold"),
            bg=bg,
            fg="white" if variant != "secondary" else COLORS["text_primary"],
            activebackground=fg,
            activeforeground="white",
            relief=tk.FLAT,
            cursor="hand2",
            padx=15,
            pady=6,
            **kwargs,
        )
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)

    def _on_enter(self, event: tk.Event | None = None) -> None:
        if self.variant == "primary":
            self.config(bg="#ee5a5a")
        elif self.variant == "secondary":
            self.config(bg=COLORS["border"])
        elif self.variant == "success":
            self.config(bg="#10ac84")

    def _on_leave(self, event: tk.Event | None = None) -> None:
        fg, bg = self.colors.get(self.variant, self.colors["primary"])
        self.config(bg=bg)


# ==============================================================================
# Main Application Window
# ==============================================================================

class VeriForgeScannerApp:
    """Main application class for the VeriForge Red Scanner GUI."""

    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title(f"{APP_TITLE} v{APP_VERSION}")
        self.root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.root.configure(bg=COLORS["bg_dark"])
        self.root.minsize(700, 600)

        # Center window on screen
        self._center_window()

        # State
        self.target_path = tk.StringVar(value="")
        self.scan_depth = tk.IntVar(value=3)
        self.scan_red = tk.BooleanVar(value=True)
        self.scan_vericlaw = tk.BooleanVar(value=True)
        self.scan_core = tk.BooleanVar(value=True)
        self.is_scanning = False
        self.findings: list[dict] = []

        # Build UI
        self._setup_styles()
        self._build_menu()
        self._build_header()
        self._build_target_section()
        self._build_options_section()
        self._build_results_section()
        self._build_status_bar()

        # Bind keyboard shortcuts
        self.root.bind("<Control-o>", lambda e: self._browse_directory())
        self.root.bind("<Control-s>", lambda e: self._start_scan())
        self.root.bind("<Control-e>", lambda e: self._export_results())
        self.root.bind("<F5>", lambda e: self._start_scan())
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------
    # Window Management
    # ------------------------------------------------------------------

    def _center_window(self) -> None:
        """Center the window on the screen."""
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (WINDOW_WIDTH // 2)
        y = (self.root.winfo_screenheight() // 2) - (WINDOW_HEIGHT // 2)
        self.root.geometry(f"+{x}+{y}")

    # ------------------------------------------------------------------
    # Styling
    # ------------------------------------------------------------------

    def _setup_styles(self) -> None:
        """Configure ttk styles for the dark theme."""
        style = ttk.Style()
        style.theme_use("clam")

        # General styles
        style.configure(".", background=COLORS["bg_dark"], foreground=COLORS["text_primary"], font=("Consolas", 10))
        style.configure("TFrame", background=COLORS["bg_dark"])
        style.configure("TLabel", background=COLORS["bg_dark"], foreground=COLORS["text_primary"], font=("Consolas", 10))
        style.configure("TCheckbutton", background=COLORS["bg_dark"], foreground=COLORS["text_primary"], font=("Consolas", 10))
        style.configure("TRadiobutton", background=COLORS["bg_dark"], foreground=COLORS["text_primary"], font=("Consolas", 10))

        # Entry styles
        style.configure("TEntry", fieldbackground=COLORS["bg_medium"], foreground=COLORS["text_primary"])

        # Progress bar
        style.configure("Horizontal.TProgressbar",
                        background=COLORS["accent_red"],
                        troughcolor=COLORS["bg_medium"],
                        borderwidth=0)
        style.configure("Green.Horizontal.TProgressbar",
                        background=COLORS["accent_green"],
                        troughcolor=COLORS["bg_medium"])

        # Treeview
        style.configure("Treeview",
                        background=COLORS["bg_medium"],
                        foreground=COLORS["text_primary"],
                        fieldbackground=COLORS["bg_medium"],
                        font=("Consolas", 9))
        style.configure("Treeview.Heading",
                        background=COLORS["bg_light"],
                        foreground=COLORS["text_primary"],
                        font=("Consolas", 10, "bold"))
        style.map("Treeview", background=[("selected", COLORS["accent_red"])])

        # Notebook
        style.configure("TNotebook", background=COLORS["bg_dark"], tabmargins=[2, 5, 2, 0])
        style.configure("TNotebook.Tab",
                        background=COLORS["bg_medium"],
                        foreground=COLORS["text_secondary"],
                        font=("Consolas", 10, "bold"),
                        padding=[15, 5])
        style.map("TNotebook.Tab",
                  background=[("selected", COLORS["accent_red"])],
                  foreground=[("selected", "white")],
                  expand=[("selected", [1, 1, 1, 0])])

        # Scale/slider
        style.configure("Horizontal.TScale",
                        background=COLORS["bg_dark"],
                        troughcolor=COLORS["bg_medium"],
                        sliderlength=20)

    # ------------------------------------------------------------------
    # Menu Bar
    # ------------------------------------------------------------------

    def _build_menu(self) -> None:
        """Build the application menu bar."""
        menubar = tk.Menu(self.root, bg=COLORS["bg_dark"], fg=COLORS["text_primary"],
                          activebackground=COLORS["accent_red"], activeforeground="white")

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_medium"],
                            fg=COLORS["text_primary"], activebackground=COLORS["accent_red"])
        file_menu.add_command(label="Open Target Directory...", command=self._browse_directory, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Export JSON", command=self._export_json, accelerator="Ctrl+Shift+J")
        file_menu.add_command(label="Export CSV", command=self._export_csv, accelerator="Ctrl+Shift+C")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close, accelerator="Alt+F4")
        menubar.add_cascade(label="File", menu=file_menu)

        # Scan menu
        scan_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_medium"],
                            fg=COLORS["text_primary"], activebackground=COLORS["accent_red"])
        scan_menu.add_command(label="Start Scan", command=self._start_scan, accelerator="F5")
        scan_menu.add_command(label="Stop Scan", command=self._stop_scan, accelerator="Esc")
        scan_menu.add_separator()
        scan_menu.add_command(label="Clear Results", command=self._clear_results)
        menubar.add_cascade(label="Scan", menu=scan_menu)

        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_medium"],
                             fg=COLORS["text_primary"], activebackground=COLORS["accent_red"])
        tools_menu.add_command(label="Dashboard", command=self._open_dashboard)
        tools_menu.add_command(label="Privacy Audit", command=self._open_audit)
        tools_menu.add_separator()
        tools_menu.add_command(label="Preferences", command=self._show_preferences)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_medium"],
                            fg=COLORS["text_primary"], activebackground=COLORS["accent_red"])
        help_menu.add_command(label="Documentation", command=lambda: self._open_url("https://docs.veriforge.dev"))
        help_menu.add_command(label="Report Issue", command=lambda: self._open_url("https://github.com/veriforge/issues"))
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menubar)

    # ------------------------------------------------------------------
    # Header Section
    # ------------------------------------------------------------------

    def _build_header(self) -> None:
        """Build the header section with logo and title."""
        header_frame = tk.Frame(self.root, bg=COLORS["bg_dark"], height=60)
        header_frame.pack(fill=tk.X, padx=15, pady=(15, 5))
        header_frame.pack_propagate(False)

        # Shield icon (using Unicode)
        shield_label = tk.Label(
            header_frame,
            text="🛡",
            font=("Consolas", 28),
            fg=COLORS["accent_red"],
            bg=COLORS["bg_dark"],
        )
        shield_label.pack(side=tk.LEFT, padx=(0, 10))

        # Title and subtitle
        title_frame = tk.Frame(header_frame, bg=COLORS["bg_dark"])
        title_frame.pack(side=tk.LEFT, fill=tk.Y)

        title = tk.Label(
            title_frame,
            text=APP_TITLE,
            font=("Consolas", 16, "bold"),
            fg=COLORS["text_primary"],
            bg=COLORS["bg_dark"],
        )
        title.pack(anchor=tk.W)

        subtitle = tk.Label(
            title_frame,
            text="Vulnerability Scanner  |  VeriForge Security Platform",
            font=("Consolas", 9),
            fg=COLORS["text_secondary"],
            bg=COLORS["bg_dark"],
        )
        subtitle.pack(anchor=tk.W)

        # Version badge
        version_label = tk.Label(
            header_frame,
            text=f"v{APP_VERSION}",
            font=("Consolas", 9),
            fg=COLORS["text_secondary"],
            bg=COLORS["bg_medium"],
            padx=8,
            pady=2,
        )
        version_label.pack(side=tk.RIGHT, pady=(5, 0))

    # ------------------------------------------------------------------
    # Target Section
    # ------------------------------------------------------------------

    def _build_target_section(self) -> None:
        """Build the target directory selection section."""
        frame = tk.Frame(self.root, bg=COLORS["bg_dark"])
        frame.pack(fill=tk.X, padx=15, pady=10)

        label = StyledLabel(frame, text="Target Path:", bold=True)
        label.pack(anchor=tk.W, pady=(0, 5))

        input_frame = tk.Frame(frame, bg=COLORS["bg_dark"])
        input_frame.pack(fill=tk.X)

        self.path_entry = tk.Entry(
            input_frame,
            textvariable=self.target_path,
            font=("Consolas", 10),
            bg=COLORS["bg_medium"],
            fg=COLORS["text_primary"],
            insertbackground=COLORS["text_primary"],
            relief=tk.FLAT,
            highlightthickness=1,
            highlightcolor=COLORS["accent_red"],
            highlightbackground=COLORS["bg_light"],
        )
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8), ipady=5)

        browse_btn = StyledButton(input_frame, text="Browse...", command=self._browse_directory, variant="secondary")
        browse_btn.pack(side=tk.RIGHT)

        # Quick paths
        quick_frame = tk.Frame(frame, bg=COLORS["bg_dark"])
        quick_frame.pack(fill=tk.X, pady=(8, 0))

        StyledLabel(quick_frame, text="Quick:", font_size=9).pack(side=tk.LEFT, padx=(0, 8))

        quick_paths = [
            ("Home", str(Path.home())),
            ("Desktop", str(Path.home() / "Desktop")),
            ("Documents", str(Path.home() / "Documents")),
            ("Downloads", str(Path.home() / "Downloads")),
        ]
        for name, path in quick_paths:
            btn = tk.Label(
                quick_frame,
                text=name,
                font=("Consolas", 9, "underline"),
                fg=COLORS["accent_blue"],
                bg=COLORS["bg_dark"],
                cursor="hand2",
            )
            btn.pack(side=tk.LEFT, padx=5)
            btn.bind("<Button-1>", lambda e, p=path: self.target_path.set(p))

    # ------------------------------------------------------------------
    # Options Section
    # ------------------------------------------------------------------

    def _build_options_section(self) -> None:
        """Build the scan options section."""
        frame = tk.LabelFrame(
            self.root,
            text=" Scan Options ",
            font=("Consolas", 10, "bold"),
            fg=COLORS["accent_red"],
            bg=COLORS["bg_dark"],
            bd=1,
            relief=tk.GROOVE,
        )
        frame.pack(fill=tk.X, padx=15, pady=10)

        # Top row: depth slider + products
        row_frame = tk.Frame(frame, bg=COLORS["bg_dark"])
        row_frame.pack(fill=tk.X, padx=10, pady=8)

        # Scan depth
        depth_frame = tk.Frame(row_frame, bg=COLORS["bg_dark"])
        depth_frame.pack(side=tk.LEFT, padx=(0, 20))

        StyledLabel(depth_frame, text="Scan Depth:", bold=True).pack(anchor=tk.W)

        depth_slider_frame = tk.Frame(depth_frame, bg=COLORS["bg_dark"])
        depth_slider_frame.pack(fill=tk.X)

        self.depth_slider = tk.Scale(
            depth_slider_frame,
            from_=1,
            to=10,
            orient=tk.HORIZONTAL,
            variable=self.scan_depth,
            bg=COLORS["bg_dark"],
            fg=COLORS["text_primary"],
            troughcolor=COLORS["bg_medium"],
            highlightthickness=0,
            sliderlength=18,
            width=12,
            length=150,
            font=("Consolas", 8),
            showvalue=True,
        )
        self.depth_slider.pack(side=tk.LEFT)

        StyledLabel(depth_frame, text="(1=fast  10=deep)", font_size=8).pack(anchor=tk.W)

        # Product checkboxes
        products_frame = tk.Frame(row_frame, bg=COLORS["bg_dark"])
        products_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        StyledLabel(products_frame, text="Products:", bold=True).pack(anchor=tk.W)

        cb_frame = tk.Frame(products_frame, bg=COLORS["bg_dark"])
        cb_frame.pack(fill=tk.X)

        products = [
            ("Red Scanner", self.scan_red, COLORS["accent_red"]),
            ("VeriClaw (Malware)", self.scan_vericlaw, COLORS["accent_orange"]),
            ("Core (Policy)", self.scan_core, COLORS["accent_blue"]),
        ]
        for name, var, color in products:
            cb = tk.Checkbutton(
                cb_frame,
                text=name,
                variable=var,
                font=("Consolas", 9),
                fg=color,
                bg=COLORS["bg_dark"],
                selectcolor=COLORS["bg_medium"],
                activebackground=COLORS["bg_dark"],
                activeforeground=color,
                cursor="hand2",
            )
            cb.pack(side=tk.LEFT, padx=(0, 15))

        # Bottom row: scan button + progress
        action_frame = tk.Frame(frame, bg=COLORS["bg_dark"])
        action_frame.pack(fill=tk.X, padx=10, pady=8)

        self.scan_btn = StyledButton(
            action_frame,
            text="▶  Start Scan",
            command=self._start_scan,
            variant="primary",
            font=("Consolas", 11, "bold"),
            padx=25,
            pady=8,
        )
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 15))

        # Progress bar
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(
            action_frame,
            variable=self.progress_var,
            maximum=100,
            mode="determinate",
            length=300,
            style="Horizontal.TProgressbar",
        )
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        self.progress_label = StyledLabel(action_frame, text="Ready", font_size=9)
        self.progress_label.pack(side=tk.RIGHT)

    # ------------------------------------------------------------------
    # Results Section
    # ------------------------------------------------------------------

    def _build_results_section(self) -> None:
        """Build the results display section with notebook tabs."""
        frame = tk.Frame(self.root, bg=COLORS["bg_dark"])
        frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        # Summary stats bar
        self.stats_frame = tk.Frame(frame, bg=COLORS["bg_medium"], height=40)
        self.stats_frame.pack(fill=tk.X, pady=(0, 5))
        self.stats_frame.pack_propagate(False)

        self.stat_labels: dict[str, tk.Label] = {}
        stats = [
            ("total", "Total", COLORS["text_primary"]),
            ("critical", "Critical", COLORS["danger"]),
            ("high", "High", COLORS["accent_red"]),
            ("medium", "Medium", COLORS["accent_orange"]),
            ("low", "Low", COLORS["accent_green"]),
            ("info", "Info", COLORS["accent_blue"]),
        ]
        for key, label, color in stats:
            tk.Label(self.stats_frame, text=f"{label}:", font=("Consolas", 9),
                     fg=COLORS["text_secondary"], bg=COLORS["bg_medium"]).pack(side=tk.LEFT, padx=(10, 2))
            val_label = tk.Label(self.stats_frame, text="0", font=("Consolas", 10, "bold"),
                                 fg=color, bg=COLORS["bg_medium"])
            val_label.pack(side=tk.LEFT, padx=(0, 15))
            self.stat_labels[key] = val_label

        # Notebook with tabs
        self.notebook = ttk.Notebook(frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab 1: Findings Table
        self.findings_frame = tk.Frame(self.notebook, bg=COLORS["bg_dark"])
        self.notebook.add(self.findings_frame, text=" Findings ")
        self._build_findings_table()

        # Tab 2: Details
        self.details_frame = tk.Frame(self.notebook, bg=COLORS["bg_dark"])
        self.notebook.add(self.details_frame, text=" Details ")
        self._build_details_panel()

        # Tab 3: Console Output
        self.console_frame = tk.Frame(self.notebook, bg=COLORS["bg_dark"])
        self.notebook.add(self.console_frame, text=" Console ")
        self._build_console_panel()

        # Export buttons
        export_frame = tk.Frame(frame, bg=COLORS["bg_dark"])
        export_frame.pack(fill=tk.X, pady=(5, 0))

        self.export_json_btn = StyledButton(export_frame, text="📄 Export JSON", command=self._export_json, variant="secondary")
        self.export_json_btn.pack(side=tk.LEFT, padx=(0, 8))

        self.export_csv_btn = StyledButton(export_frame, text="📊 Export CSV", command=self._export_csv, variant="secondary")
        self.export_csv_btn.pack(side=tk.LEFT, padx=(0, 8))

        StyledLabel(export_frame, text="Ctrl+E to export  |  Right-click row for details", font_size=8).pack(side=tk.RIGHT)

    def _build_findings_table(self) -> None:
        """Build the findings treeview table."""
        columns = ("severity", "title", "file", "line", "product")
        self.tree = ttk.Treeview(
            self.findings_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        col_config = {
            "severity": ("Severity", 80, tk.CENTER),
            "title": ("Finding", 300, tk.W),
            "file": ("File", 200, tk.W),
            "line": ("Line", 50, tk.CENTER),
            "product": ("Product", 100, tk.CENTER),
        }

        for col, (heading, width, anchor) in col_config.items():
            self.tree.heading(col, text=heading, anchor=anchor)
            self.tree.column(col, width=width, anchor=anchor)

        # Scrollbars
        vsb = ttk.Scrollbar(self.findings_frame, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(self.findings_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        self.findings_frame.grid_rowconfigure(0, weight=1)
        self.findings_frame.grid_columnconfigure(0, weight=1)

        # Bind selection event
        self.tree.bind("<<TreeviewSelect>>", self._on_finding_select)
        self.tree.bind("<Double-1>", self._on_finding_double_click)
        self.tree.bind("<Button-3>", self._show_context_menu)

    def _build_details_panel(self) -> None:
        """Build the details panel for showing finding details."""
        self.details_text = scrolledtext.ScrolledText(
            self.details_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg=COLORS["bg_medium"],
            fg=COLORS["text_primary"],
            insertbackground=COLORS["text_primary"],
            padx=10,
            pady=10,
            state=tk.DISABLED,
        )
        self.details_text.pack(fill=tk.BOTH, expand=True)

        # Configure tags
        self.details_text.tag_configure("header", font=("Consolas", 12, "bold"), foreground=COLORS["accent_red"])
        self.details_text.tag_configure("label", font=("Consolas", 10, "bold"), foreground=COLORS["accent_blue"])
        self.details_text.tag_configure("code", font=("Consolas", 9), foreground=COLORS["accent_green"],
                                         background=COLORS["bg_dark"])
        self.details_text.tag_configure("critical", foreground=COLORS["danger"])
        self.details_text.tag_configure("high", foreground=COLORS["accent_red"])
        self.details_text.tag_configure("medium", foreground=COLORS["accent_orange"])
        self.details_text.tag_configure("low", foreground=COLORS["accent_green"])

    def _build_console_panel(self) -> None:
        """Build the console output panel."""
        self.console_text = scrolledtext.ScrolledText(
            self.console_frame,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg=COLORS["bg_dark"],
            fg=COLORS["text_secondary"],
            insertbackground=COLORS["text_primary"],
            padx=8,
            pady=8,
            state=tk.DISABLED,
        )
        self.console_text.pack(fill=tk.BOTH, expand=True)

        self.console_text.tag_configure("info", foreground=COLORS["accent_blue"])
        self.console_text.tag_configure("success", foreground=COLORS["accent_green"])
        self.console_text.tag_configure("warning", foreground=COLORS["accent_orange"])
        self.console_text.tag_configure("error", foreground=COLORS["danger"])
        self.console_text.tag_configure("timestamp", foreground=COLORS["text_secondary"], font=("Consolas", 8))

    def _build_status_bar(self) -> None:
        """Build the status bar at the bottom."""
        self.status_bar = tk.Frame(self.root, bg=COLORS["bg_medium"], height=25)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_bar.pack_propagate(False)

        self.status_label = tk.Label(
            self.status_bar,
            text="Ready  |  Select a target directory to begin",
            font=("Consolas", 9),
            fg=COLORS["text_secondary"],
            bg=COLORS["bg_medium"],
        )
        self.status_label.pack(side=tk.LEFT, padx=10)

        self.scan_time_label = tk.Label(
            self.status_bar,
            text="",
            font=("Consolas", 9),
            fg=COLORS["text_secondary"],
            bg=COLORS["bg_medium"],
        )
        self.scan_time_label.pack(side=tk.RIGHT, padx=10)

    # ------------------------------------------------------------------
    # Event Handlers
    # ------------------------------------------------------------------

    def _browse_directory(self) -> None:
        """Open a directory picker dialog."""
        directory = filedialog.askdirectory(
            title="Select Target Directory for Scan",
            mustexist=True,
        )
        if directory:
            self.target_path.set(directory)
            self._log_console(f"Target set: {directory}", "info")

    def _start_scan(self) -> None:
        """Start the scan process."""
        target = self.target_path.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Please select a target directory to scan.")
            return

        if not os.path.isdir(target):
            messagebox.showerror("Invalid Path", f"Directory not found:\n{target}")
            return

        if self.is_scanning:
            return

        self.is_scanning = True
        self.scan_btn.config(text="⏹  Stop Scan", command=self._stop_scan)
        self.progress_label.config(text="Scanning...")
        self.status_label.config(text=f"Scanning: {target}")
        self._clear_results()

        # Run scan in background thread
        thread = threading.Thread(target=self._run_scan_thread, args=(target,), daemon=True)
        thread.start()

    def _stop_scan(self) -> None:
        """Stop the current scan."""
        self.is_scanning = False
        self.scan_btn.config(text="▶  Start Scan", command=self._start_scan)
        self.progress_label.config(text="Stopped")
        self.status_label.config(text="Scan stopped by user")
        self._log_console("Scan stopped by user", "warning")

    def _run_scan_thread(self, target: str) -> None:
        """Run the scan in a background thread."""
        start_time = time.time()

        try:
            self._simulate_scan(target)
        except Exception as e:
            self.root.after(0, lambda: self._scan_error(str(e)))
            return

        elapsed = time.time() - start_time
        self.root.after(0, lambda: self._scan_complete(elapsed))

    def _simulate_scan(self, target: str) -> None:
        """Simulate a scan with progress updates (demo mode)."""
        self._log_console(f"Starting scan of: {target}", "info")
        self._log_console(f"Depth: {self.scan_depth.get()}, Products: Red={'on' if self.scan_red.get() else 'off'}, "
                          f"VeriClaw={'on' if self.scan_vericlaw.get() else 'off'}, "
                          f"Core={'on' if self.scan_core.get() else 'off'}", "info")

        steps = [
            ("Initializing scanners...", 10),
            ("Enumerating files...", 25),
            ("Analyzing code patterns...", 45),
            ("Running Red vulnerability checks...", 60),
            ("Running VeriClaw malware detection...", 75),
            ("Running Core policy checks...", 85),
            ("Aggregating results...", 95),
            ("Finalizing report...", 100),
        ]

        for message, progress in steps:
            if not self.is_scanning:
                return

            self.root.after(0, lambda m=message, p=progress: self._update_progress(p, m))
            self._log_console(message, "info")
            time.sleep(0.4 + (self.scan_depth.get() * 0.1))

        # Add demo findings (in real implementation, this comes from the SDK)
        self.findings = DEMO_FINDINGS.copy()
        self.root.after(0, self._populate_findings)

    def _update_progress(self, value: int, message: str) -> None:
        """Update the progress bar."""
        self.progress_var.set(value)
        self.progress_label.config(text=message)

    def _populate_findings(self) -> None:
        """Populate the findings table with results."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        counts = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for finding in self.findings:
            sev = finding["severity"]
            color = SEVERITY_COLORS.get(sev, COLORS["text_primary"])

            item = self.tree.insert(
                "",
                tk.END,
                values=(
                    sev.upper(),
                    finding["title"],
                    finding["file"],
                    finding["line"],
                    finding["product"],
                ),
                tags=(sev,),
            )

            # Configure tag color for this row
            self.tree.tag_configure(sev, foreground=color)
            counts["total"] += 1
            counts[sev] = counts.get(sev, 0) + 1

        # Update stats
        for key, label in self.stat_labels.items():
            label.config(text=str(counts.get(key, 0)))

    def _clear_results(self) -> None:
        """Clear all results from the UI."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.findings = []
        self.progress_var.set(0)
        self.progress_label.config(text="Ready")

        for key, label in self.stat_labels.items():
            label.config(text="0")

        self._clear_details()
        self._clear_console()

    def _clear_details(self) -> None:
        """Clear the details panel."""
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete("1.0", tk.END)
        self.details_text.config(state=tk.DISABLED)

    def _clear_console(self) -> None:
        """Clear the console panel."""
        self.console_text.config(state=tk.NORMAL)
        self.console_text.delete("1.0", tk.END)
        self.console_text.config(state=tk.DISABLED)

    def _scan_complete(self, elapsed: float) -> None:
        """Handle scan completion."""
        self.is_scanning = False
        self.scan_btn.config(text="▶  Start Scan", command=self._start_scan)
        self.progress_var.set(100)
        self.progress_label.config(text="Complete")
        self.status_label.config(text=f"Scan complete  |  {len(self.findings)} findings")
        self.scan_time_label.config(text=f"Scan time: {elapsed:.1f}s")
        self._log_console(f"Scan complete: {len(self.findings)} findings in {elapsed:.1f}s", "success")

    def _scan_error(self, error: str) -> None:
        """Handle scan error."""
        self.is_scanning = False
        self.scan_btn.config(text="▶  Start Scan", command=self._start_scan)
        self.progress_label.config(text="Error")
        self.status_label.config(text=f"Scan failed: {error}")
        self._log_console(f"Error: {error}", "error")
        messagebox.showerror("Scan Error", f"Scan failed:\n{error}")

    def _on_finding_select(self, event: tk.Event | None = None) -> None:
        """Handle finding selection in the table."""
        selection = self.tree.selection()
        if not selection:
            return

        item = selection[0]
        values = self.tree.item(item, "values")
        if not values:
            return

        severity, title, file_path, line, product = values

        # Find the full finding
        finding = None
        for f in self.findings:
            if f["title"] == title:
                finding = f
                break

        self._show_finding_details(finding or {"severity": severity, "title": title, "file": file_path, "line": line, "product": product})

    def _on_finding_double_click(self, event: tk.Event | None = None) -> None:
        """Handle double-click on a finding."""
        self._on_finding_select()
        self.notebook.select(self.details_frame)

    def _show_finding_details(self, finding: dict) -> None:
        """Show detailed information about a finding."""
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete("1.0", tk.END)

        self.details_text.insert(tk.END, finding["title"] + "\n", "header")
        self.details_text.insert(tk.END, "=" * 60 + "\n\n")

        sev = finding.get("severity", "info")
        sev_tag = sev if sev in ("critical", "high", "medium", "low") else "info"

        self.details_text.insert(tk.END, "Severity:  ", "label")
        self.details_text.insert(tk.END, f"{sev.upper()}\n\n", sev_tag)

        self.details_text.insert(tk.END, "File:      ", "label")
        self.details_text.insert(tk.END, f"{finding.get('file', 'N/A')}\n")

        self.details_text.insert(tk.END, "Line:      ", "label")
        self.details_text.insert(tk.END, f"{finding.get('line', 'N/A')}\n")

        self.details_text.insert(tk.END, "Product:   ", "label")
        self.details_text.insert(tk.END, f"{finding.get('product', 'N/A')}\n\n")

        self.details_text.insert(tk.END, "Description:\n", "label")
        self.details_text.insert(tk.END, f"  This finding was detected by the {finding.get('product', 'unknown')} scanner. "
                                          f"Review the affected file and apply appropriate remediation.\n\n")

        self.details_text.insert(tk.END, "Remediation:\n", "label")
        self.details_text.insert(tk.END, "  1. Review the affected code location\n")
        self.details_text.insert(tk.END, "  2. Apply the recommended fix\n")
        self.details_text.insert(tk.END, "  3. Re-run the scanner to verify\n")

        self.details_text.config(state=tk.DISABLED)

    def _show_context_menu(self, event: tk.Event) -> None:
        """Show context menu on right-click."""
        region = self.tree.identify_region(event.x, event.y)
        if region != "cell":
            return

        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self._on_finding_select()

            menu = tk.Menu(self.root, tearoff=0, bg=COLORS["bg_medium"],
                           fg=COLORS["text_primary"], activebackground=COLORS["accent_red"])
            menu.add_command(label="View Details", command=lambda: self.notebook.select(self.details_frame))
            menu.add_separator()
            menu.add_command(label="Copy File Path", command=lambda: self.root.clipboard_append(self.tree.item(item, "values")[2]))
            menu.add_command(label="Export This Finding", command=lambda: self._export_single_finding(item))
            menu.post(event.x_root, event.y_root)

    def _log_console(self, message: str, level: str = "info") -> None:
        """Add a log message to the console panel."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console_text.config(state=tk.NORMAL)
        self.console_text.insert(tk.END, f"[{timestamp}] ", "timestamp")
        self.console_text.insert(tk.END, f"{message}\n", level)
        self.console_text.see(tk.END)
        self.console_text.config(state=tk.DISABLED)

    # ------------------------------------------------------------------
    # Export Functions
    # ------------------------------------------------------------------

    def _export_results(self) -> None:
        """Show export dialog."""
        if not self.findings:
            messagebox.showinfo("No Data", "No findings to export. Run a scan first.")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Export Results")
        dialog.geometry("300x150")
        dialog.configure(bg=COLORS["bg_dark"])
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="Export Format:", font=("Consolas", 11, "bold"),
                 fg=COLORS["text_primary"], bg=COLORS["bg_dark"]).pack(pady=10)

        btn_frame = tk.Frame(dialog, bg=COLORS["bg_dark"])
        btn_frame.pack(pady=10)

        StyledButton(btn_frame, text="JSON", command=lambda: [self._export_json(), dialog.destroy()]).pack(side=tk.LEFT, padx=5)
        StyledButton(btn_frame, text="CSV", command=lambda: [self._export_csv(), dialog.destroy()]).pack(side=tk.LEFT, padx=5)
        StyledButton(btn_frame, text="Cancel", command=dialog.destroy, variant="secondary").pack(side=tk.LEFT, padx=5)

    def _export_json(self) -> None:
        """Export findings as JSON."""
        if not self.findings:
            messagebox.showinfo("No Data", "No findings to export. Run a scan first.")
            return

        filepath = filedialog.asksaveasfilename(
            title="Export as JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"veriforge-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json",
        )
        if not filepath:
            return

        try:
            export_data = {
                "scan_info": {
                    "tool": "VeriForge Red Scanner",
                    "version": APP_VERSION,
                    "timestamp": datetime.now().isoformat(),
                    "target": self.target_path.get(),
                    "depth": self.scan_depth.get(),
                },
                "findings": self.findings,
                "summary": self._get_summary(),
            }

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)

            self._log_console(f"Exported JSON: {filepath}", "success")
            self.status_label.config(text=f"Exported: {filepath}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export JSON:\n{e}")

    def _export_csv(self) -> None:
        """Export findings as CSV."""
        if not self.findings:
            messagebox.showinfo("No Data", "No findings to export. Run a scan first.")
            return

        filepath = filedialog.asksaveasfilename(
            title="Export as CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"veriforge-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv",
        )
        if not filepath:
            return

        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["severity", "title", "file", "line", "product"])
                writer.writeheader()
                writer.writerows(self.findings)

            self._log_console(f"Exported CSV: {filepath}", "success")
            self.status_label.config(text=f"Exported: {filepath}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export CSV:\n{e}")

    def _export_single_finding(self, item_id: str) -> None:
        """Export a single finding to clipboard or file."""
        values = self.tree.item(item_id, "values")
        if values:
            text = f"Severity: {values[0]}\nTitle: {values[1]}\nFile: {values[2]}\nLine: {values[3]}\nProduct: {values[4]}"
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self._log_console("Finding copied to clipboard", "success")

    def _get_summary(self) -> dict:
        """Get summary statistics of findings."""
        summary = {"total": len(self.findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.get("severity", "info")
            summary[sev] = summary.get(sev, 0) + 1
        return summary

    # ------------------------------------------------------------------
    # Tools Menu Actions
    # ------------------------------------------------------------------

    def _open_dashboard(self) -> None:
        """Open the VeriForge Dashboard."""
        try:
            subprocess.Popen([sys.executable, "-m", "veriforge_sdk", "dashboard"],
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            self._log_console("Dashboard launched", "success")
        except Exception as e:
            self._log_console(f"Failed to open dashboard: {e}", "error")

    def _open_audit(self) -> None:
        """Open the Privacy Audit tool."""
        try:
            subprocess.Popen([sys.executable, "-m", "veriforge_sdk", "audit"],
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            self._log_console("Privacy audit launched", "success")
        except Exception as e:
            self._log_console(f"Failed to open audit: {e}", "error")

    def _show_preferences(self) -> None:
        """Show preferences dialog."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Preferences")
        dialog.geometry("400x200")
        dialog.configure(bg=COLORS["bg_dark"])
        dialog.transient(self.root)

        tk.Label(dialog, text="Preferences", font=("Consolas", 14, "bold"),
                 fg=COLORS["accent_red"], bg=COLORS["bg_dark"]).pack(pady=10)
        tk.Label(dialog, text="Preferences will be available in a future update.",
                 font=("Consolas", 10), fg=COLORS["text_secondary"],
                 bg=COLORS["bg_dark"]).pack(pady=20)
        StyledButton(dialog, text="Close", command=dialog.destroy, variant="secondary").pack(pady=10)

    def _show_about(self) -> None:
        """Show the about dialog."""
        about_text = (
            f"{APP_TITLE}\n"
            f"Version {APP_VERSION}\n"
            f"\n"
            f"Part of the VeriForge Security Platform\n"
            f"\n"
            f"A comprehensive security scanning solution with\n"
            f"7 integrated products for vulnerability detection,\n"
            f"malware analysis, and compliance auditing.\n"
            f"\n"
            f"https://veriforge.dev\n"
            f"https://docs.veriforge.dev"
        )
        messagebox.showinfo(f"About {APP_TITLE}", about_text)

    def _open_url(self, url: str) -> None:
        """Open a URL in the default browser."""
        import webbrowser
        webbrowser.open(url)

    # ------------------------------------------------------------------
    # Window Management
    # ------------------------------------------------------------------

    def _on_close(self) -> None:
        """Handle window close event."""
        if self.is_scanning:
            if not messagebox.askyesno("Scan in Progress",
                                        "A scan is currently running. Are you sure you want to exit?"):
                return
        self.root.destroy()

    def run(self) -> None:
        """Start the application main loop."""
        self.root.mainloop()


# ==============================================================================
# Entry Point
# ==============================================================================

def main() -> int:
    """Application entry point."""
    try:
        app = VeriForgeScannerApp()
        app.run()
        return 0
    except Exception as e:
        messagebox.showerror("Fatal Error", f"Application error:\n{e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
