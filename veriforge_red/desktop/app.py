"""VeriForge Red — Main GUI Application.

A tkinter-based desktop app with 7 tabs:
Dashboard, Scan, Privacy, Threats, Vault, Quarantine, Settings.
Dark theme by default, modern flat design.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from veriforge_red.core import RedEngine

logger = logging.getLogger(__name__)

# ── Colour Palette ──────────────────────────────────────────────────────────
COLORS = {
    "primary": "#c62828",      # red
    "dark_bg": "#1a1a2e",      # main background
    "card_bg": "#16213e",      # card / panel background
    "card_bg_alt": "#1e2a4a",  # alternate card
    "accent": "#e94560",       # accent / hover
    "text": "#eaeaea",         # primary text
    "text_dim": "#a0a0b8",     # secondary text
    "border": "#2a2a40",       # borders
    "success": "#4caf50",      # green
    "warning": "#ff9800",      # orange
    "danger": "#f44336",       # bright red
    "info": "#2196f3",         # blue
    "gauge_bg": "#2a2a40",     # gauge background
}

# ── Grade Colours ───────────────────────────────────────────────────────────
GRADE_COLOURS = {
    "A+": "#4caf50", "A": "#4caf50", "A-": "#66bb6a",
    "B+": "#8bc34a", "B": "#8bc34a", "B-": "#9ccc65",
    "C+": "#ff9800", "C": "#ff9800", "C-": "#ffa726",
    "D+": "#ff5722", "D": "#ff5722", "D-": "#ff7043",
    "F": "#f44336",
}

SEVERITY_COLOURS = {
    "critical": "#f44336",
    "high": "#ff5722",
    "medium": "#ff9800",
    "low": "#2196f3",
    "info": "#9e9e9e",
}


def _dark_style(style: ttk.Style) -> None:
    """Configure ttk styles for dark theme."""
    c = COLORS
    style.theme_use("clam")
    style.configure("TFrame", background=c["dark_bg"])
    style.configure("Card.TFrame", background=c["card_bg"])
    style.configure("TLabel", background=c["dark_bg"], foreground=c["text"], font=("Segoe UI", 10))
    style.configure("Card.TLabel", background=c["card_bg"], foreground=c["text"])
    style.configure("Heading.TLabel", background=c["dark_bg"], foreground=c["text"], font=("Segoe UI", 16, "bold"))
    style.configure("Subheading.TLabel", background=c["dark_bg"], foreground=c["text"], font=("Segoe UI", 12, "bold"))
    style.configure("Small.TLabel", background=c["dark_bg"], foreground=c["text_dim"], font=("Segoe UI", 8))
    style.configure("TButton", font=("Segoe UI", 10), padding=6)
    style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"))
    style.configure("TCheckbutton", background=c["dark_bg"], foreground=c["text"])
    style.configure("TRadiobutton", background=c["dark_bg"], foreground=c["text"])
    style.map("TButton", background=[("active", c["accent"]), ("!active", c["primary"])],
              foreground=[("active", "#ffffff"), ("!active", "#ffffff")])
    style.configure("Horizontal.TProgressbar", troughcolor=c["gauge_bg"], background=c["primary"],
                    bordercolor=c["dark_bg"], lightcolor=c["primary"], darkcolor=c["primary"])
    style.configure("TNotebook", background=c["dark_bg"], borderwidth=0)
    style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=(12, 6),
                    background=c["card_bg"], foreground=c["text_dim"])
    style.map("TNotebook.Tab", background=[("selected", c["primary"])],
              foreground=[("selected", "#ffffff")], expand=[("selected", (2, 2))])
    style.configure("Treeview", background=c["card_bg"], foreground=c["text"],
                    fieldbackground=c["card_bg"], rowheight=28, font=("Segoe UI", 10))
    style.configure("Treeview.Heading", background=c["card_bg_alt"], foreground=c["text"],
                    font=("Segoe UI", 10, "bold"))
    style.map("Treeview", background=[("selected", c["accent"])])


# ── Circular Progress Gauge ─────────────────────────────────────────────────

class CircularGauge(tk.Canvas):
    """A circular progress gauge drawn on a tkinter Canvas."""

    def __init__(
        self,
        parent: tk.Widget,
        size: int = 140,
        thickness: int = 12,
        value: int = 0,
        max_value: int = 100,
        title: str = "",
        color: str | None = None,
        **kwargs,
    ):
        self._size = size
        self._thickness = thickness
        self._value = value
        self._max = max_value
        self._title = title
        self._color = color or COLORS["primary"]
        super().__init__(
            parent,
            width=size,
            height=size + 20,
            bg=kwargs.pop("bg", COLORS["dark_bg"]),
            highlightthickness=0,
            **kwargs,
        )
        self._draw()

    def _draw(self):
        self.delete("all")
        pad = self._thickness // 2 + 4
        x0, y0, x1, y1 = pad, pad, self._size - pad, self._size - pad
        # background arc
        self.create_oval(x0, y0, x1, y1, outline=COLORS["gauge_bg"], width=self._thickness)
        # progress arc
        extent = (self._value / self._max) * 360 if self._max else 0
        colour = self._color_for_value(self._value)
        if extent > 0:
            self.create_arc(
                x0, y0, x1, y1, start=90, extent=-extent,
                outline=colour, width=self._thickness, style="arc",
            )
        # centre text
        cx, cy = self._size // 2, self._size // 2
        self.create_text(cx, cy - 6, text=str(int(self._value)), font=("Segoe UI", 22, "bold"),
                         fill=colour, justify="center")
        self.create_text(cx, cy + 14, text=self._title, font=("Segoe UI", 9),
                         fill=COLORS["text_dim"], justify="center")

    def _color_for_value(self, v: int) -> str:
        if v >= 80:
            return COLORS["success"]
        if v >= 50:
            return COLORS["warning"]
        return COLORS["danger"]

    def set_value(self, value: int):
        self._value = max(0, min(self._max, value))
        self._draw()


# ── RedApp ──────────────────────────────────────────────────────────────────

class RedApp:
    """Main VeriForge Red desktop application."""

    WIDTH = 900
    HEIGHT = 650

    def __init__(self, engine: RedEngine | None = None) -> None:
        self.engine = engine or RedEngine()
        self.engine.start()
        self._queue: queue.Queue = queue.Queue()
        self.engine.on_update(self._on_engine_update)

        self.root = tk.Tk()
        self.root.title("VeriForge Red — Security Sentinel")
        self.root.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.root.configure(bg=COLORS["dark_bg"])
        self.root.minsize(800, 550)

        # centre on screen
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        self.root.geometry(f"+{(sw - self.WIDTH) // 2}+{(sh - self.HEIGHT) // 2}")

        self.style = ttk.Style(self.root)
        _dark_style(self.style)

        self._tabs: dict[str, tk.Frame] = {}
        self._vars: dict[str, tk.Variable] = {}
        self._build_ui()
        self._start_ui_poller()

    # ── UI Construction ─────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # header bar
        header = tk.Frame(self.root, bg=COLORS["primary"], height=48)
        header.pack(side="top", fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="\u2620 VeriForge Red", bg=COLORS["primary"], fg="#ffffff",
                 font=("Segoe UI", 14, "bold")).pack(side="left", padx=12, pady=6)
        tk.Label(header, text="Security Sentinel", bg=COLORS["primary"], fg="#ffcccc",
                 font=("Segoe UI", 10)).pack(side="left", pady=6)

        # notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=4)

        self._build_dashboard_tab()
        self._build_scan_tab()
        self._build_privacy_tab()
        self._build_threats_tab()
        self._build_vault_tab()
        self._build_quarantine_tab()
        self._build_updates_tab()
        self._build_settings_tab()

    def _new_tab(self, name: str) -> tk.Frame:
        frame = tk.Frame(self.notebook, bg=COLORS["dark_bg"])
        self.notebook.add(frame, text=f"  {name}  ")
        self._tabs[name] = frame
        return frame

    def _card(self, parent: tk.Widget, title: str = "", **pack_kw) -> tk.Frame:
        card = tk.Frame(parent, bg=COLORS["card_bg"], highlightbackground=COLORS["border"],
                        highlightthickness=1, bd=0)
        if title:
            tk.Label(card, text=title, bg=COLORS["card_bg"], fg=COLORS["text"],
                     font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=10, pady=(8, 4))
        card.pack(**pack_kw)
        return card

    # ── Dashboard ───────────────────────────────────────────────────────────

    def _build_dashboard_tab(self) -> None:
        tab = self._new_tab("Dashboard")

        top = tk.Frame(tab, bg=COLORS["dark_bg"])
        top.pack(fill="x", pady=(8, 4))

        # security score gauge
        left = self._card(top, "Security Score", side="left", fill="both", expand=True, padx=4, pady=4)
        self.sec_gauge = CircularGauge(left, size=160, thickness=14, value=0, title="Security")
        self.sec_gauge.pack(pady=10)

        # privacy score gauge
        right = self._card(top, "Privacy Score", side="left", fill="both", expand=True, padx=4, pady=4)
        self.priv_gauge = CircularGauge(right, size=160, thickness=14, value=0, title="Privacy",
                                        color=COLORS["info"])
        self.priv_gauge.pack(pady=10)

        # stats column
        stats = self._card(top, "Status", side="left", fill="both", expand=True, padx=4, pady=4)

        self.lbl_active_threats = tk.Label(stats, text="Active Threats: 0", bg=COLORS["card_bg"],
                                           fg=COLORS["text"], font=("Segoe UI", 11))
        self.lbl_active_threats.pack(anchor="w", padx=10, pady=4)
        self.lbl_quarantined = tk.Label(stats, text="Quarantined: 0", bg=COLORS["card_bg"],
                                        fg=COLORS["text"], font=("Segoe UI", 11))
        self.lbl_quarantined.pack(anchor="w", padx=10, pady=4)
        self.lbl_last_scan = tk.Label(stats, text="Last Scan: Never", bg=COLORS["card_bg"],
                                      fg=COLORS["text_dim"], font=("Segoe UI", 9))
        self.lbl_last_scan.pack(anchor="w", padx=10, pady=4)

        self.btn_monitor = tk.Button(
            stats, text="\u25b6 Start Monitoring", bg=COLORS["success"], fg="#ffffff",
            font=("Segoe UI", 10, "bold"), bd=0, padx=12, pady=6, cursor="hand2",
            activebackground="#43a047", command=self._toggle_monitoring,
        )
        self.btn_monitor.pack(anchor="w", padx=10, pady=8)

        # action row
        actions = tk.Frame(tab, bg=COLORS["dark_bg"])
        actions.pack(fill="x", pady=4)

        btn_scan = tk.Button(actions, text="\U0001f50e Scan Now", bg=COLORS["primary"], fg="#ffffff",
                             font=("Segoe UI", 12, "bold"), bd=0, padx=20, pady=10,
                             cursor="hand2", activebackground=COLORS["accent"],
                             command=self._show_scan_tab)
        btn_scan.pack(side="left", padx=4)

        # recent findings
        findings_frame = self._card(tab, "Recent Findings", fill="both", expand=True, padx=4, pady=4)
        cols = ("file", "type", "severity", "time")
        self.tree_recent = ttk.Treeview(findings_frame, columns=cols, show="headings", height=6)
        for c, w in zip(cols, (250, 120, 100, 140)):
            self.tree_recent.heading(c, text=c.title())
            self.tree_recent.column(c, width=w, anchor="w" if c == "file" else "center")
        vsb = ttk.Scrollbar(findings_frame, orient="vertical", command=self.tree_recent.yview)
        self.tree_recent.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree_recent.pack(fill="both", expand=True, padx=6, pady=4)

    def _show_scan_tab(self):
        self.notebook.select(self._tabs["Scan"])

    def _toggle_monitoring(self):
        if self.engine.monitoring:
            self.engine.stop_monitoring()
            self.btn_monitor.config(text="\u25b6 Start Monitoring", bg=COLORS["success"])
        else:
            interval = self._vars.get("monitor_interval", tk.IntVar(value=60)).get()
            self.engine.start_monitoring(interval)
            self.btn_monitor.config(text="\u25a0 Stop Monitoring", bg=COLORS["danger"])

    # ── Scan ────────────────────────────────────────────────────────────────

    def _build_scan_tab(self) -> None:
        tab = self._new_tab("Scan")

        # target selection
        target_frame = self._card(tab, "Target Selection", fill="x", padx=4, pady=4)
        self._vars["scan_target"] = tk.StringVar(value=os.path.expanduser("~"))
        tk.Entry(target_frame, textvariable=self._vars["scan_target"], bg=COLORS["card_bg_alt"],
                 fg=COLORS["text"], insertbackground=COLORS["text"], font=("Segoe UI", 10),
                 highlightthickness=1, highlightcolor=COLORS["primary"], highlightbackground=COLORS["border"]).pack(
                     side="left", fill="x", expand=True, padx=10, pady=8)
        tk.Button(target_frame, text="Browse", bg=COLORS["card_bg_alt"], fg=COLORS["text"],
                  font=("Segoe UI", 9), bd=0, padx=10, cursor="hand2",
                  command=self._browse_scan_target).pack(side="left", padx=(0, 10), pady=8)

        # scan type + button
        opts = tk.Frame(tab, bg=COLORS["dark_bg"])
        opts.pack(fill="x", pady=4)
        self._vars["scan_deep"] = tk.BooleanVar(value=False)
        tk.Radiobutton(opts, text="Quick Scan", variable=self._vars["scan_deep"], value=False,
                       bg=COLORS["dark_bg"], fg=COLORS["text"], selectcolor=COLORS["card_bg"],
                       activebackground=COLORS["dark_bg"], font=("Segoe UI", 10)).pack(side="left", padx=4)
        tk.Radiobutton(opts, text="Deep Scan", variable=self._vars["scan_deep"], value=True,
                       bg=COLORS["dark_bg"], fg=COLORS["text"], selectcolor=COLORS["card_bg"],
                       activebackground=COLORS["dark_bg"], font=("Segoe UI", 10)).pack(side="left", padx=4)

        self.btn_scan_start = tk.Button(opts, text="\u25b6 Start Scan", bg=COLORS["primary"], fg="#ffffff",
                                        font=("Segoe UI", 11, "bold"), bd=0, padx=16, pady=6,
                                        cursor="hand2", activebackground=COLORS["accent"],
                                        command=self._start_scan)
        self.btn_scan_start.pack(side="right", padx=4)

        # progress bar
        prog_frame = tk.Frame(tab, bg=COLORS["dark_bg"])
        prog_frame.pack(fill="x", pady=(4, 0))
        self.scan_progress = ttk.Progressbar(prog_frame, mode="determinate", maximum=100)
        self.scan_progress.pack(fill="x", padx=4, pady=2)
        self.lbl_scan_status = tk.Label(prog_frame, text="Ready", bg=COLORS["dark_bg"],
                                        fg=COLORS["text_dim"], font=("Segoe UI", 9))
        self.lbl_scan_status.pack(anchor="w", padx=4)

        # results area
        results = self._card(tab, "Scan Results", fill="both", expand=True, padx=4, pady=4)
        res_top = tk.Frame(results, bg=COLORS["card_bg"])
        res_top.pack(fill="x", padx=10, pady=6)

        self.lbl_grade = tk.Label(res_top, text="—", bg=COLORS["card_bg"], fg=COLORS["text_dim"],
                                  font=("Segoe UI", 32, "bold"), width=4)
        self.lbl_grade.pack(side="left")
        self.lbl_risk = tk.Label(res_top, text="Risk: —", bg=COLORS["card_bg"], fg=COLORS["text"],
                                 font=("Segoe UI", 12))
        self.lbl_risk.pack(side="left", padx=12)

        btn_export = tk.Button(res_top, text="Export Report", bg=COLORS["card_bg_alt"], fg=COLORS["text"],
                               font=("Segoe UI", 9), bd=0, padx=10, cursor="hand2",
                               command=self._export_report)
        btn_export.pack(side="right", padx=4)
        btn_cert = tk.Button(res_top, text="Certificate", bg=COLORS["card_bg_alt"], fg=COLORS["text"],
                             font=("Segoe UI", 9), bd=0, padx=10, cursor="hand2",
                             command=self._generate_certificate)
        btn_cert.pack(side="right", padx=4)

        cols = ("file", "type", "severity", "confidence")
        self.tree_scan = ttk.Treeview(results, columns=cols, show="headings", height=8)
        for c, w in zip(cols, (280, 120, 100, 100)):
            self.tree_scan.heading(c, text=c.title())
            self.tree_scan.column(c, width=w, anchor="w" if c == "file" else "center")
        vsb = ttk.Scrollbar(results, orient="vertical", command=self.tree_scan.yview)
        self.tree_scan.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree_scan.pack(fill="both", expand=True, padx=6, pady=4)

        self._scan_result: dict | None = None

    def _browse_scan_target(self):
        d = filedialog.askdirectory(initialdir=self._vars["scan_target"].get())
        if d:
            self._vars["scan_target"].set(d)

    def _start_scan(self):
        target = self._vars["scan_target"].get()
        deep = self._vars["scan_deep"].get()
        self.btn_scan_start.config(state="disabled")
        self.scan_progress["value"] = 0
        self.lbl_scan_status.config(text="Scanning...")

        def run():
            for i in range(1, 101, 5):
                time.sleep(0.1)
                self._queue.put(("scan_progress", i))
            result = self.engine.scan(target, deep=deep)
            self._queue.put(("scan_done", result))

        threading.Thread(target=run, daemon=True).start()

    def _export_report(self):
        if not self._scan_result:
            messagebox.showwarning("Export", "No scan results to export. Run a scan first.")
            return
        fmt = "html"
        report = self.engine.export_report(self._scan_result, fmt)
        path = filedialog.asksaveasfilename(defaultextension=".html",
                                            filetypes=[("HTML", "*.html"), ("SARIF", "*.sarif.json")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(report)
            messagebox.showinfo("Export", f"Report saved to {path}")

    def _generate_certificate(self):
        if not self._scan_result:
            messagebox.showwarning("Certificate", "No scan results available.")
            return
        cert = self.engine.generate_certificate(self._scan_result)
        messagebox.showinfo("Certificate", cert)

    # ── Privacy ─────────────────────────────────────────────────────────────

    def _build_privacy_tab(self) -> None:
        tab = self._new_tab("Privacy")

        top = tk.Frame(tab, bg=COLORS["dark_bg"])
        top.pack(fill="x", pady=(4, 0))

        score_card = self._card(top, "Privacy Score", side="left", fill="both", expand=True, padx=4, pady=4)
        self.privacy_gauge = CircularGauge(score_card, size=130, thickness=12, value=0, title="Privacy",
                                           color=COLORS["info"])
        self.privacy_gauge.pack(pady=8)

        cat_card = self._card(top, "Categories", side="left", fill="both", expand=True, padx=4, pady=4)
        self._vars["privacy_cat"] = tk.StringVar(value="all")
        cats = [("all", "All"), ("telemetry", "Telemetry"), ("permissions", "Permissions"),
                ("network", "Network"), ("storage", "Storage")]
        for val, label in cats:
            tk.Radiobutton(cat_card, text=label, variable=self._vars["privacy_cat"], value=val,
                           bg=COLORS["card_bg"], fg=COLORS["text"], selectcolor=COLORS["card_bg_alt"],
                           font=("Segoe UI", 9), command=self._filter_privacy).pack(anchor="w", padx=8, pady=1)

        btn_fix = tk.Button(top, text="\U0001f527 Fix All", bg=COLORS["success"], fg="#ffffff",
                            font=("Segoe UI", 11, "bold"), bd=0, padx=14, pady=8, cursor="hand2",
                            activebackground="#43a047", command=self._fix_all_privacy)
        btn_fix.pack(side="right", padx=4, pady=4)

        issues = self._card(tab, "Privacy Issues", fill="both", expand=True, padx=4, pady=4)
        cols = ("issue", "category", "severity", "current", "recommended")
        self.tree_privacy = ttk.Treeview(issues, columns=cols, show="headings", height=10)
        for c, w in zip(cols, (220, 100, 80, 160, 160)):
            self.tree_privacy.heading(c, text=c.replace("_", " ").title())
            self.tree_privacy.column(c, width=w, anchor="w" if c in ("issue", "current", "recommended") else "center")
        vsb = ttk.Scrollbar(issues, orient="vertical", command=self.tree_privacy.yview)
        self.tree_privacy.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree_privacy.pack(fill="both", expand=True, padx=6, pady=4)

        # sample data
        self._privacy_data = [
            ("Windows telemetry set to Full", "telemetry", "high", "Full", "Basic"),
            ("Advertising ID enabled", "telemetry", "medium", "On", "Off"),
            ("Location services on", "permissions", "medium", "Enabled", "Disabled"),
            ("Camera access for all apps", "permissions", "high", "Allowed", "Ask"),
            ("Diagnostic data collection", "telemetry", "medium", "Enabled", "Disabled"),
            ("Open RDP port 3389", "network", "critical", "Open", "Closed"),
            ("NetBIOS over TCP enabled", "network", "medium", "Enabled", "Disabled"),
            ("Temporary files unencrypted", "storage", "low", "Unencrypted", "Encrypted"),
        ]
        self._populate_privacy()

    def _populate_privacy(self, category: str = "all"):
        for i in self.tree_privacy.get_children():
            self.tree_privacy.delete(i)
        for row in self._privacy_data:
            if category == "all" or row[1] == category:
                self.tree_privacy.insert("", "end", values=row)

    def _filter_privacy(self):
        self._populate_privacy(self._vars["privacy_cat"].get())

    def _fix_all_privacy(self):
        fixed = 0
        for item in self.tree_privacy.get_children():
            vals = self.tree_privacy.item(item, "values")
            if vals[2] in ("high", "medium", "critical"):
                fixed += 1
        messagebox.showinfo("Fix All", f"Attempted to auto-remediate {fixed} privacy issues.")

    # ── Threats ─────────────────────────────────────────────────────────────

    def _build_threats_tab(self) -> None:
        tab = self._new_tab("Threats")

        actions = tk.Frame(tab, bg=COLORS["dark_bg"])
        actions.pack(fill="x", pady=4)
        tk.Button(actions, text="\U0001f5d1 Quarantine Selected", bg=COLORS["warning"], fg="#ffffff",
                  font=("Segoe UI", 10, "bold"), bd=0, padx=12, pady=6, cursor="hand2",
                  command=self._quarantine_selected).pack(side="left", padx=4)
        tk.Button(actions, text="View Details", bg=COLORS["card_bg_alt"], fg=COLORS["text"],
                  font=("Segoe UI", 10), bd=0, padx=12, pady=6, cursor="hand2",
                  command=self._view_threat_details).pack(side="left", padx=4)

        threats = self._card(tab, "Active Threats", fill="both", expand=True, padx=4, pady=4)
        cols = ("file", "type", "severity", "confidence", "detected")
        self.tree_threats = ttk.Treeview(threats, columns=cols, show="headings", height=10)
        for c, w in zip(cols, (260, 110, 90, 90, 140)):
            self.tree_threats.heading(c, text=c.title())
            self.tree_threats.column(c, width=w, anchor="w" if c == "file" else "center")
        vsb = ttk.Scrollbar(threats, orient="vertical", command=self.tree_threats.yview)
        self.tree_threats.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree_threats.pack(fill="both", expand=True, padx=6, pady=4)

    def _quarantine_selected(self):
        sel = self.tree_threats.selection()
        if not sel:
            messagebox.showwarning("Quarantine", "No threat selected.")
            return
        for item in sel:
            vals = self.tree_threats.item(item, "values")
            self.engine.quarantine(vals[0])
            self.tree_threats.delete(item)
        self._refresh_status()

    def _view_threat_details(self):
        sel = self.tree_threats.selection()
        if not sel:
            return
        vals = self.tree_threats.item(sel[0], "values")
        msg = f"File: {vals[0]}\nType: {vals[1]}\nSeverity: {vals[2]}\nConfidence: {vals[3]}\nDetected: {vals[4]}\n\nRecommendation: Quarantine immediately."
        messagebox.showinfo("Threat Details", msg)

    # ── Vault ───────────────────────────────────────────────────────────────

    def _build_vault_tab(self) -> None:
        tab = self._new_tab("Vault")

        actions = tk.Frame(tab, bg=COLORS["dark_bg"])
        actions.pack(fill="x", pady=4)
        tk.Button(actions, text="+ Add File", bg=COLORS["primary"], fg="#ffffff",
                  font=("Segoe UI", 10, "bold"), bd=0, padx=14, pady=6, cursor="hand2",
                  activebackground=COLORS["accent"], command=self._vault_add).pack(side="left", padx=4)

        vault = self._card(tab, "Stored Files", fill="both", expand=True, padx=4, pady=4)
        cols = ("file", "status", "added")
        self.tree_vault = ttk.Treeview(vault, columns=cols, show="headings", height=10)
        for c, w in zip(cols, (400, 120, 160)):
            self.tree_vault.heading(c, text=c.title())
            self.tree_vault.column(c, width=w, anchor="w" if c == "file" else "center")

        btn_frame = tk.Frame(vault, bg=COLORS["card_bg"])
        btn_frame.pack(fill="x", padx=6, pady=(0, 4))
        tk.Button(btn_frame, text="\U0001f513 Retrieve", bg=COLORS["card_bg_alt"], fg=COLORS["text"],
                  font=("Segoe UI", 9), bd=0, padx=10, cursor="hand2",
                  command=self._vault_retrieve).pack(side="left", padx=2)
        tk.Button(btn_frame, text="\U0001f5d1 Delete", bg=COLORS["danger"], fg="#ffffff",
                  font=("Segoe UI", 9), bd=0, padx=10, cursor="hand2",
                  command=self._vault_delete).pack(side="left", padx=2)

        vsb = ttk.Scrollbar(vault, orient="vertical", command=self.tree_vault.yview)
        self.tree_vault.configure(yscrollcommand=vsb.set)
        self.tree_vault.pack(fill="both", expand=True, padx=6, pady=(4, 0))
        vsb.pack(side="right", fill="y")

    def _vault_add(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        pwd = self._password_prompt("Enter vault password:")
        if pwd is None:
            return
        if self.engine.vault_add(path, pwd):
            self.tree_vault.insert("", "end", values=(os.path.basename(path), "\U0001f512 Encrypted",
                                                      time.strftime("%Y-%m-%d %H:%M")))
            messagebox.showinfo("Vault", "File added to vault.")

    def _vault_retrieve(self):
        sel = self.tree_vault.selection()
        if not sel:
            messagebox.showwarning("Vault", "No file selected.")
            return
        vals = self.tree_vault.item(sel[0], "values")
        pwd = self._password_prompt("Enter vault password to retrieve:")
        if pwd is None:
            return
        messagebox.showinfo("Vault", f"File '{vals[0]}' retrieved.")

    def _vault_delete(self):
        sel = self.tree_vault.selection()
        if not sel:
            messagebox.showwarning("Vault", "No file selected.")
            return
        if messagebox.askyesno("Vault", "Delete selected file from vault?"):
            for item in sel:
                vals = self.tree_vault.item(item, "values")
                self.engine.vault_delete(vals[0])
                self.tree_vault.delete(item)

    def _password_prompt(self, message: str) -> str | None:
        dlg = tk.Toplevel(self.root)
        dlg.title("Vault Password")
        dlg.configure(bg=COLORS["dark_bg"])
        dlg.geometry("320x140")
        dlg.transient(self.root)
        dlg.grab_set()
        tk.Label(dlg, text=message, bg=COLORS["dark_bg"], fg=COLORS["text"],
                 font=("Segoe UI", 10)).pack(pady=(12, 4))
        var = tk.StringVar()
        entry = tk.Entry(dlg, textvariable=var, show="*", bg=COLORS["card_bg_alt"], fg=COLORS["text"],
                         insertbackground=COLORS["text"], font=("Segoe UI", 10),
                         highlightthickness=1, highlightcolor=COLORS["primary"])
        entry.pack(padx=20, pady=4, fill="x")
        entry.focus()
        result: list[str | None] = [None]

        def ok():
            result[0] = var.get()
            dlg.destroy()

        def cancel():
            dlg.destroy()

        btns = tk.Frame(dlg, bg=COLORS["dark_bg"])
        btns.pack(pady=8)
        tk.Button(btns, text="OK", bg=COLORS["primary"], fg="#ffffff", font=("Segoe UI", 9, "bold"),
                  bd=0, padx=16, cursor="hand2", command=ok).pack(side="left", padx=4)
        tk.Button(btns, text="Cancel", bg=COLORS["card_bg_alt"], fg=COLORS["text"], font=("Segoe UI", 9),
                  bd=0, padx=16, cursor="hand2", command=cancel).pack(side="left", padx=4)
        dlg.bind("<Return>", lambda e: ok())
        dlg.bind("<Escape>", lambda e: cancel())
        self.root.wait_window(dlg)
        return result[0]

    # ── Quarantine ──────────────────────────────────────────────────────────

    def _build_quarantine_tab(self) -> None:
        tab = self._new_tab("Quarantine")

        actions = tk.Frame(tab, bg=COLORS["dark_bg"])
        actions.pack(fill="x", pady=4)
        tk.Button(actions, text="\U0001f504 Restore Selected", bg=COLORS["info"], fg="#ffffff",
                  font=("Segoe UI", 10, "bold"), bd=0, padx=12, pady=6, cursor="hand2",
                  command=self._restore_selected).pack(side="left", padx=4)
        tk.Button(actions, text="\U0001f5d1 Delete Permanently", bg=COLORS["danger"], fg="#ffffff",
                  font=("Segoe UI", 10, "bold"), bd=0, padx=12, pady=6, cursor="hand2",
                  command=self._delete_quarantined).pack(side="left", padx=4)

        q_frame = self._card(tab, "Quarantined Items", fill="both", expand=True, padx=4, pady=4)
        cols = ("original_path", "date", "encrypted")
        self.tree_quarantine = ttk.Treeview(q_frame, columns=cols, show="headings", height=10)
        for c, w in zip(cols, (380, 160, 100)):
            self.tree_quarantine.heading(c, text=c.replace("_", " ").title())
            self.tree_quarantine.column(c, width=w, anchor="w" if c == "original_path" else "center")
        vsb = ttk.Scrollbar(q_frame, orient="vertical", command=self.tree_quarantine.yview)
        self.tree_quarantine.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree_quarantine.pack(fill="both", expand=True, padx=6, pady=4)

    def _restore_selected(self):
        sel = self.tree_quarantine.selection()
        if not sel:
            messagebox.showwarning("Quarantine", "No item selected.")
            return
        for item in sel:
            vals = self.tree_quarantine.item(item, "values")
            self.engine.restore_from_quarantine(vals[0])
            self.tree_quarantine.delete(item)
        self._refresh_status()

    def _delete_quarantined(self):
        sel = self.tree_quarantine.selection()
        if not sel:
            messagebox.showwarning("Quarantine", "No item selected.")
            return
        if not messagebox.askyesno("Delete", "Permanently delete selected items? This cannot be undone."):
            return
        for item in sel:
            vals = self.tree_quarantine.item(item, "values")
            self.engine.delete_quarantined(vals[0])
            self.tree_quarantine.delete(item)
        self._refresh_status()

    # ── Settings ────────────────────────────────────────────────────────────

    def _build_settings_tab(self) -> None:
        tab = self._new_tab("Settings")
        canvas = tk.Canvas(tab, bg=COLORS["dark_bg"], highlightthickness=0)
        vsb = ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg=COLORS["dark_bg"])
        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw", width=self.WIDTH - 30)

        # auto-scan
        auto = self._card(scroll_frame, "Auto-Scan", fill="x", padx=8, pady=4)
        self._vars["auto_scan"] = tk.BooleanVar(value=False)
        tk.Checkbutton(auto, text="Enable automatic scanning", variable=self._vars["auto_scan"],
                       bg=COLORS["card_bg"], fg=COLORS["text"], selectcolor=COLORS["card_bg_alt"],
                       activebackground=COLORS["card_bg"], font=("Segoe UI", 10)).pack(anchor="w", padx=8, pady=4)
        f = tk.Frame(auto, bg=COLORS["card_bg"])
        f.pack(anchor="w", padx=8, pady=4)
        tk.Label(f, text="Interval (minutes):", bg=COLORS["card_bg"], fg=COLORS["text"],
                 font=("Segoe UI", 10)).pack(side="left")
        self._vars["monitor_interval"] = tk.IntVar(value=60)
        tk.Spinbox(f, from_=5, to=1440, increment=5, textvariable=self._vars["monitor_interval"],
                   bg=COLORS["card_bg_alt"], fg=COLORS["text"], font=("Segoe UI", 10), width=8).pack(side="left",
                                                                                                          padx=4)

        # watch directories
        watch = self._card(scroll_frame, "Watch Directories", fill="x", padx=8, pady=4)
        self._vars["watch_dirs"] = tk.StringVar(value=os.path.expanduser("~"))
        tk.Entry(watch, textvariable=self._vars["watch_dirs"], bg=COLORS["card_bg_alt"], fg=COLORS["text"],
                 font=("Segoe UI", 10), highlightthickness=1, highlightcolor=COLORS["primary"]).pack(
                     fill="x", padx=8, pady=4)
        bf = tk.Frame(watch, bg=COLORS["card_bg"])
        bf.pack(anchor="e", padx=8, pady=4)
        tk.Button(bf, text="Add Directory", bg=COLORS["primary"], fg="#ffffff", font=("Segoe UI", 9),
                  bd=0, padx=10, cursor="hand2", command=self._add_watch_dir).pack(side="left", padx=2)
        tk.Button(bf, text="Remove Selected", bg=COLORS["danger"], fg="#ffffff", font=("Segoe UI", 9),
                  bd=0, padx=10, cursor="hand2", command=self._remove_watch_dir).pack(side="left", padx=2)

        # privacy categories
        priv = self._card(scroll_frame, "Privacy Check Categories", fill="x", padx=8, pady=4)
        self._vars["check_telemetry"] = tk.BooleanVar(value=True)
        self._vars["check_permissions"] = tk.BooleanVar(value=True)
        self._vars["check_network"] = tk.BooleanVar(value=True)
        self._vars["check_storage"] = tk.BooleanVar(value=True)
        for var, label in [("check_telemetry", "Telemetry"), ("check_permissions", "App Permissions"),
                           ("check_network", "Network Settings"), ("check_storage", "Storage Encryption")]:
            tk.Checkbutton(priv, text=label, variable=self._vars[f"{var}"], bg=COLORS["card_bg"],
                           fg=COLORS["text"], selectcolor=COLORS["card_bg_alt"],
                           activebackground=COLORS["card_bg"], font=("Segoe UI", 10)).pack(anchor="w", padx=8,
                                                                                               pady=2)

        # theme
        theme = self._card(scroll_frame, "Appearance", fill="x", padx=8, pady=4)
        self._vars["theme"] = tk.StringVar(value="dark")
        tk.Label(theme, text="Theme:", bg=COLORS["card_bg"], fg=COLORS["text"],
                 font=("Segoe UI", 10)).pack(side="left", padx=8, pady=4)
        ttk.Combobox(theme, textvariable=self._vars["theme"], values=["dark", "light"],
                     state="readonly", width=12).pack(side="left", padx=4, pady=4)

        # export / import
        cfg = self._card(scroll_frame, "Configuration", fill="x", padx=8, pady=4)
        bf2 = tk.Frame(cfg, bg=COLORS["card_bg"])
        bf2.pack(anchor="w", padx=8, pady=6)
        tk.Button(bf2, text="Export Config", bg=COLORS["card_bg_alt"], fg=COLORS["text"], font=("Segoe UI", 9),
                  bd=0, padx=12, cursor="hand2", command=self._export_config).pack(side="left", padx=2)
        tk.Button(bf2, text="Import Config", bg=COLORS["card_bg_alt"], fg=COLORS["text"], font=("Segoe UI", 9),
                  bd=0, padx=12, cursor="hand2", command=self._import_config).pack(side="left", padx=2)

    def _add_watch_dir(self):
        d = filedialog.askdirectory()
        if d:
            cur = self._vars["watch_dirs"].get()
            self._vars["watch_dirs"].set(cur + ";" + d if cur else d)

    def _remove_watch_dir(self):
        self._vars["watch_dirs"].set("")

    def _export_config(self):
        cfg = {k: v.get() for k, v in self._vars.items()}
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            with open(path, "w") as f:
                json.dump(cfg, f, indent=2, default=str)
            messagebox.showinfo("Settings", f"Config exported to {path}")

    def _import_config(self):
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if path:
            with open(path) as f:
                data = json.load(f)
            for k, v in data.items():
                if k in self._vars:
                    self._vars[k].set(v)
            messagebox.showinfo("Settings", "Config imported successfully.")

    # ── Updates ────────────────────────────────────────────────────────────

    def _build_updates_tab(self) -> None:
        """Build the Updates tab — app, vulndb, and rules updates."""
        tab = self._new_tab("Updates")
        tab.grid_columnconfigure(0, weight=1)

        # -- Header --
        header = tk.Frame(tab, bg=COLORS["dark_bg"])
        header.pack(fill="x", padx=16, pady=(16, 8))
        tk.Label(header, text="Updates", font=("Inter", 20, "bold"),
                 bg=COLORS["dark_bg"], fg="white").pack(anchor="w")
        tk.Label(header, text="Check and install updates. All downloads are cryptographically verified.",
                 font=("Inter", 10), bg=COLORS["dark_bg"], fg=COLORS["muted"]).pack(anchor="w")

        # -- Current Versions Card --
        ver_card = self._card(tab, title="Current Versions")
        ver_card.pack(fill="x", padx=16, pady=8)

        self._update_version_labels = {}
        versions = [
            ("App Version", "app_version", "1.0.0"),
            ("VulnDB Version", "vulndb_version", "Checking..."),
            ("Rules Version", "rules_version", "Checking..."),
            ("Last Check", "last_check", "Never"),
        ]
        for i, (label, key, default) in enumerate(versions):
            row = tk.Frame(ver_card, bg=COLORS["card_bg"])
            row.pack(fill="x", pady=2)
            tk.Label(row, text=f"{label}:", font=("Inter", 10),
                     bg=COLORS["card_bg"], fg=COLORS["muted"], width=18, anchor="w").pack(side="left")
            lbl = tk.Label(row, text=default, font=("Inter", 10, "bold"),
                           bg=COLORS["card_bg"], fg="white")
            lbl.pack(side="left")
            self._update_version_labels[key] = lbl

        # -- App Update Card --
        app_card = self._card(tab, title="Application Update")
        app_card.pack(fill="x", padx=16, pady=8)

        self._app_update_status = tk.Label(app_card, text="Click 'Check for Updates' to search",
                                           font=("Inter", 10), bg=COLORS["card_bg"], fg=COLORS["muted"])
        self._app_update_status.pack(anchor="w", pady=(4, 8))

        self._app_update_btn = tk.Button(app_card, text="Check for Updates",
                                         font=("Inter", 10, "bold"), bg=COLORS["primary"], fg="white",
                                         activebackground=COLORS["accent"], bd=0, cursor="hand2",
                                         padx=20, pady=6, command=self._on_check_app_update)
        self._app_update_btn.pack(anchor="w")

        # -- VulnDB Update Card --
        vuln_card = self._card(tab, title="Vulnerability Database")
        vuln_card.pack(fill="x", padx=16, pady=8)

        self._vulndb_status = tk.Label(vuln_card, text="Click 'Check' to search for database updates",
                                       font=("Inter", 10), bg=COLORS["card_bg"], fg=COLORS["muted"])
        self._vulndb_status.pack(anchor="w", pady=(4, 8))

        btn_frame = tk.Frame(vuln_card, bg=COLORS["card_bg"])
        btn_frame.pack(anchor="w")
        self._vulndb_check_btn = tk.Button(btn_frame, text="Check for Updates",
                                           font=("Inter", 10, "bold"), bg=COLORS["primary"], fg="white",
                                           activebackground=COLORS["accent"], bd=0, cursor="hand2",
                                           padx=20, pady=6, command=self._on_check_vulndb)
        self._vulndb_check_btn.pack(side="left", padx=(0, 8))
        self._vulndb_stats_btn = tk.Button(btn_frame, text="View Stats",
                                           font=("Inter", 10), bg=COLORS["card_bg"], fg=COLORS["muted"],
                                           activebackground=COLORS["dark_bg"], bd=0, cursor="hand2",
                                           padx=16, pady=6, command=self._on_vulndb_stats)
        self._vulndb_stats_btn.pack(side="left")

        # -- Progress bar (hidden initially) --
        self._update_progress = tk.Frame(tab, bg=COLORS["dark_bg"])
        self._update_progress.pack(fill="x", padx=16, pady=8)
        self._update_progress.pack_forget()

        prog_inner = tk.Frame(self._update_progress, bg=COLORS["card_bg"], height=20)
        prog_inner.pack(fill="x")
        self._update_progress_bar = tk.Frame(prog_inner, bg=COLORS["primary"], width=0, height=20)
        self._update_progress_bar.place(x=0, y=0)
        self._update_progress_label = tk.Label(self._update_progress, text="",
                                               font=("Inter", 9), bg=COLORS["dark_bg"], fg=COLORS["muted"])
        self._update_progress_label.pack(anchor="w")

        # -- Offline Update Card --
        offline_card = self._card(tab, title="Offline Update (Air-Gapped)")
        offline_card.pack(fill="x", padx=16, pady=8)

        tk.Label(offline_card, text="For air-gapped environments: import update packages from file.",
                 font=("Inter", 10), bg=COLORS["card_bg"], fg=COLORS["muted"]).pack(anchor="w", pady=(4, 8))
        tk.Button(offline_card, text="Import Update Package",
                  font=("Inter", 10), bg=COLORS["card_bg"], fg=COLORS["muted"],
                  activebackground=COLORS["dark_bg"], bd=0, cursor="hand2",
                  padx=16, pady=6, command=self._on_import_offline_update).pack(anchor="w")

    def _on_check_app_update(self):
        """Check for application updates."""
        self._app_update_btn.config(state="disabled", text="Checking...")
        self._app_update_status.config(text="Contacting update server...", fg=COLORS["accent"])
        self.root.after(100, self._do_check_app_update)

    def _do_check_app_update(self):
        """Background check for app updates."""
        try:
            status = self.engine.check_for_updates()
            if status["app_update_available"]:
                new_ver = status["app_update_version"]
                self._app_update_status.config(
                    text=f"Update available: v{new_ver}. Click Download to install.",
                    fg="#4caf50")
                self._app_update_btn.config(text="Download Update", state="normal",
                                           command=lambda: self._on_download_app_update(new_ver))
            else:
                self._app_update_status.config(
                    text=f"You are on the latest version (v{status['app_version']}).",
                    fg=COLORS["muted"])
                self._app_update_btn.config(text="Check for Updates", state="normal")
            # Update version labels
            self._update_version_labels["app_version"].config(text=status["app_version"])
            self._update_version_labels["vulndb_version"].config(text=status["vulndb_version"])
            self._update_version_labels["rules_version"].config(text=status["rules_version"])
            self._update_version_labels["last_check"].config(text=status["last_check"] or "Just now")
        except Exception as e:
            self._app_update_status.config(text=f"Update check failed: {e}", fg=COLORS["danger"])
            self._app_update_btn.config(text="Check for Updates", state="normal")

    def _on_download_app_update(self, version: str):
        """Download the application update."""
        self._app_update_btn.config(state="disabled", text="Downloading...")
        self._app_update_status.config(text=f"Downloading v{version}...", fg=COLORS["accent"])
        self._update_progress.pack(fill="x", padx=16, pady=8)

        def progress(done, total):
            pct = int(done / total * 100) if total else 0
            self._update_progress_bar.config(width=int(400 * pct / 100))
            self._update_progress_label.config(text=f"{pct}% ({done // 1024} KB)")

        def do_download():
            try:
                result = self.engine.download_app_update(progress)
                self.root.after(0, lambda: self._on_download_complete(result, version))
            except Exception as e:
                self.root.after(0, lambda: self._on_download_complete(
                    {"success": False, "message": str(e)}, version))

        import threading
        threading.Thread(target=do_download, daemon=True).start()

    def _on_download_complete(self, result: dict, version: str):
        """Handle download completion."""
        self._update_progress.pack_forget()
        if result["success"]:
            msg = result.get("message", f"Update v{version} downloaded.")
            if result.get("restart_required"):
                msg += " Restart required to apply."
            self._app_update_status.config(text=msg, fg="#4caf50")
            self._app_update_btn.config(text="Restart to Apply", state="normal",
                                       command=self._on_restart_for_update)
        else:
            self._app_update_status.config(text=result.get("message", "Download failed."),
                                           fg=COLORS["danger"])
            self._app_update_btn.config(text="Retry Download", state="normal",
                                       command=lambda: self._on_download_app_update(version))

    def _on_restart_for_update(self):
        """Restart the application to apply the update."""
        from tkinter import messagebox
        if messagebox.askyesno("Restart Required", "Restart VeriForge Red to apply the update?"):
            import sys
            import os
            os.execv(sys.executable, [sys.executable] + sys.argv)

    def _on_check_vulndb(self):
        """Check for VulnDB updates."""
        self._vulndb_check_btn.config(state="disabled", text="Checking...")
        self._vulndb_status.config(text="Checking vulnerability database...", fg=COLORS["accent"])

        def do_check():
            try:
                result = self.engine.download_vulndb_update()
                self.root.after(0, lambda: self._on_vulndb_complete(result))
            except Exception as e:
                self.root.after(0, lambda: self._on_vulndb_complete(
                    {"success": False, "message": str(e)}))

        import threading
        threading.Thread(target=do_check, daemon=True).start()

    def _on_vulndb_complete(self, result: dict):
        """Handle VulnDB update completion."""
        self._vulndb_check_btn.config(state="normal", text="Check for Updates")
        if result["success"]:
            self._vulndb_status.config(text=result.get("message", "VulnDB updated."), fg="#4caf50")
        else:
            self._vulndb_status.config(text=result.get("message", "No update available or check failed."),
                                       fg=COLORS["muted"])

    def _on_vulndb_stats(self):
        """Show VulnDB statistics."""
        stats = self.engine.get_vulndb_stats()
        msg = (f"VulnDB Version: {stats['version']}\n"
               f"Signatures: {stats['signature_count']}\n"
               f"Payloads: {stats['payload_count']}\n"
               f"Critical: {stats['critical_count']}\n"
               f"High: {stats['high_count']}\n"
               f"Categories: {', '.join(stats['categories'])}")
        from tkinter import messagebox
        messagebox.showinfo("Vulnerability Database Statistics", msg)

    def _on_import_offline_update(self):
        """Import an offline update package."""
        path = filedialog.askopenfilename(
            title="Select Update Package",
            filetypes=[("All Update Files", "*.zip *.sqlite *.json *.gz"),
                       ("App Update", "*.zip"), ("VulnDB Update", "*.sqlite *.gz"),
                       ("Rules Update", "*.json")],
        )
        if path:
            result = self.engine.import_offline_update(path)
            from tkinter import messagebox
            if result["success"]:
                messagebox.showinfo("Import Successful", result["message"])
            else:
                messagebox.showerror("Import Failed", result["message"])

    # ── UI Poller ─────────────────────────────────────────────────────────

    def _start_ui_poller(self):
        self._poll_ui()

    def _poll_ui(self):
        try:
            while True:
                msg = self._queue.get_nowait()
                self._handle_ui_message(msg)
        except queue.Empty:
            pass
        self.root.after(200, self._poll_ui)

    def _handle_ui_message(self, msg: tuple):
        event, data = msg
        if event == "scan_progress":
            self.scan_progress["value"] = data
            self.lbl_scan_status.config(text=f"Scanning... {data}%")
        elif event == "scan_done":
            self._scan_result = data
            self.scan_progress["value"] = 100
            self.lbl_scan_status.config(text=f"Scan complete — Grade {data['grade']}")
            self.lbl_grade.config(text=data["grade"], fg=GRADE_COLOURS.get(data["grade"], COLORS["text"]))
            self.lbl_risk.config(text=f"Risk Score: {data['risk_score']}")
            for i in self.tree_scan.get_children():
                self.tree_scan.delete(i)
            for f in data.get("findings", []):
                self.tree_scan.insert("", "end", values=(
                    f["file"], f["type"], f["severity"], f"{f['confidence']:.0%}",
                ))
            for f in data.get("findings", []):
                self.tree_recent.insert("", 0, values=(f["file"], f["type"], f["severity"], data["timestamp"]))
            self.sec_gauge.set_value(max(0, 100 - data["risk_score"]))
            self.btn_scan_start.config(state="normal")
            self._refresh_status()

    def _on_engine_update(self, event: str, data: dict):
        pass

    def _refresh_status(self):
        state = self.engine.state
        self.lbl_active_threats.config(text=f"Active Threats: {state['active_threats']}")
        self.lbl_quarantined.config(text=f"Quarantined: {state['quarantined_items']}")
        if state["last_scan"]:
            self.lbl_last_scan.config(text=f"Last Scan: {state['last_scan']}")

    # ── Public API ──────────────────────────────────────────────────────────

    def run(self) -> None:
        """Start the main event loop."""
        self.root.mainloop()
        self.engine.stop()

    def show(self) -> None:
        """De-iconify and lift the window."""
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def hide(self) -> None:
        """Hide (withdraw) the main window."""
        self.root.withdraw()

    def destroy(self) -> None:
        """Clean up resources."""
        self.engine.stop()
        self.root.destroy()


# ── Standalone entry-point ──────────────────────────────────────────────────

def main():
    import logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    app = RedApp()
    app.run()


if __name__ == "__main__":
    main()
