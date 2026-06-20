#!/usr/bin/env python3
"""
VeriForge GUI - Kivy Android Application
========================================
A native-feeling Android GUI for the VeriForge security platform.
Runs as an APK (built via Buildozer) or directly in Termux/Kivy.

Features:
- Target path input (default /sdcard/Download)
- Scan type selector (Quick, Full, Privacy Audit)
- Scan execution with threaded background processing
- Scrollable results display
- Status bar at bottom
- Menu with Settings, About, Help dialogs
"""

import os
import sys
import threading
import subprocess
import time
import json
from datetime import datetime

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.spinner import Spinner
from kivy.uix.popup import Popup
from kivy.uix.progressbar import ProgressBar
from kivy.uix.widget import Widget
from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelHeader
from kivy.core.window import Window
from kivy.clock import Clock, mainthread
from kivy.properties import StringProperty, BooleanProperty, ObjectProperty
from kivy.graphics import Color, Rectangle, RoundedRectangle
from kivy.metrics import dp
from kivy.animation import Animation

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_TARGET = "/sdcard/Download"
if not os.path.exists(DEFAULT_TARGET):
    DEFAULT_TARGET = "/sdcard"

SCAN_TYPES = ["Quick Scan", "Full Scan", "Privacy Audit"]

VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# UI Components
# ---------------------------------------------------------------------------

class StatusBar(BoxLayout):
    """Status bar at the bottom showing current state."""

    status_text = StringProperty("Ready")
    status_color = StringProperty("#888888")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.size_hint_y = None
        self.height = dp(36)
        self.padding = [dp(8), dp(4)]
        self.spacing = dp(8)

        with self.canvas.before:
            Color(0.12, 0.12, 0.14, 1)
            self.rect = Rectangle(pos=self.pos, size=self.size)
        self.bind(pos=self._update_rect, size=self._update_rect)

        self.icon_label = Label(
            text="●",
            size_hint_x=None,
            width=dp(24),
            color=(0.3, 0.8, 0.3, 1),
            font_size=dp(14),
        )
        self.text_label = Label(
            text=self.status_text,
            halign="left",
            valign="middle",
            text_size=(None, None),
            color=(0.85, 0.85, 0.87, 1),
            font_size=dp(12),
            markup=True,
        )
        self.bind(status_text=self._update_text)
        self.bind(status_color=self._update_color)

        self.add_widget(self.icon_label)
        self.add_widget(self.text_label)

    def _update_rect(self, *args):
        self.rect.pos = self.pos
        self.rect.size = self.size

    def _update_text(self, instance, value):
        self.text_label.text = value

    def _update_color(self, instance, value):
        r, g, b = self._hex_to_rgb(value)
        self.icon_label.color = (r, g, b, 1)

    def _hex_to_rgb(self, hex_color):
        hex_color = hex_color.lstrip("#")
        return tuple(int(hex_color[i:i + 2], 16) / 255.0 for i in (0, 2, 4))

    def set_status(self, text, color="#888888"):
        self.status_text = text
        self.status_color = color


class ResultsPanel(ScrollView):
    """Scrollable panel for displaying scan results."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.results_layout = GridLayout(
            cols=1,
            spacing=dp(4),
            size_hint_y=None,
            padding=[dp(8), dp(8)],
        )
        self.results_layout.bind(
            minimum_height=self.results_layout.setter("height")
        )
        self.add_widget(self.results_layout)

    def add_result(self, text, result_type="info"):
        """Add a result entry with color coding."""
        color_map = {
            "info":    (0.7, 0.7, 0.75, 1),
            "success": (0.3, 0.85, 0.4, 1),
            "warning": (0.95, 0.7, 0.2, 1),
            "error":   (0.95, 0.3, 0.3, 1),
            "header":  (0.4, 0.7, 0.95, 1),
        }
        color = color_map.get(result_type, color_map["info"])

        label = Label(
            text=text,
            size_hint_y=None,
            halign="left",
            valign="top",
            text_size=(self.width - dp(24), None),
            color=color,
            font_size=dp(12),
            markup=True,
            padding=[dp(8), dp(6)],
        )
        label.bind(
            width=lambda instance, value: setattr(
                instance, "text_size", (value - dp(16), None)
            )
        )
        label.bind(
            texture_size=lambda instance, value: setattr(
                instance, "height", value[1] + dp(12)
            )
        )

        with label.canvas.before:
            Color(0.15, 0.15, 0.17, 1)
            rect = RoundedRectangle(
                pos=label.pos,
                size=label.size,
                radius=[dp(4), dp(4), dp(4), dp(4)],
            )
        label.bind(pos=lambda inst, val: setattr(rect, "pos", val))
        label.bind(size=lambda inst, val: setattr(rect, "size", val))

        self.results_layout.add_widget(label)

        # Auto-scroll to bottom
        Clock.schedule_once(lambda dt: setattr(
            self, "scroll_y", 0
        ), 0.05)

    def clear_results(self):
        self.results_layout.clear_widgets()


class MenuBar(BoxLayout):
    """Top menu bar with Settings, About, Help buttons."""

    def __init__(self, app_instance, **kwargs):
        super().__init__(**kwargs)
        self.app = app_instance
        self.size_hint_y = None
        self.height = dp(48)
        self.padding = [dp(4), dp(4)]
        self.spacing = dp(4)

        with self.canvas.before:
            Color(0.12, 0.12, 0.16, 1)
            self.rect = Rectangle(pos=self.pos, size=self.size)
        self.bind(pos=self._update_rect, size=self._update_rect)

        self.title_label = Label(
            text=f"[b]VeriForge[/b] [color=#888888]Red[/color]",
            markup=True,
            halign="left",
            valign="middle",
            text_size=(None, None),
            color=(0.9, 0.9, 0.92, 1),
            font_size=dp(16),
            size_hint_x=0.5,
        )

        self.add_widget(self.title_label)
        self.add_widget(Widget(size_hint_x=0.2))  # spacer

        buttons = [
            ("Settings", self.show_settings),
            ("Help", self.show_help),
            ("About", self.show_about),
        ]

        for text, callback in buttons:
            btn = Button(
                text=text,
                size_hint_x=None,
                width=dp(72),
                background_color=(0.2, 0.2, 0.25, 1),
                color=(0.85, 0.85, 0.9, 1),
                font_size=dp(11),
            )
            btn.bind(on_release=callback)
            self.add_widget(btn)

    def _update_rect(self, *args):
        self.rect.pos = self.pos
        self.rect.size = self.size

    def show_settings(self, *args):
        content = BoxLayout(orientation="vertical", spacing=dp(8), padding=dp(16))

        content.add_widget(Label(
            text="[b]Settings[/b]",
            markup=True,
            font_size=dp(18),
            color=(0.9, 0.9, 0.92, 1),
            size_hint_y=None,
            height=dp(40),
        ))

        # Default target path setting
        path_box = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(8))
        path_box.add_widget(Label(
            text="Default Target:",
            size_hint_x=0.35,
            halign="left",
            color=(0.8, 0.8, 0.85, 1),
            font_size=dp(12),
        ))
        self.path_input = TextInput(
            text=self.app.target_path,
            multiline=False,
            font_size=dp(12),
            background_color=(0.15, 0.15, 0.18, 1),
            foreground_color=(0.9, 0.9, 0.92, 1),
            cursor_color=(0.4, 0.7, 0.95, 1),
        )
        path_box.add_widget(self.path_input)
        content.add_widget(path_box)

        # Scan timeout setting
        timeout_box = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(8))
        timeout_box.add_widget(Label(
            text="Scan Timeout (s):",
            size_hint_x=0.35,
            halign="left",
            color=(0.8, 0.8, 0.85, 1),
            font_size=dp(12),
        ))
        self.timeout_input = TextInput(
            text=str(self.app.scan_timeout),
            multiline=False,
            input_filter="int",
            font_size=dp(12),
            background_color=(0.15, 0.15, 0.18, 1),
            foreground_color=(0.9, 0.9, 0.92, 1),
            cursor_color=(0.4, 0.7, 0.95, 1),
        )
        timeout_box.add_widget(self.timeout_input)
        content.add_widget(timeout_box)

        content.add_widget(Widget())  # Spacer

        btn_box = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(8))
        save_btn = Button(
            text="Save",
            background_color=(0.2, 0.6, 0.3, 1),
            color=(1, 1, 1, 1),
        )
        cancel_btn = Button(
            text="Cancel",
            background_color=(0.3, 0.3, 0.35, 1),
            color=(0.8, 0.8, 0.85, 1),
        )

        popup = Popup(
            title="",
            content=content,
            size_hint=(0.85, 0.6),
            auto_dismiss=True,
            background_color=(0.12, 0.12, 0.15, 1),
            separator_color=(0.25, 0.25, 0.3, 1),
        )

        save_btn.bind(on_release=lambda x: self._save_settings(popup))
        cancel_btn.bind(on_release=popup.dismiss)
        btn_box.add_widget(save_btn)
        btn_box.add_widget(cancel_btn)
        content.add_widget(btn_box)

        popup.open()

    def _save_settings(self, popup):
        self.app.target_path = self.path_input.text.strip() or DEFAULT_TARGET
        try:
            self.app.scan_timeout = int(self.timeout_input.text)
        except ValueError:
            self.app.scan_timeout = 300
        popup.dismiss()

    def show_about(self, *args):
        content = BoxLayout(orientation="vertical", spacing=dp(8), padding=dp(16))
        content.add_widget(Label(
            text=(
                f"[b]VeriForge Red[/b]\n"
                f"Version {VERSION}\n\n"
                f"A mobile security scanning platform\n"
                f"for Android devices.\n\n"
                f"[color=#888888]Built with Kivy + Python[/color]"
            ),
            markup=True,
            font_size=dp(14),
            halign="center",
            color=(0.85, 0.85, 0.9, 1),
        ))

        close_btn = Button(
            text="Close",
            size_hint_y=None,
            height=dp(44),
            background_color=(0.2, 0.5, 0.8, 1),
            color=(1, 1, 1, 1),
        )

        popup = Popup(
            title="",
            content=content,
            size_hint=(0.75, 0.45),
            auto_dismiss=True,
            background_color=(0.12, 0.12, 0.15, 1),
        )
        close_btn.bind(on_release=popup.dismiss)
        content.add_widget(close_btn)
        popup.open()

    def show_help(self, *args):
        content = ScrollView()
        layout = BoxLayout(orientation="vertical", spacing=dp(4),
                          padding=dp(12), size_hint_y=None)
        layout.bind(minimum_height=layout.setter("height"))

        help_text = (
            "[b]VeriForge Quick Help[/b]\n\n"
            "[b]Quick Scan[/b]\n"
            "  Fast scan of common vulnerability patterns.\n"
            "  Best for: rapid security checks\n\n"
            "[b]Full Scan[/b]\n"
            "  Comprehensive scan with deep analysis.\n"
            "  Best for: thorough security audits\n\n"
            "[b]Privacy Audit[/b]\n"
            "  Scan for privacy-sensitive data exposure.\n"
            "  Best for: compliance & data protection\n\n"
            "[b]Target Path[/b]\n"
            "  Default is /sdcard/Download.\n"
            "  You can scan any accessible directory.\n\n"
            "[b]Permissions[/b]\n"
            "  Grant storage permission when prompted.\n"
            "  Required to scan files on your device.\n\n"
            "[b]Termux Mode[/b]\n"
            "  This app can also run inside Termux.\n"
            "  Use the install.sh script to set up."
        )

        layout.add_widget(Label(
            text=help_text,
            markup=True,
            font_size=dp(13),
            halign="left",
            color=(0.8, 0.8, 0.85, 1),
            text_size=(Window.width * 0.7, None),
        ))
        content.add_widget(layout)

        popup = Popup(
            title="",
            content=content,
            size_hint=(0.85, 0.7),
            auto_dismiss=True,
            background_color=(0.12, 0.12, 0.15, 1),
        )

        close_btn = Button(
            text="Close",
            size_hint_y=None,
            height=dp(44),
            background_color=(0.3, 0.3, 0.35, 1),
            color=(0.85, 0.85, 0.9, 1),
        )
        close_btn.bind(on_release=popup.dismiss)
        layout.add_widget(close_btn)

        popup.open()


class ScanPanel(BoxLayout):
    """Main scan panel with controls and results."""

    def __init__(self, app_instance, **kwargs):
        super().__init__(**kwargs)
        self.app = app_instance
        self.orientation = "vertical"
        self.spacing = dp(8)
        self.padding = [dp(12), dp(8)]

        # --- Controls section ---
        controls = GridLayout(cols=1, spacing=dp(8),
                              size_hint_y=None, height=dp(180))

        # Target path row
        target_box = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(8))
        target_box.add_widget(Label(
            text="Target:",
            size_hint_x=0.22,
            halign="right",
            color=(0.8, 0.8, 0.85, 1),
            font_size=dp(13),
        ))
        self.target_input = TextInput(
            text=app_instance.target_path,
            multiline=False,
            font_size=dp(13),
            background_color=(0.14, 0.14, 0.17, 1),
            foreground_color=(0.9, 0.9, 0.92, 1),
            cursor_color=(0.4, 0.7, 0.95, 1),
            hint_text="/sdcard/Download",
        )
        target_box.add_widget(self.target_input)
        controls.add_widget(target_box)

        # Scan type row
        type_box = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(8))
        type_box.add_widget(Label(
            text="Type:",
            size_hint_x=0.22,
            halign="right",
            color=(0.8, 0.8, 0.85, 1),
            font_size=dp(13),
        ))
        self.type_spinner = Spinner(
            text=SCAN_TYPES[0],
            values=SCAN_TYPES,
            size_hint_x=0.78,
            background_color=(0.18, 0.18, 0.22, 1),
            color=(0.9, 0.9, 0.92, 1),
            font_size=dp(13),
            sync_height=True,
        )
        type_box.add_widget(self.type_spinner)
        controls.add_widget(type_box)

        # Scan button row
        btn_box = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(8))

        self.scan_btn = Button(
            text="[b]▶  START SCAN[/b]",
            markup=True,
            background_color=(0.15, 0.55, 0.25, 1),
            color=(1, 1, 1, 1),
            font_size=dp(14),
        )
        self.scan_btn.bind(on_release=self.start_scan)

        self.stop_btn = Button(
            text="[b]⏹  STOP[/b]",
            markup=True,
            background_color=(0.65, 0.2, 0.2, 1),
            color=(1, 1, 1, 1),
            font_size=dp(14),
            disabled=True,
            opacity=0.5,
        )
        self.stop_btn.bind(on_release=self.stop_scan)

        self.clear_btn = Button(
            text="Clear",
            size_hint_x=None,
            width=dp(72),
            background_color=(0.25, 0.25, 0.3, 1),
            color=(0.8, 0.8, 0.85, 1),
            font_size=dp(12),
        )
        self.clear_btn.bind(on_release=self.clear_results)

        btn_box.add_widget(self.scan_btn)
        btn_box.add_widget(self.stop_btn)
        btn_box.add_widget(self.clear_btn)
        controls.add_widget(btn_box)

        # Progress bar (hidden until scan starts)
        self.progress_bar = ProgressBar(
            max=100,
            value=0,
            size_hint_y=None,
            height=dp(8),
            opacity=0,
        )
        controls.add_widget(self.progress_bar)

        self.add_widget(controls)

        # --- Results section ---
        self.results_panel = ResultsPanel()
        self.add_widget(self.results_panel)

        # --- Scan state ---
        self.scan_thread = None
        self.stop_event = threading.Event()

    def start_scan(self, *args):
        target = self.target_input.text.strip()
        scan_type = self.type_spinner.text

        if not target:
            self.app.show_error("Please enter a target path.")
            return
        if not os.path.exists(target):
            self.app.show_error(f"Path does not exist:\n{target}")
            return

        self.stop_event.clear()
        self.results_panel.clear_results()

        # Update UI state
        self.scan_btn.disabled = True
        self.scan_btn.opacity = 0.4
        self.stop_btn.disabled = False
        self.stop_btn.opacity = 1.0
        self.progress_bar.opacity = 1.0
        self.progress_bar.value = 0

        self.app.status_bar.set_status(
            f"Scanning: {scan_type} on {target}...",
            "#ffaa00",
        )

        self.results_panel.add_result(
            f"[b]Scan Started[/b]  —  {scan_type}\n"
            f"Target: {target}\n"
            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "header",
        )

        # Start scan in background thread
        self.scan_thread = threading.Thread(
            target=self._run_scan,
            args=(target, scan_type),
            daemon=True,
        )
        self.scan_thread.start()

        # Animate progress bar
        self._animate_progress()

    def _animate_progress(self):
        """Simulate progress animation during scan."""
        def increment(dt):
            if self.stop_event.is_set():
                return False
            if self.progress_bar.value < 95:
                self.progress_bar.value += 1.5
                return True
            return False
        Clock.schedule_interval(increment, 0.3)

    def stop_scan(self, *args):
        self.stop_event.set()
        self.app.status_bar.set_status("Scan stopped by user", "#ff6600")
        self._reset_ui_state()

    def clear_results(self, *args):
        self.results_panel.clear_results()
        self.progress_bar.value = 0
        self.progress_bar.opacity = 0

    @mainthread
    def _reset_ui_state(self):
        self.scan_btn.disabled = False
        self.scan_btn.opacity = 1.0
        self.stop_btn.disabled = True
        self.stop_btn.opacity = 0.5
        self.progress_bar.value = 100 if not self.stop_event.is_set() else 0
        Clock.schedule_once(lambda dt: setattr(self.progress_bar, "opacity", 0), 1.5)

    def _run_scan(self, target, scan_type):
        """Execute the scan in a background thread."""
        start_time = time.time()

        try:
            result = self._execute_scan_command(target, scan_type)

            elapsed = time.time() - start_time
            if not self.stop_event.is_set():
                Clock.schedule_once(
                    lambda dt: self._on_scan_complete(result, elapsed), 0
                )
        except Exception as e:
            if not self.stop_event.is_set():
                Clock.schedule_once(
                    lambda dt: self._on_scan_error(str(e)), 0
                )

    def _execute_scan_command(self, target, scan_type):
        """Run the actual scan command via subprocess."""
        cmd_map = {
            "Quick Scan": ["veriforge-red", target, "--quick"],
            "Full Scan":  ["veriforge-red", target],
            "Privacy Audit": ["veriforge-privacy", target],
        }
        cmd = cmd_map.get(scan_type, cmd_map["Quick Scan"])

        # Fallback: try direct Python module execution
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.app.scan_timeout,
            )
        except FileNotFoundError:
            # Try Python fallback
            python_cmd = [
                sys.executable, "-m", "veriforge_red",
                "scan" if "Privacy" not in scan_type else "privacy",
                target,
            ]
            if scan_type == "Quick Scan":
                python_cmd.append("--quick")
            result = subprocess.run(
                python_cmd,
                capture_output=True,
                text=True,
                timeout=self.app.scan_timeout,
            )

        return result

    @mainthread
    def _on_scan_complete(self, result, elapsed):
        """Handle scan completion (runs on main thread)."""
        self._reset_ui_state()

        stdout = result.stdout or ""
        stderr = result.stderr or ""

        # Parse and display results
        if stdout.strip():
            for line in stdout.strip().splitlines()[:100]:
                line_type = self._classify_line(line)
                self.results_panel.add_result(
                    self._escape_markup(line),
                    line_type,
                )

        if stderr.strip() and result.returncode != 0:
            self.results_panel.add_result(
                f"[b]Errors:[/b]\n{self._escape_markup(stderr[:500])}",
                "error",
            )

        status = "SUCCESS" if result.returncode == 0 else f"EXIT {result.returncode}"
        color = "#00cc44" if result.returncode == 0 else "#ff4444"

        self.results_panel.add_result(
            f"[b]Scan Complete[/b]  —  {status}\n"
            f"Duration: {elapsed:.1f}s  |  Exit code: {result.returncode}",
            "success" if result.returncode == 0 else "error",
        )

        self.app.status_bar.set_status(
            f"Scan complete: {status} ({elapsed:.1f}s)",
            color,
        )

    @mainthread
    def _on_scan_error(self, error_msg):
        """Handle scan error (runs on main thread)."""
        self._reset_ui_state()
        self.results_panel.add_result(f"[b]Scan Error[/b]\n{error_msg}", "error")
        self.app.status_bar.set_status(f"Error: {error_msg[:60]}", "#ff4444")

    @staticmethod
    def _classify_line(line):
        """Classify a line for color coding."""
        line_lower = line.lower()
        if any(k in line_lower for k in ["error", "fail", "critical"]):
            return "error"
        if any(k in line_lower for k in ["warning", "warn", "caution"]):
            return "warning"
        if any(k in line_lower for k in ["found", "scanning", "checking"]):
            return "header"
        if any(k in line_lower for k in ["ok", "pass", "success", "clean"]):
            return "success"
        return "info"

    @staticmethod
    def _escape_markup(text):
        """Escape Kivy markup characters."""
        return text.replace("[", "[[").replace("]", "]]")


# ---------------------------------------------------------------------------
# Main Application
# ---------------------------------------------------------------------------

class VeriForgeApp(App):
    """Main Kivy application for VeriForge Android GUI."""

    target_path = StringProperty(DEFAULT_TARGET)
    scan_timeout = 300  # seconds

    def build(self):
        Window.clearcolor = (0.08, 0.08, 0.1, 1)

        root = BoxLayout(orientation="vertical")

        # Menu bar
        self.menu_bar = MenuBar(self)
        root.add_widget(self.menu_bar)

        # Main scan panel
        self.scan_panel = ScanPanel(self)
        root.add_widget(self.scan_panel)

        # Status bar
        self.status_bar = StatusBar()
        self.status_bar.set_status("Ready — Enter a target path and tap Start Scan")
        root.add_widget(self.status_bar)

        # Keyboard shortcut: Enter to start scan
        Window.bind(on_key_down=self._on_key_down)

        return root

    def _on_key_down(self, window, key, scancode, codepoint, modifier):
        if key == 13:  # Enter key
            if not self.scan_panel.scan_btn.disabled:
                self.scan_panel.start_scan()

    def show_error(self, message):
        """Show an error popup."""
        content = BoxLayout(orientation="vertical", spacing=dp(8), padding=dp(16))
        content.add_widget(Label(
            text=f"[color=#ff6666]⚠[/color]  {message}",
            markup=True,
            font_size=dp(14),
            halign="center",
            color=(0.9, 0.9, 0.92, 1),
        ))
        btn = Button(
            text="OK",
            size_hint_y=None,
            height=dp(44),
            background_color=(0.65, 0.2, 0.2, 1),
            color=(1, 1, 1, 1),
        )
        popup = Popup(
            title="Error",
            content=content,
            size_hint=(0.75, 0.3),
            auto_dismiss=False,
            background_color=(0.12, 0.12, 0.15, 1),
        )
        btn.bind(on_release=popup.dismiss)
        content.add_widget(btn)
        popup.open()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    VeriForgeApp().run()
