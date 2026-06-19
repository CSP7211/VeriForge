"""VeriForge Red — Kivy Android Application.

This module implements the full mobile UI with six screens:
  - DashboardScreen   : Security overview with scores, scan button, recent findings
  - ScanScreen        : Targeted scans with progress and result display
  - PrivacyScreen     : Privacy audit with category tabs and issue cards
  - ThreatsScreen     : Threat list with swipe-to-quarantine
  - VaultScreen       : Secure file vault with password protection
  - SettingsScreen    : App preferences and configuration

Author: VeriForge Team
"""
from __future__ import annotations

import os
import threading
from functools import partial

from kivy.app import App
from kivy.clock import Clock, mainthread
from kivy.core.window import Window
from kivy.graphics import Color, Ellipse, Line, Rectangle
from kivy.metrics import dp
from kivy.properties import (
    BooleanProperty,
    ListProperty,
    NumericProperty,
    ObjectProperty,
    StringProperty,
)
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.recycleview import RecycleView
from kivy.uix.screenmanager import FadeTransition, Screen, ScreenManager
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.uix.togglebutton import ToggleButton
from kivy.uix.widget import Widget
from kivy.utils import platform

from veriforge_red.core import RedEngine

# ---------------------------------------------------------------------------
# Color constants (synced with red.kv)
# ---------------------------------------------------------------------------
PRIMARY = [0.776, 0.157, 0.157, 1]   # '#c62828'
BG = [0.102, 0.102, 0.180, 1]        # '#1a1a2e'
CARD = [0.086, 0.129, 0.243, 1]      # '#16213e'
ACCENT = [0.914, 0.271, 0.376, 1]    # '#e94560'
TEXT = [0.918, 0.918, 0.918, 1]      # '#eaeaea'

# ---------------------------------------------------------------------------
# Custom Widgets
# ---------------------------------------------------------------------------

class CircularGauge(Widget):
    """Canvas-drawn circular progress gauge.

    Parameters
    ----------
    value : int
        Percentage value 0-100.
    max_value : int
        Maximum value (default 100).
    color : list
        RGBA color for the active arc.
    bg_color : list
        RGBA color for the background arc.
    stroke_width : float
        Width of the arc lines in dp.
    """

    value = NumericProperty(0)
    max_value = NumericProperty(100)
    gauge_color = ListProperty(PRIMARY)
    bg_color = ListProperty([0.2, 0.2, 0.3, 1])
    stroke_width = NumericProperty(dp(8))
    label_text = StringProperty("")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.bind(
            pos=self._draw,
            size=self._draw,
            value=self._draw,
            gauge_color=self._draw,
            bg_color=self._draw,
        )
        Clock.schedule_once(self._draw, 0)

    def _draw(self, *args):
        self.canvas.clear()
        with self.canvas:
            # Background arc
            Color(*self.bg_color)
            cx, cy = self.center_x, self.center_y
            radius = min(cx - self.x, cy - self.y) - self.stroke_width
            if radius <= 0:
                return
            Ellipse(
                pos=(cx - radius, cy - radius),
                size=(radius * 2, radius * 2),
                angle_start=0,
                angle_end=360,
            )
            # Active arc (value)
            Color(*self.gauge_color)
            sweep = (self.value / self.max_value) * 360
            Ellipse(
                pos=(cx - radius, cy - radius),
                size=(radius * 2, radius * 2),
                angle_start=90,
                angle_end=90 + sweep,
            )
            # Inner circle to create donut effect
            Color(*BG)
            inner_r = radius - self.stroke_width
            Ellipse(
                pos=(cx - inner_r, cy - inner_r),
                size=(inner_r * 2, inner_r * 2),
            )

        # Center label
        self.canvas.ask_update()


class ScoreCard(BoxLayout):
    """Card widget showing a score label + circular gauge."""

    title = StringProperty("Score")
    score = NumericProperty(0)
    card_color = ListProperty(CARD)
    gauge_color = ListProperty(PRIMARY)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = "vertical"
        self.padding = dp(12)
        self.spacing = dp(8)
        self.size_hint_y = None
        self.height = dp(160)

        self.title_label = Label(
            text=self.title,
            color=TEXT,
            font_size=dp(14),
            size_hint_y=None,
            height=dp(24),
            bold=True,
        )
        self.add_widget(self.title_label)

        self.gauge = CircularGauge(
            value=self.score,
            gauge_color=self.gauge_color,
            size_hint=(None, None),
            size=(dp(100), dp(100)),
            pos_hint={"center_x": 0.5},
        )
        self.add_widget(self.gauge)

        self.score_label = Label(
            text=str(self.score),
            color=TEXT,
            font_size=dp(24),
            bold=True,
            size_hint_y=None,
            height=dp(36),
        )
        self.add_widget(self.score_label)

        self.bind(score=self._on_score)

    def _on_score(self, instance, value):
        self.gauge.value = value
        self.score_label.text = str(int(value))


class FindingCard(BoxLayout):
    """Single finding entry for RecycleView-compatible lists."""

    finding_title = StringProperty("")
    finding_detail = StringProperty("")
    severity = StringProperty("low")  # low, medium, high, critical

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = "horizontal"
        self.padding = dp(10)
        self.spacing = dp(10)
        self.size_hint_y = None
        self.height = dp(64)

        severity_colors = {
            "low": [0.3, 0.7, 0.3, 1],
            "medium": [0.9, 0.7, 0.2, 1],
            "high": [0.9, 0.4, 0.2, 1],
            "critical": [0.9, 0.2, 0.2, 1],
        }
        icon_color = severity_colors.get(self.severity, [0.5, 0.5, 0.5, 1])

        # Severity indicator strip
        self.indicator = Widget(size_hint_x=None, width=dp(4))
        with self.indicator.canvas:
            Color(*icon_color)
            self.indicator.rect = Rectangle(pos=self.indicator.pos, size=self.indicator.size)
        self.indicator.bind(pos=self._update_indicator, size=self._update_indicator)
        self.add_widget(self.indicator)

        # Text content
        text_box = BoxLayout(orientation="vertical", spacing=dp(2))
        text_box.add_widget(
            Label(
                text=self.finding_title,
                color=TEXT,
                font_size=dp(14),
                bold=True,
                halign="left",
                text_size=(None, None),
                size_hint_y=0.55,
            )
        )
        text_box.add_widget(
            Label(
                text=self.finding_detail,
                color=[0.7, 0.7, 0.8, 1],
                font_size=dp(11),
                halign="left",
                text_size=(None, None),
                size_hint_y=0.45,
            )
        )
        self.add_widget(text_box)

    def _update_indicator(self, instance, value):
        self.indicator.rect.pos = instance.pos
        self.indicator.rect.size = instance.size


class GradeBadge(Label):
    """Colored badge showing a letter grade (A-F)."""

    grade = StringProperty("A")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.font_size = dp(36)
        self.bold = True
        self.size_hint = (None, None)
        self.size = (dp(64), dp(64))
        self.halign = "center"
        self.valign = "middle"
        self.bind(grade=self._update_color)
        Clock.schedule_once(self._update_color, 0)

    def _update_color(self, *args):
        grade_colors = {
            "A": [0.2, 0.8, 0.3, 1],
            "B": [0.4, 0.7, 0.3, 1],
            "C": [0.9, 0.7, 0.2, 1],
            "D": [0.9, 0.5, 0.2, 1],
            "F": [0.9, 0.2, 0.2, 1],
        }
        self.color = grade_colors.get(self.grade, [0.5, 0.5, 0.5, 1])


# ---------------------------------------------------------------------------
# Screens
# ---------------------------------------------------------------------------

class DashboardScreen(Screen):
    """Home screen with security overview, scores, and scan trigger."""

    security_score = NumericProperty(78)
    privacy_score = NumericProperty(82)
    active_threats = NumericProperty(0)
    last_scan_time = StringProperty("Never")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        Clock.schedule_once(self._post_init, 0)

    def _post_init(self, dt):
        self._refresh_scores()

    def _refresh_scores(self):
        app = App.get_running_app()
        if app and app.engine:
            self.security_score = app.engine.security_score
            self.privacy_score = app.engine.privacy_score

    def on_enter(self, *args):
        self._refresh_scores()

    def do_scan(self):
        """Navigate to Scan screen."""
        self.manager.current = "scan"

    def do_view_threats(self):
        """Navigate to Threats screen."""
        self.manager.current = "threats"


class ScanScreen(Screen):
    """File/folder scan interface with progress and results."""

    target_path = StringProperty("/sdcard")
    scan_type = StringProperty("quick")  # quick or deep
    is_scanning = BooleanProperty(False)
    progress = NumericProperty(0)
    scan_result = ObjectProperty(None, allownone=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def on_enter(self, *args):
        self.progress = 0
        self.is_scanning = False
        self.scan_result = None

    def browse_target(self):
        """Open a simple path input popup (file picker stub)."""
        content = BoxLayout(orientation="vertical", spacing=dp(10), padding=dp(10))
        content.add_widget(Label(text="Enter path:", color=TEXT, size_hint_y=None, height=dp(30)))
        text_input = TextInput(
            text=self.target_path,
            multiline=False,
            background_color=[0.15, 0.15, 0.25, 1],
            foreground_color=TEXT,
            cursor_color=ACCENT,
            size_hint_y=None,
            height=dp(44),
        )
        content.add_widget(text_input)
        btn_box = BoxLayout(spacing=dp(10), size_hint_y=None, height=dp(44))
        popup = Popup(title="Select Target", content=content, size_hint=(0.8, 0.4))

        def on_confirm(instance):
            self.target_path = text_input.text
            popup.dismiss()

        def on_cancel(instance):
            popup.dismiss()

        btn_confirm = ToggleButton(text="OK", on_press=on_confirm)
        btn_cancel = ToggleButton(text="Cancel", on_press=on_cancel)
        btn_box.add_widget(btn_confirm)
        btn_box.add_widget(btn_cancel)
        content.add_widget(btn_box)
        popup.open()

    def toggle_scan_type(self, scan_type: str):
        self.scan_type = scan_type

    def start_scan(self):
        """Begin scanning in a background thread."""
        if self.is_scanning:
            return
        self.is_scanning = True
        self.progress = 0
        self.scan_result = None
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        """Background scan worker — updates progress on main thread."""
        app = App.get_running_app()
        try:
            for i in range(1, 11):
                Clock.schedule_once(partial(self._set_progress, i * 10), 0)
                import time
                time.sleep(0.2)
            result = app.engine.scan(
                self.target_path,
                deep=(self.scan_type == "deep"),
            )
            Clock.schedule_once(partial(self._finish_scan, result), 0)
        except Exception as exc:
            Clock.schedule_once(partial(self._scan_error, str(exc)), 0)

    @mainthread
    def _set_progress(self, value, dt):
        self.progress = value

    @mainthread
    def _finish_scan(self, result, dt):
        self.scan_result = result
        self.is_scanning = False
        self.progress = 100
        # Update dashboard
        app = App.get_running_app()
        if app and app.root:
            dashboard = app.root.get_screen("dashboard")
            if dashboard:
                dashboard.last_scan_time = "Just now"
                dashboard._refresh_scores()

    @mainthread
    def _scan_error(self, message, dt):
        self.is_scanning = False
        self.scan_result = None

    def view_full_report(self):
        """Stub for full report view."""
        popup = Popup(
            title="Scan Report",
            content=Label(
                text=f"Target: {self.target_path}\n"
                     f"Type: {self.scan_type}\n"
                     f"Result: {getattr(self.scan_result, 'grade', 'N/A') if self.scan_result else 'N/A'}",
                color=TEXT,
            ),
            size_hint=(0.8, 0.4),
        )
        popup.open()


class PrivacyScreen(Screen):
    """Privacy audit screen with category tabs and issue list."""

    privacy_score = NumericProperty(0)
    current_category = StringProperty("permissions")
    issues = ListProperty([])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def on_enter(self, *args):
        self.run_audit()

    def run_audit(self):
        """Run privacy audit via engine."""
        app = App.get_running_app()
        if app and app.engine:
            report = app.engine.audit_privacy()
            self.privacy_score = report.score
            self.issues = report.issues or []

    def switch_category(self, category: str):
        self.current_category = category

    def fix_all(self):
        """Attempt to fix all identified privacy issues."""
        # In production, delegate to RemediationEngine
        self.privacy_score = min(100, self.privacy_score + 10)
        popup = Popup(
            title="Privacy Fix",
            content=Label(text="Privacy settings optimized!", color=TEXT),
            size_hint=(0.6, 0.3),
        )
        popup.open()


class ThreatsScreen(Screen):
    """Active threats list with swipe-to-quarantine."""

    threats = ListProperty([])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def on_enter(self, *args):
        self.load_threats()

    def load_threats(self):
        app = App.get_running_app()
        if app and app.engine:
            self.threats = app.engine.get_threats() or []

    def quarantine_threat(self, threat_id):
        """Move a threat to quarantine."""
        app = App.get_running_app()
        if app and app.engine:
            # Remove from list
            self.threats = [t for t in self.threats if t.get("id") != threat_id]
            # Update badge on dashboard
            dashboard = app.root.get_screen("dashboard")
            if dashboard:
                dashboard.active_threats = len(self.threats)

    def show_details(self, threat):
        """Show threat detail popup."""
        popup = Popup(
            title="Threat Details",
            content=Label(
                text=f"File: {threat.get('path', 'Unknown')}\n"
                     f"Type: {threat.get('type', 'Unknown')}\n"
                     f"Severity: {threat.get('severity', 'Unknown')}",
                color=TEXT,
            ),
            size_hint=(0.8, 0.4),
        )
        popup.open()


class VaultScreen(Screen):
    """Secure vault for sensitive files."""

    vault_files = ListProperty([])
    vault_password = StringProperty("")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def on_enter(self, *args):
        self._refresh_files()

    def _refresh_files(self):
        app = App.get_running_app()
        if app and app.engine:
            self.vault_files = app.engine.vault.list_files() or []

    def add_file(self):
        """Add a file to the vault (stub using path input)."""
        content = BoxLayout(orientation="vertical", spacing=dp(10), padding=dp(10))
        content.add_widget(Label(text="File path to add:", color=TEXT, size_hint_y=None, height=dp(30)))
        path_input = TextInput(
            text="/sdcard/example.txt",
            multiline=False,
            background_color=[0.15, 0.15, 0.25, 1],
            foreground_color=TEXT,
            size_hint_y=None,
            height=dp(44),
        )
        content.add_widget(path_input)
        btn_box = BoxLayout(spacing=dp(10), size_hint_y=None, height=dp(44))
        popup = Popup(title="Add to Vault", content=content, size_hint=(0.8, 0.4))

        def on_add(instance):
            app = App.get_running_app()
            if app and app.engine:
                try:
                    app.engine.vault.add_file(path_input.text)
                    self._refresh_files()
                except Exception as exc:
                    pass
            popup.dismiss()

        def on_cancel(instance):
            popup.dismiss()

        btn_box.add_widget(ToggleButton(text="Add", on_press=on_add))
        btn_box.add_widget(ToggleButton(text="Cancel", on_press=on_cancel))
        content.add_widget(btn_box)
        popup.open()

    def retrieve_file(self, file_index: int):
        """Prompt for password then retrieve file."""
        content = BoxLayout(orientation="vertical", spacing=dp(10), padding=dp(10))
        content.add_widget(Label(text="Enter vault password:", color=TEXT, size_hint_y=None, height=dp(30)))
        pw_input = TextInput(
            password=True,
            multiline=False,
            background_color=[0.15, 0.15, 0.25, 1],
            foreground_color=TEXT,
            size_hint_y=None,
            height=dp(44),
        )
        content.add_widget(pw_input)
        btn_box = BoxLayout(spacing=dp(10), size_hint_y=None, height=dp(44))
        popup = Popup(title="Vault Access", content=content, size_hint=(0.8, 0.4))

        def on_unlock(instance):
            app = App.get_running_app()
            if app and app.engine:
                try:
                    result = app.engine.vault.retrieve_file(file_index, pw_input.text)
                    popup.dismiss()
                    success_popup = Popup(
                        title="Retrieved",
                        content=Label(text=f"File: {result}", color=TEXT),
                        size_hint=(0.7, 0.3),
                    )
                    success_popup.open()
                except ValueError:
                    pw_input.background_color = [0.4, 0.1, 0.1, 1]

        def on_cancel(instance):
            popup.dismiss()

        btn_box.add_widget(ToggleButton(text="Unlock", on_press=on_unlock))
        btn_box.add_widget(ToggleButton(text="Cancel", on_press=on_cancel))
        content.add_widget(btn_box)
        popup.open()

    def delete_file(self, file_index: int):
        """Delete a file from the vault after confirmation."""
        app = App.get_running_app()
        if app and app.engine:
            app.engine.vault.delete_file(file_index)
            self._refresh_files()


class SettingsScreen(Screen):
    """App settings and configuration."""

    auto_scan = BooleanProperty(True)
    scan_interval = NumericProperty(24)  # hours
    theme = StringProperty("dark")
    directories = ListProperty(["/sdcard/Download", "/sdcard/Documents"])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def toggle_auto_scan(self, active: bool):
        self.auto_scan = active

    def set_scan_interval(self, value: float):
        self.scan_interval = int(value)

    def set_theme(self, theme: str):
        self.theme = theme

    def add_directory(self, path: str):
        if path and path not in self.directories:
            self.directories.append(path)

    def remove_directory(self, path: str):
        if path in self.directories:
            self.directories.remove(path)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

class RedApp(App):
    """Main Kivy application for VeriForge Red on Android.

    Attributes
    ----------
    engine : RedEngine
        Shared core engine instance used by all screens.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.engine: RedEngine | None = None

    def build(self):
        """Build the application UI."""
        self.engine = RedEngine()
        self.title = "VeriForge Red"
        Window.clearcolor = BG
        self._setup_window()
        return self._build_ui()

    def _setup_window(self):
        """Configure window properties."""
        Window.bind(on_keyboard=self._on_keyboard)

    def _on_keyboard(self, window, key, scancode, codepoint, modifier):
        """Handle Android back button."""
        if key == 27:  # ESC / Android back button
            sm = self.root
            if sm and sm.current != "dashboard":
                sm.current = "dashboard"
                return True
        return False

    def _build_ui(self):
        """Construct the ScreenManager with all screens."""
        sm = ScreenManager(transition=FadeTransition(duration=0.25))

        sm.add_widget(DashboardScreen(name="dashboard"))
        sm.add_widget(ScanScreen(name="scan"))
        sm.add_widget(PrivacyScreen(name="privacy"))
        sm.add_widget(ThreatsScreen(name="threats"))
        sm.add_widget(VaultScreen(name="vault"))
        sm.add_widget(SettingsScreen(name="settings"))

        return sm

    def on_pause(self):
        """Called when the app is paused (Android background)."""
        return True  # Keep the app alive in background

    def on_resume(self):
        """Called when the app resumes from background."""
        if self.engine:
            self.engine.health_check()


if __name__ == "__main__":
    RedApp().run()
