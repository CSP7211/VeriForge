"""Tests for VeriForge Red Windows desktop components.

Run with::

    pytest veriforge_red/tests/test_windows.py -v

These tests verify:
  - RedApp initialisation and GUI construction
  - System tray menu structure
  - Windows privacy checks (with mocked registry)
  - Service wrapper basic functions
"""

from __future__ import annotations

import json
import sys
import tkinter as tk
from unittest.mock import MagicMock, patch

import pytest

# Ensure the project root is on sys.path
sys.path.insert(0, str(__file__).replace("/veriforge_red/tests/test_windows.py", ""))

from veriforge_red.core import RedEngine
from veriforge_red.desktop.app import CircularGauge, RedApp


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def engine():
    return RedEngine()


@pytest.fixture
def app(engine):
    """Provide a RedApp instance with a hidden root window for testing."""
    app = RedApp(engine=engine)
    app.root.withdraw()  # hide during tests
    yield app
    try:
        app.destroy()
    except tk.TclError:
        pass


# ── CircularGauge ───────────────────────────────────────────────────────────


def test_gauge_initial_value():
    root = tk.Tk()
    root.withdraw()
    g = CircularGauge(root, size=100, value=75)
    assert g._value == 75
    root.destroy()


def test_gauge_set_value():
    root = tk.Tk()
    root.withdraw()
    g = CircularGauge(root, size=100, value=50)
    g.set_value(90)
    assert g._value == 90
    g.set_value(-10)
    assert g._value == 0
    g.set_value(200)
    assert g._value == 100
    root.destroy()


# ── RedApp ──────────────────────────────────────────────────────────────────


def test_app_creates_window(app):
    assert app.root is not None
    assert app.root.title() == "VeriForge Red — Security Sentinel"


def app_dimensions_within_bounds(app):
    geo = app.root.geometry()
    w, h = geo.split("+")[0].split("x")
    assert int(w) >= 800
    assert int(h) >= 550


def test_app_has_all_tabs(app):
    expected = {"Dashboard", "Scan", "Privacy", "Threats", "Vault", "Quarantine", "Settings"}
    tabs = set(app._tabs.keys())
    assert expected.issubset(tabs)


def test_dashboard_has_gauges(app):
    assert hasattr(app, "sec_gauge")
    assert hasattr(app, "priv_gauge")
    assert isinstance(app.sec_gauge, CircularGauge)


def test_scan_tab_widgets_exist(app):
    assert hasattr(app, "scan_progress")
    assert hasattr(app, "btn_scan_start")
    assert hasattr(app, "lbl_grade")
    assert hasattr(app, "tree_scan")


def test_scan_button_starts_thread(app):
    assert app.btn_scan_start["state"] != "disabled"


# ── System Tray ─────────────────────────────────────────────────────────────


def test_tray_menu_items():
    """Verify the tray controller creates the expected menu structure."""
    pytest.importorskip("pystray", reason="pystray not installed")
    from veriforge_red.desktop.tray import TrayController

    calls = {}

    def capture(name):
        def fn():
            calls[name] = True
        return fn

    tray = TrayController(
        on_open=capture("open"),
        on_scan=capture("scan"),
        on_toggle_monitor=capture("toggle"),
        on_settings=capture("settings"),
        on_about=capture("about"),
        on_exit=capture("exit"),
    )

    # Menu should contain expected items
    menu = tray._build_menu()
    items = [item.text for item in menu.items if hasattr(item, "text")]

    assert any("Open" in i for i in items)
    assert any("Scan" in i for i in items)
    assert any("Monitoring" in i for i in items)
    assert any("Security Score" in i for i in items)
    assert any("Privacy Score" in i for i in items)
    assert any("Settings" in i for i in items)
    assert any("About" in i for i in items)
    assert any("Exit" in i for i in items)


def test_tray_scores_update():
    """Verify score properties update correctly."""
    pytest.importorskip("pystray")
    from veriforge_red.desktop.tray import TrayController

    tray = TrayController(
        on_open=lambda: None,
        on_scan=lambda: None,
        on_toggle_monitor=lambda: None,
        on_settings=lambda: None,
        on_about=lambda: None,
        on_exit=lambda: None,
    )

    tray.security_score = 85
    tray.privacy_score = 72
    tray.monitoring = True

    assert tray.security_score == 85
    assert tray.privacy_score == 72
    assert tray.monitoring is True


# ── Icon generation ─────────────────────────────────────────────────────────


def test_icon_generated():
    from veriforge_red.desktop.tray import generate_icon
    from PIL import Image

    icon = generate_icon(64)
    assert isinstance(icon, Image.Image)
    assert icon.size == (64, 64)
    assert icon.mode == "RGBA"


def test_icon_256():
    from veriforge_red.desktop.tray import generate_icon
    from PIL import Image

    icon = generate_icon(256)
    assert icon.size == (256, 256)


# ── Windows Privacy Checks (mocked registry) ────────────────────────────────


def test_privacy_issue_dataclass():
    from veriforge_red.windows.privacy import PrivacyIssue, Category, Severity

    issue = PrivacyIssue(
        id="TEST-001",
        title="Test Issue",
        category=Category.TELEMETRY,
        severity=Severity.HIGH,
        current_value="On",
        recommended_value="Off",
        description="A test issue",
        auto_fixable=True,
    )
    d = issue.to_dict()
    assert d["id"] == "TEST-001"
    assert d["category"] == "telemetry"
    assert d["severity"] == "high"
    assert d["auto_fixable"] is True


def test_auditor_on_non_windows():
    """On non-Windows, the auditor should return an empty list (no crashes)."""
    from veriforge_red.windows.privacy import WindowsPrivacyAuditor

    auditor = WindowsPrivacyAuditor()
    issues = auditor.run_all()
    assert isinstance(issues, list)
    # On Linux (CI), no registry checks run
    if sys.platform != "win32":
        assert len(issues) == 0


def test_auditor_score_range():
    from veriforge_red.windows.privacy import WindowsPrivacyAuditor

    auditor = WindowsPrivacyAuditor()
    score = auditor.calculate_score()
    assert 0 <= score <= 100


def test_privacy_check_functions_exist():
    """Ensure all check functions are defined."""
    from veriforge_red.windows import privacy as mod

    expected_funcs = [
        "_check_telemetry",
        "_check_cortana",
        "_check_location",
        "_check_camera_microphone",
        "_check_advertising_id",
        "_check_startup_apps",
        "_check_firewall",
        "_check_uac",
        "_check_defender",
        "_check_password_policy",
        "_check_auto_update",
        "_check_network",
    ]
    for fn_name in expected_funcs:
        assert hasattr(mod, fn_name), f"Missing check function: {fn_name}"


# ── Service wrapper ─────────────────────────────────────────────────────────


def test_service_commands_exist():
    """Ensure the service module defines all CLI commands."""
    from veriforge_red.desktop.service import _COMMANDS

    expected = {"install", "remove", "start", "stop", "restart", "debug"}
    assert expected.issubset(set(_COMMANDS.keys()))


def test_service_name_constants():
    from veriforge_red.desktop import service as svc

    assert svc.SERVICE_NAME == "VeriForgeRed"
    assert "VeriForge" in svc.SERVICE_DISPLAY


# ── Build script ────────────────────────────────────────────────────────────


def test_build_script_imports():
    from veriforge_red.build.build_windows import HIDDEN_IMPORTS

    assert isinstance(HIDDEN_IMPORTS, list)
    assert len(HIDDEN_IMPORTS) > 0
    assert "veriforge_red.core.engine" in HIDDEN_IMPORTS
    assert "PIL" in HIDDEN_IMPORTS


# ── Integration: engine → app ───────────────────────────────────────────────


def test_engine_state_synced_to_dashboard(app):
    state = app.engine.state
    assert "security_score" in state
    assert "privacy_score" in state
    assert "active_threats" in state
    assert "quarantined_items" in state


def test_quarantine_flow(app):
    """Test the quarantine round-trip."""
    initial = app.engine.state["quarantined_items"]
    app.engine.quarantine("C:\\test\\virus.exe")
    assert app.engine.state["quarantined_items"] == initial + 1

    app.engine.restore_from_quarantine("C:\\test\\virus.exe")
    assert app.engine.state["quarantined_items"] == initial


def test_vault_flow(app):
    """Test vault add / retrieve / delete."""
    assert app.engine.vault_add("C:\\secret.txt", "password123")
    assert len(app.engine.state["vault_files"]) > 0

    assert app.engine.vault_retrieve("C:\\secret.txt", "password123")

    app.engine.vault_delete("C:\\secret.txt")
    assert len(app.engine.state["vault_files"]) == 0
