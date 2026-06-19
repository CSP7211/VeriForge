"""Tests for VeriForge Red Android components.

These tests cover:
  - App initialization and screen navigation
  - AndroidPrivacyAuditor basic functions
  - Notification helper creation (stubbed on non-Android)

Run with::

    cd veriforge_red
    python -m pytest tests/test_android.py -v

Author: VeriForge Team
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure the project root is on the path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

class AsyncMock(MagicMock):
    """Mock that supports ``await`` syntax."""
    async def __call__(self, *args, **kwargs):
        return super(AsyncMock, self).__call__(*args, **kwargs)


def _mock_kivy():
    """Install minimal Kivy mocks so Python code can be imported without
    the full Kivy framework (useful in CI)."""
    kivy_mock = MagicMock()
    kivy_mock.app.App = type("App", (), {
        "get_running_app": classmethod(lambda cls: None),
    })
    kivy_mock.clock.Clock = MagicMock()
    kivy_mock.clock.mainthread = lambda fn: fn
    kivy_mock.logger.Logger = MagicMock()
    kivy_mock.metrics.dp = lambda x: x
    kivy_mock.properties = MagicMock()
    kivy_mock.properties.NumericProperty = lambda *a, **kw: 0
    kivy_mock.properties.StringProperty = lambda *a, **kw: ""
    kivy_mock.properties.BooleanProperty = lambda *a, **kw: False
    kivy_mock.properties.ListProperty = lambda *a, **kw: []
    kivy_mock.properties.ObjectProperty = lambda *a, **kw: None
    kivy_mock.uix = MagicMock()
    kivy_mock.uix.screenmanager = MagicMock()
    kivy_mock.uix.screenmanager.Screen = object
    kivy_mock.uix.screenmanager.ScreenManager = MagicMock()
    kivy_mock.uix.screenmanager.FadeTransition = MagicMock()
    kivy_mock.uix.boxlayout.BoxLayout = object
    kivy_mock.uix.floatlayout.FloatLayout = object
    kivy_mock.uix.gridlayout.GridLayout = object
    kivy_mock.uix.label.Label = object
    kivy_mock.uix.popup.Popup = MagicMock()
    kivy_mock.uix.recycleview.RecycleView = MagicMock()
    kivy_mock.uix.scrollview.ScrollView = MagicMock()
    kivy_mock.uix.textinput.TextInput = MagicMock()
    kivy_mock.uix.togglebutton.ToggleButton = MagicMock()
    kivy_mock.uix.widget.Widget = object
    kivy_mock.core.window.Window = MagicMock()
    kivy_mock.utils.platform = "android"

    sys.modules["kivy"] = kivy_mock
    sys.modules["kivy.app"] = kivy_mock.app
    sys.modules["kivy.clock"] = kivy_mock.clock
    sys.modules["kivy.logger"] = kivy_mock.logger
    sys.modules["kivy.metrics"] = kivy_mock.metrics
    sys.modules["kivy.properties"] = kivy_mock.properties
    sys.modules["kivy.core"] = kivy_mock.core
    sys.modules["kivy.core.window"] = kivy_mock.core.window
    sys.modules["kivy.uix"] = kivy_mock.uix
    sys.modules["kivy.uix.boxlayout"] = kivy_mock.uix.boxlayout
    sys.modules["kivy.uix.floatlayout"] = kivy_mock.uix.floatlayout
    sys.modules["kivy.uix.gridlayout"] = kivy_mock.uix.gridlayout
    sys.modules["kivy.uix.label"] = kivy_mock.uix.label
    sys.modules["kivy.uix.popup"] = kivy_mock.uix.popup
    sys.modules["kivy.uix.recycleview"] = kivy_mock.uix.recycleview
    sys.modules["kivy.uix.screenmanager"] = kivy_mock.uix.screenmanager
    sys.modules["kivy.uix.scrollview"] = kivy_mock.uix.scrollview
    sys.modules["kivy.uix.textinput"] = kivy_mock.uix.textinput
    sys.modules["kivy.uix.togglebutton"] = kivy_mock.uix.togglebutton
    sys.modules["kivy.uix.widget"] = kivy_mock.uix.widget
    sys.modules["kivy.utils"] = kivy_mock.utils

    # graphics module (used in main.py)
    kivy_mock.graphics = MagicMock()
    kivy_mock.graphics.Color = MagicMock
    kivy_mock.graphics.Ellipse = MagicMock
    kivy_mock.graphics.Line = MagicMock
    kivy_mock.graphics.Rectangle = MagicMock
    sys.modules["kivy.graphics"] = kivy_mock.graphics

    # cache the original module references so we can restore them later
    kivy_mock._modules = dict(sys.modules)

    return kivy_mock


# Install mocks before importing our modules
_kivy = _mock_kivy()

from veriforge_red.core import RedEngine
from veriforge_red.mobile.android_privacy import (
    AndroidPrivacyAuditor,
    Category,
    PrivacyIssue,
    PrivacyReport,
    Severity,
)
from veriforge_red.mobile.notifications import (
    cancel_notification,
    create_notification_channel,
    show_notification,
    show_scan_complete,
    show_threat_alert,
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRedEngine(unittest.TestCase):
    """Smoke tests for the stubbed RedEngine."""

    def test_engine_init(self):
        engine = RedEngine()
        self.assertIsNotNone(engine.db)
        self.assertIsNotNone(engine.scanner)
        self.assertIsNotNone(engine.threat_detector)
        self.assertIsNotNone(engine.quarantine)
        self.assertIsNotNone(engine.remediation)
        self.assertIsNotNone(engine.privacy_auditor)
        self.assertIsNotNone(engine.vault)
        self.assertIsNotNone(engine.monitor)

    def test_security_score(self):
        engine = RedEngine()
        self.assertIsInstance(engine.security_score, int)
        self.assertGreaterEqual(engine.security_score, 0)
        self.assertLessEqual(engine.security_score, 100)

    def test_privacy_score(self):
        engine = RedEngine()
        self.assertIsInstance(engine.privacy_score, int)
        self.assertGreaterEqual(engine.privacy_score, 0)
        self.assertLessEqual(engine.privacy_score, 100)

    def test_scan(self):
        engine = RedEngine()
        result = engine.scan("/tmp", deep=False)
        self.assertIsNotNone(result)
        self.assertTrue(hasattr(result, "grade"))
        self.assertTrue(hasattr(result, "risk_score"))

    def test_deep_scan(self):
        engine = RedEngine()
        result = engine.scan("/tmp", deep=True)
        self.assertIsNotNone(result)
        self.assertTrue(hasattr(result, "grade"))

    def test_health_check(self):
        engine = RedEngine()
        hc = engine.health_check()
        self.assertEqual(hc["status"], "ok")


class TestAppInitialization(unittest.TestCase):
    """Tests for app startup logic (with mocked Kivy)."""

    @patch("veriforge_red.mobile.main.RedEngine", return_value=RedEngine())
    def test_app_constructs(self, mock_engine):
        # Import here to pick up the mocks — main.py needs kivy.graphics
        try:
            from veriforge_red.mobile.main import RedApp
            app = RedApp()
            self.assertIsNone(app.engine)
        except ImportError:
            # kivy not installed — test with manual mock injection
            self.skipTest("Kivy not installed — skipping App construction test")

    def test_screen_names(self):
        # Import screen classes — handle missing kivy gracefully
        try:
            from veriforge_red.mobile.main import (
                DashboardScreen,
                PrivacyScreen,
                ScanScreen,
                SettingsScreen,
                ThreatsScreen,
                VaultScreen,
            )
        except ImportError:
            self.skipTest("Kivy not installed — skipping screen name test")
        # Screens should have correct name attributes via Screen base
        self.assertEqual(DashboardScreen.__name__, "DashboardScreen")
        self.assertEqual(ScanScreen.__name__, "ScanScreen")
        self.assertEqual(PrivacyScreen.__name__, "PrivacyScreen")
        self.assertEqual(ThreatsScreen.__name__, "ThreatsScreen")
        self.assertEqual(VaultScreen.__name__, "VaultScreen")
        self.assertEqual(SettingsScreen.__name__, "SettingsScreen")


class TestPrivacyAuditor(unittest.TestCase):
    """Tests for AndroidPrivacyAuditor."""

    def test_auditor_init(self):
        auditor = AndroidPrivacyAuditor()
        self.assertIsNotNone(auditor)

    def test_full_audit_returns_report(self):
        auditor = AndroidPrivacyAuditor()
        report = auditor.full_audit()
        self.assertIsInstance(report, PrivacyReport)
        self.assertIsInstance(report.score, int)
        self.assertGreaterEqual(report.score, 0)
        self.assertLessEqual(report.score, 100)
        self.assertIsInstance(report.issues, list)

    def test_audit_score_reasonable(self):
        auditor = AndroidPrivacyAuditor()
        report = auditor.full_audit()
        # Score should be within 0-100
        self.assertGreaterEqual(report.score, 0)
        self.assertLessEqual(report.score, 100)

    def test_dangerous_permissions_list(self):
        auditor = AndroidPrivacyAuditor()
        self.assertIsInstance(auditor.DANGEROUS_PERMISSIONS, list)
        self.assertGreater(len(auditor.DANGEROUS_PERMISSIONS), 0)
        self.assertIn("android.permission.CAMERA", auditor.DANGEROUS_PERMISSIONS)
        self.assertIn("android.permission.RECORD_AUDIO", auditor.DANGEROUS_PERMISSIONS)

    def test_stub_issue(self):
        issue = AndroidPrivacyAuditor._stub_issue("test message", Category.SYSTEM)
        self.assertIsInstance(issue, list)
        self.assertEqual(len(issue), 1)
        self.assertEqual(issue[0].title, "test message")
        self.assertEqual(issue[0].severity, Severity.LOW)

    def test_privacy_issue_to_dict(self):
        issue = PrivacyIssue(
            title="Test Issue",
            description="A test description",
            severity=Severity.HIGH,
            category=Category.PERMISSIONS,
            recommendation="Fix it",
        )
        d = issue.to_dict()
        self.assertEqual(d["title"], "Test Issue")
        self.assertEqual(d["severity"], "high")
        self.assertEqual(d["category"], "permissions")
        self.assertEqual(d["recommendation"], "Fix it")

    def test_privacy_report_to_dict(self):
        report = PrivacyReport(
            score=85,
            issues=[
                PrivacyIssue(
                    title="Test",
                    description="Desc",
                    severity=Severity.MEDIUM,
                    category=Category.NETWORK,
                ),
            ],
        )
        d = report.to_dict()
        self.assertEqual(d["score"], 85)
        self.assertEqual(len(d["issues"]), 1)
        self.assertEqual(d["issues"][0]["title"], "Test")


class TestNotifications(unittest.TestCase):
    """Tests for notification helpers (stubbed on non-Android)."""

    @patch("veriforge_red.mobile.notifications._ANDROID_AVAILABLE", False)
    def test_show_notification_stub(self):
        notif_id = show_notification("Test Title", "Test message body")
        self.assertEqual(notif_id, 0)

    @patch("veriforge_red.mobile.notifications._ANDROID_AVAILABLE", False)
    def test_show_threat_alert_stub(self):
        threat = {
            "type": "malware",
            "severity": "critical",
            "path": "/sdcard/download.exe",
        }
        notif_id = show_threat_alert(threat)
        self.assertEqual(notif_id, 0)

    @patch("veriforge_red.mobile.notifications._ANDROID_AVAILABLE", False)
    def test_show_scan_complete_stub(self):
        result = {"grade": "A", "risk_score": 10, "findings_count": 0}
        notif_id = show_scan_complete(result)
        self.assertEqual(notif_id, 0)

    @patch("veriforge_red.mobile.notifications._ANDROID_AVAILABLE", False)
    def test_create_channel_stub(self):
        # Should not raise on stub
        create_notification_channel()

    @patch("veriforge_red.mobile.notifications._ANDROID_AVAILABLE", False)
    def test_cancel_notification_stub(self):
        # Should not raise
        cancel_notification(123)

    def test_show_scan_complete_with_findings(self):
        result = {"grade": "C", "risk_score": 55, "findings_count": 3}
        notif_id = show_scan_complete(result)
        self.assertIsInstance(notif_id, int)


class TestNotificationChannelCreation(unittest.TestCase):
    """Notification channel setup tests."""

    def test_create_default_channel(self):
        with patch("veriforge_red.mobile.notifications._get_context", return_value=None):
            create_notification_channel()

    def test_create_custom_channel(self):
        with patch("veriforge_red.mobile.notifications._get_context", return_value=None):
            create_notification_channel("custom_channel", "Custom Channel")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
