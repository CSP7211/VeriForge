"""Android foreground service for background security monitoring.

This module implements a persistent foreground service that:
  - Runs a file-system monitoring loop
  - Performs periodic privacy audits
  - Detects threats on newly created/modified files
  - Posts notification alerts when threats are found

It uses ``pyjnius`` to access Android Java APIs from Python.
"""
from __future__ import annotations

import os
import threading
import time
from enum import IntEnum

from kivy.clock import Clock, mainthread
from kivy.logger import Logger

# ---------------------------------------------------------------------------
# Android imports via pyjnius
# ---------------------------------------------------------------------------

try:
    from jnius import autoclass, cast

    _ANDROID_AVAILABLE = True
except ImportError:
    _ANDROID_AVAILABLE = False
    Logger.warning("android_service: pyjnius not available — running in stub mode")

    # Stubs for development on non-Android platforms
    class _autoclass_stub:
        """Stub for jnius.autoclass when not on Android."""

        def __init__(self, name: str):
            self._name = name

        def __call__(self, *args, **kwargs):
            class _stub:
                def __init__(self, *a, **kw):
                    pass

                def __getattr__(self, item):
                    return lambda *a, **kw: None

            return _stub(*args, **kwargs)

    autoclass = _autoclass_stub
    cast = lambda cls, obj: obj


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SERVICE_CHANNEL_ID = "veriforge_red_monitor"
SERVICE_CHANNEL_NAME = "VeriForge Red Monitor"
SERVICE_NOTIFICATION_ID = 1001

WAKE_LOCK_TAG = "VeriForgeRed::MonitorWakeLock"


class ServiceAction(IntEnum):
    """Actions that can be sent to the service via intents."""
    START = 1
    STOP = 2
    SCAN_TRIGGERED = 3
    THREAT_FOUND = 4


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_android_context():
    """Return the current Android application context."""
    if not _ANDROID_AVAILABLE:
        return None
    PythonActivity = autoclass("org.kivy.android.PythonActivity")
    return PythonActivity.mActivity


def _create_notification_channel(context) -> None:
    """Create a notification channel for Android O+ (API 26+)."""
    if not _ANDROID_AVAILABLE or context is None:
        return
    try:
        NotificationChannel = autoclass("android.app.NotificationChannel")
        NotificationManager = autoclass("android.app.NotificationManager")
        IMPORTANCE_LOW = autoclass("android.app.NotificationManager").IMPORTANCE_LOW

        channel = NotificationChannel(
            SERVICE_CHANNEL_ID,
            SERVICE_CHANNEL_NAME,
            IMPORTANCE_LOW,
        )
        channel.setDescription("Background security monitoring and threat detection")
        nm = cast(
            "android.app.NotificationManager",
            context.getSystemService(context.NOTIFICATION_SERVICE),
        )
        nm.createNotificationChannel(channel)
        Logger.info("android_service: notification channel created")
    except Exception as exc:
        Logger.error("android_service: failed to create channel: %s", exc)


def _build_foreground_notification(context) -> object:
    """Build the persistent foreground notification.

    Returns the Notification object to pass to startForeground().
    """
    if not _ANDROID_AVAILABLE or context is None:
        return None
    try:
        NotificationBuilder = autoclass("android.app.Notification$Builder")
        Intent = autoclass("android.content.Intent")
        PendingIntent = autoclass("android.app.PendingIntent")
        PythonActivity = autoclass("org.kivy.android.PythonActivity")

        _create_notification_channel(context)

        intent = Intent(context, PythonActivity)
        pending_intent = PendingIntent.getActivity(
            context, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT,
        )

        builder = NotificationBuilder(context, SERVICE_CHANNEL_ID)
        builder.setContentTitle("VeriForge Red")
        builder.setContentText("Security monitoring active")
        builder.setSmallIcon(context.getApplicationInfo().icon)
        builder.setContentIntent(pending_intent)
        builder.setOngoing(True)
        builder.setAutoCancel(False)

        return builder.build()
    except Exception as exc:
        Logger.error("android_service: failed to build notification: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Foreground Service
# ---------------------------------------------------------------------------

class RedMonitorService:
    """Android foreground service for background monitoring.

    The service runs a background thread that:
      1. Acquires a partial wake lock to keep the CPU alive.
      2. Monitors configured directories for changes.
      3. Runs periodic privacy audits (default every 4 hours).
      4. Scans new/modified files for threats.
      5. Posts notifications when threats are detected.

    Usage
    -----
    service = RedMonitorService(engine=RedEngine())
    service.start()
    # ... later
    service.stop()
    """

    def __init__(self, engine=None, scan_interval_sec: int = 3600 * 4):
        """
        Parameters
        ----------
        engine : RedEngine, optional
            The VeriForge Red core engine instance.
        scan_interval_sec : int
            Seconds between periodic scans (default 4 hours).
        """
        self._engine = engine
        self._scan_interval = scan_interval_sec
        self._running = False
        self._thread: threading.Thread | None = None
        self._wake_lock = None
        self._notification_manager = None

    # -- Public API ---------------------------------------------------------

    def start(self) -> None:
        """Start the foreground service."""
        if self._running:
            Logger.warning("android_service: service already running")
            return
        self._running = True
        context = _get_android_context()
        if context is not None:
            self._start_foreground(context)
            self._acquire_wake_lock(context)
            self._notification_manager = cast(
                "android.app.NotificationManager",
                context.getSystemService(context.NOTIFICATION_SERVICE),
            )
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        Logger.info("android_service: service started")

    def stop(self) -> None:
        """Request a graceful shutdown."""
        self._running = False
        self._release_wake_lock()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        Logger.info("android_service: service stopped")

    def is_running(self) -> bool:
        return self._running

    def on_file_changed(self, path: str) -> None:
        """Callback invoked when a monitored file changes.

        Triggers a scan and posts a notification if a threat is found.
        """
        Logger.info("android_service: file changed — %s", path)
        if self._engine is None:
            return
        try:
            findings = self._engine.detect_threat(path)
            if findings:
                self._post_threat_notification(path, findings)
        except Exception as exc:
            Logger.error("android_service: scan error for %s: %s", path, exc)

    # -- Internal -----------------------------------------------------------

    def _start_foreground(self, context) -> None:
        """Promote the service to a foreground service with a notification."""
        try:
            notification = _build_foreground_notification(context)
            if notification is not None:
                Service = autoclass("android.app.Service")
                context.startForeground(SERVICE_NOTIFICATION_ID, notification)
                Logger.info("android_service: entered foreground mode")
        except Exception as exc:
            Logger.error("android_service: foreground start failed: %s", exc)

    def _acquire_wake_lock(self, context) -> None:
        """Acquire a partial wake lock to keep the CPU running."""
        try:
            PowerManager = autoclass("android.os.PowerManager")
            pm = cast(
                "android.os.PowerManager",
                context.getSystemService(context.POWER_SERVICE),
            )
            self._wake_lock = pm.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                WAKE_LOCK_TAG,
            )
            self._wake_lock.acquire()
            Logger.info("android_service: wake lock acquired")
        except Exception as exc:
            Logger.error("android_service: wake lock failed: %s", exc)

    def _release_wake_lock(self) -> None:
        """Release the wake lock."""
        if self._wake_lock is not None:
            try:
                self._wake_lock.release()
                Logger.info("android_service: wake lock released")
            except Exception as exc:
                Logger.error("android_service: wake lock release error: %s", exc)
            finally:
                self._wake_lock = None

    def _monitor_loop(self) -> None:
        """Main background loop."""
        last_privacy_check = 0
        monitored_paths = ["/sdcard/Download", "/sdcard/Documents"]
        last_mtimes: dict[str, float] = {}

        while self._running:
            try:
                # Check for file changes
                for path in monitored_paths:
                    if os.path.exists(path):
                        current_mtime = os.path.getmtime(path)
                        if path in last_mtimes and current_mtime != last_mtimes[path]:
                            self.on_file_changed(path)
                        last_mtimes[path] = current_mtime

                # Periodic privacy audit
                now = time.time()
                if now - last_privacy_check > self._scan_interval:
                    self._run_privacy_audit()
                    last_privacy_check = now

                time.sleep(30)  # 30-second polling interval
            except Exception as exc:
                Logger.error("android_service: monitor loop error: %s", exc)
                time.sleep(60)

    def _run_privacy_audit(self) -> None:
        """Run a privacy audit and report findings."""
        if self._engine is None:
            return
        try:
            report = self._engine.audit_privacy()
            Logger.info("android_service: privacy audit complete — score %s", report.score)
            if report.score < 50:
                self._post_notification(
                    "Privacy Alert",
                    f"Your privacy score is low ({report.score}). Review settings.",
                )
        except Exception as exc:
            Logger.error("android_service: privacy audit error: %s", exc)

    def _post_notification(self, title: str, message: str) -> None:
        """Post a standard notification."""
        if not _ANDROID_AVAILABLE or self._notification_manager is None:
            return
        try:
            NotificationBuilder = autoclass("android.app.Notification$Builder")
            context = _get_android_context()
            if context is None:
                return
            builder = NotificationBuilder(context, SERVICE_CHANNEL_ID)
            builder.setContentTitle(title)
            builder.setContentText(message)
            builder.setSmallIcon(context.getApplicationInfo().icon)
            builder.setAutoCancel(True)
            self._notification_manager.notify(
                hash(title) % 10000,
                builder.build(),
            )
        except Exception as exc:
            Logger.error("android_service: notification error: %s", exc)

    def _post_threat_notification(self, path: str, findings: list) -> None:
        """Post an urgent threat notification."""
        severity = findings[0].get("severity", "unknown") if findings else "unknown"
        title = f"Threat Detected ({severity.upper()})"
        message = os.path.basename(path)
        self._post_notification(title, message)


# ---------------------------------------------------------------------------
# Entry point used by Android service launcher
# ---------------------------------------------------------------------------

def run_service(engine=None):
    """Entry point for the Android service process.

    Called by ``org.kivy.android.PythonService`` when the service starts.
    """
    service = RedMonitorService(engine=engine)
    service.start()
    # Block the service thread
    try:
        while service.is_running():
            time.sleep(1)
    except KeyboardInterrupt:
        service.stop()


if __name__ == "__main__":
    from veriforge_red.core import RedEngine
    run_service(engine=RedEngine())
