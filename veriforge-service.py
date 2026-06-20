#!/usr/bin/env python3
"""
VeriForge Background Service — Android Foreground Service Stub
===============================================================

This module implements an Android foreground service that runs security
scans in the background with a persistent notification.

Architecture:
    - Started via Android Intent (from the Kivy GUI or external apps)
    - Creates a persistent notification (required for foreground services)
    - Runs the scan in a background thread
    - Updates the notification with progress
    - Publishes results back to the GUI via broadcast intents

Usage (from the Kivy app):
    from android import AndroidService
    service = AndroidService('VeriForge Scan', 'Running security scan...')
    service.start('target=/sdcard&type=quick')

Usage (from Termux command line):
    am startservice -n com.veriforge.red/.VeriForgeScan \
        --es target /sdcard --es type quick

Permissions required:
    - FOREGROUND_SERVICE
    - FOREGROUND_SERVICE_DATA_SYNC (Android 14+)
    - POST_NOTIFICATIONS (Android 13+)
    - WAKE_LOCK (to keep scan running)
"""

import os
import sys
import time
import threading
import subprocess
import json
from datetime import datetime

# ---------------------------------------------------------------------------
# Android bridging via PyJNIus
# ---------------------------------------------------------------------------
try:
    from jnius import autoclass, cast
    from android import python_activity as PythonActivity
    from android.runnable import run_on_ui_thread
    ANDROID_AVAILABLE = True
except ImportError:
    ANDROID_AVAILABLE = False
    # Stub classes for development/testing outside Android
    class MockClass:
        def __getattr__(self, name):
            return lambda *args, **kwargs: None
    autoclass = lambda name: MockClass()
    cast = lambda cls, obj: obj
    run_on_ui_thread = lambda fn: fn
    PythonActivity = None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SERVICE_NAME = "VeriForgeScan"
NOTIFICATION_CHANNEL_ID = "veriforge_scan_channel"
NOTIFICATION_CHANNEL_NAME = "VeriForge Security Scans"
NOTIFICATION_ID = 1001

SCAN_TYPE_MAP = {
    "quick": "Quick Scan",
    "full": "Full Scan",
    "privacy": "Privacy Audit",
}

# ---------------------------------------------------------------------------
# Android System Classes (lazy-loaded)
# ---------------------------------------------------------------------------
_android_classes = {}

def _get_android_class(name):
    """Lazy-load Android classes via autoclass."""
    if name not in _android_classes:
        try:
            _android_classes[name] = autoclass(name)
        except Exception:
            _android_classes[name] = None
    return _android_classes[name]


# ---------------------------------------------------------------------------
# Notification Management
# ---------------------------------------------------------------------------

class ScanNotification:
    """Manages the persistent foreground service notification."""

    def __init__(self):
        self.notification_manager = None
        self.builder = None
        self._create_channel()

    def _create_channel(self):
        """Create the notification channel (required for Android 8+)."""
        if not ANDROID_AVAILABLE:
            return

        try:
            context = self._get_context()
            NotificationChannel = _get_android_class(
                "android.app.NotificationChannel"
            )
            NotificationManager = _get_android_class(
                "android.app.NotificationManager"
            )
            Importance = _get_android_class(
                "android.app.NotificationManager"
            )

            if NotificationChannel is None:
                return

            channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                NOTIFICATION_CHANNEL_NAME,
                2,  # IMPORTANCE_LOW = 2 (no sound, shows in tray)
            )
            channel.setDescription(
                "Shows progress of ongoing VeriForge security scans"
            )
            channel.setShowBadge(False)

            nm = context.getSystemService(
                context.NOTIFICATION_SERVICE
            )
            if nm:
                nm.createNotificationChannel(channel)
                self.notification_manager = nm

        except Exception as e:
            self._log(f"Notification channel creation failed: {e}")

    def _get_context(self):
        """Get the current Android application context."""
        if PythonActivity is not None:
            return PythonActivity.mActivity
        # Fallback: try to get context via autoclass
        PythonActivityCls = _get_android_class(
            "org.kivy.android.PythonActivity"
        )
        if PythonActivityCls:
            return PythonActivityCls.mActivity
        return None

    def build_notification(self, title, message, progress=None, max_progress=100):
        """Build a notification with optional progress."""
        if not ANDROID_AVAILABLE:
            return None

        try:
            context = self._get_context()
            NotificationBuilder = _get_android_class(
                "android.app.Notification$Builder"
            )
            if NotificationBuilder is None:
                return None

            builder = NotificationBuilder(context, NOTIFICATION_CHANNEL_ID)
            builder.setContentTitle(title)
            builder.setContentText(message)
            builder.setSmallIcon(
                context.getApplicationInfo().icon
            )
            builder.setOngoing(True)
            builder.setAutoCancel(False)
            builder.setOnlyAlertOnce(True)

            # Add progress bar if specified
            if progress is not None:
                builder.setProgress(max_progress, progress, progress == 0)

            return builder.build()

        except Exception as e:
            self._log(f"Failed to build notification: {e}")
            return None

    def show(self, title, message, progress=None):
        """Show or update the notification."""
        if self.notification_manager is None:
            return

        notification = self.build_notification(title, message, progress)
        if notification:
            try:
                self.notification_manager.notify(
                    NOTIFICATION_ID, notification
                )
            except Exception as e:
                self._log(f"Failed to show notification: {e}")

    def cancel(self):
        """Cancel the notification."""
        if self.notification_manager:
            try:
                self.notification_manager.cancel(NOTIFICATION_ID)
            except Exception as e:
                self._log(f"Failed to cancel notification: {e}")

    def _log(self, message):
        """Write to log file for debugging."""
        log_file = os.path.join(
            os.path.expanduser("~"), "veriforge_service.log"
        )
        timestamp = datetime.now().isoformat()
        with open(log_file, "a") as f:
            f.write(f"[{timestamp}] {message}\n")


# ---------------------------------------------------------------------------
# Foreground Service
# ---------------------------------------------------------------------------

class VeriForgeScanService:
    """
    Android foreground service that manages background security scans.

    Lifecycle:
        1. Service started via intent
        2. Start foreground with persistent notification
        3. Execute scan in background thread
        4. Update notification with progress
        5. Publish results, stop foreground
    """

    def __init__(self):
        self.notification = ScanNotification()
        self._stop_event = threading.Event()
        self._scan_thread = None
        self._start_time = None
        self.results = []

    # ---- Service lifecycle ----

    def on_start(self, arguments=None):
        """
        Called when the service is started.

        Args:
            arguments: String of key=value pairs separated by &.
                       e.g. "target=/sdcard&type=quick"
        """
        self._log("=" * 50)
        self._log("VeriForgeScanService.on_start()")
        self._log(f"arguments={arguments}")

        # Parse arguments
        params = self._parse_arguments(arguments or "")
        target = params.get("target", "/sdcard")
        scan_type = params.get("type", "quick")

        self._log(f"target={target}, scan_type={scan_type}")

        # Start as foreground service
        self._start_foreground("VeriForge Scan starting...")

        # Begin scan in background thread
        self._start_time = time.time()
        self._scan_thread = threading.Thread(
            target=self._execute_scan,
            args=(target, scan_type),
            daemon=True,
        )
        self._scan_thread.start()

    def on_stop(self):
        """Called when the service is being stopped."""
        self._log("VeriForgeScanService.on_stop()")
        self._stop_event.set()
        self._stop_foreground()

    # ---- Foreground management ----

    def _start_foreground(self, initial_message):
        """Promote service to foreground with persistent notification."""
        self._log("Starting foreground service...")
        self.notification.show("VeriForge Scan", initial_message, progress=0)

        if ANDROID_AVAILABLE:
            try:
                Service = _get_android_class("android.app.Service")
                Notification = _get_android_class("android.app.Notification")
                if Service and Notification:
                    notification = self.notification.build_notification(
                        "VeriForge Scan", initial_message
                    )
                    if notification:
                        # startForeground requires a notification
                        service_instance = self._get_service_instance()
                        if service_instance:
                            service_instance.startForeground(
                                NOTIFICATION_ID, notification
                            )
                            self._log("Foreground service started")
            except Exception as e:
                self._log(f"Foreground start error: {e}")

    def _stop_foreground(self):
        """Stop the foreground service and remove notification."""
        self._log("Stopping foreground service...")
        self.notification.cancel()

        if ANDROID_AVAILABLE:
            try:
                service_instance = self._get_service_instance()
                if service_instance:
                    service_instance.stopForeground(True)
                    self._log("Foreground service stopped")
            except Exception as e:
                self._log(f"Foreground stop error: {e}")

    def _get_service_instance(self):
        """Get the current Android service instance."""
        try:
            if PythonActivity is not None:
                return PythonActivity.mService
            PythonService = _get_android_class(
                "org.kivy.android.PythonService"
            )
            if PythonService:
                return PythonService.mService
        except Exception:
            pass
        return None

    # ---- Scan execution ----

    def _execute_scan(self, target, scan_type):
        """Execute the scan command and handle results."""
        self._log(f"Starting scan: type={scan_type}, target={target}")

        # Map scan type to command
        cmd = self._build_command(target, scan_type)
        self._log(f"Command: {' '.join(cmd)}")

        # Update notification
        self.notification.show(
            "VeriForge Scan Running",
            f"{SCAN_TYPE_MAP.get(scan_type, scan_type)} on {target}",
            progress=10,
        )

        try:
            # Run scan with subprocess
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            # Stream output and update progress
            output_lines = []
            progress = 10
            for line in proc.stdout:
                line = line.rstrip()
                output_lines.append(line)
                self._log(f"SCAN: {line}")

                # Increment progress toward 90%
                if progress < 90:
                    progress += 2
                    self.notification.show(
                        "VeriForge Scan Running",
                        f"Scanning... ({len(output_lines)} items checked)",
                        progress=progress,
                    )

                if self._stop_event.is_set():
                    proc.terminate()
                    self._log("Scan terminated by stop request")
                    break

            proc.wait()
            exit_code = proc.returncode

        except FileNotFoundError:
            self._log(f"Command not found: {cmd[0]}")
            # Fallback: try Python module
            output_lines, exit_code = self._fallback_python_scan(
                target, scan_type
            )
        except Exception as e:
            self._log(f"Scan execution error: {e}")
            output_lines = [f"Error: {e}"]
            exit_code = 1

        elapsed = time.time() - self._start_time
        self._log(f"Scan completed in {elapsed:.1f}s (exit={exit_code})")

        # Final notification
        if exit_code == 0:
            self.notification.show(
                "✓ VeriForge Scan Complete",
                f"Scan finished in {elapsed:.1f}s. "
                f"Tap to view results.",
            )
        else:
            self.notification.show(
                "⚠ VeriForge Scan Finished",
                f"Scan completed with issues (exit={exit_code}).",
            )

        # Store results
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "scan_type": scan_type,
            "exit_code": exit_code,
            "elapsed_seconds": round(elapsed, 1),
            "output": output_lines,
        }

        # Save results to file for the GUI to read
        self._save_results()

        # Stop foreground after a delay so user sees completion
        def delayed_stop():
            time.sleep(5)
            self._stop_foreground()
        threading.Thread(target=delayed_stop, daemon=True).start()

    def _build_command(self, target, scan_type):
        """Build the scan command based on scan type."""
        base = ["veriforge-red"]
        if scan_type == "quick":
            return [*base, target, "--quick"]
        elif scan_type == "privacy":
            return ["veriforge-privacy", target]
        else:
            return [*base, target]

    def _fallback_python_scan(self, target, scan_type):
        """Fallback scan using direct Python module invocation."""
        self._log("Attempting fallback Python scan...")
        try:
            cmd = [
                sys.executable, "-m", "veriforge_red",
                "scan" if scan_type != "privacy" else "privacy",
                target,
            ]
            if scan_type == "quick":
                cmd.append("--quick")

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )
            return (result.stdout.splitlines(), result.returncode)
        except Exception as e:
            self._log(f"Fallback scan failed: {e}")
            return ([f"Scan unavailable: {e}"], 1)

    def _save_results(self):
        """Save scan results to a JSON file."""
        results_path = os.path.join(
            os.path.expanduser("~"), ".veriforge_last_scan.json"
        )
        try:
            with open(results_path, "w") as f:
                json.dump(self.results, f, indent=2)
            self._log(f"Results saved to {results_path}")
        except Exception as e:
            self._log(f"Failed to save results: {e}")

    # ---- Utilities ----

    @staticmethod
    def _parse_arguments(arg_string):
        """Parse argument string into a dict.

        Format: key1=value1&key2=value2
        """
        params = {}
        if not arg_string:
            return params
        for pair in arg_string.split("&"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                params[key.strip()] = value.strip()
        return params

    @staticmethod
    def _log(message):
        """Write to the service log file."""
        log_file = os.path.join(
            os.path.expanduser("~"), "veriforge_service.log"
        )
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(log_file, "a") as f:
                f.write(f"[{timestamp}] {message}\n")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Service Entry Point
# ---------------------------------------------------------------------------

def main():
    """Main entry point when run as an Android service."""
    service = VeriForgeScanService()

    # In a real Android environment, arguments come via Intent extras
    # When run via python-for-android service mechanism, sys.argv contains
    # the arguments passed from the parent app.
    arguments = "&".join(sys.argv[1:]) if len(sys.argv) > 1 else ""

    try:
        service.on_start(arguments)

        # Keep the service alive while scan runs
        while service._scan_thread and service._scan_thread.is_alive():
            time.sleep(1)

    except KeyboardInterrupt:
        service._log("Service interrupted")
    finally:
        service.on_stop()


# When invoked as the __main__ module (python-for-android service entry point)
if __name__ == "__main__":
    main()
