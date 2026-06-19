"""Background monitoring loop for VeriForge Red.

Monitors:
1. Watched directories (file changes trigger scans)
2. Privacy settings (periodic audit)
3. Active threats (continuous pattern detection)
4. Scheduled scans (cron-like)

Runs in a background thread with configurable intervals.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

if False:
    from .database import Database
    from .scanner import Scanner
    from .privacy import PrivacyAuditor
    from .threat_detector import ThreatDetector
    from .quarantine import QuarantineManager
    from .remediation import RemediationEngine


# ---------------------------------------------------------------------------
# Default intervals (seconds)
# ---------------------------------------------------------------------------

_DEFAULT_PRIVACY_INTERVAL = 3600       # 1 hour
_DEFAULT_THREAT_INTERVAL = 300         # 5 minutes
_DEFAULT_SCHEDULED_SCAN_INTERVAL = 86400  # 24 hours
_DEFAULT_STATUS_INTERVAL = 60          # 1 minute


class Monitor:
    """Background monitoring coordinator."""

    def __init__(
        self,
        scanner: Scanner,
        privacy: PrivacyAuditor,
        threat_detector: ThreatDetector,
        quarantine: QuarantineManager,
        remediation: RemediationEngine,
        db: Database,
        intervals: Optional[dict[str, int]] = None,
    ) -> None:
        self.scanner = scanner
        self.privacy = privacy
        self.threat_detector = threat_detector
        self.quarantine = quarantine
        self.remediation = remediation
        self.db = db

        self.intervals = intervals or {}
        self._privacy_interval = self.intervals.get("privacy", _DEFAULT_PRIVACY_INTERVAL)
        self._threat_interval = self.intervals.get("threat", _DEFAULT_THREAT_INTERVAL)
        self._scan_interval = self.intervals.get("scheduled_scan", _DEFAULT_SCHEDULED_SCAN_INTERVAL)

        self._running = False
        self._threads: list[threading.Thread] = []
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._status: dict[str, Any] = {
            "started_at": None,
            "privacy_audits": 0,
            "threat_scans": 0,
            "scheduled_scans": 0,
            "last_privacy_audit": None,
            "last_threat_scan": None,
            "last_scheduled_scan": None,
            "errors": [],
        }

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        """Start all monitoring threads."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._status["started_at"] = self._now()

        # Start watcher if not already running
        self._start_watcher()

        # Privacy audit thread
        t_privacy = threading.Thread(target=self._privacy_loop, daemon=True)
        t_privacy.start()
        self._threads.append(t_privacy)

        # Threat detection thread
        t_threat = threading.Thread(target=self._threat_loop, daemon=True)
        t_threat.start()
        self._threads.append(t_threat)

        # Scheduled scan thread
        t_scan = threading.Thread(target=self._scan_loop, daemon=True)
        t_scan.start()
        self._threads.append(t_scan)

    def stop(self) -> None:
        """Graceful shutdown of all monitoring threads."""
        self._running = False
        self._stop_event.set()
        self.scanner.stop_watching()
        for t in self._threads:
            t.join(timeout=5)
        self._threads.clear()

    def is_running(self) -> bool:
        return self._running

    # -- status -----------------------------------------------------------

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._status)

    # -- internal loops ---------------------------------------------------

    def _start_watcher(self) -> None:
        """Enable directory watching on common paths."""
        watch_paths = [str(__import__("pathlib").Path.cwd())]
        for wp in watch_paths:
            try:
                self.scanner.watch_directory(wp)
            except Exception as exc:
                self._status["errors"].append(f"Watcher error: {exc}")

    def _privacy_loop(self) -> None:
        """Periodically run privacy audits."""
        while not self._stop_event.wait(timeout=self._privacy_interval):
            if not self._running:
                break
            try:
                issues = self.privacy.audit_privacy()
                with self._lock:
                    self._status["privacy_audits"] += 1
                    self._status["last_privacy_audit"] = self._now()
                    self._status["last_privacy_issue_count"] = len(issues)
                # Auto-fix privacy issues where possible
                for issue in issues:
                    if getattr(issue, "category", "") in (
                        "file_permissions", "telemetry", "location_services"
                    ):
                        try:
                            self.remediation.fix_privacy_issue(issue)
                        except Exception:
                            pass
            except Exception as exc:
                with self._lock:
                    self._status["errors"].append(f"Privacy audit error: {exc}")

    def _threat_loop(self) -> None:
        """Periodically scan for active threats."""
        while not self._stop_event.wait(timeout=self._threat_interval):
            if not self._running:
                break
            try:
                # Scan current directory for threats
                cwd = str(__import__("pathlib").Path.cwd())
                threats = self.threat_detector.scan_directory(cwd)
                with self._lock:
                    self._status["threat_scans"] += 1
                    self._status["last_threat_scan"] = self._now()
                    self._status["last_threat_count"] = len(threats)
                # Auto-quarantine critical threats
                for threat in threats:
                    if getattr(threat, "severity", "") == "critical":
                        try:
                            self.quarantine.quarantine(
                                getattr(threat, "file_path", ""),
                                threat_info={
                                    "threat_type": getattr(threat, "threat_type", "unknown"),
                                    "severity": "critical",
                                },
                            )
                        except Exception:
                            pass
            except Exception as exc:
                with self._lock:
                    self._status["errors"].append(f"Threat scan error: {exc}")

    def _scan_loop(self) -> None:
        """Run scheduled full system scans."""
        while not self._stop_event.wait(timeout=self._scan_interval):
            if not self._running:
                break
            try:
                cwd = str(__import__("pathlib").Path.cwd())
                self.scanner.scan_target(cwd)
                with self._lock:
                    self._status["scheduled_scans"] += 1
                    self._status["last_scheduled_scan"] = self._now()
            except Exception as exc:
                with self._lock:
                    self._status["errors"].append(f"Scheduled scan error: {exc}")

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()
