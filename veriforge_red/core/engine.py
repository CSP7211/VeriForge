"""Main RedEngine — coordinates all VeriForge Red security functions."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from .database import Database
from .monitor import Monitor
from .privacy import AndroidPrivacyAuditor, PrivacyAuditor, WindowsPrivacyAuditor
from .quarantine import QuarantineManager
from .remediation import RemediationEngine
from .scanner import Scanner
from .threat_detector import ThreatDetector
from .updater import Updater
from .vault import Vault
from .vulndb_loader import VulnDBLoader


class RedEngine:
    """Main engine for VeriForge Red. Coordinates all security functions."""

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        cfg = config or {}
        self.config = cfg

        self.db = Database(db_path=cfg.get("db_path"))
        self.scanner = Scanner(self.db)

        # Platform-specific privacy auditor
        platform = cfg.get("platform", self._detect_platform())
        if platform == "windows":
            self.privacy = WindowsPrivacyAuditor(self.db)
        elif platform == "android":
            self.privacy = AndroidPrivacyAuditor(self.db)
        else:
            self.privacy = WindowsPrivacyAuditor(self.db)  # default

        self.threat_detector = ThreatDetector(self.db)
        self.quarantine = QuarantineManager(
            self.db,
            quarantine_dir=cfg.get("quarantine_dir"),
        )
        self.remediation = RemediationEngine(self.db, self.quarantine)
        self.vault = Vault(
            vault_dir=cfg.get("vault_dir"),
            db=self.db,
        )
        self.monitor = Monitor(
            self.scanner, self.privacy, self.threat_detector,
            self.quarantine, self.remediation, self.db,
            intervals=cfg.get("monitor_intervals"),
        )

        # Update system and vulnerability database
        self.updater = Updater(self.db)
        self.vulndb = VulnDBLoader()

    # -- core operations --------------------------------------------------

    def full_system_scan(self) -> dict[str, Any]:
        """Run complete scan: code + privacy + threats."""
        import os
        target = self.config.get("scan_target", os.getcwd())

        # 1. Code scan via VeriClaw
        code_result = self.scanner.deep_scan(target)

        # 2. Privacy audit
        privacy_issues = self.privacy.audit_privacy()

        # 3. Threat detection
        threats = self.threat_detector.scan_directory(target)

        # Calculate composite grade
        code_grade = code_result.get("grade", "F")
        privacy_score = self.get_privacy_score()
        threat_count = len([t for t in threats if getattr(t, "status", "") == "active"])

        grade_map = {"A+": 0, "A": 1, "B": 2, "C": 3, "D": 4, "F": 5}
        code_penalty = grade_map.get(code_grade, 5)
        privacy_penalty = (100 - privacy_score) / 20  # 0–5
        threat_penalty = min(threat_count * 0.5, 5)  # cap at 5

        total_penalty = code_penalty + privacy_penalty + threat_penalty
        overall_score = max(0.0, 100.0 - (total_penalty * 10))

        # Map to grade
        grade = "A+"
        for g, threshold in [("A+", 95), ("A", 85), ("B", 70), ("C", 55), ("D", 40)]:
            if overall_score >= threshold:
                grade = g
                break
        else:
            grade = "F"

        return {
            "overall_score": round(overall_score, 1),
            "grade": grade,
            "code_scan": code_result,
            "privacy_issue_count": len(privacy_issues),
            "privacy_issues": [p.to_dict() for p in privacy_issues],
            "threat_count": len(threats),
            "threats": [t.to_dict() for t in threats],
            "timestamp": self._now(),
        }

    def get_dashboard(self) -> dict[str, Any]:
        """Return dashboard data for the UI."""
        overall = self.get_overall_score()
        security = self.get_security_score()
        privacy = self.get_privacy_score()
        active_threats = self.db.get_threat_count()
        quarantined = self.db.get_quarantine_count()
        last_scan = self.db.get_last_scan_time()
        scan_count_7d = self.db.get_scan_count_last_7d()
        recent_scans = self.db.get_all_scans(limit=10)
        recent_threats = self.db.get_all_threats(limit=10)
        recent_privacy = self.db.get_all_privacy_issues(limit=10)

        # Chart data: scans per day for last 7 days
        chart_data = self._build_chart_data(recent_scans)

        return {
            "overall_score": overall,
            "security_score": security,
            "privacy_score": privacy,
            "active_threats_count": active_threats,
            "quarantined_count": quarantined,
            "last_scan_time": last_scan,
            "scans_last_7d": scan_count_7d,
            "scan_history_chart_data": chart_data,
            "recent_findings": [
                {
                    "id": s.id,
                    "target": s.target,
                    "grade": s.grade,
                    "risk_score": s.risk_score,
                    "timestamp": s.timestamp,
                    "findings_count": len(s.findings),
                }
                for s in recent_scans
            ],
            "recent_threats": [
                {
                    "id": t.id,
                    "file_path": t.file_path,
                    "threat_type": t.threat_type,
                    "severity": t.severity,
                    "status": t.status,
                    "timestamp": t.timestamp,
                }
                for t in recent_threats
            ],
            "privacy_issues": [
                {
                    "id": p.id,
                    "category": p.category,
                    "setting_name": p.setting_name,
                    "severity": p.severity,
                    "description": p.description,
                    "timestamp": p.timestamp,
                }
                for p in recent_privacy
            ],
            "monitor_status": self.monitor.get_status(),
        }

    def start_monitoring(self) -> None:
        """Start background monitoring."""
        self.monitor.start()

    def stop_monitoring(self) -> None:
        """Stop background monitoring."""
        self.monitor.stop()

    # -- quarantine operations --------------------------------------------

    def quarantine_threat(self, threat_id: int) -> bool:
        """Quarantine a threat by its database ID."""
        threat = self.db.get_threat(threat_id)
        if threat is None:
            return False
        try:
            qid = self.quarantine.quarantine(
                threat.file_path,
                threat_info={
                    "threat_type": threat.threat_type,
                    "severity": threat.severity,
                },
            )
            self.db.update_threat_status(threat_id, "quarantined")
            return True
        except Exception:
            return False

    def restore_from_quarantine(self, quarantine_id: str) -> bool:
        """Restore a file from quarantine."""
        try:
            self.quarantine.restore(quarantine_id)
            return True
        except Exception:
            return False

    # -- vault operations -------------------------------------------------

    def store_in_vault(self, file_path: str, password: Optional[str] = None) -> str:
        """Encrypt and store a file in the vault."""
        return self.vault.store(file_path, password=password)

    # -- scoring ----------------------------------------------------------

    def get_privacy_score(self) -> float:
        """Return overall privacy score (0–100)."""
        return self.privacy.get_privacy_score()

    def get_security_score(self) -> float:
        """Return security score based on scan history and active threats."""
        active_threats = self.db.get_threat_count()
        quarantined = self.db.get_quarantine_count()
        last_scan = self.db.get_last_scan_time()

        # Base score
        score = 100.0
        # Deduct for active threats
        score -= active_threats * 10
        # Deduct for quarantined items (still a risk indicator)
        score -= quarantined * 5
        # Deduct if no recent scan
        if last_scan is None:
            score -= 20

        return max(0.0, round(score, 1))

    def get_overall_score(self) -> float:
        """Return composite score combining security + privacy."""
        sec = self.get_security_score()
        priv = self.get_privacy_score()
        # Weighted: 60% security, 40% privacy
        overall = (sec * 0.6) + (priv * 0.4)
        return round(overall, 1)

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _detect_platform() -> str:
        """Detect the current platform."""
        import sys
        if sys.platform == "win32":
            return "windows"
        # Heuristic for Android: check for /system/build.prop
        if __import__("os").path.isfile("/system/build.prop"):
            return "android"
        return "windows"  # default

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _build_chart_data(scans: list[Any]) -> list[dict[str, Any]]:
        """Build daily scan count chart data from recent scans."""
        from collections import Counter
        dates = []
        for s in scans:
            try:
                dt = datetime.fromisoformat(s.timestamp)
                dates.append(dt.strftime("%Y-%m-%d"))
            except Exception:
                pass
        counts = Counter(dates)
        return [{"date": d, "count": c} for d, c in sorted(counts.items())]

    # -- update system -----------------------------------------------------

    def check_for_updates(self, channel: str = "stable") -> dict:
        """Check for all available updates (app, vulndb, rules).

        Returns a dict with update status for the UI.
        """
        status = self.updater.get_full_status(channel)
        return {
            "app_version": status.app_version,
            "vulndb_version": status.vulndb_version,
            "rules_version": status.rules_version,
            "last_check": status.last_check,
            "app_update_available": status.app_update_available is not None,
            "app_update_version": status.app_update_available.version if status.app_update_available else None,
            "vulndb_update_available": status.vulndb_update_available is not None,
            "vulndb_update_version": status.vulndb_update_available.version if status.vulndb_update_available else None,
            "rules_update_available": status.rules_update_available is not None,
            "update_channel": status.update_channel,
        }

    def download_app_update(self, progress_callback=None):
        """Download the latest application update."""
        update_info = self.updater.check_app_update()
        if not update_info:
            return {"success": False, "message": "No application update available."}
        result = self.updater.download_app_update(update_info, progress_callback)
        return {"success": result.success, "message": result.message, "restart_required": result.restart_required}

    def download_vulndb_update(self, progress_callback=None):
        """Download the latest vulnerability database update."""
        vulndb_info = self.updater.check_vulndb_update()
        if not vulndb_info:
            return {"success": False, "message": "No vulnerability database update available."}
        result = self.updater.download_vulndb_update(vulndb_info, progress_callback)
        if result.success:
            # Reload the vuln DB
            self.vulndb = VulnDBLoader()
        return {"success": result.success, "message": result.message}

    def import_offline_update(self, package_path: str):
        """Import an update package from a file (for air-gapped environments)."""
        result = self.updater.import_offline_update(Path(package_path))
        if result.success and "vulndb" in result.action_taken:
            self.vulndb = VulnDBLoader()
        return {"success": result.success, "message": result.message}

    def get_vulndb_stats(self) -> dict:
        """Get statistics about the loaded vulnerability database."""
        return self.vulndb.get_stats()
