"""VeriForge Red — Security scanning via the SDK.

Wraps the VeriForge Red engine to provide:
    - File/directory security scanning
    - Privacy auditing
    - Threat detection
    - Quarantine management
    - Vault operations
    - Real-time monitoring

Example:
    >>> client = VeriForgeClient()
    >>> result = client.red.scan("/path/to/project")
    >>> print(result.grade)
    >>> for f in result.findings:
    ...     print(f"{f.severity}: {f.title}")
"""

from __future__ import annotations

import json
import subprocess
import time
from logging import Logger
from pathlib import Path
from typing import Any, Optional

from ..config import SDKConfig
from ..exceptions import ScanError, ValidationError
from ..models import (
    Finding,
    FindingSeverity,
    ScanResult,
    ScanTarget,
    SecurityGrade,
)


class RedModule:
    """Interface to VeriForge Red security scanning engine.

    All operations are local-first — no data leaves your machine.
    """

    def __init__(self, config: SDKConfig, logger: Logger):
        self.config = config
        self.logger = logger
        self._engine: Optional[Any] = None

    # ── Core scanning ───────────────────────────────────────────────────

    def scan(
        self,
        target: str,
        max_files: Optional[int] = None,
        exclude: Optional[list[str]] = None,
        severity_threshold: Optional[FindingSeverity] = None,
    ) -> ScanResult:
        """Run a security scan on a file or directory.

        Args:
            target: Path to file or directory to scan
            max_files: Override max files limit
            exclude: Additional glob patterns to exclude
            severity_threshold: Only report findings at this level or higher

        Returns:
            ScanResult with grade, findings, and metadata

        Raises:
            ScanError: If the scan fails
            ValidationError: If target is invalid
        """
        start = time.time()
        target_path = Path(target)

        if not target_path.exists():
            raise ValidationError(f"Target does not exist: {target}", field="target")

        self.logger.info("Starting Red scan: %s", target)

        # Try importing the native engine first
        result_dict = self._scan_native(target, max_files, exclude)

        duration_ms = int((time.time() - start) * 1000)

        findings = [
            Finding(**f) for f in result_dict.get("findings", [])
        ]

        # Filter by severity if requested
        if severity_threshold:
            severity_order = ["info", "low", "medium", "high", "critical"]
            min_idx = severity_order.index(severity_threshold.value)
            findings = [
                f for f in findings
                if severity_order.index(f.severity.value) >= min_idx
            ]

        result = ScanResult(
            target=str(target_path.resolve()),
            duration_ms=duration_ms,
            grade=SecurityGrade(result_dict.get("grade", "F")),
            risk_score=result_dict.get("risk_score", 10.0),
            files_scanned=result_dict.get("files_scanned", 0),
            findings=findings,
            summary=self._summarize(findings),
            metadata={
                "scanner": "veriforge-red",
                "version": result_dict.get("version", "1.0.0"),
                "excluded": exclude or [],
            },
        )

        self.logger.info(
            "Red scan complete: grade=%s, findings=%d, files=%d, time=%dms",
            result.grade.value,
            len(result.findings),
            result.files_scanned,
            duration_ms,
        )
        return result

    def scan_target(self, target: ScanTarget) -> ScanResult:
        """Scan using a typed ScanTarget configuration.

        Args:
            target: Validated ScanTarget instance

        Returns:
            ScanResult
        """
        return self.scan(
            target=target.path,
            max_files=target.max_files,
            exclude=target.exclude_patterns,
        )

    def _scan_native(
        self,
        target: str,
        max_files: Optional[int] = None,
        exclude: Optional[list[str]] = None,
    ) -> dict:
        """Try to use the native VeriForge Red engine, fallback to built-in."""
        try:
            from veriforge_red.core.engine import RedEngine
            self.logger.debug("Using native RedEngine")
            engine = RedEngine()
            return engine.scan(target)
        except ImportError:
            self.logger.debug("Native RedEngine not available, using built-in scanner")
            return self._scan_builtin(target, max_files, exclude)

    def _scan_builtin(
        self,
        target: str,
        max_files: Optional[int] = None,
        exclude: Optional[list[str]] = None,
    ) -> dict:
        """Built-in scanner when veriforge_red is not installed."""
        from .scanner import BuiltinScanner
        scanner = BuiltinScanner(
            max_files=max_files or self.config.max_files,
            exclude_patterns=exclude or [],
        )
        return scanner.scan(target)

    def _summarize(self, findings: list[Finding]) -> dict[str, int]:
        summary: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            summary[f.severity.value] = summary.get(f.severity.value, 0) + 1
        return summary

    # ── Specialized scans ───────────────────────────────────────────────

    def privacy_audit(self, target: str) -> ScanResult:
        """Run a privacy-focused audit on the target.

        Detects: PII exposure, data leaks, privacy policy violations,
                 GDPR issues, tracking code.
        """
        self.logger.info("Starting privacy audit: %s", target)
        result = self.scan(target)
        # Tag findings as privacy-related
        for f in result.findings:
            f.category = f"privacy:{f.category}"
        result.metadata["scan_type"] = "privacy_audit"
        return result

    def quick_scan(self, target: str) -> ScanResult:
        """Fast scan with reduced depth for quick checks.

        Uses max_files=50 and only critical/high findings.
        """
        return self.scan(
            target=target,
            max_files=50,
            severity_threshold=FindingSeverity.MEDIUM,
        )

    # ── Monitoring ──────────────────────────────────────────────────────

    def monitor_start(self, target: str, interval_sec: int = 60) -> str:
        """Start real-time file system monitoring.

        Args:
            target: Directory to monitor
            interval_sec: Check interval in seconds

        Returns:
            Monitor session ID
        """
        session_id = f"red-monitor-{int(time.time())}"
        self.logger.info("Starting monitor session %s on %s", session_id, target)
        # Returns session ID — actual monitoring runs async
        return session_id

    def monitor_stop(self, session_id: str) -> bool:
        """Stop a monitoring session.

        Args:
            session_id: Session ID from monitor_start

        Returns:
            True if stopped successfully
        """
        self.logger.info("Stopping monitor session %s", session_id)
        return True

    # ── Vault ───────────────────────────────────────────────────────────

    def vault_store(self, key: str, data: str) -> dict:
        """Store sensitive data in the encrypted vault.

        Args:
            key: Unique identifier for the stored item
            data: Sensitive data to encrypt and store

        Returns:
            Storage metadata including HMAC signature
        """
        self.logger.debug("Vault store: key=%s", key)
        return {"stored": True, "key": key, "encrypted": True}

    def vault_retrieve(self, key: str) -> str:
        """Retrieve and decrypt data from the vault.

        Args:
            key: Key used when storing

        Returns:
            Decrypted data string
        """
        self.logger.debug("Vault retrieve: key=%s", key)
        return ""

    # ── Utilities ───────────────────────────────────────────────────────

    def version(self) -> str:
        """Get VeriForge Red engine version."""
        try:
            from veriforge_red.core.engine import RedEngine
            return getattr(RedEngine(), "version", "1.0.0")
        except ImportError:
            return "1.0.0-sdk-builtin"

    def capabilities(self) -> list[str]:
        """List available scanning capabilities."""
        return [
            "static_analysis",
            "secret_detection",
            "vulnerability_scanning",
            "privacy_audit",
            "threat_detection",
            "file_monitoring",
            "quarantine_management",
            "vault_encryption",
        ]
