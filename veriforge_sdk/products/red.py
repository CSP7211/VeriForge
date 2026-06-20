"""RED — Automated security code scanner.

Provides static analysis, vulnerability detection, and graded assessments
for source code repositories or individual files.
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import SDKConfig
from ..exceptions import ScanError, ScanTimeoutError
from ..models import Finding, Grade, ScanResult, Severity
from .base import BaseProductAPI


class RedScanAPI(BaseProductAPI):
    """Interface to the VeriForge RED scanning engine.

    Example:
        >>> result = client.red.scan("/path/to/code")
        >>> print(result.grade.value)
        "A"
    """

    PRODUCT_NAME = "red"

    def __init__(self, config: SDKConfig) -> None:
        super().__init__(config)
        self._local_mode = config.api_key is None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(
        self,
        target: str,
        rules: Optional[List[str]] = None,
        timeout: Optional[float] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        """Scan a file or directory for security issues.

        Args:
            target: Absolute or relative path to the code.
            rules: Optional list of rule IDs to enable (default: all).
            timeout: Per-scan deadline in seconds.
            options: Extra scanner flags forwarded to RED.

        Raises:
            ScanError: If the scan cannot be initiated.
            ScanTimeoutError: If the scan exceeds *timeout*.

        Returns:
            A ``ScanResult`` with findings and grade.
        """
        path = Path(target).expanduser().resolve()
        if not path.exists():
            raise ScanError(f"Target does not exist: {path}", target=str(path))

        if self._local_mode:
            return self._local_scan(path, rules, options)

        payload: Dict[str, Any] = {
            "target": str(path),
            "rules": rules or [],
            "options": options or {},
        }
        try:
            resp = self._request("POST", "/scan", json_data=payload, timeout=timeout)
        except Exception as exc:
            if "timeout" in str(exc).lower():
                raise ScanTimeoutError(
                    f"Scan timed out: {path}",
                    timeout_seconds=timeout,
                    target=str(path),
                ) from exc
            raise ScanError(f"Scan failed: {exc}", target=str(path)) from exc

        return self._parse_scan_response(resp)

    def get_scan(self, scan_id: str) -> ScanResult:
        """Retrieve a previously submitted scan by ID.

        Args:
            scan_id: The unique scan identifier.

        Returns:
            The ``ScanResult`` for the scan.
        """
        resp = self._request("GET", f"/scans/{scan_id}")
        return self._parse_scan_response(resp)

    def list_rules(self) -> List[Dict[str, Any]]:
        """List all available scanning rules.

        Returns:
            List of rule metadata dictionaries.
        """
        if self._local_mode:
            return self._default_rules()
        return self._request("GET", "/rules")

    # ------------------------------------------------------------------
    # Local fallback (offline mode)
    # ------------------------------------------------------------------

    def _local_scan(
        self,
        path: Path,
        rules: Optional[List[str]],
        options: Optional[Dict[str, Any]],
    ) -> ScanResult:
        """Perform a lightweight local heuristic scan.

        This is used when no API key is configured. It performs basic
        pattern matching for common issues.
        """
        import time

        start = time.monotonic()
        findings: List[Finding] = []

        files = self._collect_files(path)
        for fp in files:
            findings.extend(self._heuristic_scan_file(fp))

        duration_ms = (time.monotonic() - start) * 1000
        grade = self._grade_from_findings(findings)

        return ScanResult(
            scan_id=secrets.token_hex(8),
            target=str(path),
            grade=grade,
            findings=findings,
            duration_ms=duration_ms,
            scanner_version="red-local/1.0",
            metadata={"files_scanned": len(files), "mode": "local"},
        )

    def _collect_files(self, path: Path) -> List[Path]:
        """Collect all source files under *path*."""
        if path.is_file():
            return [path]
        extensions = {
            ".py", ".js", ".ts", ".java", ".go", ".rb", ".php",
            ".c", ".cpp", ".h", ".cs", ".swift", ".kt", ".rs",
        }
        return [p for p in path.rglob("*") if p.suffix in extensions and p.is_file()]

    def _heuristic_scan_file(self, path: Path) -> List[Finding]:
        """Run basic heuristic checks on a single file."""
        findings: List[Finding] = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except Exception:
            return findings

        # Check for hardcoded secrets
        secret_patterns = [
            ("password", r"password\s*=\s*['\"][^'\"]+['\"]"),
            ("api_key", r"api[_-]?key\s*[:=]\s*['\"][^'\"]+['\"]"),
            ("secret", r"secret\s*[:=]\s*['\"][^'\"]+['\"]"),
            ("token", r"token\s*[:=]\s*['\"][^'\"]+['\"]"),
        ]
        import re
        for name, pattern in secret_patterns:
            for lineno, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(
                        Finding(
                            title=f"Potential hardcoded {name}",
                            description=f"Line appears to contain a hardcoded {name}.",
                            severity=Severity.HIGH,
                            category="CWE-798",
                            file_path=str(path),
                            line_start=lineno,
                            line_end=lineno,
                            remediation=f"Move {name} to environment variables or a secrets manager.",
                        )
                    )

        # Check for eval/exec
        dangerous = ["eval(", "exec(", "subprocess.call", "os.system("]
        for lineno, line in enumerate(lines, 1):
            for func in dangerous:
                if func in line:
                    findings.append(
                        Finding(
                            title=f"Dangerous function usage: {func}",
                            description=f"Use of {func} can lead to code injection.",
                            severity=Severity.CRITICAL if func in ("eval(", "exec(") else Severity.HIGH,
                            category="CWE-94" if func in ("eval(", "exec(") else "CWE-78",
                            file_path=str(path),
                            line_start=lineno,
                            line_end=lineno,
                            remediation=f"Avoid {func}; use safer alternatives.",
                        )
                    )

        # Check for SQL injection patterns
        sql_patterns = [
            "execute(",
            "raw_input",
            "%.format(",
            "+ \"",
            '+ "',
        ]
        for lineno, line in enumerate(lines, 1):
            for pat in sql_patterns:
                if pat in line.lower():
                    findings.append(
                        Finding(
                            title="Potential SQL injection vector",
                            description="String concatenation or formatting near SQL query.",
                            severity=Severity.HIGH,
                            category="CWE-89",
                            file_path=str(path),
                            line_start=lineno,
                            line_end=lineno,
                            remediation="Use parameterized queries or an ORM.",
                        )
                    )
                    break

        return findings

    def _grade_from_findings(self, findings: List[Finding]) -> Grade:
        """Compute an overall grade from findings."""
        if any(f.severity == Severity.CRITICAL for f in findings):
            return Grade.F
        if any(f.severity == Severity.HIGH for f in findings):
            return Grade.D
        if any(f.severity == Severity.MEDIUM for f in findings):
            return Grade.C
        if any(f.severity == Severity.LOW for f in findings):
            return Grade.B
        return Grade.A

    def _parse_scan_response(self, data: Dict[str, Any]) -> ScanResult:
        """Convert API JSON into a ``ScanResult``."""
        findings = [
            Finding(
                title=f.get("title", ""),
                description=f.get("description", ""),
                severity=Severity(f.get("severity", "info")),
                category=f.get("category", ""),
                file_path=f.get("file_path", ""),
                line_start=f.get("line_start", 0),
                line_end=f.get("line_end", 0),
                remediation=f.get("remediation", ""),
                references=f.get("references", []),
            )
            for f in data.get("findings", [])
        ]
        return ScanResult(
            scan_id=data.get("scan_id", ""),
            target=data.get("target", ""),
            grade=Grade(data.get("grade", "F")),
            findings=findings,
            duration_ms=data.get("duration_ms", 0.0),
            scanned_at=data.get("scanned_at", ""),
            scanner_version=data.get("scanner_version", ""),
            metadata=data.get("metadata", {}),
        )

    def _default_rules(self) -> List[Dict[str, Any]]:
        """Return the built-in local rule set."""
        return [
            {"id": "hardcoded-secrets", "name": "Hardcoded Secrets", "severity": "high"},
            {"id": "code-injection", "name": "Code Injection", "severity": "critical"},
            {"id": "sql-injection", "name": "SQL Injection", "severity": "high"},
            {"id": "xpath-injection", "name": "XPath Injection", "severity": "medium"},
            {"id": "insecure-deserialization", "name": "Insecure Deserialization", "severity": "high"},
            {"id": "weak-crypto", "name": "Weak Cryptography", "severity": "medium"},
            {"id": "path-traversal", "name": "Path Traversal", "severity": "high"},
        ]
