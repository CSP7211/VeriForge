"""Built-in security scanner for when veriforge_red is not installed.

Provides core scanning capabilities without external dependencies.
Detects common security issues in Python code.
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path
from typing import Any, Optional

from ..models import Finding, FindingSeverity, SecurityGrade


class BuiltinScanner:
    """Lightweight built-in scanner — no external dependencies."""

    # Patterns to detect
    PATTERNS: dict[str, dict] = {
        "eval_exec": {
            "severity": FindingSeverity.CRITICAL,
            "pattern": re.compile(r"\b(eval|exec)\s*\("),
            "title": "Dynamic Code Execution",
            "description": "Use of eval() or exec() can lead to arbitrary code execution.",
            "remediation": "Replace with ast.literal_eval() or a safer alternative.",
            "cwe": "CWE-95",
        },
        "hardcoded_password": {
            "severity": FindingSeverity.HIGH,
            "pattern": re.compile(r"(?i)(password|passwd|pwd)\s*=\s*[\"'][^\"']+[\"']"),
            "title": "Hardcoded Password",
            "description": "Password detected in source code.",
            "remediation": "Use environment variables or a secrets manager.",
            "cwe": "CWE-798",
        },
        "hardcoded_secret": {
            "severity": FindingSeverity.HIGH,
            "pattern": re.compile(r"(?i)(api_key|apikey|secret|token)\s*=\s*[\"'][^\"']{8,}[\"']"),
            "title": "Hardcoded Secret",
            "description": "API key or secret token detected in source code.",
            "remediation": "Move secrets to environment variables or vault.",
            "cwe": "CWE-798",
        },
        "sql_injection": {
            "severity": FindingSeverity.CRITICAL,
            "pattern": re.compile(r'(?i)(execute|cursor\.execute)\s*\(\s*["\'].*%s.*["\']'),
            "title": "Potential SQL Injection",
            "description": "String formatting in SQL query detected.",
            "remediation": "Use parameterized queries with placeholders.",
            "cwe": "CWE-89",
        },
        "pickle_load": {
            "severity": FindingSeverity.HIGH,
            "pattern": re.compile(r"\bpickle\.load\s*\("),
            "title": "Unsafe Deserialization",
            "description": "pickle.load() can execute arbitrary code on deserialization.",
            "remediation": "Use json.loads() or a safe serializer.",
            "cwe": "CWE-502",
        },
        "subprocess_shell": {
            "severity": FindingSeverity.HIGH,
            "pattern": re.compile(r"\bsubprocess\.(call|run|Popen).*shell\s*=\s*True"),
            "title": "Shell Injection via subprocess",
            "description": "subprocess with shell=True is dangerous with untrusted input.",
            "remediation": "Use shell=False and pass command as a list.",
            "cwe": "CWE-78",
        },
        "yaml_load": {
            "severity": FindingSeverity.HIGH,
            "pattern": re.compile(r"\byaml\.load\s*\([^)]*\)"),
            "title": "Unsafe YAML Loading",
            "description": "yaml.load() without Loader can execute arbitrary code.",
            "remediation": "Use yaml.safe_load() instead.",
            "cwe": "CWE-502",
        },
        "debug_true": {
            "severity": FindingSeverity.MEDIUM,
            "pattern": re.compile(r"\bDEBUG\s*=\s*True"),
            "title": "Debug Mode Enabled",
            "description": "DEBUG=True should not be used in production.",
            "remediation": "Set DEBUG=False in production configurations.",
            "cwe": "CWE-489",
        },
        "http_url": {
            "severity": FindingSeverity.LOW,
            "pattern": re.compile(r"http://[^\"'\s]+"),
            "title": "Insecure HTTP URL",
            "description": "HTTP URL found — consider using HTTPS.",
            "remediation": "Replace http:// with https:// where possible.",
            "cwe": "CWE-319",
        },
        "todo_fixme": {
            "severity": FindingSeverity.INFO,
            "pattern": re.compile(r"(?i)#\s*(TODO|FIXME|HACK|XXX|BUG)"),
            "title": "Code Marker Found",
            "description": "Development marker indicates incomplete or temporary code.",
            "remediation": "Review and resolve before production.",
            "cwe": None,
        },
    }

    def __init__(self, max_files: int = 1000, exclude_patterns: Optional[list[str]] = None):
        self.max_files = max_files
        self.exclude_patterns = exclude_patterns or []

    def scan(self, target: str) -> dict:
        """Run built-in scan and return raw dict."""
        target_path = Path(target)
        findings: list[dict] = []
        files_scanned = 0

        files_to_scan = [target_path] if target_path.is_file() else self._collect_files(target_path)

        for file_path in files_to_scan:
            if files_scanned >= self.max_files:
                break
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                file_findings = self._scan_file(file_path, content)
                findings.extend(file_findings)
                files_scanned += 1
            except Exception:
                continue

        # Calculate grade
        risk_score = self._calc_risk(findings)
        grade = self._grade(risk_score)

        return {
            "target": str(target_path),
            "grade": grade,
            "risk_score": risk_score,
            "files_scanned": files_scanned,
            "findings": findings,
            "version": "1.0.0-builtin",
        }

    def _collect_files(self, directory: Path) -> list[Path]:
        """Collect Python files to scan."""
        files: list[Path] = []
        for pattern in ["**/*.py", "**/*.js", "**/*.ts", "**/*.java", "**/*.go"]:
            files.extend(directory.glob(pattern))
        # Apply exclusions
        filtered = []
        for f in files:
            rel = str(f.relative_to(directory))
            if not any(ex in rel for ex in self.exclude_patterns):
                filtered.append(f)
        return filtered[:self.max_files]

    def _scan_file(self, file_path: Path, content: str) -> list[dict]:
        """Scan a single file for security patterns."""
        findings: list[dict] = []
        lines = content.split("\n")

        for check_name, check in self.PATTERNS.items():
            for match in check["pattern"].finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                findings.append({
                    "id": f"BUILTIN-{check_name.upper()}-{hashlib.sha256(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                    "severity": check["severity"].value,
                    "category": check_name,
                    "title": check["title"],
                    "description": check["description"],
                    "file_path": str(file_path),
                    "line_number": line_num,
                    "remediation": check["remediation"],
                    "cwe_id": check.get("cwe"),
                })

        return findings

    def _calc_risk(self, findings: list[dict]) -> float:
        """Calculate risk score 0.0–10.0."""
        weights = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.5, "info": 0.1}
        score = sum(weights.get(f["severity"], 0.5) for f in findings)
        return min(score, 10.0)

    def _grade(self, risk_score: float) -> str:
        """Convert risk score to letter grade."""
        if risk_score == 0:
            return "A+"
        elif risk_score < 2:
            return "A"
        elif risk_score < 4:
            return "B"
        elif risk_score < 6:
            return "C"
        elif risk_score < 8:
            return "D"
        else:
            return "F"
