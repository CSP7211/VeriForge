"""veriforge_red/core/vulndb_loader.py — Vulnerability Database Loader.

Manages loading and querying the vulnerability database that powers
threat detection and payload generation. Supports:

1. **Bundled DB** — Shipped with the application (works offline)
2. **Downloaded DB** — User-downloaded updates (preferred if available)
3. **Custom DB** — Enterprise users can supply their own
4. **Fallback** — In-memory minimal rules when no DB is available

All operations are local — no network calls in this module.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

VULNDB_DIR = Path.home() / ".veriforge_red" / "vulndb"
BUNDLED_VULNDB = Path(__file__).parent.parent / "data" / "vulndb_bundled.json"


@dataclass
class VulnSignature:
    """A single vulnerability signature."""

    sig_id: str
    name: str
    category: str  # injection, traversal, secret, obfuscation, etc.
    severity: str  # critical, high, medium, low
    patterns: list[str] = field(default_factory=list)  # regex patterns
    description: str = ""
    cwe_id: str = ""
    cvss_score: float = 0.0
    affected_languages: list[str] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class PayloadSignature:
    """A payload signature for adversarial testing."""

    payload_id: str
    name: str
    vuln_type: str  # sqli, xss, cmdi, path_traversal, etc.
    payloads: list[str] = field(default_factory=list)
    context: str = ""  # When this payload is applicable
    encoding_variants: list[str] = field(default_factory=list)


@dataclass
class CVEMapping:
    """CVE to signature mapping."""

    cve_id: str
    description: str
    affected_packages: list[str]
    severity: str
    signatures: list[str] = field(default_factory=list)
    fix_version: str = ""
    published_date: str = ""


class VulnDBLoader:
    """Load and query the vulnerability database.

    Priority order:
    1. User-downloaded SQLite DB (~/.veriforge_red/vulndb/current)
    2. Bundled JSON DB (shipped with app)
    3. In-memory fallback (always works)
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path
        self._sqlite_conn: Optional[sqlite3.Connection] = None
        self._json_data: Optional[dict] = None
        self._fallback_data: dict = self._build_fallback()
        self._version = "fallback"
        self._load()

    def _load(self) -> None:
        """Attempt to load the best available database."""
        # Priority 1: Downloaded SQLite DB
        current_link = VULNDB_DIR / "current"
        if current_link.exists() and current_link.is_symlink():
            resolved = current_link.resolve()
            if resolved.exists():
                self._load_sqlite(resolved)
                self._version = f"sqlite:{resolved.stem}"
                return

        # Also check for direct .sqlite files
        sqlite_files = sorted(VULNDB_DIR.glob("*.sqlite*"), reverse=True)
        for f in sqlite_files:
            if f.is_file() and not f.is_symlink():
                self._load_sqlite(f)
                self._version = f"sqlite:{f.stem}"
                return

        # Priority 2: Bundled JSON
        if BUNDLED_VULNDB.exists():
            self._load_json(BUNDLED_VULNDB)
            self._version = "bundled"
            return

        # Priority 3: In-memory fallback (always works)
        self._json_data = self._fallback_data
        self._version = "fallback"

    def _load_sqlite(self, path: Path) -> None:
        """Load a SQLite vulnerability database."""
        try:
            self._sqlite_conn = sqlite3.connect(str(path))
            self._sqlite_conn.row_factory = sqlite3.Row
        except sqlite3.Error:
            self._sqlite_conn = None

    def _load_json(self, path: Path) -> None:
        """Load a JSON vulnerability database."""
        try:
            self._json_data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            self._json_data = self._fallback_data

    def _build_fallback(self) -> dict:
        """Build a minimal in-memory vulnerability database.

        This ensures VeriForge Red works fully offline even with no
        downloaded or bundled database.
        """
        return {
            "version": "fallback-v1",
            "signatures": [
                {
                    "sig_id": "VF-SIG-001",
                    "name": "Python eval() usage",
                    "category": "code_execution",
                    "severity": "critical",
                    "patterns": [r"\beval\s*\("],
                    "description": "Use of eval() allows arbitrary code execution",
                    "cwe_id": "CWE-95",
                    "cvss_score": 9.8,
                    "affected_languages": ["python"],
                    "remediation": "Replace eval() with ast.literal_eval() or safe parsing",
                },
                {
                    "sig_id": "VF-SIG-002",
                    "name": "Python exec() usage",
                    "category": "code_execution",
                    "severity": "critical",
                    "patterns": [r"\bexec\s*\("],
                    "description": "Use of exec() allows arbitrary code execution",
                    "cwe_id": "CWE-95",
                    "cvss_score": 9.8,
                    "affected_languages": ["python"],
                    "remediation": "Avoid exec(). Use safer alternatives.",
                },
                {
                    "sig_id": "VF-SIG-003",
                    "name": "Hardcoded password",
                    "category": "secret_exposure",
                    "severity": "high",
                    "patterns": [
                        r'password\s*=\s*["\'][^"\']+["\']',
                        r'passwd\s*=\s*["\'][^"\']+["\']',
                        r'secret\s*=\s*["\'][^"\']+["\']',
                        r'token\s*=\s*["\'][^"\']+["\']',
                        r'api_key\s*=\s*["\'][^"\']+["\']',
                    ],
                    "description": "Hardcoded credentials detected in source code",
                    "cwe_id": "CWE-798",
                    "cvss_score": 7.5,
                    "affected_languages": ["python", "javascript", "java", "go"],
                    "remediation": "Use environment variables or a secrets manager",
                },
                {
                    "sig_id": "VF-SIG-004",
                    "name": "SQL injection (string concat)",
                    "category": "injection",
                    "severity": "critical",
                    "patterns": [
                        r'execute\s*\(\s*["\'].*%s',
                        r'execute\s*\(\s*f["\']',
                        r'\.format\s*\(.*\)',
                        r'\+.*["\'].*SELECT',
                    ],
                    "description": "String concatenation in SQL queries enables injection",
                    "cwe_id": "CWE-89",
                    "cvss_score": 9.1,
                    "affected_languages": ["python"],
                    "remediation": "Use parameterized queries",
                },
                {
                    "sig_id": "VF-SIG-005",
                    "name": "Subprocess with shell=True",
                    "category": "command_injection",
                    "severity": "high",
                    "patterns": [
                        r'subprocess\..*shell\s*=\s*True',
                        r'os\.system\s*\(',
                        r'os\.popen\s*\(',
                    ],
                    "description": "Shell=True in subprocess enables command injection",
                    "cwe_id": "CWE-78",
                    "cvss_score": 8.1,
                    "affected_languages": ["python"],
                    "remediation": "Use subprocess.run() with shell=False and argument list",
                },
                {
                    "sig_id": "VF-SIG-006",
                    "name": "Deserialization (pickle)",
                    "category": "deserialization",
                    "severity": "critical",
                    "patterns": [
                        r'pickle\.loads?\s*\(',
                        r'yaml\.load\s*\([^,)]*\)',
                    ],
                    "description": "Unsafe deserialization can lead to RCE",
                    "cwe_id": "CWE-502",
                    "cvss_score": 9.8,
                    "affected_languages": ["python"],
                    "remediation": "Use yaml.safe_load(), json.loads(), or validate data before pickle",
                },
                {
                    "sig_id": "VF-SIG-007",
                    "name": "Debug mode enabled",
                    "category": "configuration",
                    "severity": "medium",
                    "patterns": [
                        r'DEBUG\s*=\s*True',
                        r'app\.run\(.*debug\s*=\s*True',
                    ],
                    "description": "Debug mode exposes sensitive information",
                    "cwe_id": "CWE-489",
                    "cvss_score": 5.3,
                    "affected_languages": ["python"],
                    "remediation": "Disable debug in production",
                },
                {
                    "sig_id": "VF-SIG-008",
                    "name": "Missing input validation",
                    "category": "input_validation",
                    "severity": "high",
                    "patterns": [
                        r'request\.(args|form)\[',
                        r'request\.(args|form)\.get\s*\(',
                    ],
                    "description": "User input used without validation",
                    "cwe_id": "CWE-20",
                    "cvss_score": 7.5,
                    "affected_languages": ["python"],
                    "remediation": "Validate and sanitize all user inputs",
                },
            ],
            "payloads": [
                {
                    "payload_id": "VF-PAY-001",
                    "name": "SQL Injection Basic",
                    "vuln_type": "sqli",
                    "payloads": ["' OR '1'='1", "' OR 1=1 --", "1 UNION SELECT *"],
                    "context": "username, password, search, id parameter",
                },
                {
                    "payload_id": "VF-PAY-002",
                    "name": "XSS Basic",
                    "vuln_type": "xss",
                    "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
                    "context": "user input rendered in HTML",
                },
                {
                    "payload_id": "VF-PAY-003",
                    "name": "Command Injection",
                    "vuln_type": "cmdi",
                    "payloads": ["; cat /etc/passwd", "| whoami", "$(id)"],
                    "context": "command parameter, filename",
                },
                {
                    "payload_id": "VF-PAY-004",
                    "name": "Path Traversal",
                    "vuln_type": "path_traversal",
                    "payloads": ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam"],
                    "context": "filename, path parameter",
                },
            ],
            "cve_mappings": [],
        }

    # -- Query API --------------------------------------------------------

    def get_signatures_for_language(self, language: str) -> list[VulnSignature]:
        """Get all signatures affecting a specific language."""
        results = []
        if self._sqlite_conn:
            cursor = self._sqlite_conn.execute(
                "SELECT * FROM signatures WHERE affected_languages LIKE ?",
                (f"%{language}%",),
            )
            for row in cursor.fetchall():
                results.append(self._row_to_signature(row))
        elif self._json_data:
            for sig in self._json_data.get("signatures", []):
                langs = sig.get("affected_languages", [])
                if language in langs or "*" in langs:
                    results.append(self._dict_to_signature(sig))
        return results

    def get_signatures_by_category(self, category: str) -> list[VulnSignature]:
        """Get signatures for a specific category."""
        results = []
        if self._sqlite_conn:
            cursor = self._sqlite_conn.execute(
                "SELECT * FROM signatures WHERE category = ?", (category,)
            )
            for row in cursor.fetchall():
                results.append(self._row_to_signature(row))
        elif self._json_data:
            for sig in self._json_data.get("signatures", []):
                if sig.get("category") == category:
                    results.append(self._dict_to_signature(sig))
        return results

    def get_all_signatures(self) -> list[VulnSignature]:
        """Get all signatures."""
        results = []
        if self._sqlite_conn:
            cursor = self._sqlite_conn.execute("SELECT * FROM signatures")
            for row in cursor.fetchall():
                results.append(self._row_to_signature(row))
        elif self._json_data:
            for sig in self._json_data.get("signatures", []):
                results.append(self._dict_to_signature(sig))
        return results

    def get_all_payloads(self) -> list[PayloadSignature]:
        """Get all payload signatures."""
        results = []
        if self._sqlite_conn:
            cursor = self._sqlite_conn.execute("SELECT * FROM payloads")
            for row in cursor.fetchall():
                results.append(self._row_to_payload(row))
        elif self._json_data:
            for pay in self._json_data.get("payloads", []):
                results.append(self._dict_to_payload(pay))
        return results

    def get_cve_mapping(self, cve_id: str) -> Optional[CVEMapping]:
        """Get CVE mapping by ID."""
        if self._sqlite_conn:
            cursor = self._sqlite_conn.execute(
                "SELECT * FROM cve_mappings WHERE cve_id = ?", (cve_id,)
            )
            row = cursor.fetchone()
            if row:
                return self._row_to_cve(row)
        elif self._json_data:
            for cve in self._json_data.get("cve_mappings", []):
                if cve.get("cve_id") == cve_id:
                    return self._dict_to_cve(cve)
        return None

    def search_signatures(self, query: str) -> list[VulnSignature]:
        """Search signatures by name or description."""
        results = []
        pattern = re.compile(query, re.IGNORECASE)
        for sig in self.get_all_signatures():
            if pattern.search(sig.name) or pattern.search(sig.description):
                results.append(sig)
        return results

    def get_db_version(self) -> str:
        """Return the currently loaded database version."""
        return self._version

    def get_stats(self) -> dict:
        """Return statistics about the loaded database."""
        sigs = self.get_all_signatures()
        payloads = self.get_all_payloads()
        return {
            "version": self._version,
            "signature_count": len(sigs),
            "payload_count": len(payloads),
            "critical_count": sum(1 for s in sigs if s.severity == "critical"),
            "high_count": sum(1 for s in sigs if s.severity == "high"),
            "categories": sorted(set(s.category for s in sigs)),
        }

    # -- Conversion helpers -----------------------------------------------

    @staticmethod
    def _row_to_signature(row: sqlite3.Row) -> VulnSignature:
        return VulnSignature(
            sig_id=row["sig_id"],
            name=row["name"],
            category=row["category"],
            severity=row["severity"],
            patterns=json.loads(row["patterns"]),
            description=row["description"],
            cwe_id=row["cwe_id"],
            cvss_score=row["cvss_score"],
            affected_languages=json.loads(row["affected_languages"]),
            remediation=row["remediation"],
        )

    @staticmethod
    def _dict_to_signature(d: dict) -> VulnSignature:
        return VulnSignature(**{k: v for k, v in d.items() if k in VulnSignature.__dataclass_fields__})

    @staticmethod
    def _row_to_payload(row: sqlite3.Row) -> PayloadSignature:
        return PayloadSignature(
            payload_id=row["payload_id"],
            name=row["name"],
            vuln_type=row["vuln_type"],
            payloads=json.loads(row["payloads"]),
            context=row.get("context", ""),
        )

    @staticmethod
    def _dict_to_payload(d: dict) -> PayloadSignature:
        return PayloadSignature(**{k: v for k, v in d.items() if k in PayloadSignature.__dataclass_fields__})

    @staticmethod
    def _row_to_cve(row: sqlite3.Row) -> CVEMapping:
        return CVEMapping(
            cve_id=row["cve_id"],
            description=row["description"],
            affected_packages=json.loads(row["affected_packages"]),
            severity=row["severity"],
            signatures=json.loads(row.get("signatures", "[]")),
            fix_version=row.get("fix_version", ""),
        )

    @staticmethod
    def _dict_to_cve(d: dict) -> CVEMapping:
        return CVEMapping(**{k: v for k, v in d.items() if k in CVEMapping.__dataclass_fields__})


__all__ = ["VulnDBLoader", "VulnSignature", "PayloadSignature", "CVEMapping"]
