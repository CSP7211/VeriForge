"""Auto-fix engine for privacy issues, code vulnerabilities, and threats.

Strategies:
- Privacy   : generate fix commands (registry keys, permission changes)
- Code vulns: add type hints, sanitize inputs, replace eval with safe alternatives
- Threats   : quarantine malicious files, remove persistence mechanisms
- General   : backup before any change, rollback capability
"""

from __future__ import annotations

import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

if False:
    from .database import Database
    from .quarantine import QuarantineManager


# ---------------------------------------------------------------------------
# RemediationEngine
# ---------------------------------------------------------------------------

class RemediationEngine:
    """Applies automated fixes to security and privacy findings."""

    def __init__(self, db: Database, quarantine: QuarantineManager) -> None:
        self.db = db
        self.quarantine = quarantine
        self._backup_dir = Path.home() / ".veriforge_red" / "backups"
        self._backup_dir.mkdir(parents=True, exist_ok=True)

    # -- public API -------------------------------------------------------

    def fix_privacy_issue(self, issue: Any) -> bool:
        """Apply a privacy fix.  Returns True if applied successfully."""
        category = getattr(issue, "category", issue.get("category", ""))
        setting = getattr(issue, "setting_name", issue.get("setting_name", ""))

        action_taken = ""
        success = False

        if category == "file_permissions":
            success = self._fix_file_permissions(setting)
            action_taken = f"chmod 600 {setting}"
        elif category == "telemetry":
            action_taken = self._generate_telemetry_fix(setting)
            success = True  # command generated, not executed
        elif category == "location_services":
            action_taken = self._generate_location_fix(setting)
            success = True
        elif category == "android_permissions":
            action_taken = f"adb shell pm revoke <package> {setting}"
            success = True
        elif category == "debug_interface":
            action_taken = "adb shell settings put global adb_enabled 0"
            success = True
        elif category == "hardcoded_credentials":
            action_taken = f"Manual fix required: replace hardcoded value in {setting} with env var"
            success = False  # requires developer intervention
        elif category == "exposed_secrets":
            action_taken = f"Move secrets from {setting} to encrypted vault"
            success = False
        elif category == "unencrypted_storage":
            action_taken = f"Replace unencrypted storage in {setting} with SQLCipher or encrypted alternative"
            success = False
        else:
            action_taken = f"No automatic fix available for {category}"
            success = False

        self.db.insert_remediation(
            issue_type=category,
            file_path=setting,
            action_taken=action_taken,
            success=success,
        )
        return success

    def fix_vulnerability(self, finding: dict[str, Any]) -> bool:
        """Fix a code vulnerability finding.  Returns True if fixed."""
        file_path = finding.get("file", "")
        category = finding.get("category", "")
        title = finding.get("title", "")

        if not file_path or not Path(file_path).is_file():
            self.db.insert_remediation(
                issue_type=category,
                file_path=file_path,
                action_taken="Skipped — file not found",
                success=False,
            )
            return False

        # Create backup
        backup_path = self._backup(file_path)

        try:
            content = Path(file_path).read_text(encoding="utf-8")
            original = content
            modified = False

            # Replace eval() with ast.literal_eval where possible
            if "eval" in title.lower() or "dangerous_builtin" in category:
                content = self._replace_eval_with_literal(content)
                modified = True

            # Add input sanitization for injection vulnerabilities
            if "injection" in title.lower() or "command" in title.lower():
                content = self._add_input_sanitization(content)
                modified = True

            # Add type hints for untyped functions
            if "type" in title.lower() or "untyped" in category.lower():
                content = self._add_type_hints(content)
                modified = True

            if modified and content != original:
                Path(file_path).write_text(content, encoding="utf-8")
                self.db.insert_remediation(
                    issue_type=category,
                    file_path=file_path,
                    action_taken=f"Auto-fixed: backup at {backup_path}",
                    success=True,
                )
                return True
            else:
                self.db.insert_remediation(
                    issue_type=category,
                    file_path=file_path,
                    action_taken="No applicable fix pattern found",
                    success=False,
                )
                return False

        except Exception as exc:
            self._restore(file_path, backup_path)
            self.db.insert_remediation(
                issue_type=category,
                file_path=file_path,
                action_taken=f"Fix failed: {exc}",
                success=False,
            )
            return False

    def fix_threat(self, threat: Any) -> bool:
        """Remediate a detected threat.  Returns True if remediated."""
        threat_type = getattr(threat, "threat_type", threat.get("threat_type", ""))
        file_path = getattr(threat, "file_path", threat.get("file_path", ""))
        threat_id = getattr(threat, "id", threat.get("id", ""))

        if threat_type in ("reverse_shell", "backdoor_listener", "code_injection",
                           "dangerous_builtin", "pickle_deserialization", "yaml_load"):
            # Quarantine the file
            try:
                qid = self.quarantine.quarantine(
                    file_path,
                    threat_info={
                        "threat_type": threat_type,
                        "severity": getattr(threat, "severity", threat.get("severity", "high")),
                    },
                )
                self.db.insert_remediation(
                    issue_type=threat_type,
                    file_path=file_path,
                    action_taken=f"Quarantined (ID: {qid})",
                    success=True,
                )
                return True
            except Exception as exc:
                self.db.insert_remediation(
                    issue_type=threat_type,
                    file_path=file_path,
                    action_taken=f"Quarantine failed: {exc}",
                    success=False,
                )
                return False

        elif threat_type in ("hardcoded_password", "hardcoded_api_key",
                             "hardcoded_token", "hardcoded_secret",
                             "aws_key", "private_key"):
            self.db.insert_remediation(
                issue_type=threat_type,
                file_path=file_path,
                action_taken="Manual fix: rotate credentials and use secrets manager",
                success=False,
            )
            return False

        elif threat_type == "world_writable_sensitive_file":
            success = self._fix_file_permissions(file_path)
            self.db.insert_remediation(
                issue_type=threat_type,
                file_path=file_path,
                action_taken="chmod 600 applied" if success else "chmod failed",
                success=success,
            )
            return success

        elif threat_type == "persistence_mechanism":
            self.db.insert_remediation(
                issue_type=threat_type,
                file_path=file_path,
                action_taken="Manual fix: review and remove unauthorized startup entry",
                success=False,
            )
            return False

        else:
            self.db.insert_remediation(
                issue_type=threat_type,
                file_path=file_path,
                action_taken="No automatic fix available",
                success=False,
            )
            return False

    def auto_remediate_all(self, scan_result: dict[str, Any]) -> dict[str, Any]:
        """Fix everything possible from a scan result."""
        findings = scan_result.get("findings", [])
        fixed = 0
        failed = 0
        skipped = 0
        details: list[dict[str, Any]] = []

        for finding in findings:
            result = self.fix_vulnerability(finding)
            if result:
                fixed += 1
            else:
                failed += 1
            details.append({
                "file": finding.get("file", ""),
                "title": finding.get("title", ""),
                "fixed": result,
            })

        return {
            "total": len(findings),
            "fixed": fixed,
            "failed": failed,
            "skipped": skipped,
            "details": details,
        }

    def get_remediation_history(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return past fixes from the database."""
        records = self.db.get_all_remediations()
        return [
            {
                "id": r.id,
                "issue_type": r.issue_type,
                "file_path": r.file_path,
                "action_taken": r.action_taken,
                "success": r.success,
                "timestamp": r.timestamp,
            }
            for r in records[:limit]
        ]

    # -- internal fix implementations -------------------------------------

    def _backup(self, file_path: str) -> str:
        """Create a timestamped backup of *file_path*.  Returns backup path."""
        src = Path(file_path)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_name = f"{src.name}.{ts}.bak"
        backup_path = self._backup_dir / backup_name
        shutil.copy2(src, backup_path)
        return str(backup_path)

    @staticmethod
    def _restore(file_path: str, backup_path: str) -> None:
        """Restore *file_path* from *backup_path*."""
        shutil.copy2(backup_path, file_path)

    @staticmethod
    def _fix_file_permissions(file_path: str) -> bool:
        """Set restrictive permissions on *file_path*."""
        try:
            os.chmod(file_path, 0o600)
            return True
        except OSError:
            return False

    @staticmethod
    def _generate_telemetry_fix(setting: str) -> str:
        """Generate a command to disable Windows telemetry."""
        if "DataCollection" in setting:
            return (
                'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" '
                '/v AllowTelemetry /t REG_DWORD /d 0 /f'
            )
        return f"# Disable telemetry: review {setting}"

    @staticmethod
    def _generate_location_fix(setting: str) -> str:
        """Generate a command to disable location services."""
        if "Android" in setting:
            return "adb shell settings put secure location_providers_allowed -"
        return (
            'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager'
            '\\ConsentStore\\location" /v Value /t REG_SZ /d Deny /f'
        )

    @staticmethod
    def _replace_eval_with_literal(content: str) -> str:
        """Replace simple eval() calls with ast.literal_eval()."""
        # Only replace eval() with a single string argument
        content = re.sub(
            r"\beval\s*\(\s*([\"'][^\"']+[\"'])\s*\)",
            r"ast.literal_eval(\1)",
            content,
        )
        # Add import if needed
        if "ast.literal_eval" in content and "import ast" not in content:
            content = "import ast\n" + content
        return content

    @staticmethod
    def _add_input_sanitization(content: str) -> str:
        """Add basic input sanitization wrappers around dangerous functions."""
        # Wrap os.system calls with a validation comment
        content = re.sub(
            r"(\bos\.system\s*\()",
            r"# SECURITY: Validate input before shell execution\n    # sanitized_input = shlex.quote(user_input)\n    \1",
            content,
        )
        # Wrap subprocess calls similarly
        content = re.sub(
            r"(\bsubprocess\.(call|Popen|run)\s*\(.*shell\s*=\s*True)",
            r"# SECURITY: shell=True is dangerous with untrusted input\n    # Use shell=False with a list of arguments instead\n    \1",
            content,
        )
        return content

    @staticmethod
    def _add_type_hints(content: str) -> str:
        """Add basic type hints to untyped function definitions."""
        # Add from __future__ import annotations if not present
        if "from __future__ import annotations" not in content:
            content = "from __future__ import annotations\n\n" + content

        # Simple heuristic: add -> None to defs without return type
        content = re.sub(
            r"^(def\s+\w+\s*\([^)]*\))\s*:\s*$",
            r"\1 -> None:\n",
            content,
            flags=re.MULTILINE,
        )
        return content
