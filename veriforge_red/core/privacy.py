"""Privacy settings auditor with platform-specific subclasses.

Provides a cross-platform abstraction for auditing privacy-relevant
configuration: hardcoded credentials, exposed secrets, overly-permissive
files, sensitive data in logs, and unencrypted storage.
"""

from __future__ import annotations

import os
import re
import stat
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

if False:
    from .database import Database


# ---------------------------------------------------------------------------
# PrivacyIssue dataclass
# ---------------------------------------------------------------------------

@dataclass
class PrivacyIssue:
    """A single privacy finding with remediation guidance."""

    category: str
    setting_name: str
    current_value: str
    recommended_value: str
    severity: str  # critical | high | medium | low
    description: str = ""
    cwe_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "setting_name": self.setting_name,
            "current_value": self.current_value,
            "recommended_value": self.recommended_value,
            "severity": self.severity,
            "description": self.description,
            "cwe_id": self.cwe_id,
        }


# ---------------------------------------------------------------------------
# Common regex patterns (shared across platforms)
# ---------------------------------------------------------------------------

# Hardcoded credentials in source files
_HARDCODED_PASSWORD_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret)\s*[=:]\s*[\"'][^\"']{3,}[\"']"
)
_HARDCODED_API_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|apikey|access[_-]?key)\s*[=:]\s*[\"'][^\"']{8,}[\"']"
)
_HARDCODED_TOKEN_RE = re.compile(
    r"(?i)(token|auth_token|bearer)\s*[=:]\s*[\"'][^\"']{8,}[\"']"
)

# Exposed secrets in config files
_SECRET_IN_CONFIG_RE = re.compile(
    r"(?i)[\"']?(password|secret|token|api_key|private_key)[\"']?\s*[:=]\s*[\"'][^\"']+[\"']"
)

# Sensitive patterns in log files
_SENSITIVE_LOG_RE = re.compile(
    r"(?i)(password|secret|token|credit[_-]?card|ssn|social[_-]?security)\s*[:=]\s*\S+"
)

# Unencrypted storage indicators
_UNENCRYPTED_STORAGE_RE = re.compile(
    r"(?i)(sqlite3\.(?!connect\s*\([^)]*password)|open\s*\([^)]*\.(db|sqlite|json|csv|txt))"
)


# ---------------------------------------------------------------------------
# Abstract base auditor
# ---------------------------------------------------------------------------

class PrivacyAuditor(ABC):
    """Abstract base class for privacy auditing.

    Subclasses must implement platform-specific checks.
    Common checks (hardcoded credentials, exposed secrets, file permissions,
    sensitive logs, unencrypted storage) are provided here.
    """

    def __init__(self, db: Database) -> None:
        self.db = db
        self._counter = 0
        self._lock = __import__("threading").Lock()

    def _next_id(self) -> int:
        with self._lock:
            self._counter += 1
            return self._counter

    # -- public API -------------------------------------------------------

    def audit_privacy(self) -> list[PrivacyIssue]:
        """Run full privacy audit: common checks + platform-specific checks."""
        issues: list[PrivacyIssue] = []
        issues.extend(self._check_hardcoded_credentials())
        issues.extend(self._check_exposed_secrets())
        issues.extend(self._check_file_permissions())
        issues.extend(self._check_sensitive_logs())
        issues.extend(self._check_unencrypted_storage())
        issues.extend(self._platform_specific_checks())

        # Persist to DB
        for issue in issues:
            self.db.insert_privacy_issue(
                category=issue.category,
                setting_name=issue.setting_name,
                current_value=issue.current_value,
                recommended_value=issue.recommended_value,
                severity=issue.severity,
                description=issue.description,
                cwe_id=issue.cwe_id,
            )
        return issues

    def get_privacy_score(self) -> float:
        """Return overall privacy score (0–100).

        100 = perfect privacy, 0 = critical issues detected.
        """
        issues = self.audit_privacy()
        if not issues:
            return 100.0

        severity_weights = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
        }
        penalty = sum(
            severity_weights.get(i.severity, 5) for i in issues
        )
        score = max(0.0, 100.0 - penalty)
        return round(score, 1)

    def recommend_fixes(self) -> list[dict[str, Any]]:
        """Return actionable privacy recommendations."""
        issues = self.audit_privacy()
        fixes: list[dict[str, Any]] = []
        for issue in issues:
            fixes.append({
                "category": issue.category,
                "setting": issue.setting_name,
                "current": issue.current_value,
                "recommended": issue.recommended_value,
                "severity": issue.severity,
                "auto_fixable": issue.category in (
                    "file_permissions", "unencrypted_storage"
                ),
                "description": issue.description,
            })
        return fixes

    # -- common checks ----------------------------------------------------

    def _check_hardcoded_credentials(self) -> list[PrivacyIssue]:
        """Search common directories for hardcoded credentials."""
        issues: list[PrivacyIssue] = []
        search_roots = self._get_search_roots()

        for root in search_roots:
            if not root.exists():
                continue
            for fpath in root.rglob("*.py"):
                if any(p.startswith(".") for p in fpath.parts):
                    continue
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                for match in _HARDCODED_PASSWORD_RE.finditer(content):
                    issues.append(PrivacyIssue(
                        category="hardcoded_credentials",
                        setting_name=f"password_in_{fpath.name}",
                        current_value=match.group(0)[:60],
                        recommended_value="Use environment variable: os.environ.get('PASSWORD')",
                        severity="critical",
                        description=f"Hardcoded password found in {fpath}",
                        cwe_id="CWE-798",
                    ))
                for match in _HARDCODED_API_KEY_RE.finditer(content):
                    issues.append(PrivacyIssue(
                        category="hardcoded_credentials",
                        setting_name=f"api_key_in_{fpath.name}",
                        current_value=match.group(0)[:60],
                        recommended_value="Use a secrets manager or environment variable",
                        severity="critical",
                        description=f"Hardcoded API key found in {fpath}",
                        cwe_id="CWE-798",
                    ))
                for match in _HARDCODED_TOKEN_RE.finditer(content):
                    issues.append(PrivacyIssue(
                        category="hardcoded_credentials",
                        setting_name=f"token_in_{fpath.name}",
                        current_value=match.group(0)[:60],
                        recommended_value="Store tokens in a secure vault",
                        severity="high",
                        description=f"Hardcoded token found in {fpath}",
                        cwe_id="CWE-798",
                    ))
        return issues

    def _check_exposed_secrets(self) -> list[PrivacyIssue]:
        """Look for secrets exposed in configuration files."""
        issues: list[PrivacyIssue] = []
        config_names = {".env", "config.json", "settings.json", "secrets.json",
                        "credentials.json", "app.config", ".ini", ".yaml", ".yml"}
        search_roots = self._get_search_roots()

        for root in search_roots:
            if not root.exists():
                continue
            for fpath in root.rglob("*"):
                if fpath.name in config_names or fpath.suffix in {".env", ".ini", ".yaml", ".yml"}:
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue
                    for match in _SECRET_IN_CONFIG_RE.finditer(content):
                        issues.append(PrivacyIssue(
                            category="exposed_secrets",
                            setting_name=f"secret_in_{fpath.name}",
                            current_value=match.group(0)[:60] + "...",
                            recommended_value="Move to encrypted vault or secrets manager",
                            severity="critical",
                            description=f"Exposed secret in config file {fpath}",
                            cwe_id="CWE-522",
                        ))
        return issues

    def _check_file_permissions(self) -> list[PrivacyIssue]:
        """Check for overly permissive sensitive files."""
        issues: list[PrivacyIssue] = []
        sensitive_paths = self._get_sensitive_paths()

        for spath in sensitive_paths:
            if not spath.exists():
                continue
            for fpath in spath.rglob("*") if spath.is_dir() else [spath]:
                if not fpath.is_file():
                    continue
                try:
                    mode = fpath.stat().st_mode
                    if mode & stat.S_IROTH or mode & stat.S_IWOTH:
                        issues.append(PrivacyIssue(
                            category="file_permissions",
                            setting_name=str(fpath),
                            current_value=oct(mode),
                            recommended_value="chmod 600" if "private" in str(fpath) else "chmod 644",
                            severity="high" if mode & stat.S_IWOTH else "medium",
                            description=f"Overly permissive file: {fpath} (world-readable/writable)",
                            cwe_id="CWE-732",
                        ))
                except Exception:
                    pass
        return issues

    def _check_sensitive_logs(self) -> list[PrivacyIssue]:
        """Check log files for sensitive data exposure."""
        issues: list[PrivacyIssue] = []
        log_dirs = self._get_log_paths()

        for ldir in log_dirs:
            if not ldir.exists():
                continue
            for log_file in ldir.rglob("*.log") if ldir.is_dir() else [ldir]:
                if not log_file.is_file():
                    continue
                try:
                    lines = log_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                except Exception:
                    continue
                for lineno, line in enumerate(lines, 1):
                    if _SENSITIVE_LOG_RE.search(line):
                        issues.append(PrivacyIssue(
                            category="sensitive_logs",
                            setting_name=str(log_file),
                            current_value=f"Line {lineno}: {line.strip()[:100]}",
                            recommended_value="Mask or remove sensitive fields from log output",
                            severity="high",
                            description=f"Sensitive data in log file {log_file}",
                            cwe_id="CWE-532",
                        ))
                        break  # one issue per log file is enough
        return issues

    def _check_unencrypted_storage(self) -> list[PrivacyIssue]:
        """Check for unencrypted local data storage."""
        issues: list[PrivacyIssue] = []
        roots = self._get_search_roots()

        for root in roots:
            if not root.exists():
                continue
            for fpath in root.rglob("*.py"):
                if any(p.startswith(".") for p in fpath.parts):
                    continue
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                for match in _UNENCRYPTED_STORAGE_RE.finditer(content):
                    issues.append(PrivacyIssue(
                        category="unencrypted_storage",
                        setting_name=f"storage_in_{fpath.name}",
                        current_value=match.group(0)[:80],
                        recommended_value="Use SQLCipher for SQLite or encrypt data at rest",
                        severity="medium",
                        description=f"Potentially unencrypted storage usage in {fpath}",
                        cwe_id="CWE-312",
                    ))
        return issues

    # -- abstract hooks ---------------------------------------------------

    @abstractmethod
    def _platform_specific_checks(self) -> list[PrivacyIssue]:
        """Return platform-specific privacy issues."""
        ...

    def _get_search_roots(self) -> list[Path]:
        """Directories to search for code / config files."""
        return [Path.cwd()]

    def _get_sensitive_paths(self) -> list[Path]:
        """Directories containing sensitive files to permission-check."""
        home = Path.home()
        return [home / ".ssh", home / ".gnupg", home / ".aws", home / ".config"]

    def _get_log_paths(self) -> list[Path]:
        """Directories containing log files to audit."""
        return [Path("/var/log")] if os.name != "nt" else [Path.home() / "AppData" / "Local" / "Logs"]


# ---------------------------------------------------------------------------
# Windows Privacy Auditor
# ---------------------------------------------------------------------------

class WindowsPrivacyAuditor(PrivacyAuditor):
    """Privacy auditor for Windows systems.

    Checks telemetry settings, registry privacy keys, app permissions,
    and Windows-specific data collection.
    """

    def _platform_specific_checks(self) -> list[PrivacyIssue]:
        issues: list[PrivacyIssue] = []
        try:
            import winreg
            # Check telemetry
            issues.extend(self._check_windows_telemetry(winreg))
            issues.extend(self._check_windows_app_permissions(winreg))
            issues.extend(self._check_windows_location(winreg))
        except ImportError:
            pass  # not on Windows
        return issues

    def _check_windows_telemetry(self, winreg: Any) -> list[PrivacyIssue]:
        issues: list[PrivacyIssue] = []
        telemetry_paths = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
             "AllowTelemetry"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
             "AllowTelemetry"),
        ]
        for hkey, path, value_name in telemetry_paths:
            try:
                with winreg.OpenKey(hkey, path) as key:
                    value, _ = winreg.QueryValueEx(key, value_name)
                    if value in (1, 2, 3):  # Basic, Enhanced, Full
                        issues.append(PrivacyIssue(
                            category="telemetry",
                            setting_name=f"Windows Telemetry ({path})",
                            current_value=str(value),
                            recommended_value="0 (Security-only) or disable via Group Policy",
                            severity="medium",
                            description=f"Windows telemetry is enabled (level {value})",
                            cwe_id="CWE-359",
                        ))
            except (FileNotFoundError, OSError):
                pass
        return issues

    def _check_windows_app_permissions(self, winreg: Any) -> list[PrivacyIssue]:
        issues: list[PrivacyIssue] = []
        # Check if app diagnostics are allowed
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\AppCompat"
            ) as key:
                value, _ = winreg.QueryValueEx(key, "DisableInventory")
                if value == 0:
                    issues.append(PrivacyIssue(
                        category="app_permissions",
                        setting_name="Windows App Diagnostics",
                        current_value="enabled",
                        recommended_value="Disable via Group Policy",
                        severity="low",
                        description="Windows app compatibility inventory is enabled",
                        cwe_id="CWE-359",
                    ))
        except (FileNotFoundError, OSError):
            pass
        return issues

    def _check_windows_location(self, winreg: Any) -> list[PrivacyIssue]:
        issues: list[PrivacyIssue] = []
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
            ) as key:
                value, _ = winreg.QueryValueEx(key, "Value")
                if str(value).lower() == "allow":
                    issues.append(PrivacyIssue(
                        category="location_services",
                        setting_name="Windows Location Services",
                        current_value="allowed",
                        recommended_value="Deny",
                        severity="medium",
                        description="Windows location services are enabled system-wide",
                        cwe_id="CWE-359",
                    ))
        except (FileNotFoundError, OSError):
            pass
        return issues

    def _get_log_paths(self) -> list[Path]:
        home = Path.home()
        return [
            home / "AppData" / "Local" / "Logs",
            Path("C:/Windows/Logs"),
        ]


# ---------------------------------------------------------------------------
# Android Privacy Auditor
# ---------------------------------------------------------------------------

class AndroidPrivacyAuditor(PrivacyAuditor):
    """Privacy auditor for Android systems.

    Checks app permissions via ``pm list permissions``, ADB settings,
    and Android-specific privacy controls.
    """

    def _platform_specific_checks(self) -> list[PrivacyIssue]:
        issues: list[PrivacyIssue] = []
        issues.extend(self._check_android_permissions())
        issues.extend(self._check_android_adb())
        issues.extend(self._check_android_location_providers())
        return issues

    def _check_android_permissions(self) -> list[PrivacyIssue]:
        """List dangerous permissions granted to packages."""
        issues: list[PrivacyIssue] = []
        dangerous_perms = {
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_SMS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        }
        try:
            import subprocess
            result = subprocess.run(
                ["pm", "list", "permissions", "-g", "-s"],
                capture_output=True, text=True, timeout=10,
            )
            for perm in dangerous_perms:
                if perm in result.stdout:
                    issues.append(PrivacyIssue(
                        category="android_permissions",
                        setting_name=perm,
                        current_value="granted",
                        recommended_value="Revoke if unnecessary",
                        severity="medium",
                        description=f"Dangerous Android permission may be granted: {perm}",
                        cwe_id="CWE-250",
                    ))
        except Exception:
            pass
        return issues

    def _check_android_adb(self) -> list[PrivacyIssue]:
        """Check if ADB (Android Debug Bridge) is enabled."""
        issues: list[PrivacyIssue] = []
        try:
            import subprocess
            result = subprocess.run(
                ["settings", "get", "global", "adb_enabled"],
                capture_output=True, text=True, timeout=5,
            )
            if result.stdout.strip() == "1":
                issues.append(PrivacyIssue(
                    category="debug_interface",
                    setting_name="ADB (Android Debug Bridge)",
                    current_value="enabled",
                    recommended_value="0 (disable)",
                    severity="high",
                    description="ADB is enabled — exposes device to USB debugging attacks",
                    cwe_id="CWE-419",
                ))
        except Exception:
            pass
        return issues

    def _check_android_location_providers(self) -> list[PrivacyIssue]:
        """Check if location providers (GPS, network) are enabled."""
        issues: list[PrivacyIssue] = []
        try:
            import subprocess
            for provider in ("gps", "network"):
                result = subprocess.run(
                    ["settings", "get", "secure", f"location_providers_allowed"],
                    capture_output=True, text=True, timeout=5,
                )
                if provider in result.stdout.lower():
                    issues.append(PrivacyIssue(
                        category="location_services",
                        setting_name=f"Android Location Provider ({provider})",
                        current_value="enabled",
                        recommended_value="Disable when not needed",
                        severity="low",
                        description=f"Android {provider} location provider is enabled",
                        cwe_id="CWE-359",
                    ))
        except Exception:
            pass
        return issues

    def _get_search_roots(self) -> list[Path]:
        # On Android, check app data directories
        return [Path("/data/data")] if Path("/data/data").exists() else [Path("/sdcard")]

    def _get_sensitive_paths(self) -> list[Path]:
        return [Path("/sdcard/Android")] if Path("/sdcard/Android").exists() else []

    def _get_log_paths(self) -> list[Path]:
        return [Path("/data/log")] if Path("/data/log").exists() else []
