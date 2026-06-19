"""VeriForge Red — Windows Privacy Auditor.

Reads privacy-related settings from the Windows Registry (``winreg``) and
WMI (``wmi``) to produce a list of ``PrivacyIssue`` objects that can be
consumed by the GUI and core engine.

On non-Windows platforms the registry functions gracefully degrade to
returning an empty list so tests and development can still run.
"""

from __future__ import annotations

import logging
import platform
import socket
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Windows imports (conditional) ───────────────────────────────────────────

_IS_WINDOWS = platform.system() == "Windows"

winreg: Any = None
wmi: Any = None

if _IS_WINDOWS:  # pragma: no cover
    try:
        import winreg
    except ImportError:
        winreg = None
    try:
        import wmi
    except ImportError:
        wmi = None


# ── Data model ──────────────────────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(Enum):
    TELEMETRY = "telemetry"
    PERMISSIONS = "permissions"
    NETWORK = "network"
    STORAGE = "storage"


@dataclass
class PrivacyIssue:
    """A single privacy issue discovered on the system."""

    id: str
    title: str
    category: Category
    severity: Severity
    current_value: str
    recommended_value: str
    description: str = ""
    remediation: str = ""
    key_path: str = ""  # registry path or WMI query source
    auto_fixable: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "current_value": self.current_value,
            "recommended_value": self.recommended_value,
            "description": self.description,
            "remediation": self.remediation,
            "key_path": self.key_path,
            "auto_fixable": self.auto_fixable,
        }


# ── Registry helpers ────────────────────────────────────────────────────────

def _read_registry_value(key_path: str, value_name: str, default: Any = None) -> Any:
    """Read a value from the Windows Registry.

    Returns *default* if the key/value does not exist or if not on Windows.
    *key_path* must start with the short hive name, e.g.
    ``HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection``.
    """
    if winreg is None:
        return default

    HIVE_MAP = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKU": winreg.HKEY_USERS,
        "HKCC": winreg.HKEY_CURRENT_CONFIG,
    }

    parts = key_path.split("\\")
    hive_name = parts[0].upper()
    subpath = "\\".join(parts[1:])

    hive = HIVE_MAP.get(hive_name)
    if hive is None:
        return default

    try:
        with winreg.OpenKey(hive, subpath) as key:
            value, _ = winreg.QueryValueEx(key, value_name)
            return value
    except (OSError, FileNotFoundError):
        return default


def _reg_int(key_path: str, value_name: str, default: int = 0) -> int:
    v = _read_registry_value(key_path, value_name, default)
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


# ── Individual check functions ──────────────────────────────────────────────

def _check_telemetry() -> List[PrivacyIssue]:
    issues: List[PrivacyIssue] = []
    if not _IS_WINDOWS:
        return issues

    # Windows 10/11 telemetry level
    tel = _reg_int(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
        "AllowTelemetry",
        -1,
    )
    if tel == -1:
        # try the Windows 11 location
        tel = _reg_int(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "AllowTelemetry",
            -1,
        )
    if tel in (-1, 2, 3):
        issues.append(PrivacyIssue(
            id="WIN-TEL-001",
            title="Windows telemetry set to Full",
            category=Category.TELEMETRY,
            severity=Severity.HIGH,
            current_value="Full" if tel in (2, 3) else "Default",
            recommended_value="Basic (1)",
            description="Windows is sending detailed telemetry data to Microsoft.",
            remediation="Set AllowTelemetry to 1 (Basic) via Group Policy or Registry.",
            key_path=r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry",
            auto_fixable=True,
        ))

    # DiagTrack (Connected User Experiences and Telemetry) service
    dt_running = _is_service_running("DiagTrack")
    if dt_running:
        issues.append(PrivacyIssue(
            id="WIN-TEL-002",
            title="DiagTrack service is running",
            category=Category.TELEMETRY,
            severity=Severity.HIGH,
            current_value="Running",
            recommended_value="Stopped & Disabled",
            description="The Connected User Experiences and Telemetry service collects usage data.",
            remediation="Stop and disable the DiagTrack service.",
            auto_fixable=True,
        ))

    # Feedback frequency
    fb = _reg_int(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "DoNotShowFeedbackNotifications", -1)
    if fb != 1:
        issues.append(PrivacyIssue(
            id="WIN-TEL-003",
            title="Windows feedback notifications enabled",
            category=Category.TELEMETRY,
            severity=Severity.LOW,
            current_value="Enabled" if fb == -1 else "Unknown",
            recommended_value="Disabled",
            description="Windows may prompt for feedback.",
            remediation="Set DoNotShowFeedbackNotifications to 1.",
            auto_fixable=True,
        ))

    return issues


def _check_cortana() -> List[PrivacyIssue]:
    issues: List[PrivacyIssue] = []
    if not _IS_WINDOWS:
        return issues

    cortana_consent = _reg_int(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Search",
        "CortanaConsent",
        -1,
    )
    if cortana_consent == 1:
        issues.append(PrivacyIssue(
            id="WIN-COR-001",
            title="Cortana collecting voice/search data",
            category=Category.TELEMETRY,
            severity=Severity.MEDIUM,
            current_value="Enabled",
            recommended_value="Disabled",
            description="Cortana may collect voice input and search history.",
            remediation="Set CortanaConsent to 0 and disable Cortana.",
            auto_fixable=True,
        ))

    # Bing search integration
    bing = _reg_int(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled", -1)
    if bing == 1:
        issues.append(PrivacyIssue(
            id="WIN-COR-002",
            title="Bing search integration enabled",
            category=Category.TELEMETRY,
            severity=Severity.LOW,
            current_value="Enabled",
            recommended_value="Disabled",
            description="Windows Search sends queries to Bing.",
            remediation="Set BingSearchEnabled to 0.",
            auto_fixable=True,
        ))

    return issues


def _check_location() -> List[PrivacyIssue]:
    issues: List[PrivacyIssue] = []
    if not _IS_WINDOWS:
        return issues

    location = _reg_int(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
        "Value",
        -1,
    )
    if location != "Deny":
        issues.append(PrivacyIssue(
            id="WIN-LOC-001",
            title="Location services enabled",
            category=Category.PERMISSIONS,
            severity=Severity.MEDIUM,
            current_value="Allowed" if location == "Allow" else "Unknown",
            recommended_value="Denied",
            description="Apps may access the device location.",
            remediation="Set location ConsentStore value to 'Deny'.",
            auto_fixable=True,
        ))

    return issues


def _check_camera_microphone() -> List[PrivacyIssue]:
    issues: List[PrivacyIssue] = []
    if not _IS_WINDOWS:
        return issues

    for cap, label in [("webcam", "Camera"), ("microphone", "Microphone")]:
        val = _read_registry_value(
            rf"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{cap}",
            "Value",
        )
        if val != "Deny":
            issues.append(PrivacyIssue(
                id=f"WIN-CAM-{cap[:3].upper()}-001",
                title=f"{label} access allowed for apps",
                category=Category.PERMISSIONS,
                severity=Severity.HIGH,
                current_value=str(val) if val else "Unknown",
                recommended_value="Deny",
                description=f"Apps may access the {label.lower()} without explicit permission.",
                remediation=f"Set {cap} ConsentStore value to 'Deny'.",
                auto_fixable=True,
            ))

    return issues


def _check_advertising_id() -> List[PrivacyIssue]:
    issues: List[PrivacyIssue] = []
    if not _IS_WINDOWS:
        return issues

    ad_id = _reg_int(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
        "Enabled",
        -1,
    )
    if ad_id == 1:
        issues.append(PrivacyIssue(
            id="WIN-ADS-001",
            title="Advertising ID is enabled",
            category=Category.TELEMETRY,
            severity=Severity.MEDIUM,
            current_value="Enabled",
            recommended_value="Disabled",
            description="Windows assigns an advertising ID for targeted ads.",
            remediation="Set Enabled to 0 under AdvertisingInfo.",
            auto_fixable=True,
        ))

    return issues


def _check_startup_apps() -> List[PrivacyIssue]:
    issues: List[PrivacyIssue] = []
    if not _IS_WINDOWS or winreg is None:
        return issues

    startup_keys = [
        (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
        (r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
    ]

    for key_path, _ in startup_keys:
        parts = key_path.split("\\")
        hive_name = parts[0].upper()
        subpath = "\\".join(parts[1:])
        hive = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}.get(hive_name)
        if hive is None:
            continue
        try:
            with winreg.OpenKey(hive, subpath) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        i += 1
                        issues.append(PrivacyIssue(
                            id=f"WIN-STR-{name[:8].upper()}-001",
                            title=f"Startup app: {name}",
                            category=Category.PERMISSIONS,
                            severity=Severity.INFO,
                            current_value=str(value)[:60],
                            recommended_value="Review necessity",
                            description=f"{name} is configured to start on boot.",
                            remediation="Remove from startup if not required.",
                            key_path=key_path,
                            auto_fixable=False,
                        ))
                    except OSError:
                        break
        except OSError:
            continue

    return issues


def _check_firewall() -> List[PrivacyIssue]:
    issues: List[PrivacyIssue] = []
    if not _IS_WINDOWS:
        return issues

    fw_enabled = _reg_int(
        r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
        "EnableFirewall",
        -1,
    )
    if fw_enabled == 0:
        issues.append(PrivacyIssue(
            id="WIN-FWL-001",
            title="Windows Firewall is disabled",
            category=Category.NETWORK,
            severity=Severity.CRITICAL,
            current_value="Disabled",
            recommended_value="Enabled",
            description="The Windows Firewall is turned off, leaving the system exposed.",
            remediation="Set EnableFirewall to 1 in the StandardProfile registry key.",
            auto_fixable=True,
        ))

    return issues


def _check_uac() -> List[PrivacyIssue]:
    issues: List[PrivacyIssue] = []
    if not _IS_WINDOWS:
        return issues

    uac = _reg_int(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableLUA",
        -1,
    )
    if uac == 0:
        issues.append(PrivacyIssue(
            id="WIN-UAC-001",
            title="User Account Control (UAC) is disabled",
            category=Category.PERMISSIONS,
            severity=Severity.CRITICAL,
            current_value="Disabled",
            recommended_value="Enabled",
            description="UAC prompts for elevation are disabled — malware can gain admin rights silently.",
            remediation="Set EnableLUA to 1.",
            auto_fixable=True,
        ))

    consent = _reg_int(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "ConsentPromptBehaviorAdmin",
        -1,
    )
    if consent in (0, 1):
        issues.append(PrivacyIssue(
            id="WIN-UAC-002",
            title="UAC prompt level is too permissive",
            category=Category.PERMISSIONS,
            severity=Severity.HIGH,
            current_value=f"Level {consent}",
            recommended_value="Level 2 (Prompt for consent)",
            description="Admin consent prompt behavior is set too low.",
            remediation="Set ConsentPromptBehaviorAdmin to 2 or higher.",
            auto_fixable=True,
        ))

    return issues


def _check_defender() -> List[PrivacyIssue]:
    issues: List[PrivacyIssue] = []
    if not _IS_WINDOWS:
        return issues

    defender_disabled = _reg_int(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
        "DisableAntiSpyware",
        0,
    )
    if defender_disabled == 1:
        issues.append(PrivacyIssue(
            id="WIN-DEF-001",
            title="Windows Defender is disabled",
            category=Category.PERMISSIONS,
            severity=Severity.CRITICAL,
            current_value="Disabled",
            recommended_value="Enabled",
            description="Windows Defender (Microsoft Defender Antivirus) is turned off.",
            remediation="Remove DisableAntiSpyware or set it to 0.",
            auto_fixable=True,
        ))

    return issues


def _check_password_policy() -> List[PrivacyIssue]:
    issues: List[PrivacyIssue] = []
    if not _IS_WINDOWS:
        return issues

    # These are SAM / LSA settings — often require admin
    min_len = _reg_int(
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "MinPasswordLen",
        -1,
    )
    if min_len == -1:
        min_len = _reg_int(
            r"HKLM\SAM\SAM\Domains\Account",
            "MinPasswordLength",
            0,
        )
    if min_len < 8:
        issues.append(PrivacyIssue(
            id="WIN-PWD-001",
            title="Minimum password length is too short",
            category=Category.PERMISSIONS,
            severity=Severity.HIGH,
            current_value=f"{min_len} chars",
            recommended_value="8+ chars",
            description="The minimum password length policy is weak.",
            remediation="Set MinPasswordLen to 8 or higher via Local Security Policy.",
            auto_fixable=False,
        ))

    return issues


def _check_auto_update() -> List[PrivacyIssue]:
    issues: List[PrivacyIssue] = []
    if not _IS_WINDOWS:
        return issues

    au = _reg_int(
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "NoAutoUpdate",
        -1,
    )
    if au == 1:
        issues.append(PrivacyIssue(
            id="WIN-AUP-001",
            title="Automatic Windows Updates are disabled",
            category=Category.PERMISSIONS,
            severity=Severity.HIGH,
            current_value="Disabled",
            recommended_value="Enabled",
            description="Security patches will not be installed automatically.",
            remediation="Set NoAutoUpdate to 0 in the AU policy key.",
            auto_fixable=True,
        ))

    return issues


def _check_network() -> List[PrivacyIssue]:
    issues: List[PrivacyIssue] = []
    if not _IS_WINDOWS:
        return issues

    # Check for common open ports using socket (port scanning)
    dangerous_ports = {
        21: "FTP",
        23: "Telnet",
        135: "MS RPC",
        139: "NetBIOS",
        445: "SMB",
        3389: "RDP",
        5985: "WinRM HTTP",
    }

    for port, name in dangerous_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex(("127.0.0.1", port))
        sock.close()
        if result == 0:
            sev = Severity.CRITICAL if port in (23, 3389) else Severity.HIGH
            issues.append(PrivacyIssue(
                id=f"WIN-NET-{port:04d}-001",
                title=f"Port {port} ({name}) is open",
                category=Category.NETWORK,
                severity=sev,
                current_value="Open",
                recommended_value="Closed",
                description=f"{name} service is listening on port {port}.",
                remediation=f"Disable the {name} service or block port {port} in the firewall.",
                auto_fixable=False,
            ))

    return issues


# ── WMI-based checks ────────────────────────────────────────────────────────

def _check_wmi() -> List[PrivacyIssue]:
    """Run checks that require the WMI interface."""
    issues: List[PrivacyIssue] = []
    if not _IS_WINDOWS or wmi is None:
        return issues

    try:
        c = wmi.WMI()

        # Windows Defender real-time protection status
        for defender in c.Win32_Service(Name="WinDefend"):
            if defender.State != "Running":
                issues.append(PrivacyIssue(
                    id="WIN-DEF-002",
                    title="Windows Defender service not running",
                    category=Category.PERMISSIONS,
                    severity=Severity.CRITICAL,
                    current_value=defender.State,
                    recommended_value="Running",
                    description="Microsoft Defender Antivirus service is not active.",
                    remediation="Start the WinDefend service.",
                    auto_fixable=True,
                ))

        # Firewall profiles
        for fw in c.Win32_Service(Name="MpsSvc"):
            if fw.State != "Running":
                issues.append(PrivacyIssue(
                    id="WIN-FWL-002",
                    title="Windows Firewall service not running",
                    category=Category.NETWORK,
                    severity=Severity.CRITICAL,
                    current_value=fw.State,
                    recommended_value="Running",
                    description="The Windows Firewall service (MpsSvc) is not running.",
                    remediation="Start the MpsSvc service.",
                    auto_fixable=True,
                ))

        # Check for guest account
        for user in c.Win32_UserAccount(LocalAccount=True):
            if user.Name and user.Name.lower() == "guest" and user.Disabled is False:
                issues.append(PrivacyIssue(
                    id="WIN-ACC-001",
                    title="Guest account is enabled",
                    category=Category.PERMISSIONS,
                    severity=Severity.HIGH,
                    current_value="Enabled",
                    recommended_value="Disabled",
                    description="The built-in Guest account is active.",
                    remediation="Disable the Guest account via Local Users.",
                    auto_fixable=False,
                ))

    except Exception as exc:
        logger.warning("WMI check failed: %s", exc)

    return issues


# ── Service helper ──────────────────────────────────────────────────────────

def _is_service_running(name: str) -> bool:
    """Check whether a Windows service is currently running.

    On non-Windows or if WMI is unavailable, returns *False*.
    """
    if not _IS_WINDOWS or wmi is None:
        return False
    try:
        c = wmi.WMI()
        for svc in c.Win32_Service(Name=name):
            return svc.State == "Running"
    except Exception:
        return False
    return False


# ── Auditor class ───────────────────────────────────────────────────────────

class WindowsPrivacyAuditor:
    """Orchestrates all Windows privacy checks and returns a list of issues."""

    _CHECKS: List[Callable[[], List[PrivacyIssue]]] = [
        _check_telemetry,
        _check_cortana,
        _check_location,
        _check_camera_microphone,
        _check_advertising_id,
        _check_startup_apps,
        _check_firewall,
        _check_uac,
        _check_defender,
        _check_password_policy,
        _check_auto_update,
        _check_network,
        _check_wmi,
    ]

    def run_all(self) -> List[PrivacyIssue]:
        """Execute every privacy check and return the combined list."""
        issues: List[PrivacyIssue] = []
        for check in self._CHECKS:
            try:
                found = check()
                issues.extend(found)
            except Exception as exc:
                logger.error("Privacy check %s failed: %s", check.__name__, exc)
        logger.info("Privacy audit complete: %d issues found", len(issues))
        return issues

    def run_category(self, category: Category) -> List[PrivacyIssue]:
        """Run only checks that match *category*."""
        return [i for i in self.run_all() if i.category == category]

    def calculate_score(self) -> int:
        """Calculate an overall privacy score (0-100).

        Each issue subtracts points based on severity:
        critical = -20, high = -10, medium = -5, low = -2, info = 0.
        """
        issues = self.run_all()
        deductions = {
            Severity.CRITICAL: 20,
            Severity.HIGH: 10,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }
        total = 100 - sum(deductions.get(i.severity, 0) for i in issues)
        return max(0, min(100, total))


# ── Convenience entry-point ─────────────────────────────────────────────────

def main() -> None:
    import json
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    auditor = WindowsPrivacyAuditor()
    issues = auditor.run_all()
    print(f"\nPrivacy Score: {auditor.calculate_score()}/100")
    print(f"Issues found: {len(issues)}\n")
    for issue in issues:
        print(f"[{issue.severity.value.upper()}] {issue.title}")
        print(f"    Current : {issue.current_value}")
        print(f"    Recommend: {issue.recommended_value}")
        print()


if __name__ == "__main__":
    main()
