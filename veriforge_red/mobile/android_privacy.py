"""Android-specific privacy checks using pyjnius.

This module provides a comprehensive set of privacy auditing functions
that inspect Android system settings, package permissions, and device
configuration.  All checks are **read-only** and do not modify any
settings.

Typical usage::

    from veriforge_red.mobile.android_privacy import AndroidPrivacyAuditor
    auditor = AndroidPrivacyAuditor()
    report = auditor.full_audit()
    print(report["score"], report["issues"])

Author: VeriForge Team
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from kivy.logger import Logger

# ---------------------------------------------------------------------------
# pyjnius imports
# ---------------------------------------------------------------------------

try:
    from jnius import autoclass, cast

    _ANDROID_AVAILABLE = True
except ImportError:
    _ANDROID_AVAILABLE = False
    Logger.warning("android_privacy: pyjnius not available — using stub implementation")

    def autoclass(name: str):
        raise RuntimeError("autoclass stub — not on Android")

    def cast(cls, obj):
        return obj


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(Enum):
    PERMISSIONS = "permissions"
    NETWORK = "network"
    STORAGE = "storage"
    LOCATION = "location"
    SYSTEM = "system"


@dataclass
class PrivacyIssue:
    """A single privacy issue found during an audit."""

    title: str
    description: str
    severity: Severity
    category: Category
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "recommendation": self.recommendation,
        }


@dataclass
class PrivacyReport:
    """Aggregated result of a full privacy audit."""

    score: int = 100  # 0-100, higher is better
    issues: list[PrivacyIssue] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "issues": [i.to_dict() for i in self.issues],
        }


# ---------------------------------------------------------------------------
# Core auditor
# ---------------------------------------------------------------------------

class AndroidPrivacyAuditor:
    """Android privacy auditor using system APIs via pyjnius.

    Each ``check_*`` method returns a list of :class:`PrivacyIssue` objects
    (empty when no issue is detected).  The :meth:`full_audit` method runs
    all checks and computes an aggregate score.
    """

    # Dangerous permissions defined by Android
    DANGEROUS_PERMISSIONS = [
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.CALL_PHONE",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.BODY_SENSORS",
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
    ]

    def __init__(self):
        self._context = None
        self._pm = None
        self._cr = None
        if _ANDROID_AVAILABLE:
            try:
                PythonActivity = autoclass("org.kivy.android.PythonActivity")
                self._context = PythonActivity.mActivity
                self._pm = self._context.getPackageManager()
                self._cr = self._context.getContentResolver()
            except Exception as exc:
                Logger.error("android_privacy: context init failed: %s", exc)

    # -- Public API --------------------------------------------------------

    def full_audit(self) -> PrivacyReport:
        """Run all privacy checks and return an aggregate report.

        The score starts at 100 and is reduced based on the severity of
        findings:
          - Critical: -15 points
          - High:     -10 points
          - Medium:   -5  points
          - Low:      -2  points
        """
        issues: list[PrivacyIssue] = []
        checks = [
            self.check_app_permissions,
            self.check_location_services,
            self.check_unknown_sources,
            self.check_usb_debugging,
            self.check_developer_options,
            self.check_screen_lock,
            self.check_encryption,
            self.check_backup_enabled,
            self.check_accessibility_services,
            self.check_notification_access,
            self.check_device_admins,
            self.check_overlay_permission,
        ]
        for check_fn in checks:
            try:
                found = check_fn()
                if found:
                    issues.extend(found)
            except Exception as exc:
                Logger.warning("android_privacy: %s failed: %s", check_fn.__name__, exc)

        # Calculate score
        deductions = {
            Severity.CRITICAL: 15,
            Severity.HIGH: 10,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
        }
        score = max(0, 100 - sum(deductions.get(i.severity, 0) for i in issues))
        return PrivacyReport(score=score, issues=issues)

    # -- Individual checks -------------------------------------------------

    def check_app_permissions(self) -> list[PrivacyIssue]:
        """Check which installed apps hold dangerous permissions."""
        if not _ANDROID_AVAILABLE or self._pm is None:
            return self._stub_issue(
                "App permissions check requires Android runtime",
                Category.PERMISSIONS,
            )
        issues = []
        try:
            PackageInfo = autoclass("android.content.pm.PackageInfo")
            GET_PERMISSIONS = 4096  # PackageManager.GET_PERMISSIONS
            packages = self._pm.getInstalledPackages(GET_PERMISSIONS)
            flagged_apps = []
            for pkg in packages:
                try:
                    perms = pkg.requestedPermissions
                    if perms is None:
                        continue
                    dangerous = [p for p in perms if p in self.DANGEROUS_PERMISSIONS]
                    if dangerous:
                        app_name = pkg.applicationInfo.loadLabel(self._pm).toString()
                        flagged_apps.append(f"{app_name}: {len(dangerous)} dangerous")
                except Exception:
                    continue
            if flagged_apps:
                sample = flagged_apps[:5]
                issues.append(PrivacyIssue(
                    title=f"{len(flagged_apps)} apps have dangerous permissions",
                    description="; ".join(sample),
                    severity=Severity.MEDIUM,
                    category=Category.PERMISSIONS,
                    recommendation="Review app permissions in Settings > Apps",
                ))
        except Exception as exc:
            Logger.error("android_privacy: check_app_permissions: %s", exc)
        return issues

    def check_location_services(self) -> list[PrivacyIssue]:
        """Check if GPS/location services are enabled."""
        if not _ANDROID_AVAILABLE or self._cr is None:
            return self._stub_issue("Location services check requires Android", Category.LOCATION)
        try:
            Secure = autoclass("android.provider.Settings$Secure")
            location_mode = Secure.getInt(self._cr, Secure.LOCATION_MODE, 0)
            if location_mode != 0:
                return [PrivacyIssue(
                    title="Location services are enabled",
                    description=f"Location mode = {location_mode}",
                    severity=Severity.LOW,
                    category=Category.LOCATION,
                    recommendation="Disable GPS when not needed",
                )]
        except Exception as exc:
            Logger.error("android_privacy: check_location_services: %s", exc)
        return []

    def check_unknown_sources(self) -> list[PrivacyIssue]:
        """Check if 'Install from unknown sources' is enabled."""
        if not _ANDROID_AVAILABLE or self._cr is None:
            return self._stub_issue("Unknown sources check requires Android", Category.SYSTEM)
        try:
            Secure = autoclass("android.provider.Settings$Secure")
            value = Secure.getInt(self._cr, Secure.INSTALL_NON_MARKET_APPS, 0)
            if value == 1:
                return [PrivacyIssue(
                    title="Unknown sources installation enabled",
                    description="Apps can be installed from outside Google Play",
                    severity=Severity.HIGH,
                    category=Category.SYSTEM,
                    recommendation="Disable: Settings > Security > Unknown Sources",
                )]
        except Exception as exc:
            Logger.error("android_privacy: check_unknown_sources: %s", exc)
        return []

    def check_usb_debugging(self) -> list[PrivacyIssue]:
        """Check if ADB / USB debugging is enabled."""
        if not _ANDROID_AVAILABLE or self._cr is None:
            return self._stub_issue("USB debugging check requires Android", Category.SYSTEM)
        try:
            Secure = autoclass("android.provider.Settings$Secure")
            value = Secure.getInt(self._cr, Secure.ADB_ENABLED, 0)
            if value == 1:
                return [PrivacyIssue(
                    title="USB debugging (ADB) is enabled",
                    description="Your device is accessible via USB debugging",
                    severity=Severity.HIGH,
                    category=Category.SYSTEM,
                    recommendation="Disable: Settings > Developer Options > USB Debugging",
                )]
        except Exception as exc:
            Logger.error("android_privacy: check_usb_debugging: %s", exc)
        return []

    def check_developer_options(self) -> list[PrivacyIssue]:
        """Check if Developer Options is enabled."""
        if not _ANDROID_AVAILABLE or self._cr is None:
            return self._stub_issue("Developer options check requires Android", Category.SYSTEM)
        try:
            Secure = autoclass("android.provider.Settings$Secure")
            value = Secure.getInt(self._cr, Secure.DEVELOPMENT_SETTINGS_ENABLED, 0)
            if value == 1:
                return [PrivacyIssue(
                    title="Developer options are enabled",
                    description="Developer mode is active on this device",
                    severity=Severity.LOW,
                    category=Category.SYSTEM,
                    recommendation="Disable if not needed: Settings > Developer Options",
                )]
        except Exception as exc:
            Logger.error("android_privacy: check_developer_options: %s", exc)
        return []

    def check_screen_lock(self) -> list[PrivacyIssue]:
        """Check if a screen lock (PIN / pattern / password) is set."""
        if not _ANDROID_AVAILABLE:
            return self._stub_issue("Screen lock check requires Android", Category.SYSTEM)
        try:
            KeyguardManager = autoclass("android.app.KeyguardManager")
            kg = cast(
                "android.app.KeyguardManager",
                self._context.getSystemService(self._context.KEYGUARD_SERVICE),
            )
            if not kg.isKeyguardSecure():
                return [PrivacyIssue(
                    title="No secure screen lock set",
                    description="Device has no PIN, pattern, or password",
                    severity=Severity.CRITICAL,
                    category=Category.SYSTEM,
                    recommendation="Set a screen lock: Settings > Security > Screen Lock",
                )]
        except Exception as exc:
            Logger.error("android_privacy: check_screen_lock: %s", exc)
        return []

    def check_encryption(self) -> list[PrivacyIssue]:
        """Check if device storage is encrypted."""
        if not _ANDROID_AVAILABLE:
            return self._stub_issue("Encryption check requires Android", Category.STORAGE)
        try:
            DevicePolicyManager = autoclass("android.app.admin.DevicePolicyManager")
            dpm = cast(
                "android.app.admin.DevicePolicyManager",
                self._context.getSystemService(self._context.DEVICE_POLICY_SERVICE),
            )
            # API 11+: getStorageEncryptionStatus
            storage_status = dpm.getStorageEncryptionStatus()
            # ENCRYPTION_STATUS_INACTIVE = 1, ENCRYPTION_STATUS_ACTIVATING = 2,
            # ENCRYPTION_STATUS_ACTIVE = 3, ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY = 4
            if storage_status in (1, 2):
                return [PrivacyIssue(
                    title="Device storage is not encrypted",
                    description="Data on this device is stored without encryption",
                    severity=Severity.CRITICAL,
                    category=Category.STORAGE,
                    recommendation="Enable encryption: Settings > Security > Encrypt Device",
                )]
        except Exception as exc:
            Logger.error("android_privacy: check_encryption: %s", exc)
        return []

    def check_backup_enabled(self) -> list[PrivacyIssue]:
        """Check if cloud backup (Android Backup Service) is enabled."""
        if not _ANDROID_AVAILABLE or self._cr is None:
            return self._stub_issue("Backup check requires Android", Category.STORAGE)
        try:
            Secure = autoclass("android.provider.Settings$Secure")
            value = Secure.getInt(self._cr, Secure.BACKUP_ENABLED, 0)
            if value == 1:
                return [PrivacyIssue(
                    title="Cloud backup is enabled",
                    description="App data may be backed up to Google servers",
                    severity=Severity.LOW,
                    category=Category.STORAGE,
                    recommendation="Review backup settings: Settings > Backup",
                )]
        except Exception as exc:
            Logger.error("android_privacy: check_backup_enabled: %s", exc)
        return []

    def check_accessibility_services(self) -> list[PrivacyIssue]:
        """List enabled accessibility services (potential overlay malware)."""
        if not _ANDROID_AVAILABLE or self._cr is None:
            return self._stub_issue("Accessibility check requires Android", Category.PERMISSIONS)
        try:
            Secure = autoclass("android.provider.Settings$Secure")
            services = Secure.getString(self._cr, Secure.ENABLED_ACCESSIBILITY_SERVICES)
            if services:
                svc_list = [s.strip() for s in services.split(":") if s.strip()]
                if svc_list:
                    return [PrivacyIssue(
                        title=f"{len(svc_list)} accessibility service(s) enabled",
                        description=f"Services: {', '.join(svc_list[:3])}",
                        severity=Severity.MEDIUM,
                        category=Category.PERMISSIONS,
                        recommendation="Review: Settings > Accessibility — disable unknown services",
                    )]
        except Exception as exc:
            Logger.error("android_privacy: check_accessibility_services: %s", exc)
        return []

    def check_notification_access(self) -> list[PrivacyIssue]:
        """Check which apps have notification listener access."""
        if not _ANDROID_AVAILABLE or self._cr is None:
            return self._stub_issue("Notification access check requires Android", Category.PERMISSIONS)
        try:
            Secure = autoclass("android.provider.Settings$Secure")
            listeners = Secure.getString(self._cr, Secure.ENABLED_NOTIFICATION_LISTENERS)
            if listeners:
                listener_list = [l.strip() for l in listeners.split(":") if l.strip()]
                if listener_list:
                    return [PrivacyIssue(
                        title=f"{len(listener_list)} app(s) have notification access",
                        description=f"Listeners: {', '.join(listener_list[:3])}",
                        severity=Severity.MEDIUM,
                        category=Category.PERMISSIONS,
                        recommendation="Review: Settings > Apps > Special Access > Notification Access",
                    )]
        except Exception as exc:
            Logger.error("android_privacy: check_notification_access: %s", exc)
        return []

    def check_device_admins(self) -> list[PrivacyIssue]:
        """Check which apps have device admin privileges."""
        if not _ANDROID_AVAILABLE:
            return self._stub_issue("Device admin check requires Android", Category.SYSTEM)
        try:
            DevicePolicyManager = autoclass("android.app.admin.DevicePolicyManager")
            dpm = cast(
                "android.app.admin.DevicePolicyManager",
                self._context.getSystemService(self._context.DEVICE_POLICY_SERVICE),
            )
            admins = dpm.getActiveAdmins()
            if admins:
                admin_names = [a.flattenToShortString() for a in admins.toArray()]
                return [PrivacyIssue(
                    title=f"{len(admin_names)} device admin app(s) active",
                    description=f"Admins: {', '.join(admin_names[:3])}",
                    severity=Severity.MEDIUM,
                    category=Category.SYSTEM,
                    recommendation="Review: Settings > Security > Device Admin Apps",
                )]
        except Exception as exc:
            Logger.error("android_privacy: check_device_admins: %s", exc)
        return []

    def check_overlay_permission(self) -> list[PrivacyIssue]:
        """Check which apps have SYSTEM_ALERT_WINDOW (draw over other apps)."""
        if not _ANDROID_AVAILABLE or self._pm is None:
            return self._stub_issue("Overlay check requires Android", Category.PERMISSIONS)
        try:
            AppOpsManager = autoclass("android.app.AppOpsManager")
            MODE_ALLOWED = autoclass("android.app.AppOpsManager").MODE_ALLOWED
            aom = cast(
                "android.app.AppOpsManager",
                self._context.getSystemService(self._context.APP_OPS_SERVICE),
            )
            # Check using app ops
            packages = self._pm.getInstalledPackages(0)
            overlay_apps = []
            for pkg in packages:
                try:
                    uid = pkg.applicationInfo.uid
                    pkg_name = pkg.packageName
                    mode = aom.checkOpNoThrow(
                        AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW,
                        uid,
                        pkg_name,
                    )
                    if mode == MODE_ALLOWED:
                        app_name = pkg.applicationInfo.loadLabel(self._pm).toString()
                        overlay_apps.append(app_name)
                except Exception:
                    continue
            if overlay_apps:
                sample = overlay_apps[:5]
                return [PrivacyIssue(
                    title=f"{len(overlay_apps)} app(s) can draw over other apps",
                    description=f"Apps: {', '.join(sample)}",
                    severity=Severity.MEDIUM,
                    category=Category.PERMISSIONS,
                    recommendation="Review: Settings > Apps > Special Access > Draw over apps",
                )]
        except Exception as exc:
            Logger.error("android_privacy: check_overlay_permission: %s", exc)
        return []

    # -- Helpers -----------------------------------------------------------

    @staticmethod
    def _stub_issue(message: str, category: Category) -> list[PrivacyIssue]:
        """Return a low-severity stub issue when Android APIs are unavailable."""
        return [PrivacyIssue(
            title=message,
            description="Running on non-Android platform — check skipped",
            severity=Severity.LOW,
            category=category,
        )]


def run_privacy_audit() -> dict:
    """Convenience function — run a full audit and return a plain dict."""
    auditor = AndroidPrivacyAuditor()
    return auditor.full_audit().to_dict()


if __name__ == "__main__":
    import json
    result = run_privacy_audit()
    print(json.dumps(result, indent=2))
