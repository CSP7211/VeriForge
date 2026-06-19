"""VeriForge Red — Local-First Security Sentinel.

A cross-platform security application that scans code for vulnerabilities,
monitors privacy settings, detects threats, quarantines them, and auto-remediates.
Built on the VeriForge hardened security foundation. 100% local — zero cloud.
"""

__version__ = "1.0.0"

from .core.engine import RedEngine
from .core.updater import Updater, UpdateInfo, UpdateResult, UpdateStatus, VulnDBInfo
from .core.vulndb_loader import VulnDBLoader, VulnSignature, PayloadSignature, CVEMapping

__all__ = [
    "CVEMapping",
    "PayloadSignature",
    "RedEngine",
    "UpdateInfo",
    "UpdateResult",
    "Updater",
    "UpdateStatus",
    "VulnDBInfo",
    "VulnDBLoader",
    "VulnSignature",
]
