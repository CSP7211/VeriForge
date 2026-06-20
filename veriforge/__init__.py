"""
VeriForge Hardened Platform — v0.4.0

A hardened code verification platform with immutable audit trails,
JWT-based authentication, HMAC integrity checks, and deep compliance
auditing for SOC2 / ISO27001 / PCI-DSS.
"""

from veriforge.config import SecureConfig
from veriforge.auth import AuthManager, Role
from veriforge.audit import AuditEntry, ImmutableAuditLog
from veriforge.semantic import SemanticAnalyzer, Finding, Severity
from veriforge.engine import VeriForgeEngine, VerificationResult, ComplianceLevel
from veriforge.compliance import SOC2Auditor, ISO27001Auditor, PCIDSSAuditor
from veriforge.agent import AgentVerifier
from veriforge.ide import IDEVerifier
from veriforge.report import ReportGenerator

__version__ = "0.4.0-hardened"
__all__ = [
    "SecureConfig",
    "AuthManager",
    "Role",
    "AuditEntry",
    "ImmutableAuditLog",
    "SemanticAnalyzer",
    "Finding",
    "Severity",
    "VeriForgeEngine",
    "VerificationResult",
    "ComplianceLevel",
    "SOC2Auditor",
    "ISO27001Auditor",
    "PCIDSSAuditor",
    "AgentVerifier",
    "IDEVerifier",
    "ReportGenerator",
]
