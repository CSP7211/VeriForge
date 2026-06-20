"""
VeriForge — Hardened Formal Verification Platform
=================================================
Version: 0.4.0-hardened
License: MIT

A production-grade formal verification engine with defense-in-depth security,
immutable audit trails, and multi-standard compliance auditing.
"""

__version__ = "0.4.0-hardened"
__author__ = "VeriForge Team"

from .engine import VeriForgeEngine, VerificationResult
from .semantic import SemanticAnalyzer, ObfuscationFinding
from .auth import AuthManager, JWTError, RBACError
from .audit import ImmutableAuditLog, AuditEntry
from .config import SecureConfig, ConfigurationError
from .compliance import SOC2Auditor, ISO27001Auditor, PCIDSSAuditor
from .agent import AgentVerifier, AgentAuthError
from .ide import IDEVerifier, PathSanitizationError
from .report import ReportGenerator

__all__ = [
    # Engine
    "VeriForgeEngine",
    "VerificationResult",
    # Semantic
    "SemanticAnalyzer",
    "ObfuscationFinding",
    # Auth
    "AuthManager",
    "JWTError",
    "RBACError",
    # Audit
    "ImmutableAuditLog",
    "AuditEntry",
    # Config
    "SecureConfig",
    "ConfigurationError",
    # Compliance
    "SOC2Auditor",
    "ISO27001Auditor",
    "PCIDSSAuditor",
    # Agent
    "AgentVerifier",
    "AgentAuthError",
    # IDE
    "IDEVerifier",
    "PathSanitizationError",
    # Report
    "ReportGenerator",
]
