"""VeriClaw — Adversarial Security Testing Framework built on VeriForge.

VeriClaw transforms VeriForge's verification engine into an active, continuous
security validation platform that discovers attack surfaces, generates adversarial
mutations, proves security properties, and certifies code safety.
"""

from __future__ import annotations

__version__ = "0.5.0"

# Import all data models so users can do ``from vericlaw import Finding, ScanResult``
from .models import (
    AttackSurface,
    AttackVector,
    Boundary,
    DataFlow,
    EntryPoint,
    Finding,
    FuzzResult,
    Mutation,
    Payload,
    PolicyDecision,
    PropertyProof,
    RedTeamResult,
    ScanResult,
    SecurityCertificate,
)

# Core engine (imports may fail during partial installs — that is okay)
try:
    from .engine import VeriClawEngine
except ImportError:  # pragma: no cover
    VeriClawEngine = None  # type: ignore[misc,assignment]

try:
    from .analyzer import AttackSurfaceAnalyzer
except ImportError:  # pragma: no cover
    AttackSurfaceAnalyzer = None  # type: ignore[misc,assignment]

try:
    from .mutator import AdversarialMutator
except ImportError:  # pragma: no cover
    AdversarialMutator = None  # type: ignore[misc,assignment]

try:
    from .payloads import PayloadGenerator
except ImportError:  # pragma: no cover
    PayloadGenerator = None  # type: ignore[misc,assignment]

try:
    from .prover import SecurityProver
except ImportError:  # pragma: no cover
    SecurityProver = None  # type: ignore[misc,assignment]

try:
    from .certifier import SecurityCertifier
except ImportError:  # pragma: no cover
    SecurityCertifier = None  # type: ignore[misc,assignment]

try:
    from .report import ReportGenerator
except ImportError:  # pragma: no cover
    ReportGenerator = None  # type: ignore[misc,assignment]

try:
    from .ci import PolicyEngine
except ImportError:  # pragma: no cover
    PolicyEngine = None  # type: ignore[misc,assignment]

try:
    from .swarm import (
        FuzzingSwarm,
        RedTeamSwarm,
        VerificationSwarm,
    )
except ImportError:  # pragma: no cover
    RedTeamSwarm = None  # type: ignore[misc,assignment]
    FuzzingSwarm = None  # type: ignore[misc,assignment]
    VerificationSwarm = None  # type: ignore[misc,assignment]

try:
    from .mcp_tools import (
        VERICLAW_TOOLS,
        handle_vericlaw_certify,
        handle_vericlaw_explain,
        handle_vericlaw_red_team,
        handle_vericlaw_scan,
    )
except ImportError:  # pragma: no cover
    VERICLAW_TOOLS = []  # type: ignore[misc,assignment]
    handle_vericlaw_scan = None  # type: ignore[misc,assignment]
    handle_vericlaw_red_team = None  # type: ignore[misc,assignment]
    handle_vericlaw_certify = None  # type: ignore[misc,assignment]
    handle_vericlaw_explain = None  # type: ignore[misc,assignment]

__all__ = [
    "__version__",
    # Core
    "VeriClawEngine",
    "AttackSurfaceAnalyzer",
    "AdversarialMutator",
    "PayloadGenerator",
    "SecurityProver",
    "SecurityCertifier",
    "ReportGenerator",
    "PolicyEngine",
    # Swarms
    "RedTeamSwarm",
    "FuzzingSwarm",
    "VerificationSwarm",
    # MCP
    "VERICLAW_TOOLS",
    "handle_vericlaw_scan",
    "handle_vericlaw_red_team",
    "handle_vericlaw_certify",
    "handle_vericlaw_explain",
    # Models
    "ScanResult",
    "RedTeamResult",
    "FuzzResult",
    "Mutation",
    "Payload",
    "PropertyProof",
    "SecurityCertificate",
    "Finding",
    "PolicyDecision",
    "AttackSurface",
    "EntryPoint",
    "DataFlow",
    "Boundary",
    "AttackVector",
]
