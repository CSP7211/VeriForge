"""vericlaw/models.py — Shared data models.

All dataclasses used across VeriClaw modules. Centralised here to avoid
circular imports between the engine, analyser, mutator, prover, certifier,
CI, swarm, and reporting layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EntryPoint:
    """An entry point into the attack surface."""

    name: str
    type: str  # "function"|"class"|"method"|"endpoint"
    line: int
    parameters: list[str] = field(default_factory=list)
    returns: Optional[str] = None
    decorators: list[str] = field(default_factory=list)
    docstring: Optional[str] = None
    risk_indicators: list[str] = field(default_factory=list)


@dataclass
class DataFlow:
    """A taint flow from source to sink."""

    source: str
    sink: str
    path: list[str] = field(default_factory=list)
    taint_level: str = "low"  # "high"|"medium"|"low"


@dataclass
class Boundary:
    """A trust boundary in the system."""

    name: str
    type: str  # "network"|"filesystem"|"database"|"process"
    protections: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)


@dataclass
class AttackVector:
    """A classified attack vector."""

    type: str  # OWASP category
    entry_point: str
    confidence: float
    evidence: str
    cwe_id: Optional[str] = None


@dataclass
class AttackSurface:
    """Complete attack surface for a target."""

    entry_points: list[EntryPoint] = field(default_factory=list)
    data_flows: list[DataFlow] = field(default_factory=list)
    trust_boundaries: list[Boundary] = field(default_factory=list)
    attack_vectors: list[AttackVector] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class Mutation:
    """An adversarial code mutation."""

    original: str
    mutated: str
    mutation_type: str  # "boundary"|"injection"|"encoding"|"semantic"|"resource"
    description: str
    severity: str  # "critical"|"high"|"medium"|"low"


@dataclass
class Payload:
    """An attack payload."""

    content: str
    payload_type: str
    context: str
    encoding: str = "raw"  # "raw"|"base64"|"urlencode"|"hex"|"unicode"
    severity: str = "high"


@dataclass
class PropertyProof:
    """Result of a formal security property proof."""

    property_name: str
    status: str  # "proven"|"violated"|"timeout"|"error"
    counterexample: Optional[str] = None
    verification_time_ms: int = 0
    confidence: float = 0.0


@dataclass
class Finding:
    """A security finding."""

    id: str
    title: str
    severity: str  # "critical"|"high"|"medium"|"low"
    category: str
    description: str
    evidence: str
    remediation: str = ""
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    confidence: float = 0.0
    exploitability: float = 0.0


@dataclass(frozen=True)
class SecurityCertificate:
    """A cryptographically signed security certificate."""

    target: str
    timestamp: str = ""
    findings: list[Finding] = field(default_factory=list)
    proofs: list[PropertyProof] = field(default_factory=list)
    risk_score: float = 0.0
    grade: str = "F"  # "A+"|"A"|"B"|"C"|"D"|"F"
    signature: str = ""  # HMAC-SHA256
    expires: str = ""


@dataclass
class ScanResult:
    """Result of a full adversarial scan."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    proofs: list[PropertyProof] = field(default_factory=list)
    timestamp: str = ""
    attack_surface: AttackSurface = field(default_factory=AttackSurface)
    mutations: list[Mutation] = field(default_factory=list)
    payloads: list[Payload] = field(default_factory=list)
    certificate: Optional[SecurityCertificate] = None
    risk_score: float = 0.0
    grade: str = "F"


@dataclass
class RedTeamResult:
    """Result of an autonomous red team simulation."""

    target: str
    rounds: int
    findings: list[Finding]
    attack_chain: list[dict] = field(default_factory=list)
    success_rate: float = 0.0
    time_elapsed_ms: int = 0


@dataclass
class PolicyDecision:
    """Result of a CI/CD policy check."""

    passed: bool
    decision: str  # "pass"|"fail"|"warn"
    violations: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class FuzzResult:
    """Result of a distributed fuzzing run."""

    target: str
    iterations: int
    total_agents: int = 0
    crashes: list[dict] = field(default_factory=list)
    violations: list[dict] = field(default_factory=list)
    unique_issues: list[dict] = field(default_factory=list)
    coverage: float = 0.0
    time_elapsed_ms: int = 0