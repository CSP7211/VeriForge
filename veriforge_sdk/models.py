"""Shared data models used across all VeriForge products.

Pydantic-style dataclasses are used so the SDK has zero mandatory heavy
dependencies while remaining fully type-safe.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(Enum):
    """Vulnerability / finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Grade(Enum):
    """Overall scan / assessment grade."""

    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class Status(Enum):
    """Lifecycle status of a result or operation."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class Confidence(Enum):
    """Confidence level in a finding or consensus vote."""

    CERTAIN = "certain"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCERTAIN = "uncertain"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Finding:
    """A single security or compliance finding.

    Attributes:
        title: Short human-readable title.
        description: Detailed explanation.
        severity: Severity classification.
        category: CWE or taxonomy category (e.g. ``CWE-79``).
        file_path: Affected file, if applicable.
        line_start: Starting line number (1-based).
        line_end: Ending line number, inclusive.
        remediation: Suggested fix or mitigation.
        references: External URLs for further reading.
        metadata: Arbitrary extra fields from the scanner.
    """

    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    category: str = ""
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def is_critical(self) -> bool:
        """Return ``True`` if severity is CRITICAL."""
        return self.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ScanResult:
    """Result of a RED code-scanning operation.

    Attributes:
        scan_id: Unique identifier for this scan.
        target: Path or URI that was scanned.
        grade: Overall grade derived from findings.
        findings: All findings produced by the scan.
        duration_ms: Wall-clock time in milliseconds.
        scanned_at: ISO-8601 timestamp.
        scanner_version: RED engine version.
        metadata: Extra context (loc, file count, etc.).
    """

    scan_id: str
    target: str
    grade: Grade
    findings: List[Finding] = field(default_factory=list)
    duration_ms: float = 0.0
    scanned_at: str = ""
    scanner_version: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if not self.scanned_at:
            from datetime import timezone
            self.scanned_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        if not self.scan_id:
            self.scan_id = secrets.token_hex(8)

    @property
    def count_by_severity(self) -> Dict[Severity, int]:
        """Return a mapping of severity -> count."""
        counts: Dict[Severity, int] = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def has_critical(self) -> bool:
        """True if any finding is CRITICAL."""
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    @property
    def fingerprint(self) -> str:
        """Return a SHA-256 fingerprint of the findings for deduplication."""
        payload = "|".join(
            f"{f.title}:{f.severity.value}:{f.file_path}:{f.line_start}"
            for f in sorted(self.findings, key=lambda x: x.title)
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# TestResult
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class TestResult:
    """Result of a VeriClaw test execution.

    Attributes:
        test_id: Unique identifier.
        suite: Test suite name.
        passed: Number of passed assertions.
        failed: Number of failed assertions.
        skipped: Number of skipped tests.
        errors: Raw error messages.
        coverage_percent: Code coverage (0-100).
        duration_ms: Wall-clock time in milliseconds.
    """

    test_id: str
    suite: str = "default"
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    errors: List[str] = field(default_factory=list)
    coverage_percent: float = 0.0
    duration_ms: float = 0.0

    @property
    def total(self) -> int:
        return self.passed + self.failed + self.skipped

    @property
    def success_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return self.passed / self.total

    @property
    def ok(self) -> bool:
        return self.failed == 0 and not self.errors


# ---------------------------------------------------------------------------
# VerificationResult
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class VerificationResult:
    """Result of a DSL verification pass.

    Attributes:
        verified: ``True`` if the DSL passes all rules.
        violations: Human-readable violation messages.
        rules_checked: Number of rules evaluated.
        rules_passed: Number of rules that passed.
    """

    verified: bool = False
    violations: List[str] = field(default_factory=list)
    rules_checked: int = 0
    rules_passed: int = 0

    @property
    def rules_failed(self) -> int:
        return self.rules_checked - self.rules_passed


# ---------------------------------------------------------------------------
# ToolCallResult
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ToolCallResult:
    """Result of an MCP tool invocation.

    Attributes:
        tool_name: Name of the tool that was called.
        output: Structured output from the tool.
        exit_code: Process exit code (0 = success).
        stdout: Raw standard output.
        stderr: Raw standard error.
        duration_ms: Wall-clock time in milliseconds.
    """

    tool_name: str
    output: Dict[str, Any] = field(default_factory=dict)
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0

    @property
    def success(self) -> bool:
        return self.exit_code == 0


# ---------------------------------------------------------------------------
# ConsensusResult
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ConsensusResult:
    """Result of a Swarm consensus round.

    Attributes:
        reached: ``True`` if quorum was achieved.
        outcome: The agreed-upon value or decision.
        votes: Mapping of node_id -> vote value.
        quorum: Required number of agreeing nodes.
        confidence: Aggregated confidence level.
    """

    reached: bool = False
    outcome: str = ""
    votes: Dict[str, str] = field(default_factory=dict)
    quorum: int = 0
    confidence: Confidence = Confidence.UNCERTAIN

    @property
    def agreement_ratio(self) -> float:
        if not self.votes:
            return 0.0
        if not self.outcome:
            return 0.0
        agreeing = sum(1 for v in self.votes.values() if v == self.outcome)
        return agreeing / len(self.votes)


# ---------------------------------------------------------------------------
# ComplianceResult
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ComplianceResult:
    """Result of a Core compliance audit.

    Attributes:
        standard: Compliance standard (e.g. ``SOC2``, ``GDPR``).
        compliant: Overall pass/fail.
        controls: List of individual control results.
        score: Numeric compliance score (0-100).
        auditor_signature: Cryptographic signature of the report.
    """

    standard: str = ""
    compliant: bool = False
    controls: List[ControlResult] = field(default_factory=list)
    score: float = 0.0
    auditor_signature: str = ""


@dataclass(slots=True)
class ControlResult:
    """Individual compliance control check.

    Attributes:
        control_id: Identifier for the control.
        title: Human-readable title.
        passed: Whether the control passed.
        evidence: Evidence collected.
        remediation: Remediation guidance if failed.
    """

    control_id: str
    title: str = ""
    passed: bool = False
    evidence: str = ""
    remediation: str = ""


# ---------------------------------------------------------------------------
# HealthStatus
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class HealthStatus:
    """Platform health check response.

    Attributes:
        status: Overall status string (``ok`` / ``degraded`` / ``down``).
        products: Per-product health map.
        version: Platform version.
        uptime_seconds: Platform uptime.
    """

    status: str = "ok"
    products: Dict[str, str] = field(default_factory=dict)
    version: str = "unknown"
    uptime_seconds: float = 0.0

    @property
    def healthy(self) -> bool:
        return self.status == "ok"


# ---------------------------------------------------------------------------
# SignedPayload
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SignedPayload:
    """Cryptographically signed result payload.

    Attributes:
        payload: The original result serialized to JSON string.
        signature: HMAC-SHA256 signature (hex).
        algorithm: Signature algorithm identifier.
        timestamp: Unix epoch seconds.
    """

    payload: str
    signature: str
    algorithm: str = "HMAC-SHA256"
    timestamp: float = 0.0
