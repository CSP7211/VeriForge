"""
vericlaw/ci.py — CI/CD security policy engine.

Enforces security gates in CI/CD pipelines with three policy levels:
- strict:    Zero tolerance, only A+/A grades allowed
- standard:  Normal enforcement, A/B grades allowed
- permissive: Critical-only, C+ grades allowed
"""

from __future__ import annotations

from typing import Any, Optional

from .models import Finding, PolicyDecision, PropertyProof, ScanResult, SecurityCertificate


# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------

# Valid grades in descending order of quality
GRADE_ORDER: dict[str, int] = {
    "A+": 6,
    "A": 5,
    "B": 4,
    "C": 3,
    "D": 2,
    "F": 1,
}

SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}

VALID_LEVELS: set[str] = {"strict", "standard", "permissive"}


class PolicyEngine:
    """CI/CD security policy enforcement engine.

    Evaluates scan results against configurable policy rules and decides
    whether code passes the security gate.

    Policy levels::

        strict:     Zero tolerance — any finding above LOW fails.
                    All property proofs must pass. Grade A+ or A only.

        standard:   CRITICAL or HIGH findings fail.
                    type_safety and injection_resistance proofs must pass.
                    Grade A or B.

        permissive: Only CRITICAL findings fail.
                    At least one property proof must pass.
                    Grade C or above.
    """

    def __init__(self, level: str = "standard") -> None:
        if level not in VALID_LEVELS:
            raise ValueError(
                f"Invalid policy level '{level}'. "
                f"Must be one of: {', '.join(sorted(VALID_LEVELS))}"
            )
        self.level = level

    # -- rule helpers --------------------------------------------------

    def _min_grade(self) -> str:
        """Return the minimum acceptable grade for the current level."""
        return {
            "strict": "A",
            "standard": "B",
            "permissive": "C",
        }[self.level]

    def _severity_threshold(self) -> int:
        """Return the minimum severity rank that triggers a failure."""
        return {
            "strict": SEVERITY_ORDER["LOW"],   # LOW and above fails
            "standard": SEVERITY_ORDER["HIGH"], # HIGH and above fails
            "permissive": SEVERITY_ORDER["CRITICAL"], # only CRITICAL fails
        }[self.level]

    def _required_proofs(self) -> list[str]:
        """Return property proofs that must pass for this level."""
        return {
            "strict": ["type_safety", "memory_safety", "injection_resistance"],
            "standard": ["type_safety", "injection_resistance"],
            "permissive": [],  # At least one must pass (checked separately)
        }[self.level]

    def _grade_passes(self, grade: str) -> bool:
        """Check if the given grade meets the minimum requirement."""
        min_grade = self._min_grade()
        return GRADE_ORDER.get(grade, 0) >= GRADE_ORDER.get(min_grade, 0)

    def _findings_pass(self, findings: list[Finding]) -> bool:
        """Check if findings are within severity threshold."""
        threshold = self._severity_threshold()
        for finding in findings:
            if SEVERITY_ORDER.get(finding.severity, 0) >= threshold:
                return False
        return True

    def _proofs_pass(self, proofs: list[PropertyProof]) -> bool:
        """Check if required proofs have passed."""
        required = self._required_proofs()
        if not required:
            # permissive: at least one proof must pass
            return any(p.status == "proven" for p in proofs)

        proven_names = {p.property_name for p in proofs if p.status == "proven"}
        return all(req in proven_names for req in required)

    def _failed_findings(self, findings: list[Finding]) -> list[Finding]:
        """Return findings that violate the severity threshold."""
        threshold = self._severity_threshold()
        return [
            f for f in findings
            if SEVERITY_ORDER.get(f.severity, 0) >= threshold
        ]

    def _failed_proofs(self, proofs: list[PropertyProof]) -> list[str]:
        """Return names of required proofs that did not pass."""
        required = self._required_proofs()
        if not required:
            # permissive mode: check if at least one passed
            if not any(p.status == "proven" for p in proofs):
                return ["at_least_one_property"]
            return []

        proven_names = {p.property_name for p in proofs if p.status == "proven"}
        return [req for req in required if req not in proven_names]

    # -- public API ----------------------------------------------------

    def check(self, result: ScanResult) -> PolicyDecision:
        """Evaluate a scan result against the active policy.

        Args:
            result: The ScanResult to evaluate.

        Returns:
            PolicyDecision with pass/fail/warn decision, list of violations,
            and actionable recommendations.
        """
        violations: list[str] = []
        recommendations: list[str] = []

        # 1. Check grade
        grade_ok = self._grade_passes(result.grade)
        if not grade_ok:
            violations.append(
                f"Grade '{result.grade}' is below minimum required "
                f"'{self._min_grade()}' for '{self.level}' policy"
            )
            recommendations.append(
                f"Improve security posture to achieve at least grade {self._min_grade()}"
            )

        # 2. Check findings severity
        failed_findings = self._failed_findings(result.findings)
        findings_ok = len(failed_findings) == 0
        if not findings_ok:
            for finding in failed_findings:
                violations.append(
                    f"[{finding.severity}] {finding.title} ({finding.category})"
                )
                if finding.remediation:
                    recommendations.append(
                        f"Fix {finding.title}: {finding.remediation}"
                    )

        # 3. Check proofs
        failed_proof_names = self._failed_proofs(result.proofs)
        proofs_ok = len(failed_proof_names) == 0
        if not proofs_ok:
            if self.level == "permissive":
                violations.append(
                    "At least one property proof must pass"
                )
                recommendations.append(
                    "Run verification scans and fix at least one property violation"
                )
            else:
                for name in failed_proof_names:
                    violations.append(
                        f"Required property proof '{name}' did not pass"
                    )
                    recommendations.append(
                        f"Fix and re-verify the '{name}' security property"
                    )

        # Determine decision
        all_ok = grade_ok and findings_ok and proofs_ok
        has_warnings = (
            not all_ok
            and findings_ok
            and (not grade_ok or not proofs_ok)
        )

        if all_ok:
            decision = "pass"
        elif has_warnings and self.level == "permissive":
            decision = "warn"
        else:
            decision = "fail"

        return PolicyDecision(
            passed=all_ok,
            decision=decision,
            violations=violations,
            recommendations=recommendations,
        )

    def gate(self, result: ScanResult) -> bool:
        """Return True if the code passes the security gate.

        This is the boolean decision used by CI/CD pipelines to block
        or allow deployments.

        Args:
            result: The ScanResult to evaluate.

        Returns:
            True if the scan result passes the active policy.
        """
        decision = self.check(result)
        return decision.decision == "pass"
