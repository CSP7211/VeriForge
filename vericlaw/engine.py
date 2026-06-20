"""Core orchestrator for VeriClaw.

VeriClawEngine coordinates the analyzer, mutator, payload generator,
prover, certifier, and policy engine into a unified scan pipeline.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .analyzer import AttackSurfaceAnalyzer
from .certifier import SecurityCertifier
from .ci import PolicyEngine
from .models import (
    AttackSurface,
    EntryPoint,
    Finding,
    Mutation,
    Payload,
    PropertyProof,
    RedTeamResult,
    ScanResult,
    SecurityCertificate,
)
from .mutator import AdversarialMutator
from .payloads import PayloadGenerator
from .prover import SecurityProver
from .report import ReportGenerator
from .swarm import RedTeamSwarm


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class VeriClawEngine:
    """Main orchestrator. Built on VeriForgeEngine concepts."""

    def __init__(self, config: Optional[dict] = None) -> None:
        """Initialize all sub-components.

        *config* may contain:
        - ``timeout`` (int): scan timeout in seconds.
        - ``max_mutations`` (int): cap on mutations per entry point.
        - ``swarm_size`` (int): number of red-team agents.
        - ``policy_level`` (str): "strict" | "standard" | "permissive".
        """
        cfg = config or {}
        self.config = cfg
        self.analyzer = AttackSurfaceAnalyzer()
        self.mutator = AdversarialMutator(config)
        self.payloads = PayloadGenerator()
        self.prover = SecurityProver()
        self.certifier = SecurityCertifier()
        self.policy = PolicyEngine(cfg.get("policy_level", "standard"))
        self.reporter = ReportGenerator()
        self.red_team_swarm = RedTeamSwarm(cfg.get("swarm_size", 5))

    # -- grade helper ------------------------------------------------------

    @staticmethod
    def _grade_from_score(score: float) -> str:
        """Map a risk score (0.0-10.0) to a letter grade."""
        if score <= 1.0:
            return "A+"
        if score <= 2.0:
            return "A"
        if score <= 3.0:
            return "B"
        if score <= 5.0:
            return "C"
        if score <= 7.0:
            return "D"
        return "F"

    # -- core pipeline -----------------------------------------------------

    def scan(self, target: str | Path, **opts) -> ScanResult:
        """Full adversarial scan: analyze -> mutate -> prove -> certify.

        Parameters
        ----------
        target:
            File path or raw Python source code string.
        opts:
            Optional overrides: ``certify`` (bool) to generate a certificate.

        Returns
        -------
        ScanResult
            Aggregated results from the entire pipeline.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        target_str = str(target)

        # 1. Read target code
        code = self._read_target(target)

        # 2. Analyze attack surface
        attack_surface = self.analyzer.analyze(code, filepath=target_str)

        # 3-5. For each high-risk entry point: mutate, generate payloads, prove
        all_mutations: list[Mutation] = []
        all_payloads: list[Payload] = []
        all_proofs: list[PropertyProof] = []
        all_findings: list[Finding] = []

        for ep in attack_surface.entry_points:
            # Determine if this entry point is high-risk
            is_high_risk = self._is_high_risk(ep, attack_surface)

            if is_high_risk:
                # 3. Mutate
                mutations = self.mutator.mutate(code, ep)
                all_mutations.extend(mutations)

                # 4. Generate payloads
                payloads = self.payloads.generate_all(ep)
                for plist in payloads.values():
                    all_payloads.extend(plist)

            # 5. Prove security properties (run on all entry points)
            proofs = self.prover.prove_all(code)
            all_proofs.extend(proofs)

            # Convert attack vectors to findings
            for vec in attack_surface.attack_vectors:
                if vec.entry_point.startswith(target_str) or vec.entry_point.split(":")[0] == target_str:
                    all_findings.append(
                        Finding(
                            id=f"VC-{len(all_findings)+1:04d}",
                            title=vec.type,
                            severity=self._confidence_to_severity(vec.confidence),
                            category=vec.type,
                            description=f"{vec.type} detected at {vec.entry_point}",
                            evidence=vec.evidence,
                            remediation="Review and sanitize input at this location.",
                            cwe_id=vec.cwe_id,
                        )
                    )

        # Deduplicate findings
        seen = set()
        deduped: list[Finding] = []
        for f in all_findings:
            key = f"{f.title}|{f.evidence}"
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        all_findings = deduped

        # 6. Grade results
        risk_score = attack_surface.risk_score
        grade = self._grade_from_score(risk_score)

        # 7. Optionally generate certificate
        certificate: Optional[SecurityCertificate] = None
        if opts.get("certify", False):
            certificate = self.certifier.certify(
                target=target_str,
                findings=all_findings,
                proofs=all_proofs,
            )

        return ScanResult(
            target=target_str,
            timestamp=timestamp,
            attack_surface=attack_surface,
            mutations=all_mutations,
            payloads=all_payloads,
            proofs=all_proofs,
            findings=all_findings,
            certificate=certificate,
            risk_score=risk_score,
            grade=grade,
        )

    def red_team(self, target: str | Path, rounds: int = 5) -> RedTeamResult:
        """Run autonomous red team simulation via swarm.

        Parameters
        ----------
        target:
            File path or raw Python source code string.
        rounds:
            Number of attack rounds.

        Returns
        -------
        RedTeamResult
            Results from the red team simulation.
        """
        return self.red_team_swarm.attack(str(target), rounds=rounds)

    def certify(self, target: str | Path) -> SecurityCertificate:
        """Generate a security certificate for *target*.

        Parameters
        ----------
        target:
            File path or raw Python source code string.

        Returns
        -------
        SecurityCertificate
            A signed security certificate.
        """
        result = self.scan(target)
        return self.certifier.certify(
            target=str(target),
            findings=result.findings,
            proofs=result.proofs,
        )

    # -- internal helpers --------------------------------------------------

    def _read_target(self, target: str | Path) -> str:
        """Resolve *target* to a Python source string."""
        s = str(target)
        if s.endswith(".py") and os.path.isfile(s):
            return Path(s).read_text(encoding="utf-8")
        # If it looks like code (contains newlines or Python syntax), treat as code
        if "\n" in s or s.strip().startswith(("def ", "class ", "import ")):
            return s
        # If it's a file that exists, read it
        if os.path.isfile(s):
            return Path(s).read_text(encoding="utf-8")
        # Otherwise assume it's raw code
        return s

    @staticmethod
    def _is_high_risk(ep: EntryPoint, surface: AttackSurface) -> bool:
        """Determine whether an entry point warrants deep mutation."""
        if ep.risk_indicators:
            return True
        # Check if any attack vectors reference this entry point
        for vec in surface.attack_vectors:
            if ep.name in vec.entry_point:
                return True
        return False

    @staticmethod
    def _confidence_to_severity(confidence: float) -> str:
        """Map attack-vector confidence to a severity string."""
        if confidence >= 0.8:
            return "critical"
        if confidence >= 0.6:
            return "high"
        if confidence >= 0.4:
            return "medium"
        return "low"
