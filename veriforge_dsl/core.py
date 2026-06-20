"""
veriforge_dsl.core -- Forge System

The Forge is the central container for specs, implementations, properties,
and verification results.  It supports registration, property-based testing,
edge-case detection, and specification refinement.
"""

from __future__ import annotations

import math
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .contracts import Contract, Spec, check_invariants, enforce_contracts
from .types import (
    VBool,
    VConstraint,
    VEnum,
    VFloat,
    VInt,
    VList,
    VOptional,
    VStr,
    VType,
    VUnion,
)
from .verification import (
    check_property,
    find_edge_cases,
    generate_inputs,
    run_verification,
)


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    """Outcome of verifying a spec/implementation pair."""

    spec_name: str
    passed: bool
    tests_run: int
    tests_passed: int
    coverage_pct: float
    counterexamples: List[Dict[str, Any]] = field(default_factory=list)
    edge_cases_run: int = 0
    edge_cases_passed: int = 0
    duration_ms: float = 0.0
    messages: List[str] = field(default_factory=list)

    def summary(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        lines = [
            f"=== VerificationResult: {self.spec_name} [{status}] ===",
            f"  Tests: {self.tests_passed}/{self.tests_run} passed",
            f"  Edge cases: {self.edge_cases_passed}/{self.edge_cases_run} passed",
            f"  Coverage: {self.coverage_pct:.1f}%",
            f"  Duration: {self.duration_ms:.1f}ms",
        ]
        if self.counterexamples:
            lines.append(f"  Counterexamples: {len(self.counterexamples)}")
            for cx in self.counterexamples:
                lines.append(f"    - {cx}")
        if self.messages:
            lines.append("  Messages:")
            for m in self.messages:
                lines.append(f"    - {m}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Forge
# ---------------------------------------------------------------------------

@dataclass
class Forge:
    """Module container for specs, implementations, and properties."""

    name: str
    specs: Dict[str, Spec] = field(default_factory=dict)
    implementations: Dict[str, Callable] = field(default_factory=dict)
    properties: List[Callable] = field(default_factory=list)
    _history: List[Dict[str, Any]] = field(default_factory=list, repr=False)

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, spec: Spec, impl: Callable) -> None:
        """Register a spec + implementation pair."""
        self.specs[spec.name] = spec
        self.implementations[spec.name] = impl

    def register_property(self, prop: Callable) -> None:
        """Register a standalone property function."""
        self.properties.append(prop)

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(
        self,
        spec_name: str,
        iterations: int = 100,
        seed: Optional[int] = None,
    ) -> VerificationResult:
        """Run property-based tests + edge cases on a spec."""
        if spec_name not in self.specs:
            return VerificationResult(
                spec_name=spec_name,
                passed=False,
                tests_run=0,
                tests_passed=0,
                coverage_pct=0.0,
                messages=[f"Spec '{spec_name}' not found in forge '{self.name}'"],
            )
        spec = self.specs[spec_name]
        impl = self.implementations.get(spec_name)
        if impl is None:
            return VerificationResult(
                spec_name=spec_name,
                passed=False,
                tests_run=0,
                tests_passed=0,
                coverage_pct=0.0,
                messages=[f"No implementation registered for '{spec_name}'"],
            )
        return run_verification(self, spec_name, iterations=iterations, seed=seed)

    def verify_all(
        self, iterations: int = 100, seed: Optional[int] = None
    ) -> List[VerificationResult]:
        """Verify every registered spec."""
        return [self.verify(name, iterations=iterations, seed=seed) for name in self.specs]

    # ------------------------------------------------------------------
    # Refinement
    # ------------------------------------------------------------------

    def refine(self, spec_name: str, feedback: str) -> Spec:
        """Refine a spec based on feedback / counterexamples.

        Returns a new Spec object with tightened constraints derived from
        the feedback string.
        """
        if spec_name not in self.specs:
            raise KeyError(f"Spec '{spec_name}' not found")
        old_spec = self.specs[spec_name]
        new_inputs = dict(old_spec.inputs)
        new_contracts = Contract(
            preconditions=list(old_spec.contracts.preconditions),
            postconditions=list(old_spec.contracts.postconditions),
            invariants=list(old_spec.contracts.invariants),
        )

        # Simple heuristic refinement based on keyword matching
        fb_lower = feedback.lower()
        if "negative" in fb_lower or "< 0" in fb_lower:
            for k, vtype in new_inputs.items():
                if isinstance(vtype, VInt):
                    new_inputs[k] = VConstraint(
                        vtype, lambda x: x >= 0, name=f"{k}_non_negative"
                    )
                if isinstance(vtype, VFloat):
                    new_inputs[k] = VConstraint(
                        vtype, lambda x: x >= 0.0, name=f"{k}_non_negative"
                    )
        if "empty" in fb_lower and "not" in fb_lower:
            for k, vtype in new_inputs.items():
                if isinstance(vtype, VList):
                    new_inputs[k] = VConstraint(
                        vtype, lambda lst: len(lst) > 0, name=f"{k}_non_empty"
                    )
        if "too large" in fb_lower or "overflow" in fb_lower:
            for k, vtype in new_inputs.items():
                if isinstance(vtype, (VInt, VFloat)) and not isinstance(vtype, VConstraint):
                    new_inputs[k] = VConstraint(
                        vtype, lambda x: x <= 1e12, name=f"{k}_bounded"
                    )
        if "null" in fb_lower or "none" in fb_lower:
            for k, vtype in new_inputs.items():
                if isinstance(vtype, VOptional):
                    new_inputs[k] = vtype.inner

        new_spec = Spec(
            name=old_spec.name,
            inputs=new_inputs,
            output=old_spec.output,
            contracts=new_contracts,
            description=old_spec.description + f"\n[Refined: {feedback}]",
        )
        self.specs[spec_name] = new_spec
        self._history.append({"action": "refine", "spec": spec_name, "feedback": feedback})
        return new_spec

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def describe(self) -> str:
        """Return a human-readable description of this forge."""
        lines = [
            f"Forge: {self.name}",
            f"  Specs: {len(self.specs)}",
            f"  Implementations: {len(self.implementations)}",
            f"  Properties: {len(self.properties)}",
        ]
        for name, spec in self.specs.items():
            lines.append(f"\n  [{name}] {spec.signature_str()}")
            if spec.contracts.preconditions:
                lines.append(f"    Pre: {len(spec.contracts.preconditions)}")
            if spec.contracts.postconditions:
                lines.append(f"    Post: {len(spec.contracts.postconditions)}")
            if spec.contracts.invariants:
                lines.append(f"    Invariants: {len(spec.contracts.invariants)}")
        return "\n".join(lines)

    def get_impl(self, spec_name: str) -> Optional[Callable]:
        return self.implementations.get(spec_name)

    def get_spec(self, spec_name: str) -> Optional[Spec]:
        return self.specs.get(spec_name)
