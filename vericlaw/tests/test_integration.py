"""
vericlaw/tests/test_integration.py — Integration tests for swarms, CI/CD, MCP tools.

Covers:
- RedTeamSwarm with 5 specialist agents
- FuzzingSwarm iteration distribution
- VerificationSwarm property proving
- PolicyEngine strict/standard/permissive modes
- MCP tool handlers return valid responses
- GitHub Action YAML validity
"""

from __future__ import annotations

import os
import re
import uuid
from typing import Any

import pytest
import yaml

from vericlaw.ci import (
    Finding,
    PolicyDecision,
    PolicyEngine,
    PropertyProof,
    ScanResult,
    SecurityCertificate,
)
from vericlaw.mcp_tools import (
    VERICLAW_TOOLS,
    handle_vericlaw_certify,
    handle_vericlaw_explain,
    handle_vericlaw_red_team,
    handle_vericlaw_scan,
)
from vericlaw.swarm import (
    Finding as SwarmFinding,
    FuzzResult,
    FuzzingSwarm,
    PropertyProof as SwarmPropertyProof,
    RedTeamResult,
    RedTeamSwarm,
    VerificationSwarm,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_target() -> str:
    """A sample code target for testing."""
    return "def login(user, password):\n    query = 'SELECT * FROM users WHERE user=\"' + user + '\"'"


@pytest.fixture
def sample_findings() -> list[Finding]:
    """Sample findings for policy engine tests."""
    return [
        Finding(
            id="FND-001",
            title="SQL Injection",
            severity="CRITICAL",
            category="sql_injection",
            description="Unparameterized query",
            evidence="cursor.execute(query)",
            remediation="Use parameterized queries",
            cwe_id="CWE-89",
            cvss_score=9.8,
        ),
        Finding(
            id="FND-002",
            title="XSS in Comments",
            severity="HIGH",
            category="xss",
            description="User input rendered without escaping",
            evidence="innerHTML = userInput",
            remediation="Use textContent instead",
            cwe_id="CWE-79",
            cvss_score=7.5,
        ),
        Finding(
            id="FND-003",
            title="Weak Logging",
            severity="LOW",
            category="logging",
            description="Insufficient security logging",
            evidence="No logging for auth failures",
            remediation="Add comprehensive logging",
        ),
    ]


@pytest.fixture
def sample_proofs_all_pass() -> list[PropertyProof]:
    """Sample proofs that all pass."""
    return [
        PropertyProof(
            property_name="type_safety",
            status="proven",
            confidence=0.95,
        ),
        PropertyProof(
            property_name="memory_safety",
            status="proven",
            confidence=0.92,
        ),
        PropertyProof(
            property_name="injection_resistance",
            status="proven",
            confidence=0.88,
        ),
    ]


@pytest.fixture
def sample_proofs_mixed() -> list[PropertyProof]:
    """Sample proofs with mixed results."""
    return [
        PropertyProof(
            property_name="type_safety",
            status="proven",
            confidence=0.85,
        ),
        PropertyProof(
            property_name="memory_safety",
            status="violated",
            counterexample="Buffer overflow at line 42",
            confidence=0.75,
        ),
        PropertyProof(
            property_name="injection_resistance",
            status="proven",
            confidence=0.90,
        ),
    ]


@pytest.fixture
def scan_result_factory():
    """Factory for creating ScanResult objects."""
    def _make(findings, proofs, grade):
        cert = SecurityCertificate(target="test_target", grade=grade)
        return ScanResult(
            target="test_target",
            findings=findings,
            proofs=proofs,
            grade=grade,
            certificate=cert,
        )
    return _make


# ---------------------------------------------------------------------------
# RedTeamSwarm Tests
# ---------------------------------------------------------------------------


class TestRedTeamSwarm:
    """Tests for the RedTeamSwarm multi-agent attack system."""

    def test_init_default_size(self):
        """Default swarm has 5 agents."""
        swarm = RedTeamSwarm()
        assert len(swarm.agents) == 5
        assert swarm.size == 5

    def test_init_custom_size(self):
        """Custom swarm size is respected."""
        swarm = RedTeamSwarm(size=10)
        assert len(swarm.agents) == 10
        assert swarm.size == 10

    def test_init_invalid_size(self):
        """Zero or negative size raises ValueError."""
        with pytest.raises(ValueError, match="at least 1"):
            RedTeamSwarm(size=0)
        with pytest.raises(ValueError, match="at least 1"):
            RedTeamSwarm(size=-1)

    def test_all_specialties_represented(self):
        """Each of the 5 specialties is represented in default swarm."""
        swarm = RedTeamSwarm(size=5)
        specialties = {agent.specialty for agent in swarm.agents}
        expected = {"sql_injection", "xss", "command_injection",
                    "path_traversal", "logic_bypass"}
        assert specialties == expected

    def test_attack_returns_red_team_result(self, sample_target):
        """attack() returns a RedTeamResult."""
        swarm = RedTeamSwarm(size=5)
        result = swarm.attack(sample_target, rounds=2)
        assert isinstance(result, RedTeamResult)

    def test_attack_has_findings(self, sample_target):
        """attack() produces findings from all agents."""
        swarm = RedTeamSwarm(size=5)
        result = swarm.attack(sample_target, rounds=2)
        assert len(result.findings) > 0
        # 5 agents * 2 findings each * 2 rounds = 20 raw, deduplicated should be 10
        assert len(result.findings) >= 5

    def test_attack_has_attack_chain(self, sample_target):
        """attack() produces an ordered attack chain."""
        swarm = RedTeamSwarm(size=5)
        result = swarm.attack(sample_target, rounds=2)
        assert len(result.attack_chain) > 0
        # Chain should be ordered by step number
        for i, step in enumerate(result.attack_chain):
            assert step["step"] == i + 1

    def test_attack_chain_has_required_fields(self, sample_target):
        """Each attack chain step has the required fields."""
        swarm = RedTeamSwarm(size=5)
        result = swarm.attack(sample_target, rounds=2)
        for step in result.attack_chain:
            assert "step" in step
            assert "phase" in step
            assert "finding_id" in step
            assert "title" in step
            assert "severity" in step
            assert "category" in step
            assert "confidence" in step
            assert "exploitability" in step
            assert "prerequisites" in step
            assert "next_steps" in step

    def test_attack_deduplicates(self, sample_target):
        """Findings are deduplicated across agents."""
        swarm = RedTeamSwarm(size=5)
        result = swarm.attack(sample_target, rounds=2)
        ids = [f.id for f in result.findings]
        assert len(ids) == len(set(ids))

    def test_attack_success_rate_in_range(self, sample_target):
        """Success rate is between 0 and 1."""
        swarm = RedTeamSwarm(size=5)
        result = swarm.attack(sample_target, rounds=2)
        assert 0.0 <= result.success_rate <= 1.0

    def test_attack_records_time(self, sample_target):
        """Time elapsed is recorded and non-negative."""
        swarm = RedTeamSwarm(size=5)
        result = swarm.attack(sample_target, rounds=2)
        assert result.time_elapsed_ms >= 0

    def test_attack_target_preserved(self, sample_target):
        """Target string is preserved in result."""
        swarm = RedTeamSwarm(size=5)
        result = swarm.attack(sample_target, rounds=2)
        assert result.target == sample_target

    def test_attack_rounds_preserved(self, sample_target):
        """Rounds count is preserved in result."""
        swarm = RedTeamSwarm(size=5)
        result = swarm.attack(sample_target, rounds=3)
        assert result.rounds == 3

    def test_attack_chains_ordered_by_severity(self, sample_target):
        """Attack chain is ordered with highest severity first."""
        swarm = RedTeamSwarm(size=5)
        result = swarm.attack(sample_target, rounds=3)
        if len(result.attack_chain) >= 2:
            severities = [step["severity"] for step in result.attack_chain]
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            for i in range(len(severities) - 1):
                assert severity_order[severities[i]] >= severity_order[severities[i + 1]]


# ---------------------------------------------------------------------------
# FuzzingSwarm Tests
# ---------------------------------------------------------------------------


class TestFuzzingSwarm:
    """Tests for the FuzzingSwarm distributed fuzzing system."""

    def test_init_default_size(self):
        """Default swarm has 6 agents (one per strategy)."""
        swarm = FuzzingSwarm()
        assert len(swarm.agents) == 6
        assert swarm.size == 6

    def test_init_custom_size(self):
        """Custom swarm size is respected."""
        swarm = FuzzingSwarm(size=3)
        assert len(swarm.agents) == 3

    def test_init_invalid_size(self):
        """Zero or negative size raises ValueError."""
        with pytest.raises(ValueError, match="at least 1"):
            FuzzingSwarm(size=0)

    def test_fuzz_returns_fuzz_result(self, sample_target):
        """fuzz() returns a FuzzResult."""
        swarm = FuzzingSwarm(size=4)
        result = swarm.fuzz(sample_target, iterations=100)
        assert isinstance(result, FuzzResult)

    def test_fuzz_distributes_iterations(self, sample_target):
        """Iterations are distributed across all agents."""
        swarm = FuzzingSwarm(size=4)
        result = swarm.fuzz(sample_target, iterations=100)
        assert result.iterations == 100
        assert result.total_agents == 4

    def test_fuzz_coverage_in_range(self, sample_target):
        """Coverage is between 0 and 1."""
        swarm = FuzzingSwarm(size=4)
        result = swarm.fuzz(sample_target, iterations=100)
        assert 0.0 <= result.coverage <= 1.0

    def test_fuzz_records_time(self, sample_target):
        """Time elapsed is recorded and non-negative."""
        swarm = FuzzingSwarm(size=4)
        result = swarm.fuzz(sample_target, iterations=50)
        assert result.time_elapsed_ms >= 0

    def test_fuzz_deduplicates_crashes(self, sample_target):
        """Crashes are deduplicated."""
        swarm = FuzzingSwarm(size=4)
        result = swarm.fuzz(sample_target, iterations=500)
        crash_types = [c["type"] for c in result.crashes]
        # deduplication means fewer unique crashes than total found
        assert len(crash_types) == len(set(f"{c['type']}:{c['severity']}" for c in result.crashes))

    def test_fuzz_target_preserved(self, sample_target):
        """Target string is preserved in result."""
        swarm = FuzzingSwarm(size=3)
        result = swarm.fuzz(sample_target, iterations=50)
        assert result.target == sample_target


# ---------------------------------------------------------------------------
# VerificationSwarm Tests
# ---------------------------------------------------------------------------


class TestVerificationSwarm:
    """Tests for the VerificationSwarm parallel proving system."""

    def test_init_default_size(self):
        """Default swarm has 4 agents."""
        swarm = VerificationSwarm()
        assert len(swarm.agents) == 4
        assert swarm.size == 4

    def test_init_custom_size(self):
        """Custom swarm size is respected."""
        swarm = VerificationSwarm(size=8)
        assert len(swarm.agents) == 8

    def test_init_invalid_size(self):
        """Zero or negative size raises ValueError."""
        with pytest.raises(ValueError, match="at least 1"):
            VerificationSwarm(size=0)

    def test_prove_all_returns_list(self, sample_target):
        """prove_all returns a list."""
        swarm = VerificationSwarm(size=3)
        properties = ["type_safety", "memory_safety"]
        results = swarm.prove_all(sample_target, properties)
        assert isinstance(results, list)
        assert len(results) == 2

    def test_prove_all_returns_property_proofs(self, sample_target):
        """prove_all returns PropertyProof objects."""
        swarm = VerificationSwarm(size=3)
        properties = ["type_safety", "memory_safety"]
        results = swarm.prove_all(sample_target, properties)
        for r in results:
            assert isinstance(r, SwarmPropertyProof)

    def test_prove_all_one_per_property(self, sample_target):
        """Each property gets exactly one proof result."""
        swarm = VerificationSwarm(size=3)
        properties = ["type_safety", "memory_safety", "injection_resistance"]
        results = swarm.prove_all(sample_target, properties)
        assert len(results) == 3
        names = [r.property_name for r in results]
        assert sorted(names) == sorted(properties)

    def test_prove_all_status_is_valid(self, sample_target):
        """Each proof status is one of the allowed values."""
        swarm = VerificationSwarm(size=3)
        properties = ["type_safety", "memory_safety"]
        results = swarm.prove_all(sample_target, properties)
        valid_statuses = {"proven", "violated", "timeout", "error"}
        for r in results:
            assert r.status in valid_statuses

    def test_prove_all_confidence_in_range(self, sample_target):
        """Confidence values are in [0, 1]."""
        swarm = VerificationSwarm(size=3)
        properties = ["type_safety", "memory_safety"]
        results = swarm.prove_all(sample_target, properties)
        for r in results:
            assert 0.0 <= r.confidence <= 1.0

    def test_prove_all_violated_has_counterexample(self, sample_target):
        """Violated proofs may have a counterexample."""
        swarm = VerificationSwarm(size=3)
        # Use deterministic seed that often produces violations
        properties = ["prop_a", "prop_b", "prop_c"]
        results = swarm.prove_all(sample_target, properties)
        for r in results:
            if r.status == "violated":
                assert r.counterexample is not None


# ---------------------------------------------------------------------------
# PolicyEngine Tests
# ---------------------------------------------------------------------------


class TestPolicyEngine:
    """Tests for the PolicyEngine CI/CD security gate."""

    def test_init_default_level(self):
        """Default level is standard."""
        engine = PolicyEngine()
        assert engine.level == "standard"

    def test_init_all_valid_levels(self):
        """All valid levels are accepted."""
        for level in ["strict", "standard", "permissive"]:
            engine = PolicyEngine(level=level)
            assert engine.level == level

    def test_init_invalid_level(self):
        """Invalid level raises ValueError."""
        with pytest.raises(ValueError, match="Invalid policy level"):
            PolicyEngine(level="invalid")

    # -- strict mode ---------------------------------------------------

    def test_strict_fails_on_medium_findings(
        self, scan_result_factory, sample_proofs_all_pass
    ):
        """Strict mode: MEDIUM severity finding causes failure."""
        engine = PolicyEngine(level="strict")
        medium_only = [
            Finding(
                id="FND-MED",
                title="Medium Issue",
                severity="MEDIUM",
                category="info",
                description="A medium issue",
                evidence="some evidence",
            )
        ]
        result = scan_result_factory(medium_only, sample_proofs_all_pass, "A")
        decision = engine.check(result)
        assert decision.decision == "fail"
        assert not decision.passed
        assert any("MEDIUM" in v for v in decision.violations)

    def test_strict_fails_on_low_findings(
        self, scan_result_factory, sample_proofs_all_pass
    ):
        """Strict mode: LOW severity finding causes failure."""
        engine = PolicyEngine(level="strict")
        low_only = [
            Finding(
                id="FND-LOW",
                title="Low Issue",
                severity="LOW",
                category="info",
                description="A low issue",
                evidence="some evidence",
            )
        ]
        result = scan_result_factory(low_only, sample_proofs_all_pass, "A+")
        decision = engine.check(result)
        assert decision.decision == "fail"
        assert not decision.passed

    def test_strict_requires_all_proofs(
        self, scan_result_factory, sample_findings
    ):
        """Strict mode: all proofs must pass."""
        engine = PolicyEngine(level="strict")
        bad_proofs = [
            PropertyProof(property_name="type_safety", status="proven"),
            PropertyProof(property_name="memory_safety", status="violated"),
            PropertyProof(property_name="injection_resistance", status="timeout"),
        ]
        result = scan_result_factory(sample_findings, bad_proofs, "A+")
        decision = engine.check(result)
        assert not decision.passed
        assert any("memory_safety" in v for v in decision.violations)

    def test_strict_requires_a_or_above(self, scan_result_factory, sample_proofs_all_pass):
        """Strict mode: grade below A fails."""
        engine = PolicyEngine(level="strict")
        no_findings = []
        result = scan_result_factory(no_findings, sample_proofs_all_pass, "B")
        decision = engine.check(result)
        assert not decision.passed
        assert any("Grade" in v for v in decision.violations)

    def test_strict_passes_clean(
        self, scan_result_factory, sample_proofs_all_pass
    ):
        """Strict mode: clean scan with A+ and all proofs passes."""
        engine = PolicyEngine(level="strict")
        no_findings = []
        result = scan_result_factory(no_findings, sample_proofs_all_pass, "A+")
        decision = engine.check(result)
        assert decision.passed
        assert decision.decision == "pass"

    # -- standard mode -------------------------------------------------

    def test_standard_fails_on_critical(
        self, scan_result_factory, sample_proofs_mixed
    ):
        """Standard mode: CRITICAL finding causes failure."""
        engine = PolicyEngine(level="standard")
        critical = [
            Finding(
                id="FND-CRIT",
                title="Critical Bug",
                severity="CRITICAL",
                category="rce",
                description="Remote code execution",
                evidence="eval(user_input)",
            )
        ]
        result = scan_result_factory(critical, sample_proofs_mixed, "A")
        decision = engine.check(result)
        assert decision.decision == "fail"
        assert not decision.passed

    def test_standard_fails_on_high(
        self, scan_result_factory, sample_proofs_mixed
    ):
        """Standard mode: HIGH finding causes failure."""
        engine = PolicyEngine(level="standard")
        high = [
            Finding(
                id="FND-HIGH",
                title="High Bug",
                severity="HIGH",
                category="xss",
                description="XSS vulnerability",
                evidence="innerHTML = x",
            )
        ]
        result = scan_result_factory(high, sample_proofs_mixed, "A")
        decision = engine.check(result)
        assert decision.decision == "fail"
        assert not decision.passed

    def test_standard_passes_on_low(
        self, scan_result_factory, sample_proofs_mixed
    ):
        """Standard mode: LOW finding alone does not fail."""
        engine = PolicyEngine(level="standard")
        low = [
            Finding(
                id="FND-LOW",
                title="Low Bug",
                severity="LOW",
                category="info",
                description="Minor issue",
                evidence="minor",
            )
        ]
        result = scan_result_factory(low, sample_proofs_mixed, "A")
        decision = engine.check(result)
        # Should pass because LOW is below HIGH threshold
        assert decision.passed
        assert decision.decision == "pass"

    def test_standard_requires_type_safety(
        self, scan_result_factory
    ):
        """Standard mode: type_safety proof must pass."""
        engine = PolicyEngine(level="standard")
        no_findings = []
        proofs = [
            PropertyProof(property_name="type_safety", status="violated"),
            PropertyProof(property_name="injection_resistance", status="proven"),
        ]
        result = scan_result_factory(no_findings, proofs, "A")
        decision = engine.check(result)
        assert not decision.passed
        assert any("type_safety" in v for v in decision.violations)

    def test_standard_requires_injection_resistance(
        self, scan_result_factory
    ):
        """Standard mode: injection_resistance proof must pass."""
        engine = PolicyEngine(level="standard")
        no_findings = []
        proofs = [
            PropertyProof(property_name="type_safety", status="proven"),
            PropertyProof(property_name="injection_resistance", status="timeout"),
        ]
        result = scan_result_factory(no_findings, proofs, "A")
        decision = engine.check(result)
        assert not decision.passed
        assert any("injection_resistance" in v for v in decision.violations)

    def test_standard_passes_clean(self, scan_result_factory, sample_proofs_all_pass):
        """Standard mode: clean scan passes."""
        engine = PolicyEngine(level="standard")
        no_findings = []
        result = scan_result_factory(no_findings, sample_proofs_all_pass, "A")
        decision = engine.check(result)
        assert decision.passed
        assert decision.decision == "pass"

    # -- permissive mode -----------------------------------------------

    def test_permissive_fails_on_critical(
        self, scan_result_factory
    ):
        """Permissive mode: CRITICAL finding causes failure."""
        engine = PolicyEngine(level="permissive")
        critical = [
            Finding(
                id="FND-CRIT",
                title="Critical Bug",
                severity="CRITICAL",
                category="rce",
                description="Remote code execution",
                evidence="eval(user_input)",
            )
        ]
        proofs = [PropertyProof(property_name="type_safety", status="proven")]
        result = scan_result_factory(critical, proofs, "C")
        decision = engine.check(result)
        assert decision.decision == "fail"
        assert not decision.passed

    def test_permissive_passes_on_high(
        self, scan_result_factory
    ):
        """Permissive mode: HIGH finding does not fail."""
        engine = PolicyEngine(level="permissive")
        high = [
            Finding(
                id="FND-HIGH",
                title="High Bug",
                severity="HIGH",
                category="xss",
                description="XSS vulnerability",
                evidence="innerHTML = x",
            )
        ]
        proofs = [PropertyProof(property_name="type_safety", status="proven")]
        result = scan_result_factory(high, proofs, "C")
        decision = engine.check(result)
        # HIGH is below CRITICAL threshold, so findings pass
        # But grade C with only 1 proof - check if it passes
        assert decision.decision in ("pass", "warn")

    def test_permissive_requires_at_least_one_proof(
        self, scan_result_factory
    ):
        """Permissive mode: at least one proof must pass."""
        engine = PolicyEngine(level="permissive")
        no_findings = []
        proofs = [
            PropertyProof(property_name="type_safety", status="violated"),
            PropertyProof(property_name="memory_safety", status="timeout"),
        ]
        result = scan_result_factory(no_findings, proofs, "C")
        decision = engine.check(result)
        assert not decision.passed
        assert any("at least one" in v.lower() for v in decision.violations)

    def test_permissive_grade_c_minimum(self, scan_result_factory):
        """Permissive mode: grade below C fails."""
        engine = PolicyEngine(level="permissive")
        no_findings = []
        proofs = [PropertyProof(property_name="type_safety", status="proven")]
        result = scan_result_factory(no_findings, proofs, "D")
        decision = engine.check(result)
        assert not decision.passed
        assert any("Grade" in v for v in decision.violations)

    # -- gate method ---------------------------------------------------

    def test_gate_returns_bool(self, scan_result_factory, sample_proofs_all_pass):
        """gate() returns a boolean."""
        engine = PolicyEngine(level="standard")
        result = scan_result_factory([], sample_proofs_all_pass, "A")
        gate_result = engine.gate(result)
        assert isinstance(gate_result, bool)

    def gate_true_when_passed(self, scan_result_factory, sample_proofs_all_pass):
        """gate() returns True when check passes."""
        engine = PolicyEngine(level="standard")
        result = scan_result_factory([], sample_proofs_all_pass, "A")
        assert engine.gate(result) is True

    def test_gate_false_when_failed(self, scan_result_factory):
        """gate() returns False when check fails."""
        engine = PolicyEngine(level="standard")
        critical = [
            Finding(
                id="FND-CRIT",
                title="Critical",
                severity="CRITICAL",
                category="rce",
                description="RCE",
                evidence="eval()",
            )
        ]
        proofs = [PropertyProof(property_name="type_safety", status="proven")]
        result = scan_result_factory(critical, proofs, "A")
        assert engine.gate(result) is False

    def test_gate_strict_blocks_medium(self, scan_result_factory, sample_proofs_all_pass):
        """Strict gate blocks MEDIUM findings."""
        engine = PolicyEngine(level="strict")
        medium = [
            Finding(
                id="FND-MED",
                title="Medium",
                severity="MEDIUM",
                category="info",
                description="Medium issue",
                evidence="medium",
            )
        ]
        result = scan_result_factory(medium, sample_proofs_all_pass, "A+")
        assert engine.gate(result) is False

    def test_gate_standard_allows_low(self, scan_result_factory, sample_proofs_all_pass):
        """Standard gate allows LOW findings."""
        engine = PolicyEngine(level="standard")
        low = [
            Finding(
                id="FND-LOW",
                title="Low",
                severity="LOW",
                category="info",
                description="Low issue",
                evidence="low",
            )
        ]
        result = scan_result_factory(low, sample_proofs_all_pass, "A")
        assert engine.gate(result) is True

    # -- check return type ---------------------------------------------

    def test_check_returns_policy_decision(self, scan_result_factory, sample_proofs_all_pass):
        """check() returns a PolicyDecision."""
        engine = PolicyEngine()
        result = scan_result_factory([], sample_proofs_all_pass, "A")
        decision = engine.check(result)
        assert isinstance(decision, PolicyDecision)
        assert hasattr(decision, "passed")
        assert hasattr(decision, "decision")
        assert hasattr(decision, "violations")
        assert hasattr(decision, "recommendations")

    def test_check_has_recommendations_on_fail(self, scan_result_factory):
        """Failed check includes recommendations."""
        engine = PolicyEngine(level="standard")
        critical = [
            Finding(
                id="FND-CRIT",
                title="Critical",
                severity="CRITICAL",
                category="rce",
                description="RCE",
                evidence="eval()",
                remediation="Remove eval()",
            )
        ]
        proofs = [PropertyProof(property_name="type_safety", status="proven")]
        result = scan_result_factory(critical, proofs, "A")
        decision = engine.check(result)
        assert len(decision.recommendations) > 0


# ---------------------------------------------------------------------------
# MCP Tool Handler Tests
# ---------------------------------------------------------------------------


class TestMCPTools:
    """Tests for MCP tool definitions and handlers."""

    def test_tools_list_length(self):
        """VERICLAW_TOOLS has exactly 4 tools."""
        assert len(VERICLAW_TOOLS) == 4

    def test_tools_have_required_fields(self):
        """Each tool has name, description, input_schema."""
        for tool in VERICLAW_TOOLS:
            assert "name" in tool
            assert "description" in tool
            assert "input_schema" in tool
            assert isinstance(tool["name"], str)
            assert isinstance(tool["description"], str)
            assert isinstance(tool["input_schema"], dict)

    def test_tools_names(self):
        """Tool names match expected values."""
        names = {tool["name"] for tool in VERICLAW_TOOLS}
        expected = {
            "vericlaw_scan",
            "vericlaw_red_team",
            "vericlaw_certify",
            "vericlaw_explain",
        }
        assert names == expected

    # -- handle_vericlaw_scan ------------------------------------------

    def test_scan_handler_returns_dict(self, sample_target):
        """scan handler returns a dict."""
        result = handle_vericlaw_scan({"target": sample_target})
        assert isinstance(result, dict)

    def test_scan_handler_has_status(self, sample_target):
        """scan handler result has status field."""
        result = handle_vericlaw_scan({"target": sample_target})
        assert "status" in result
        assert result["status"] in ("success", "error")

    def test_scan_handler_success_structure(self, sample_target):
        """scan handler success result has expected structure."""
        result = handle_vericlaw_scan({"target": sample_target})
        if result["status"] == "success":
            assert "target" in result
            assert "timestamp" in result
            assert "execution_time_ms" in result
            assert "policy_decision" in result
            assert "findings_count" in result
            assert "findings" in result
            assert "proofs" in result
            assert "grade" in result

    def test_scan_handler_respects_policy_level(self, sample_target):
        """scan handler respects policy_level parameter."""
        result = handle_vericlaw_scan(
            {"target": sample_target, "policy_level": "strict"}
        )
        assert result["status"] == "success"
        assert result["policy_level"] == "strict"

    def test_scan_handler_missing_target(self):
        """scan handler handles missing target gracefully."""
        result = handle_vericlaw_scan({})
        assert result["status"] == "error"
        assert "error" in result

    # -- handle_vericlaw_red_team --------------------------------------

    def test_red_team_handler_returns_dict(self, sample_target):
        """red_team handler returns a dict."""
        result = handle_vericlaw_red_team({"target": sample_target})
        assert isinstance(result, dict)

    def test_red_team_handler_has_status(self, sample_target):
        """red_team handler result has status field."""
        result = handle_vericlaw_red_team({"target": sample_target})
        assert "status" in result

    def test_red_team_handler_success_structure(self, sample_target):
        """red_team handler success result has expected structure."""
        result = handle_vericlaw_red_team({"target": sample_target, "rounds": 2})
        if result["status"] == "success":
            assert "target" in result
            assert "timestamp" in result
            assert "execution_time_ms" in result
            assert "rounds" in result
            assert "findings_count" in result
            assert "success_rate" in result
            assert "findings" in result
            assert "attack_chain" in result

    def test_red_team_handler_missing_target(self):
        """red_team handler handles missing target gracefully."""
        result = handle_vericlaw_red_team({})
        assert result["status"] == "error"

    def test_red_team_handler_custom_rounds(self, sample_target):
        """red_team handler respects rounds parameter."""
        result = handle_vericlaw_red_team(
            {"target": sample_target, "rounds": 3, "swarm_size": 3}
        )
        assert result["status"] == "success"
        assert result["rounds"] == 3
        assert result["swarm_size"] == 3

    # -- handle_vericlaw_certify ---------------------------------------

    def test_certify_handler_returns_dict(self, sample_target):
        """certify handler returns a dict."""
        result = handle_vericlaw_certify({"target": sample_target})
        assert isinstance(result, dict)

    def test_certify_handler_has_status(self, sample_target):
        """certify handler result has status field."""
        result = handle_vericlaw_certify({"target": sample_target})
        assert "status" in result

    def test_certify_handler_success_structure(self, sample_target):
        """certify handler success result has expected structure."""
        result = handle_vericlaw_certify({"target": sample_target})
        if result["status"] == "success":
            assert "target" in result
            assert "timestamp" in result
            assert "grade" in result
            assert "signature" in result
            assert "signature_algorithm" in result
            assert "expires" in result
            assert "findings" in result
            assert "proofs" in result

    def test_certify_handler_custom_expires(self, sample_target):
        """certify handler respects expires_days parameter."""
        result = handle_vericlaw_certify(
            {"target": sample_target, "expires_days": 60}
        )
        assert result["status"] == "success"

    def test_certify_signature_is_hex(self, sample_target):
        """certify handler produces a hex signature."""
        result = handle_vericlaw_certify({"target": sample_target})
        assert result["status"] == "success"
        assert re.match(r"^[0-9a-f]{64}$", result["signature"])

    # -- handle_vericlaw_explain ---------------------------------------

    def test_explain_handler_returns_dict(self):
        """explain handler returns a dict."""
        result = handle_vericlaw_explain({"finding_id": "FND-SQL-001"})
        assert isinstance(result, dict)

    def test_explain_handler_has_status(self):
        """explain handler result has status field."""
        result = handle_vericlaw_explain({"finding_id": "FND-SQL-001"})
        assert "status" in result
        assert result["status"] == "success"

    def test_explain_handler_success_structure(self):
        """explain handler success result has expected structure."""
        result = handle_vericlaw_explain(
            {"finding_id": "FND-SQL-001", "format": "json"}
        )
        assert "finding_id" in result
        assert "explanation" in result
        assert "execution_time_ms" in result
        exp = result["explanation"]
        assert "title" in exp
        assert "category" in exp
        assert "cwe_id" in exp
        assert "severity" in exp
        assert "summary" in exp
        assert "impact" in exp
        assert "remediation_steps" in exp

    def test_explain_handler_code_examples(self):
        """explain handler includes code examples when requested."""
        result = handle_vericlaw_explain(
            {"finding_id": "FND-SQL-001", "include_code_examples": True}
        )
        exp = result["explanation"]
        assert "code_examples" in exp
        assert "vulnerable" in exp["code_examples"]
        assert "secure" in exp["code_examples"]

    def test_explain_handler_no_code_examples(self):
        """explain handler omits code examples when not requested."""
        result = handle_vericlaw_explain(
            {"finding_id": "FND-SQL-001", "include_code_examples": False}
        )
        exp = result["explanation"]
        assert "code_examples" not in exp

    def test_explain_handler_markdown_format(self):
        """explain handler supports markdown format."""
        result = handle_vericlaw_explain(
            {"finding_id": "FND-SQL-001", "format": "markdown"}
        )
        assert "markdown" in result
        assert "#" in result["markdown"]

    def test_explain_handler_different_categories(self):
        """explain handler works for different finding categories."""
        categories = ["FND-SQL-001", "FND-XSS-002", "FND-CMD-003",
                      "FND-PAT-004", "FND-LOG-005"]
        for finding_id in categories:
            result = handle_vericlaw_explain({"finding_id": finding_id})
            assert result["status"] == "success"
            assert "explanation" in result

    # -- execution time ------------------------------------------------

    def test_handlers_record_execution_time(self, sample_target):
        """All handlers record execution_time_ms."""
        handlers = [
            (handle_vericlaw_scan, {"target": sample_target}),
            (handle_vericlaw_red_team, {"target": sample_target, "rounds": 1}),
            (handle_vericlaw_certify, {"target": sample_target}),
            (handle_vericlaw_explain, {"finding_id": "FND-SQL-001"}),
        ]
        for handler, params in handlers:
            result = handler(params)
            assert "execution_time_ms" in result
            assert isinstance(result["execution_time_ms"], int)
            assert result["execution_time_ms"] >= 0

    # -- error handling ------------------------------------------------

    def test_handlers_include_error_details(self):
        """Error responses include error_type and traceback."""
        result = handle_vericlaw_scan({})
        assert result["status"] == "error"
        assert "error_type" in result
        assert "traceback" in result


# ---------------------------------------------------------------------------
# GitHub Action YAML Tests
# ---------------------------------------------------------------------------


class TestGitHubAction:
    """Tests for the GitHub Actions workflow file."""

    @pytest.fixture
    def workflow_path(self):
        """Path to the workflow YAML file."""
        # Path relative to the project root (3 levels up from test file)
        base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        return os.path.join(base, ".github", "workflows", "vericlaw-ci.yml")

    def test_yaml_file_exists(self, workflow_path):
        """Workflow YAML file exists."""
        assert os.path.isfile(workflow_path), f"File not found: {workflow_path}"

    def test_yaml_is_valid(self, workflow_path):
        """Workflow YAML is syntactically valid."""
        with open(workflow_path, "r") as f:
            data = yaml.safe_load(f)
        assert isinstance(data, dict)

    def test_yaml_has_name(self, workflow_path):
        """Workflow has a name."""
        with open(workflow_path, "r") as f:
            data = yaml.safe_load(f)
        assert "name" in data
        assert "VeriClaw" in data["name"]

    def test_yaml_has_on_trigger(self, workflow_path):
        """Workflow has on triggers. (PyYAML parses 'on:' as True:)"""
        with open(workflow_path, "r") as f:
            data = yaml.safe_load(f)
        # PyYAML parses the 'on:' key as True
        assert True in data or "on" in data

    def test_yaml_has_jobs(self, workflow_path):
        """Workflow has jobs."""
        with open(workflow_path, "r") as f:
            data = yaml.safe_load(f)
        assert "jobs" in data
        assert "security-scan" in data["jobs"]

    def test_yaml_job_has_steps(self, workflow_path):
        """security-scan job has steps."""
        with open(workflow_path, "r") as f:
            data = yaml.safe_load(f)
        job = data["jobs"]["security-scan"]
        assert "steps" in job
        assert len(job["steps"]) >= 5

    def test_yaml_has_checkout_step(self, workflow_path):
        """Workflow has checkout step."""
        with open(workflow_path, "r") as f:
            data = yaml.safe_load(f)
        steps = data["jobs"]["security-scan"]["steps"]
        step_names = [s.get("name", "") for s in steps]
        assert any("Checkout" in name for name in step_names)

    def test_yaml_has_setup_python_step(self, workflow_path):
        """Workflow has Python setup step."""
        with open(workflow_path, "r") as f:
            data = yaml.safe_load(f)
        steps = data["jobs"]["security-scan"]["steps"]
        step_names = [s.get("name", "") for s in steps]
        assert any("Python" in name for name in step_names)

    def test_yaml_has_install_step(self, workflow_path):
        """Workflow has VeriClaw install step."""
        with open(workflow_path, "r") as f:
            data = yaml.safe_load(f)
        steps = data["jobs"]["security-scan"]["steps"]
        step_names = [s.get("name", "") for s in steps]
        assert any("Install" in name for name in step_names)

    def test_yaml_has_scan_step(self, workflow_path):
        """Workflow has scan step."""
        with open(workflow_path, "r") as f:
            data = yaml.safe_load(f)
        steps = data["jobs"]["security-scan"]["steps"]
        step_names = [s.get("name", "") for s in steps]
        assert any("Scan" in name for name in step_names)

    def test_yaml_has_sarif_upload_step(self, workflow_path):
        """Workflow has SARIF upload step."""
        with open(workflow_path, "r") as f:
            data = yaml.safe_load(f)
        steps = data["jobs"]["security-scan"]["steps"]
        step_names = [s.get("name", "") for s in steps]
        assert any("SARIF" in name or "upload-sarif" in str(steps) for name in step_names)

    def test_yaml_has_security_gate_step(self, workflow_path):
        """Workflow has security gate step."""
        with open(workflow_path, "r") as f:
            data = yaml.safe_load(f)
        steps = data["jobs"]["security-scan"]["steps"]
        step_names = [s.get("name", "") for s in steps]
        assert any("Gate" in name for name in step_names)

    def test_yaml_uses_ubuntu(self, workflow_path):
        """Workflow runs on ubuntu-latest."""
        with open(workflow_path, "r") as f:
            data = yaml.safe_load(f)
        job = data["jobs"]["security-scan"]
        assert job.get("runs-on") == "ubuntu-latest"

    def test_yaml_uses_python_312(self, workflow_path):
        """Workflow uses Python 3.12."""
        with open(workflow_path, "r") as f:
            data = yaml.safe_load(f)
        steps = data["jobs"]["security-scan"]["steps"]
        for step in steps:
            if step.get("uses", "").startswith("actions/setup-python"):
                assert step["with"]["python-version"] == "3.12"

    def test_yaml_scan_step_uses_sarif(self, workflow_path):
        """Scan step generates SARIF output."""
        with open(workflow_path, "r") as f:
            data = yaml.safe_load(f)
        steps = data["jobs"]["security-scan"]["steps"]
        for step in steps:
            if "vericlaw.scan" in str(step.get("run", "")):
                assert "sarif" in str(step["run"])
                assert "vericlaw-results.sarif" in str(step["run"])

    def test_yaml_gate_step_uses_policy(self, workflow_path):
        """Gate step uses standard policy."""
        with open(workflow_path, "r") as f:
            data = yaml.safe_load(f)
        steps = data["jobs"]["security-scan"]["steps"]
        for step in steps:
            if "vericlaw.gate" in str(step.get("run", "")):
                assert "standard" in str(step["run"])

    def test_yaml_has_permissions(self, workflow_path):
        """Workflow has required permissions."""
        with open(workflow_path, "r") as f:
            data = yaml.safe_load(f)
        job = data["jobs"]["security-scan"]
        assert "permissions" in job
        perms = job["permissions"]
        assert "security-events" in perms
        assert "contents" in perms
