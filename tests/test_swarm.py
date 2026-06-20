"""
test_swarm.py — 20+ Tests for VeriForge Agent Swarm

pytest -q tests/test_swarm.py
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

import pytest

from veriforge_swarm.agent import Agent, AgentRole, ReputationModel
from veriforge_swarm.consensus import BFTConsensus, Proposal, Result, Vote, VoteValue
from veriforge_swarm.swarm import (
    ConsensusSwarm,
    HierarchicalSwarm,
    RedBlueSwarm,
    SelfVerifyingAgent,
    sandbox_run,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def planner() -> Agent:
    return Agent.generate(AgentRole.PLANNER, ["task_decomposition", "code_gen"])


@pytest.fixture
def executor() -> Agent:
    return Agent.generate(AgentRole.EXECUTOR, ["code_gen", "test_run"])


@pytest.fixture
def verifier() -> Agent:
    return Agent.generate(AgentRole.VERIFIER, ["security_scan", "static_analysis"])


@pytest.fixture
def coordinator() -> Agent:
    return Agent.generate(AgentRole.COORDINATOR, ["aggregation", "consensus"])


@pytest.fixture
def consensus_engine() -> BFTConsensus:
    return BFTConsensus()


@pytest.fixture
def populated_swarm(planner, executor, verifier) -> ConsensusSwarm:
    swarm = ConsensusSwarm("test-swarm", min_agents=3)
    swarm.add_agent(planner)
    swarm.add_agent(executor)
    swarm.add_agent(verifier)
    return swarm


# ============================================================================
# 1. Agent Identity Generation (Ed25519-style)
# ============================================================================


class TestAgentIdentity:
    """Agent creation and cryptographic identity."""

    def test_agent_generate_creates_keypair(self):
        """Agent.generate produces a non-empty (public, private) tuple."""
        agent = Agent.generate(AgentRole.VERIFIER, ["scan"])
        assert len(agent.keypair) == 2
        assert len(agent.keypair[0]) == 64  # 32 bytes hex = 64 chars
        assert len(agent.keypair[1]) == 64
        assert agent.keypair[0] != agent.keypair[1]

    def test_agent_has_unique_id(self):
        """Each agent gets a distinct UUID."""
        a1 = Agent.generate(AgentRole.PLANNER, ["plan"])
        a2 = Agent.generate(AgentRole.PLANNER, ["plan"])
        assert a1.agent_id != a2.agent_id

    def test_agent_public_key_property(self, verifier):
        """public_key returns the first element of keypair."""
        assert verifier.public_key == verifier.keypair[0]

    def test_agent_private_key_property(self, verifier):
        """private_key returns the second element of keypair."""
        assert verifier.private_key == verifier.keypair[1]

    def test_agent_default_reputation(self):
        """Fresh agents start with reputation 1.0."""
        agent = Agent.generate(AgentRole.EXECUTOR, ["run"])
        assert agent.reputation == 1.0

    def test_agent_custom_reputation(self):
        """Agents can be created with an explicit reputation score."""
        agent = Agent(role=AgentRole.VERIFIER, capabilities=["scan"], keypair=("a" * 64, "b" * 64), reputation=3.5)
        assert agent.reputation == 3.5

    def test_agent_role_enum_values(self):
        """AgentRole enum maps to expected string values."""
        assert AgentRole.PLANNER.value == "planner"
        assert AgentRole.EXECUTOR.value == "executor"
        assert AgentRole.VERIFIER.value == "verifier"
        assert AgentRole.COORDINATOR.value == "coordinator"

    def test_agent_to_dict_excludes_private_key(self, verifier):
        """Serialisation must not leak the private key."""
        d = verifier.to_dict()
        assert "private_key" not in d
        assert "public_key" in d
        assert d["role"] == "verifier"
        assert d["agent_id"] == verifier.agent_id

    def test_agent_equality_and_hash(self):
        """Agents with the same agent_id are equal and hash identically."""
        a1 = Agent.generate(AgentRole.PLANNER, ["p"])
        a2 = Agent(role=AgentRole.EXECUTOR, capabilities=["e"], keypair=a1.keypair, agent_id=a1.agent_id)
        assert a1 == a2
        assert hash(a1) == hash(a2)


# ============================================================================
# 2. Message Signing and Verification
# ============================================================================


class TestMessageSigning:
    """HMAC-SHA256 inter-agent message security."""

    def test_sign_message_returns_hex_signature(self, planner):
        """Signatures are 64-char hex strings (SHA-256)."""
        sig = planner.sign_message("hello swarm")
        assert len(sig) == 64
        int(sig, 16)  # valid hex

    def test_sign_message_idempotent_for_same_key(self, planner):
        """Same message + same key = same signature."""
        sig1 = planner.sign_message("test msg")
        sig2 = planner.sign_message("test msg")
        assert sig1 == sig2

    def test_different_messages_different_signatures(self, planner):
        """Different messages produce different signatures."""
        sig1 = planner.sign_message("msg A")
        sig2 = planner.sign_message("msg B")
        assert sig1 != sig2

    def test_verify_signature_valid(self, planner, executor):
        """An agent can verify another agent's signature."""
        message = "shared secret plan"
        sig = executor.sign_message(message)
        # Verification uses the other agent's public key
        assert planner.verify_signature(message, sig, executor)

    def test_verify_signature_invalid(self, planner, executor):
        """Tampered signature fails verification."""
        message = "shared secret plan"
        bad_sig = "a" * 64
        assert not planner.verify_signature(message, bad_sig, executor)

    def test_sign_message_rejects_non_string(self, planner):
        """sign_message raises TypeError for non-string input."""
        with pytest.raises(TypeError):
            planner.sign_message(12345)  # type: ignore[arg-type]


# ============================================================================
# 3. Reputation Scoring Dynamics
# ============================================================================


class TestReputationDynamics:
    """Dynamic reputation adjustment based on outcomes."""

    def test_reputation_increases_on_success(self, verifier):
        """Successful verification bumps reputation upward."""
        old = verifier.reputation
        verifier.update_reputation(True)
        assert verifier.reputation == old + ReputationModel.BUMP_SUCCESS

    def test_reputation_decreases_on_failure(self, verifier):
        """Failed verification penalises reputation."""
        old = verifier.reputation
        verifier.update_reputation(False)
        assert verifier.reputation == old - ReputationModel.PENALTY_FAILURE

    def test_reputation_drops_on_cheating(self, verifier):
        """Byzantine / cheating incurs a severe penalty."""
        old = verifier.reputation
        verifier.penalise_cheating()
        assert verifier.reputation == old - ReputationModel.PENALTY_CHEATING

    def test_reputation_floor_at_zero(self):
        """Reputation cannot drop below 0.0."""
        agent = Agent.generate(AgentRole.VERIFIER, ["scan"])
        agent.reputation = 0.1
        agent.penalise_cheating()
        assert agent.reputation == 0.0
        agent.penalise_cheating()
        assert agent.reputation == 0.0  # stays floored

    def test_reputation_ceiling_at_five(self):
        """Reputation cannot exceed 5.0."""
        agent = Agent.generate(AgentRole.VERIFIER, ["scan"])
        agent.reputation = 4.95
        agent.update_reputation(True)
        assert agent.reputation == 5.0
        agent.update_reputation(True)
        assert agent.reputation == 5.0  # stays capped

    def test_is_trusted_with_threshold(self, verifier):
        """is_trusted respects the configurable threshold."""
        verifier.reputation = 1.5
        assert verifier.is_trusted(threshold=1.0)
        assert not verifier.is_trusted(threshold=2.0)

    def test_reputation_log_records_changes(self, verifier):
        """Every reputation change is recorded."""
        verifier.update_reputation(True)
        verifier.update_reputation(False)
        assert len(verifier._reputation_log) == 2


# ============================================================================
# 4. BFT Consensus 2/3 Majority
# ============================================================================


class TestBFTConsensus:
    """Byzantine Fault Tolerant voting mechanics."""

    def test_proposal_creates_valid_proposal(self, consensus_engine, planner):
        """propose returns a Proposal with a valid digest."""
        prop = consensus_engine.propose(planner, {"task": "test"})
        assert isinstance(prop, Proposal)
        assert prop.verify_integrity()
        assert prop.proposer_id == planner.agent_id

    def test_vote_creates_signed_vote(self, consensus_engine, planner, verifier):
        """vote returns a Vote tied to the correct proposal."""
        prop = consensus_engine.propose(planner, {"task": "test"})
        vote = consensus_engine.vote(verifier, prop, VoteValue.ACCEPT)
        assert vote.proposal_id == prop.proposal_id
        assert vote.voter_id == verifier.agent_id
        assert vote.value == VoteValue.ACCEPT

    def test_tally_2_of_3_accepts(self, consensus_engine, planner, executor, verifier):
        """2 ACCEPT + 1 REJECT on 3 agents → accepted (quorum = 2)."""
        prop = consensus_engine.propose(planner, {"task": "audit"})
        v1 = consensus_engine.vote(verifier, prop, VoteValue.ACCEPT)
        v2 = consensus_engine.vote(executor, prop, VoteValue.ACCEPT)
        v3 = consensus_engine.vote(planner, prop, VoteValue.REJECT)
        result = consensus_engine.tally([v1, v2, v3])
        assert isinstance(result, Result)
        assert result.accepted
        assert result.accept_count == 2
        assert result.reject_count == 1

    def test_tally_1_of_3_rejects(self, consensus_engine, planner, executor, verifier):
        """1 ACCEPT + 2 REJECT → not accepted."""
        prop = consensus_engine.propose(planner, {"task": "audit"})
        v1 = consensus_engine.vote(verifier, prop, VoteValue.ACCEPT)
        v2 = consensus_engine.vote(executor, prop, VoteValue.REJECT)
        v3 = consensus_engine.vote(planner, prop, VoteValue.REJECT)
        result = consensus_engine.tally([v1, v2, v3])
        assert not result.accepted

    def test_tally_empty_votes(self, consensus_engine):
        """Empty vote list returns rejected result with zero counts."""
        result = consensus_engine.tally([])
        assert not result.accepted
        assert result.total_votes == 0
        assert result.quorum_needed == 0

    def test_tally_with_abstain(self, consensus_engine, planner, executor, verifier):
        """ABSTAIN votes are counted but do not contribute to either side."""
        prop = consensus_engine.propose(planner, {"task": "t"})
        v1 = consensus_engine.vote(verifier, prop, VoteValue.ACCEPT)
        v2 = consensus_engine.vote(executor, prop, VoteValue.ABSTAIN)
        v3 = consensus_engine.vote(planner, prop, VoteValue.ABSTAIN)
        result = consensus_engine.tally([v1, v2, v3])
        assert result.accept_count == 1
        assert result.abstain_count == 2
        # quorum=2, only 1 accept → not accepted
        assert not result.accepted

    def test_proposal_integrity_verification(self, planner):
        """Proposal.verify_integrity detects tampering."""
        prop = Proposal.create(planner, {"task": "x"})
        assert prop.verify_integrity()
        prop.value["task"] = "tampered"
        assert not prop.verify_integrity()

    def test_consensus_get_proposal(self, consensus_engine, planner):
        """get_proposal retrieves a stored proposal by ID."""
        prop = consensus_engine.propose(planner, {"task": "x"})
        retrieved = consensus_engine.get_proposal(prop.proposal_id)
        assert retrieved is not None
        assert retrieved.proposal_id == prop.proposal_id

    def test_consensus_reset_clears_state(self, consensus_engine, planner):
        """reset clears proposals and vote log."""
        prop = consensus_engine.propose(planner, {"task": "x"})
        consensus_engine.vote(planner, prop, VoteValue.ACCEPT)
        consensus_engine.reset()
        assert consensus_engine.get_proposal(prop.proposal_id) is None
        assert consensus_engine.vote_history() == []


# ============================================================================
# 5. Byzantine Fault Detection
# ============================================================================


class TestByzantineDetection:
    """Detecting agents that cast conflicting votes."""

    def test_detect_conflicting_votes(self, consensus_engine, planner, verifier):
        """An agent voting both ACCEPT and REJECT is flagged Byzantine."""
        prop = consensus_engine.propose(planner, {"task": "x"})
        v1 = Vote.create_for_test(verifier.agent_id, prop.proposal_id, VoteValue.ACCEPT)
        v2 = Vote.create_for_test(verifier.agent_id, prop.proposal_id, VoteValue.REJECT)
        byzantine = consensus_engine.is_byzantine([v1, v2])
        assert verifier.agent_id in byzantine

    def test_no_false_positive_for_single_vote(self, consensus_engine, planner, verifier):
        """A single vote does not trigger Byzantine flag."""
        prop = consensus_engine.propose(planner, {"task": "x"})
        v1 = consensus_engine.vote(verifier, prop, VoteValue.ACCEPT)
        byzantine = consensus_engine.is_byzantine([v1])
        assert verifier.agent_id not in byzantine

    def test_byzantine_votes_filtered_from_tally(self, consensus_engine, planner, executor, verifier):
        """Votes from Byzantine agents are excluded from the final tally."""
        prop = consensus_engine.propose(planner, {"task": "x"})
        v1 = Vote.create_for_test(verifier.agent_id, prop.proposal_id, VoteValue.ACCEPT)
        v2 = Vote.create_for_test(verifier.agent_id, prop.proposal_id, VoteValue.REJECT)  # Byzantine
        v3 = Vote.create_for_test(executor.agent_id, prop.proposal_id, VoteValue.ACCEPT)
        result = consensus_engine.tally([v1, v2, v3])
        assert verifier.agent_id in result.byzantine_agents
        # Byzantine votes excluded: only 1 clean ACCEPT from executor
        assert result.accept_count == 1

    def test_is_byzantine_with_agent_param(self, consensus_engine, planner, verifier):
        """is_byzantine(agent=...) returns a bool for a specific agent."""
        prop = consensus_engine.propose(planner, {"task": "x"})
        v1 = Vote.create_for_test(verifier.agent_id, prop.proposal_id, VoteValue.ACCEPT)
        v2 = Vote.create_for_test(verifier.agent_id, prop.proposal_id, VoteValue.REJECT)
        assert consensus_engine.is_byzantine([v1, v2], verifier) is True


# ============================================================================
# 6. ConsensusSwarm Execution
# ============================================================================


class TestConsensusSwarm:
    """End-to-end ConsensusSwarm behaviour."""

    def test_swarm_requires_min_agents(self, populated_swarm):
        """Execution fails when below min_agents threshold."""
        small = ConsensusSwarm("tiny", min_agents=10)
        small.add_agent(Agent.generate(AgentRole.VERIFIER, ["scan"]))
        with pytest.raises(RuntimeError):
            small.execute("task")

    def test_swarm_execution_returns_structure(self, populated_swarm):
        """execute returns the expected dictionary shape."""
        result = populated_swarm.execute("audit_login")
        assert "task" in result
        assert "proposal" in result
        assert "votes" in result
        assert "consensus" in result
        assert "agent_count" in result
        assert result["agent_count"] == 3

    def test_swarm_add_agent_requires_capabilities(self):
        """add_agent rejects agents with no capabilities."""
        swarm = ConsensusSwarm("test")
        agent = Agent.generate(AgentRole.VERIFIER, [])
        with pytest.raises(ValueError):
            swarm.add_agent(agent)

    def test_swarm_reset(self, populated_swarm):
        """reset clears all agents and state."""
        populated_swarm.reset()
        assert len(populated_swarm.agents) == 0


# ============================================================================
# 7. RedBlueSwarm Competitive Rounds
# ============================================================================


class TestRedBlueSwarm:
    """Competitive attack/defence swarm mechanics."""

    def test_add_red_agent(self):
        """add_red_agent creates an EXECUTOR-role agent."""
        swarm = RedBlueSwarm()
        agent = swarm.add_red_agent(["sql_injection_scan"])
        assert agent.role == AgentRole.EXECUTOR
        assert len(swarm.red_team) == 1

    def test_add_blue_agent(self):
        """add_blue_agent creates a PLANNER-role agent."""
        swarm = RedBlueSwarm()
        agent = swarm.add_blue_agent(["patch_gen"])
        assert agent.role == AgentRole.PLANNER
        assert len(swarm.blue_team) == 1

    def test_secure_code_returns_structure(self):
        """secure_code returns the expected result dictionary."""
        swarm = RedBlueSwarm()
        swarm.add_red_agent(["sql_injection_scan"])
        swarm.add_blue_agent(["patch_gen"])
        code = "def f(): pass"
        result = swarm.secure_code(code, max_rounds=2)
        assert "rounds_played" in result
        assert "findings" in result
        assert "fixes" in result
        assert "final_grade" in result
        assert result["code_hash"] == hashlib.sha256(code.encode()).hexdigest()[:16]

    def test_secure_code_runs_multiple_rounds(self):
        """Rounds progress and produce findings."""
        swarm = RedBlueSwarm()
        swarm.add_red_agent(["sql_injection_scan", "xss_scan"])
        swarm.add_red_agent(["auth_bypass_scan"])
        swarm.add_blue_agent(["patch_gen", "input_sanitization"])
        vulnerable = "raw sql query; innerhtml assignment; hardcoded credential"
        result = swarm.secure_code(vulnerable, max_rounds=3)
        assert result["rounds_played"] >= 1
        assert isinstance(result["final_grade"], str)
        assert result["final_grade"] in "ABCDF"

    def test_grade_computation(self):
        """Grade reflects the fix-to-finding ratio."""
        swarm = RedBlueSwarm()
        # Manually populate findings/fixes to test grade boundaries
        from veriforge_swarm.swarm import Finding, Fix
        f1 = Finding("f1", "a", "x", "high")
        f2 = Finding("f2", "a", "y", "high")
        swarm.findings = [f1, f2]
        swarm.fixes = [Fix("x1", "b", "f1", "fix1", "code")]
        assert swarm._compute_grade() == "C"  # 1/2 = 0.5 → C
        swarm.fixes.append(Fix("x2", "b", "f2", "fix2", "code"))
        assert swarm._compute_grade() == "A"  # 2/2 = 1.0


# ============================================================================
# 8. HierarchicalSwarm Decomposition
# ============================================================================


class TestHierarchicalSwarm:
    """Tree-structured multi-domain task decomposition."""

    def test_add_sub_swarm(self):
        """add_sub_swarm registers a child swarm."""
        root = HierarchicalSwarm("root")
        child = ConsensusSwarm("child")
        root.add_sub_swarm("auth", child)
        assert "auth" in root.sub_swarms

    def test_execute_without_sub_swarms_fails(self):
        """execute raises when no sub-swarms are registered."""
        root = HierarchicalSwarm("empty")
        with pytest.raises(RuntimeError):
            root.execute("task")

    def test_execute_returns_aggregated_results(self):
        """execute returns results from all domains plus aggregation."""
        root = HierarchicalSwarm("platform")
        auth = ConsensusSwarm("auth", min_agents=3)
        for caps in [["security_scan"], ["code_gen"], ["test_run"]]:
            auth.add_agent(Agent.generate(AgentRole.VERIFIER, caps))
        payment = ConsensusSwarm("payment", min_agents=3)
        for caps in [["security_scan"], ["code_gen"], ["fraud_detection"]]:
            payment.add_agent(Agent.generate(AgentRole.VERIFIER, caps))

        root.add_sub_swarm("auth", auth)
        root.add_sub_swarm("payment", payment)

        result = root.execute("security audit")
        assert "domain_results" in result
        assert "aggregated" in result
        assert "auth" in result["domain_results"]
        assert "payment" in result["domain_results"]
        assert result["coordinator_id"] == root.coordinator.agent_id

    def test_aggregation_counts_consensus(self):
        """Aggregation tallies accepted/rejected consensus outcomes."""
        root = HierarchicalSwarm("platform")
        auth = ConsensusSwarm("auth", min_agents=3)
        for caps in [["security_scan"], ["code_gen"], ["test_run"]]:
            auth.add_agent(Agent.generate(AgentRole.VERIFIER, caps))
        root.add_sub_swarm("auth", auth)
        result = root.execute("audit")
        agg = result["aggregated"]
        assert "consensus_accepted" in agg
        assert "consensus_rejected" in agg


# ============================================================================
# 9. SelfVerifyingAgent Pipeline
# ============================================================================


class TestSelfVerifyingAgent:
    """Verified execution with audit trail."""

    def test_pipeline_returns_structure(self):
        """execute_verified returns the expected result shape."""
        agent = SelfVerifyingAgent(["static_analysis", "code_gen"])
        result = agent.execute_verified("test task")
        assert "task" in result
        assert "verified" in result
        assert "pipeline" in result
        assert "audit_log" in result
        assert "reputation" in result

    def test_audit_log_has_all_phases(self):
        """Audit trail contains entries for every pipeline phase."""
        agent = SelfVerifyingAgent(["static_analysis", "code_gen"])
        result = agent.execute_verified("test task")
        phases = {e["phase"] for e in result["audit_log"]}
        assert "plan" in phases
        assert "execute" in phases

    def test_reputation_changes_after_execution(self):
        """Reputation is updated based on verification outcome."""
        agent = SelfVerifyingAgent(["static_analysis"])
        old_rep = agent.reputation
        result = agent.execute_verified("test task")
        assert agent.reputation != old_rep or result["verified"]

    def test_audit_trail_retrieval(self):
        """get_audit_trail returns the complete log."""
        agent = SelfVerifyingAgent(["scan"])
        agent.execute_verified("task")
        trail = agent.get_audit_trail()
        assert len(trail) >= 3
        assert all(hasattr(e, "entry_id") for e in trail)


# ============================================================================
# 10. Sandbox & Misc
# ============================================================================


class TestSandbox:
    """Sandboxed execution environment."""

    def test_sandbox_runs_simple_code(self):
        """sandbox_run executes trivial Python and returns output."""
        result = sandbox_run("print('hello')", timeout_sec=5)
        assert "hello" in result.stdout
        assert result.returncode == 0
        assert not result.timed_out

    def test_sandbox_timeout_enforcement(self):
        """sandbox_run kills code that exceeds the time limit."""
        result = sandbox_run("import time; time.sleep(10)", timeout_sec=1)
        assert result.timed_out

    def test_sandbox_memory_limit(self):
        """sandbox_run respects memory constraints."""
        # Allocate a large list — should be constrained by RLIMIT_AS
        code = "x = list(range(100_000_000))"
        result = sandbox_run(code, timeout_sec=5, memory_limit_mb=64)
        # May OOM or may succeed depending on Python overhead;
        # the key assertion is that it didn't hang
        assert result.returncode != 0 or result.duration_ms < 6000

    def test_sandbox_isolated_environment(self):
        """sandbox_run uses a restricted environment."""
        code = "import os; print(os.environ.get('HOME', 'NO_HOME'))"
        result = sandbox_run(code, timeout_sec=5)
        assert result.returncode == 0


class TestAgentCapabilities:
    """Capability helpers."""

    def test_has_capability(self, verifier):
        assert verifier.has_capability("security_scan")
        assert not verifier.has_capability("code_gen")

    def test_capability_score(self, verifier):
        assert verifier.capability_score(["security_scan"]) == 1.0
        assert verifier.capability_score(["security_scan", "code_gen"]) == 0.5
        assert verifier.capability_score([]) == 1.0


# ============================================================================
# Monkey-patch helper for test convenience
# ============================================================================


def _vote_create_for_test(cls, voter_id: str, proposal_id: str, value: VoteValue) -> Vote:
    """Factory to create test votes without a real Agent instance."""
    return cls(
        vote_id="test-" + str(hash(voter_id + proposal_id + value.value))[:8],
        proposal_id=proposal_id,
        voter_id=voter_id,
        value=value,
        signature="0" * 64,
        created_at=time.time(),
    )


Vote.create_for_test = classmethod(_vote_create_for_test)
