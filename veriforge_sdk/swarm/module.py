"""Swarm module — multi-agent consensus, BFT voting, red/blue teaming.

This module provides the :class:`SwarmModule` facade.  When the optional
``veriforge_swarm`` companion package is installed it is used as the
primary backend; otherwise a pure-Python fallback implementation is used.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    from veriforge_swarm import SwarmClient  # type: ignore[import-untyped]

    _HAS_SWARM_LIB = True
except ImportError:
    _HAS_SWARM_LIB = False

# ---------------------------------------------------------------------------
# Models (local fallback when veriforge_swarm is unavailable)
# ---------------------------------------------------------------------------


@dataclass
class AgentConfig:
    """Configuration for a single swarm agent.

    Attributes:
        name: Human-readable agent identifier.
        role: Role this agent plays (e.g. ``validator``, ``attacker``,
            ``defender``).
        weight: Voting weight in consensus rounds (default ``1.0``).
        metadata: Arbitrary key/value metadata for the agent.
    """

    name: str
    role: str = "validator"
    weight: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SwarmConsensus:
    """Result of a swarm consensus round.

    Attributes:
        question: The original question posed to the swarm.
        answer: Consensus answer (may be ``None`` if no quorum reached).
        confidence: Aggregated confidence score in ``[0.0, 1.0]``.
        votes: Mapping of ``agent_name → vote_value``.
        elapsed_ms: Wall-clock time for the round in milliseconds.
        quorum_reached: Whether a 2/3 quorum was achieved.
        metadata: Additional details from the consensus engine.
    """

    question: str
    answer: Optional[str] = None
    confidence: float = 0.0
    votes: Dict[str, str] = field(default_factory=dict)
    elapsed_ms: int = 0
    quorum_reached: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# BFT Consensus engine
# ---------------------------------------------------------------------------


class BFTConsensus:
    """Byzantine fault-tolerant consensus using 2/3-majority voting.

    Implements a simplified PBFT-inspired commit phase:

    1. **Request** — broadcast the question to all agents.
    2. **Pre-prepare** — each agent returns a local vote.
    3. **Prepare** — collect votes, tolerate up to ``f`` Byzantine faults
       where ``3f + 1 ≤ n`` (i.e. ``f = floor((n-1)/3)``).
    4. **Commit** — if a single answer reaches ≥ ``2/3`` weighted votes,
       quorum is declared.

    The class is intentionally decoupled from ``SwarmModule`` so it can be
    unit-tested in isolation.

    Example::

        engine = BFTConsensus()
        result = engine.run(
            agents=[AgentConfig("A"), AgentConfig("B"), AgentConfig("C")],
            question="Is the code safe?",
        )
    """

    # Threshold for Byzantine quorum (2/3)
    QUORUM_NUMERATOR = 2
    QUORUM_DENOMINATOR = 3

    def __init__(self, max_faults: Optional[int] = None) -> None:
        """Initialise the BFT engine.

        Args:
            max_faults: Override the default fault tolerance derived from
                participant count.  Usually left as ``None`` so the engine
                computes ``f = floor((n-1)/3)`` at runtime.
        """
        self._max_faults = max_faults
        self._log = logging.getLogger(__name__ + ".BFTConsensus")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        agents: List[AgentConfig],
        question: str,
        timeout_ms: int = 30_000,
    ) -> SwarmConsensus:
        """Execute a full BFT consensus round.

        Args:
            agents: List of participating agents.
            question: The question or proposal to vote on.
            timeout_ms: Maximum wall-clock time for the round.

        Returns:
            A :class:`SwarmConsensus` dataclass describing the outcome.

        Raises:
            ValueError: If fewer than 4 agents are supplied (BFT requires
                ``n ≥ 3f + 1``).
        """
        start = time.monotonic()

        if len(agents) < 4:
            raise ValueError(
                f"BFT requires at least 4 agents (got {len(agents)}). "
                "Use n ≥ 3f + 1 to tolerate f Byzantine faults."
            )

        # ---- Phase 1: broadcast (simulated) ----
        self._log.debug("Broadcasting question to %d agents", len(agents))
        raw_votes = self._gather_votes(agents, question, timeout_ms)

        # ---- Phase 2: prepare / commit ----
        tally, total_weight = self._tally_votes(agents, raw_votes)
        quorum_threshold = total_weight * self.QUORUM_NUMERATOR / self.QUORUM_DENOMINATOR

        answer: Optional[str] = None
        quorum_reached = False
        best_confidence = 0.0

        if tally:
            best_answer = max(tally, key=lambda k: tally[k]["weight"])
            best_weight = tally[best_answer]["weight"]
            best_confidence = best_weight / total_weight if total_weight else 0.0

            if best_weight >= quorum_threshold:
                answer = best_answer
                quorum_reached = True
                self._log.info(
                    "Quorum reached for answer %r (confidence=%.2f)",
                    answer,
                    best_confidence,
                )
            else:
                self._log.warning(
                    "No quorum — best answer %r has weight %.2f / %.2f required",
                    best_answer,
                    best_weight,
                    quorum_threshold,
                )

        elapsed_ms = int((time.monotonic() - start) * 1000)

        return SwarmConsensus(
            question=question,
            answer=answer,
            confidence=round(best_confidence, 4),
            votes=raw_votes,
            elapsed_ms=elapsed_ms,
            quorum_reached=quorum_reached,
            metadata={
                "fault_tolerance": self._fault_tolerance(len(agents)),
                "total_agents": len(agents),
                "total_weight": total_weight,
                "tally": {k: v["count"] for k, v in tally.items()},
            },
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _fault_tolerance(self, n: int) -> int:
        """Return the maximum number *f* of Byzantine faults tolerated."""
        if self._max_faults is not None:
            return self._max_faults
        return (n - 1) // 3

    def _gather_votes(
        self,
        agents: List[AgentConfig],
        question: str,
        timeout_ms: int,
    ) -> Dict[str, str]:
        """Request a vote from every agent (fallback simulation).

        In production this would dispatch RPCs to distributed agents.
        The fallback hashes the agent name + question deterministically so
        the result is reproducible in tests.
        """
        votes: Dict[str, str] = {}

        # Use a thread pool so we can honour *timeout_ms* even if a
        # single agent hangs.
        with ThreadPoolExecutor(max_workers=min(len(agents), 8)) as pool:
            futures = {
                pool.submit(self._agent_vote, agent, question): agent
                for agent in agents
            }
            deadline = time.monotonic() + timeout_ms / 1000.0
            for fut in futures:
                remaining = deadline - time.monotonic()
                try:
                    vote = fut.result(timeout=max(remaining, 0.001))
                except FutureTimeout:
                    vote = "timeout"
                agent = futures[fut]
                votes[agent.name] = vote

        return votes

    @staticmethod
    def _agent_vote(agent: AgentConfig, question: str) -> str:
        """Simulate a single agent's vote.

        The vote is derived from ``H(agent_name || question)`` so it is
        deterministic yet appears random across different questions.
        """
        digest = hashlib.sha256(
            f"{agent.name}:{question}".encode()
        ).hexdigest()
        # Map the first byte to a ternary outcome
        val = int(digest[:2], 16) % 3
        return "yes" if val == 0 else "no" if val == 1 else "abstain"

    @staticmethod
    def _tally_votes(
        agents: List[AgentConfig],
        raw_votes: Dict[str, str],
    ) -> tuple[Dict[str, Dict[str, Any]], float]:
        """Aggregate weighted votes.

        Returns:
            A tuple of *(tally, total_weight)* where *tally* maps each
            answer to ``{"count": int, "weight": float}``.
        """
        weight_map = {a.name: a.weight for a in agents}
        tally: Dict[str, Dict[str, Any]] = {}
        total_weight = 0.0

        for agent_name, vote in raw_votes.items():
            w = weight_map.get(agent_name, 1.0)
            total_weight += w
            tally.setdefault(vote, {"count": 0, "weight": 0.0})
            tally[vote]["count"] += 1
            tally[vote]["weight"] += w

        return tally, total_weight


# ---------------------------------------------------------------------------
# SwarmModule facade
# ---------------------------------------------------------------------------


class SwarmModule:
    """High-level facade for multi-agent swarm operations.

    The module attempts to delegate to the native ``veriforge_swarm``
    package when it is installed; otherwise it falls back to the pure-Python
    :class:`BFTConsensus` engine bundled here.

    All public methods are thread-safe (they do not mutate shared state).

    Args:
        config: Arbitrary configuration dictionary forwarded to the backend.
        logger: Python :class:`logging.Logger` instance.
    """

    # Sentinel used to detect missing HMAC secrets in config
    _MISSING_SECRET = object()

    def __init__(
        self,
        config: Dict[str, Any],
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._config = dict(config)
        self._log = logger or logging.getLogger(__name__)
        self._backend: Any = None

        if _HAS_SWARM_LIB:
            try:
                self._backend = SwarmClient(**config)
                self._log.info("Using native veriforge_swarm backend")
            except Exception as exc:  # noqa: BLE001
                self._log.warning(
                    "Failed to initialise SwarmClient (%s); using fallback", exc
                )

        if self._backend is None:
            self._bft = BFTConsensus(
                max_faults=config.get("swarm_max_faults")
            )
            self._log.info("Using built-in BFTConsensus fallback")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def consensus(
        self,
        agents: List[AgentConfig],
        question: str,
        timeout_ms: int = 30_000,
    ) -> SwarmConsensus:
        """Run a BFT consensus round across *agents*.

        Args:
            agents: Participating agents (minimum 4 for BFT guarantees).
            question: The proposal or question to reach consensus on.
            timeout_ms: Maximum time to wait for the round.

        Returns:
            A :class:`SwarmConsensus` result object.

        Raises:
            ValueError: If fewer than 4 agents are provided.
            RuntimeError: If the consensus engine fails catastrophically.
        """
        self._log.info(
            "Starting consensus round: question=%r agents=%d timeout=%dms",
            question,
            len(agents),
            timeout_ms,
        )

        if self._backend is not None:
            try:
                return self._backend.consensus(
                    agents=[self._agent_to_dict(a) for a in agents],
                    question=question,
                    timeout_ms=timeout_ms,
                )
            except Exception as exc:  # noqa: BLE001
                self._log.warning(
                    "Native consensus failed (%s); falling back to BFTConsensus", exc
                )

        return self._bft.run(agents, question, timeout_ms)

    def red_team(self, target: str, iterations: int = 5) -> Dict[str, Any]:
        """Run a red-team attack simulation against *target*.

        Args:
            target: The target identifier (e.g. URL, contract address).
            iterations: Number of attack iterations to simulate.

        Returns:
            Dictionary with keys ``findings`` (list of attack results),
            ``target``, ``iterations``, and ``risk_score`` (0-100).
        """
        self._log.info("Red-team simulation target=%r iterations=%d", target, iterations)

        if self._backend is not None:
            try:
                return self._backend.red_team(target=target, iterations=iterations)
            except Exception as exc:  # noqa: BLE001
                self._log.warning("Native red_team failed (%s); using fallback", exc)

        findings: List[Dict[str, Any]] = []
        total_risk = 0.0

        for i in range(1, iterations + 1):
            # Deterministic pseudo-random attack vector seeded by target
            seed = f"{target}:{i}"
            digest = hashlib.sha256(seed.encode()).hexdigest()
            attack_type = self._attack_vector(int(digest[:4], 16))
            severity = (int(digest[4:6], 16) % 10) + 1  # 1-10
            total_risk += severity
            findings.append(
                {
                    "iteration": i,
                    "attack_vector": attack_type,
                    "severity": severity,
                    "description": f"Simulated {attack_type} attack on {target}",
                    "mitigated": severity <= 5,
                }
            )

        return {
            "target": target,
            "iterations": iterations,
            "findings": findings,
            "risk_score": min(int(total_risk / iterations * 10), 100),
            "engine": "fallback",
        }

    def blue_team(self, target: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run a blue-team defense analysis against *findings*.

        Args:
            target: The target being defended.
            findings: Output from :meth:`red_team` or external scanner.

        Returns:
            Dictionary with ``defenses`` (list of countermeasures),
            ``target``, ``coverage_score`` (0-100), and ``residual_risk``.
        """
        self._log.info(
            "Blue-team analysis target=%r findings=%d", target, len(findings)
        )

        if self._backend is not None:
            try:
                return self._backend.blue_team(target=target, findings=findings)
            except Exception as exc:  # noqa: BLE001
                self._log.warning("Native blue_team failed (%s); using fallback", exc)

        defenses: List[Dict[str, Any]] = []
        mitigated = 0
        residual_risk = 0

        for finding in findings:
            defense = self._defense_for(finding)
            defenses.append(defense)
            if finding.get("severity", 0) <= 5 or defense.get("effectiveness", 0) >= 7:
                mitigated += 1
            else:
                residual_risk += finding.get("severity", 0)

        coverage = int((mitigated / max(len(findings), 1)) * 100)

        return {
            "target": target,
            "defenses": defenses,
            "mitigated_count": mitigated,
            "total_findings": len(findings),
            "coverage_score": coverage,
            "residual_risk": residual_risk,
            "engine": "fallback",
        }

    def hierarchical(self, task: str, depth: int = 3) -> Dict[str, Any]:
        """Hierarchical agent delegation for complex tasks.

        The task is recursively decomposed into sub-tasks up to *depth*
        levels.  Each level assigns work to specialist agents.

        Args:
            task: The high-level task description.
            depth: Maximum recursion depth (default ``3``).

        Returns:
            Nested dictionary representing the delegation tree with keys
            ``task``, ``subtasks`` (list), and ``agents_assigned``.
        """
        self._log.info("Hierarchical delegation task=%r depth=%d", task, depth)

        if self._backend is not None:
            try:
                return self._backend.hierarchical(task=task, depth=depth)
            except Exception as exc:  # noqa: BLE001
                self._log.warning(
                    "Native hierarchical failed (%s); using fallback", exc
                )

        return self._delegate(task, depth, current_depth=0)

    def self_verifying(
        self,
        claim: str,
        evidence: List[str],
    ) -> Dict[str, Any]:
        """Self-verifying consensus for a *claim* backed by *evidence*.

        The method simulates an internal debate where one agent argues
        *for* the claim and another argues *against*, then a third
        (judge) agent evaluates the evidence.

        Args:
            claim: The assertion to verify.
            evidence: List of evidence strings supporting or refuting the
                claim.

        Returns:
            Dictionary with ``claim``, ``verified`` (bool),
            ``confidence`` (0-100), and ``reasoning``.
        """
        self._log.info(
            "Self-verifying claim=%r evidence_items=%d", claim, len(evidence)
        )

        if self._backend is not None:
            try:
                return self._backend.self_verifying(
                    claim=claim, evidence=evidence
                )
            except Exception as exc:  # noqa: BLE001
                self._log.warning(
                    "Native self_verifying failed (%s); using fallback", exc
                )

        # Fallback: simulate debate
        pro_score = 0
        con_score = 0
        for ev in evidence:
            ev_hash = int(hashlib.sha256(ev.encode()).hexdigest()[:4], 16)
            if ev_hash % 2 == 0:
                pro_score += 1
            else:
                con_score += 1

        total = len(evidence) or 1
        confidence = int(max(pro_score, con_score) / total * 100)
        verified = pro_score > con_score

        return {
            "claim": claim,
            "verified": verified,
            "confidence": confidence,
            "pro_score": pro_score,
            "con_score": con_score,
            "evidence_count": len(evidence),
            "reasoning": (
                f"Pro evidence ({pro_score}) outweighs con ({con_score})."
                if verified
                else f"Con evidence ({con_score}) outweighs pro ({pro_score})."
            ),
            "engine": "fallback",
        }

    def capabilities(self) -> List[str]:
        """Return the list of capabilities exposed by this module.

        Returns:
            A list of capability name strings.
        """
        caps = [
            "swarm.consensus",
            "swarm.red_team",
            "swarm.blue_team",
            "swarm.hierarchical",
            "swarm.self_verifying",
            "swarm.bft_consensus",
        ]
        if self._backend is not None:
            caps.append("swarm.native_backend")
        else:
            caps.append("swarm.fallback_backend")
        return caps

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _agent_to_dict(agent: AgentConfig) -> Dict[str, Any]:
        """Serialize an :class:`AgentConfig` for the native backend."""
        return {
            "name": agent.name,
            "role": agent.role,
            "weight": agent.weight,
            "metadata": dict(agent.metadata),
        }

    @staticmethod
    def _attack_vector(seed: int) -> str:
        """Map a seed value to a named attack vector."""
        vectors = [
            "prompt_injection",
            "adversarial_example",
            "model_extraction",
            "data_poisoning",
            "supply_chain",
            "membership_inference",
            "model_inversion",
            "evasion",
        ]
        return vectors[seed % len(vectors)]

    @staticmethod
    def _defense_for(finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a countermeasure for a given finding."""
        vector = finding.get("attack_vector", "unknown")
        defense_map = {
            "prompt_injection": {
                "defense": "input_validation",
                "description": "Strict input sanitisation and prompt boundaries",
                "effectiveness": 8,
            },
            "adversarial_example": {
                "defense": "adversarial_training",
                "description": "Retrain with adversarial augmentations",
                "effectiveness": 7,
            },
            "model_extraction": {
                "defense": "rate_limiting",
                "description": "Query throttling and output perturbation",
                "effectiveness": 6,
            },
            "data_poisoning": {
                "defense": "anomaly_detection",
                "description": "Training-data anomaly filtering",
                "effectiveness": 7,
            },
            "supply_chain": {
                "defense": "dependency_scanning",
                "description": "Automated SBOM and dependency auditing",
                "effectiveness": 9,
            },
            "membership_inference": {
                "defense": "differential_privacy",
                "description": "DP-SGD training with epsilon budget",
                "effectiveness": 8,
            },
            "model_inversion": {
                "defense": "output_constraints",
                "description": "Limit granularity of model outputs",
                "effectiveness": 7,
            },
            "evasion": {
                "defense": "ensemble_hardening",
                "description": "Multi-model ensemble with majority voting",
                "effectiveness": 6,
            },
        }
        return defense_map.get(
            vector,
            {
                "defense": "generic_mitigation",
                "description": f"General hardening for {vector}",
                "effectiveness": 5,
            },
        )

    def _delegate(
        self, task: str, max_depth: int, current_depth: int
    ) -> Dict[str, Any]:
        """Recursive delegation helper (fallback implementation)."""
        digest = hashlib.sha256(f"{task}:{current_depth}".encode()).hexdigest()
        agent_roles = ["planner", "executor", "reviewer", "specialist"]
        assigned = agent_roles[current_depth % len(agent_roles)]

        node: Dict[str, Any] = {
            "task": task,
            "depth": current_depth,
            "agent_role": assigned,
            "subtasks": [],
        }

        if current_depth < max_depth:
            num_subtasks = 2 + (int(digest[:2], 16) % 3)  # 2-4 subtasks
            for i in range(num_subtasks):
                subtask = f"{task} — sub-task #{i + 1} (L{current_depth + 1})"
                node["subtasks"].append(
                    self._delegate(subtask, max_depth, current_depth + 1)
                )

        return node
