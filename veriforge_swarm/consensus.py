"""
consensus.py — Byzantine Fault Tolerant Consensus Protocol

Implements a classic 2/3-majority BFT voting scheme with
conflicting-vote detection for identifying Byzantine agents.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from .agent import Agent


class VoteValue(Enum):
    """Possible vote dispositions."""

    ACCEPT = "accept"
    REJECT = "reject"
    ABSTAIN = "abstain"


@dataclass
class Proposal:
    """A value proposed to the swarm for consensus.

    Attributes
    ----------
    proposal_id:
        Unique identifier (UUID4).
    proposer_id:
        ``agent_id`` of the agent that created the proposal.
    value:
        Arbitrary dictionary payload — the actual data being voted on.
    digest:
        SHA-256 hex digest of the canonical JSON serialisation of *value*.
    created_at:
        Unix timestamp when the proposal was created.
    metadata:
        Optional extra context (e.g. task name, priority).
    """

    proposal_id: str
    proposer_id: str
    value: dict[str, Any]
    digest: str
    created_at: float
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, agent: "Agent", value: dict[str, Any], **meta: Any) -> "Proposal":
        """Factory: create a cryptographically-hashed proposal."""
        canonical = _canonical_json(value)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return cls(
            proposal_id=str(uuid.uuid4()),
            proposer_id=agent.agent_id,
            value=dict(value),
            digest=digest,
            created_at=time.time(),
            metadata=meta,
        )

    def verify_integrity(self) -> bool:
        """Recompute digest and verify it matches the stored one."""
        canonical = _canonical_json(self.value)
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return expected == self.digest


@dataclass
class Vote:
    """A single vote cast by an agent on a proposal.

    Attributes
    ----------
    vote_id:
        Unique identifier.
    proposal_id:
        The proposal this vote refers to.
    voter_id:
        ``agent_id`` of the voting agent.
    value:
        ``ACCEPT``, ``REJECT``, or ``ABSTAIN``.
    signature:
        HMAC-SHA256 signature over ``proposal_id + value.value``.
    created_at:
        Unix timestamp.
    """

    vote_id: str
    proposal_id: str
    voter_id: str
    value: VoteValue
    signature: str
    created_at: float

    @classmethod
    def cast(
        cls, agent: "Agent", proposal: Proposal, value: VoteValue
    ) -> "Vote":
        """Factory: agent casts a signed vote on *proposal*."""
        message = f"{proposal.proposal_id}:{value.value}"
        signature = agent.sign_message(message)
        return cls(
            vote_id=str(uuid.uuid4()),
            proposal_id=proposal.proposal_id,
            voter_id=agent.agent_id,
            value=value,
            signature=signature,
            created_at=time.time(),
        )


@dataclass
class Result:
    """Outcome of a consensus round.

    Attributes
    ----------
    proposal_id:
        Which proposal was decided.
    accepted:
        ``True`` if 2/3 majority was reached with ACCEPT.
    accept_count:
        Number of ACCEPT votes.
    reject_count:
        Number of REJECT votes.
    abstain_count:
        Number of ABSTAIN votes.
    total_votes:
        Total votes tallied.
    byzantine_agents:
        List of ``agent_id``\ s detected as Byzantine (conflicting votes).
    quorum_needed:
        Minimum votes required for a valid result.
    metadata:
        Extra context (e.g. timing, agent reputations).
    """

    proposal_id: str
    accepted: bool
    accept_count: int
    reject_count: int
    abstain_count: int
    total_votes: int
    byzantine_agents: list[str]
    quorum_needed: int
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# BFT Consensus engine
# ---------------------------------------------------------------------------


class BFTConsensus:
    """2/3 Byzantine Fault Tolerant voting engine.

    Typical lifecycle::

        engine = BFTConsensus()
        prop = engine.propose(agent, {"task": "scan", "target": "api"})
        v1 = engine.vote(agent1, prop, VoteValue.ACCEPT)
        v2 = engine.vote(agent2, prop, VoteValue.ACCEPT)
        v3 = engine.vote(agent3, prop, VoteValue.REJECT)
        result = engine.tally([v1, v2, v3])
        # result.accepted is True  (2 ACCEPT >= 2 needed for quorum of 3)
    """

    def __init__(self, description: str = "VeriForge-BFT") -> None:
        self.description = description
        self._proposals: dict[str, Proposal] = {}
        self._vote_log: list[Vote] = []

    # ------------------------------------------------------------------
    # Proposal phase
    # ------------------------------------------------------------------

    def propose(self, agent: "Agent", value: dict[str, Any]) -> Proposal:
        """Submit a proposal to the swarm.

        The proposal is hashed and stored internally for later tallying.
        """
        proposal = Proposal.create(agent, value)
        self._proposals[proposal.proposal_id] = proposal
        return proposal

    # ------------------------------------------------------------------
    # Vote phase
    # ------------------------------------------------------------------

    def vote(self, agent: "Agent", proposal: Proposal, value: VoteValue) -> Vote:
        """Cast a vote on *proposal*.

        *value* must be one of ``VoteValue.ACCEPT``, ``REJECT``,
        or ``ABSTAIN``.
        """
        vote = Vote.cast(agent, proposal, value)
        self._vote_log.append(vote)
        return vote

    # ------------------------------------------------------------------
    # Tally phase
    # ------------------------------------------------------------------

    def tally(self, votes: list[Vote]) -> Result:
        """Count votes and determine whether 2/3 majority was achieved.

        Also detects conflicting votes (same agent voting twice on the
        same proposal with different values) and flags those agents as
        Byzantine.
        """
        if not votes:
            return Result(
                proposal_id="", accepted=False,
                accept_count=0, reject_count=0, abstain_count=0,
                total_votes=0, byzantine_agents=[],
                quorum_needed=0,
            )

        proposal_id = votes[0].proposal_id
        total = len(votes)
        quorum_needed = max(1, (2 * total) // 3)

        # Detect conflicting votes (Byzantine behaviour)
        byzantine = self.is_byzantine(votes)

        # Filter out votes from detected Byzantine agents
        clean_votes = [v for v in votes if v.voter_id not in byzantine]
        accept_count = sum(1 for v in clean_votes if v.value == VoteValue.ACCEPT)
        reject_count = sum(1 for v in clean_votes if v.value == VoteValue.REJECT)
        abstain_count = sum(1 for v in clean_votes if v.value == VoteValue.ABSTAIN)
        clean_total = len(clean_votes)

        accepted = accept_count >= quorum_needed and accept_count > reject_count

        return Result(
            proposal_id=proposal_id,
            accepted=accepted,
            accept_count=accept_count,
            reject_count=reject_count,
            abstain_count=abstain_count,
            total_votes=clean_total,
            byzantine_agents=sorted(set(byzantine)),
            quorum_needed=quorum_needed,
            metadata={
                "raw_votes": total,
                "byzantine_filtered": len(byzantine),
                "timestamp": time.time(),
            },
        )

    # ------------------------------------------------------------------
    # Byzantine detection
    # ------------------------------------------------------------------

    def is_byzantine(self, votes: list[Vote], agent: "Agent" | None = None) -> bool | list[str]:
        """Detect agents casting conflicting votes.

        When *agent* is ``None``, returns a **list** of all Byzantine
        ``agent_id``\ s found in *votes*.

        When *agent* is provided, returns ``True`` if that specific agent
        cast conflicting votes in *votes*.
        """
        votes_by_agent: dict[str, set[str]] = {}
        for v in votes:
            votes_by_agent.setdefault(v.voter_id, set()).add(v.value.value)

        if agent is not None:
            return len(votes_by_agent.get(agent.agent_id, set())) > 1

        return [aid for aid, vals in votes_by_agent.items() if len(vals) > 1]

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def get_proposal(self, proposal_id: str) -> Optional[Proposal]:
        """Look up a previously submitted proposal by ID."""
        return self._proposals.get(proposal_id)

    def vote_history(self) -> list[Vote]:
        """Return the full vote log (for audit / replay)."""
        return list(self._vote_log)

    def reset(self) -> None:
        """Clear all internal state — useful for testing."""
        self._proposals.clear()
        self._vote_log.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _canonical_json(value: dict[str, Any]) -> str:
    """Return a stable string representation of *value* for hashing.

    Keys are sorted recursively so that equivalent dicts always produce
    the same digest regardless of insertion order.
    """
    import json

    def _sort(o: Any) -> Any:
        if isinstance(o, dict):
            return {k: _sort(v) for k, v in sorted(o.items())}
        if isinstance(o, list):
            return [_sort(i) for i in o]
        return o

    return json.dumps(_sort(value), separators=(",", ":"), ensure_ascii=False)
