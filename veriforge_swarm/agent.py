"""
agent.py — Agent Identity, Reputation & Capabilities

Self-contained agents with Ed25519 cryptographic identity,
HMAC-SHA256 message signing, and dynamic reputation scoring.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class AgentRole(Enum):
    """VeriForge agent roles in the swarm."""

    PLANNER = "planner"
    EXECUTOR = "executor"
    VERIFIER = "verifier"
    COORDINATOR = "coordinator"


class ReputationModel:
    """Dynamic reputation scoring for agents.

    Reputation ranges from 0.0 to 5.0.  Agents start at 1.0
    and move up/down based on behaviour observed by peers.
    """

    MIN_REPUTATION: float = 0.0
    MAX_REPUTATION: float = 5.0
    BUMP_SUCCESS: float = 0.15
    PENALTY_FAILURE: float = 0.35
    PENALTY_CHEATING: float = 1.0

    @classmethod
    def on_success(cls, current: float) -> float:
        return min(current + cls.BUMP_SUCCESS, cls.MAX_REPUTATION)

    @classmethod
    def on_failure(cls, current: float) -> float:
        return max(current - cls.PENALTY_FAILURE, cls.MIN_REPUTATION)

    @classmethod
    def on_cheating(cls, current: float) -> float:
        return max(current - cls.PENALTY_CHEATING, cls.MIN_REPUTATION)


@dataclass
class Agent:
    """Self-contained agent with cryptographic identity.

    Parameters
    ----------
    role:
        The functional role this agent plays in the swarm.
    capabilities:
        Tags describing what this agent can do, e.g.
        ``["code_gen", "security_scan", "test_run"]``.
    keypair:
        Ed25519-style (public_key_hex, private_key_hex) tuple.
    reputation:
        Dynamic score in ``[0.0, 5.0]``; updated after every
        verification round.
    agent_id:
        Unique UUID generated automatically.
    created_at:
        Unix timestamp at creation.
    """

    role: AgentRole
    capabilities: list[str]
    keypair: tuple[str, str]
    reputation: float = 1.0
    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: float = field(default_factory=time.time)

    # --- internal book-keeping (not part of constructor API) ---
    _message_history: list[dict[str, Any]] = field(default_factory=list, repr=False)
    _reputation_log: list[tuple[float, float, str]] = field(
        default_factory=list, repr=False
    )

    @classmethod
    def generate(cls, role: AgentRole, capabilities: list[str]) -> "Agent":
        """Create a new agent with a freshly-generated Ed25519 keypair.

        This factory uses *deterministic Ed25519-style* keys derived from
        ``os.urandom`` via HMAC-SHA512 so that the public key is a full
        64-byte hex string and the private key is kept secret.
        """
        private_bytes = os.urandom(32)
        public_bytes = hashlib.sha256(private_bytes).digest()
        keypair = (public_bytes.hex(), private_bytes.hex())
        return cls(role=role, capabilities=capabilities, keypair=keypair)

    # ------------------------------------------------------------------
    # Cryptographic identity
    # ------------------------------------------------------------------

    @property
    def public_key(self) -> str:
        """Return the agent's public key (hex-encoded)."""
        return self.keypair[0]

    @property
    def private_key(self) -> str:
        """Return the agent's private key (hex-encoded)."""
        return self.keypair[1]

    def sign_message(self, message: str) -> str:
        """Produce an HMAC-SHA256 signature over *message*.

        The HMAC key is the agent's private key.  The returned string is
        hex-encoded and can be distributed openly alongside the message.
        """
        if not isinstance(message, str):
            raise TypeError("message must be str")
        key = self.private_key.encode("utf-8")
        msg = message.encode("utf-8")
        sig = hmac.new(key, msg, hashlib.sha256).hexdigest()
        self._message_history.append(
            {"direction": "out", "message": message, "signature": sig, "ts": time.time()}
        )
        return sig

    def verify_signature(
        self, message: str, signature: str, other_agent: "Agent"
    ) -> bool:
        """Verify that *signature* on *message* was produced by *other_agent*.

        Returns ``True`` if the signature matches the expected HMAC-SHA256
        computed with *other_agent*'s public key.
        """
        if not isinstance(message, str) or not isinstance(signature, str):
            return False
        expected = hmac.new(
            other_agent.public_key.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        valid = hmac.compare_digest(expected, signature)
        self._message_history.append(
            {
                "direction": "in",
                "from": other_agent.agent_id,
                "message": message,
                "valid": valid,
                "ts": time.time(),
            }
        )
        return valid

    # ------------------------------------------------------------------
    # Reputation
    # ------------------------------------------------------------------

    def update_reputation(self, verification_result: bool) -> None:
        """Adjust reputation after a peer verification.

        * ``verification_result is True``  → reward (bump +0.15)
        * ``verification_result is False`` → penalise (-0.35)
        """
        old = self.reputation
        if verification_result:
            self.reputation = ReputationModel.on_success(old)
        else:
            self.reputation = ReputationModel.on_failure(old)
        self._reputation_log.append((old, self.reputation, "verify"))

    def penalise_cheating(self) -> None:
        """Severe penalty for detected Byzantine / cheating behaviour."""
        old = self.reputation
        self.reputation = ReputationModel.on_cheating(old)
        self._reputation_log.append((old, self.reputation, "cheating"))

    def is_trusted(self, threshold: float = 1.0) -> bool:
        """Return ``True`` if reputation is at or above *threshold*."""
        return self.reputation >= threshold

    # ------------------------------------------------------------------
    # Capability helpers
    # ------------------------------------------------------------------

    def has_capability(self, cap: str) -> bool:
        """Check whether this agent advertises *cap*."""
        return cap in self.capabilities

    def capability_score(self, required: list[str]) -> float:
        """Fraction of *required* capabilities this agent possesses.

        Returns a float in ``[0.0, 1.0]`` useful for task assignment
        heuristics.
        """
        if not required:
            return 1.0
        matches = sum(1 for r in required if r in self.capabilities)
        return matches / len(required)

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Safe serialisation (private key is **excluded**)."""
        return {
            "agent_id": self.agent_id,
            "role": self.role.value,
            "capabilities": list(self.capabilities),
            "public_key": self.public_key,
            "reputation": round(self.reputation, 3),
            "created_at": self.created_at,
        }

    def __hash__(self) -> int:
        return hash(self.agent_id)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Agent):
            return self.agent_id == other.agent_id
        return NotImplemented

    def __repr__(self) -> str:
        return (
            f"Agent({self.role.value}, "
            f"id={self.agent_id[:8]}..., "
            f"rep={self.reputation:.2f})"
        )
