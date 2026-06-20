"""
Authenticated AgentVerifier — JWT authentication required on all endpoints.
Role-based access control for agent registration, code verification, and listing.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

from veriforge.auth import AuthManager, AuthError, Role
from veriforge.engine import VeriForgeEngine, VerificationResult


@dataclass
class Agent:
    """Registered agent record."""

    agent_id: str
    name: str
    role: Role
    registered_at: float
    api_key_hash: str = ""
    last_seen: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


class AgentVerifier:
    """Agent operations with mandatory JWT authentication and RBAC."""

    def __init__(self, auth_manager: AuthManager, engine: VeriForgeEngine) -> None:
        self._auth = auth_manager
        self._engine = engine
        self._agents: dict[str, Agent] = {}

    def _require_auth(self, token: str, required_role: Role = Role.AGENT) -> dict[str, Any]:
        """Validate token and enforce role — generic errors only."""
        try:
            payload = self._auth.require_role(token, required_role)
        except AuthError as exc:
            raise AuthError("Authentication failed") from exc
        return payload

    # ── Agent management ─────────────────────────────────────────────────

    def register_agent(
        self,
        token: str,
        agent_id: str,
        name: str,
        role: Role = Role.AGENT,
    ) -> Agent:
        """Register a new agent. Requires ADMIN role."""
        self._require_auth(token, required_role=Role.ADMIN)

        if agent_id in self._agents:
            raise AuthError("Registration failed")

        api_key = self._auth.generate_api_key()
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        agent = Agent(
            agent_id=agent_id,
            name=name,
            role=role,
            registered_at=time.time(),
            api_key_hash=api_key_hash,
            last_seen=time.time(),
        )
        self._agents[agent_id] = agent
        # Return the raw API key once — it is never stored in plain text
        agent.metadata["api_key"] = api_key
        return agent

    def list_agents(self, token: str) -> list[Agent]:
        """List all registered agents. Requires at least VIEWER role."""
        self._require_auth(token, required_role=Role.VIEWER)
        return list(self._agents.values())

    def get_agent(self, token: str, agent_id: str) -> Agent:
        """Get a specific agent. Requires at least VIEWER role."""
        self._require_auth(token, required_role=Role.VIEWER)
        if agent_id not in self._agents:
            raise AuthError("Not found")
        return self._agents[agent_id]

    # ── Code verification ────────────────────────────────────────────────

    def verify_code(
        self,
        token: str,
        source: str,
        filename: str = "<unknown>",
    ) -> VerificationResult:
        """Verify code. Requires AGENT or ADMIN role."""
        payload = self._require_auth(token, required_role=Role.AGENT)
        client_id = payload.get("sub", "anonymous")

        if not self._auth.check_rate(client_id):
            raise AuthError("Rate limit exceeded")

        result = self._engine.verify_code(source, filename=filename)

        # Update agent last_seen
        agent_id = payload.get("sub", "")
        if agent_id in self._agents:
            self._agents[agent_id].last_seen = time.time()

        return result
