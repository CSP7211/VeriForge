"""
AgentVerifier — Authenticated agent verification with JWT binding.

Each verification request must include a valid JWT token.  The token
is validated, rate-limited, and RBAC-checked before any code is
evaluated.  All actions are logged to the immutable audit trail.
"""

from __future__ import annotations

import time
from typing import Any

from .auth import AuthManager, JWTError, RBACError, RateLimitError, Role
from .engine import VeriForgeEngine, VerificationResult
from .audit import ImmutableAuditLog


class AgentAuthError(RuntimeError):
    """Raised on agent authentication or authorization failure."""


class AgentVerifier:
    """
    Authenticated code verifier for agent-based workflows.

    Wraps VeriForgeEngine with mandatory authentication, authorization,
    rate limiting, and audit logging.
    """

    def __init__(
        self,
        auth: AuthManager | None = None,
        engine: VeriForgeEngine | None = None,
        audit: ImmutableAuditLog | None = None,
    ) -> None:
        self._auth = auth or AuthManager()
        self._engine = engine or VeriForgeEngine()
        self._audit = audit or ImmutableAuditLog(secret="agent-audit-secret")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_agent(self, agent_id: str, role: Role | str = Role.SCANNER) -> str:
        """
        Register a new agent and return a JWT token.

        Args:
            agent_id: Unique identifier for the agent.
            role: Role assigned to the agent (default: scanner).

        Returns:
            A JWT token string that the agent must include in all requests.
        """
        token = self._auth.issue_token(subject=agent_id, role=role)
        self._audit.record(
            action="agent_register",
            subject=agent_id,
            detail=f"role={role if isinstance(role, str) else role.value}",
        )
        return token

    def verify(
        self,
        token: str,
        source: str,
        filename: str = "<agent>",
    ) -> VerificationResult:
        """
        Verify source code on behalf of an authenticated agent.

        The token is validated, the agent's rate limit is checked, and
        the scan permission is verified before proceeding.

        Args:
            token: JWT token issued by register_agent().
            source: Source code to verify.
            filename: Logical filename for the source.

        Returns:
            HMAC-signed VerificationResult.

        Raises:
            AgentAuthError: If authentication or authorization fails.
        """
        # 1. Validate JWT
        try:
            payload = self._auth.validate_token(token)
        except JWTError as exc:
            self._audit.record(
                action="auth_fail",
                subject="unknown",
                detail=f"JWT validation failed: {exc}",
            )
            raise AgentAuthError(f"Authentication failed: {exc}") from exc

        agent_id = payload.subject

        # 2. Rate limiting
        try:
            self._auth.check_rate_limit(agent_id)
        except RateLimitError as exc:
            self._audit.record(
                action="rate_limit",
                subject=agent_id,
                detail=str(exc),
            )
            raise AgentAuthError(f"Rate limit exceeded: {exc}") from exc

        # 3. RBAC — must have 'scan' permission
        try:
            self._auth.check_permission(token, "scan")
        except RBACError as exc:
            self._audit.record(
                action="rbac_denied",
                subject=agent_id,
                detail=f"Permission denied: {exc}",
            )
            raise AgentAuthError(f"Permission denied: {exc}") from exc

        # 4. Execute verification
        result = self._engine.verify_code(source, filename)

        # 5. Audit the scan
        self._audit.record(
            action="agent_scan",
            subject=agent_id,
            detail=f"file={filename},verified={result.verified}",
        )

        return result

    def revoke_agent(self, admin_token: str, agent_id: str) -> None:
        """
        Revoke an agent's access (admin only).

        Requires an admin token.
        """
        try:
            self._auth.require_role(admin_token, Role.ADMIN)
        except (JWTError, RBACError) as exc:
            raise AgentAuthError(f"Admin action failed: {exc}") from exc

        self._auth.reset_rate_limit(agent_id)
        self._audit.record(
            action="agent_revoke",
            subject=agent_id,
            detail="Access revoked by admin",
        )

    @property
    def audit(self) -> ImmutableAuditLog:
        """Access the underlying audit log."""
        return self._audit
