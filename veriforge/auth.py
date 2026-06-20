"""
AuthManager — JWT-based authentication with RBAC and rate limiting.

Features:
  * HS256 JWT tokens with configurable expiry
  * Role-based access control (RBAC)
  * Sliding-window rate limiting
  * Constant-time token comparison
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class JWTError(RuntimeError):
    """Raised on JWT token validation failures."""


class RBACError(RuntimeError):
    """Raised on role-based access control violations."""


class RateLimitError(RuntimeError):
    """Raised when rate limit is exceeded."""


class Role(str, Enum):
    """Predefined roles for RBAC."""

    ADMIN = "admin"
    AUDITOR = "auditor"
    SCANNER = "scanner"
    VIEWER = "viewer"


# Permission matrix: role -> set of allowed actions
PERMISSIONS: dict[Role, set[str]] = {
    Role.ADMIN: {"scan", "audit", "config", "admin", "view"},
    Role.AUDITOR: {"audit", "view"},
    Role.SCANNER: {"scan", "view"},
    Role.VIEWER: {"view"},
}


@dataclass(slots=True, frozen=True)
class TokenPayload:
    """Decoded JWT payload (immutable)."""

    subject: str
    role: Role
    issued_at: float
    expires_at: float


class AuthManager:
    """
    Authentication and authorization manager.

    Implements JWT token issuance/validation, RBAC enforcement, and
    per-subject rate limiting.
    """

    def __init__(
        self,
        jwt_secret: str | None = None,
        token_ttl_seconds: int = 3600,
        rate_limit_max: int = 100,
        rate_limit_window: int = 60,
    ) -> None:
        self._jwt_secret = jwt_secret or secrets.token_hex(32)
        self._token_ttl = token_ttl_seconds
        self._rate_limit_max = rate_limit_max
        self._rate_limit_window = rate_limit_window
        # In-memory rate-limit store: subject -> list of timestamps
        self._rate_store: dict[str, list[float]] = {}

    # ------------------------------------------------------------------
    # Token lifecycle
    # ------------------------------------------------------------------

    def issue_token(self, subject: str, role: Role | str = Role.VIEWER) -> str:
        """
        Issue a new JWT token for *subject* with *role*.

        The returned string is a URL-safe base64-encoded JWT.
        """
        if not subject or len(subject) > 256:
            raise JWTError("Invalid subject")
        role_enum = Role(role) if isinstance(role, str) else role
        now = time.time()
        payload = {
            "sub": subject,
            "role": role_enum.value,
            "iat": now,
            "exp": now + self._token_ttl,
        }
        return self._encode_jwt(payload)

    def validate_token(self, token: str) -> TokenPayload:
        """
        Validate a JWT token.

        Raises:
            JWTError: If the token is malformed, expired, or has an invalid signature.
        """
        if not token or len(token) > 4096:
            raise JWTError("Invalid token format")

        payload = self._decode_jwt(token)
        now = time.time()
        if payload["exp"] < now:
            raise JWTError("Token expired")
        if payload["iat"] > now:
            raise JWTError("Token issued in the future")

        return TokenPayload(
            subject=payload["sub"],
            role=Role(payload["role"]),
            issued_at=payload["iat"],
            expires_at=payload["exp"],
        )

    # ------------------------------------------------------------------
    # RBAC
    # ------------------------------------------------------------------

    def check_permission(self, token: str, action: str) -> None:
        """
        Verify that the token bearer is allowed to perform *action*.

        Raises:
            RBACError: If the action is not permitted for the token's role.
        """
        payload = self.validate_token(token)
        role_perms = PERMISSIONS.get(payload.role, set())
        if action not in role_perms:
            raise RBACError(
                f"Action '{action}' not permitted for role '{payload.role.value}'"
            )

    def require_role(self, token: str, min_role: Role) -> TokenPayload:
        """
        Require the token bearer to have at least *min_role*.

        Role ordering: admin > auditor > scanner > viewer
        """
        payload = self.validate_token(token)
        role_hierarchy = [Role.VIEWER, Role.SCANNER, Role.AUDITOR, Role.ADMIN]
        if role_hierarchy.index(payload.role) < role_hierarchy.index(min_role):
            raise RBACError(
                f"Role '{payload.role.value}' insufficient; need '{min_role.value}'"
            )
        return payload

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def check_rate_limit(self, subject: str) -> None:
        """
        Check and record a request for *subject*.

        Raises:
            RateLimitError: If the subject has exceeded the rate limit.
        """
        now = time.time()
        window_start = now - self._rate_limit_window
        timestamps = self._rate_store.get(subject, [])
        # Drop old entries
        timestamps = [ts for ts in timestamps if ts > window_start]
        if len(timestamps) >= self._rate_limit_max:
            raise RateLimitError(
                f"Rate limit exceeded for '{subject}': "
                f"{self._rate_limit_max} requests per {self._rate_limit_window}s"
            )
        timestamps.append(now)
        self._rate_store[subject] = timestamps

    def reset_rate_limit(self, subject: str) -> None:
        """Reset rate-limit counters for *subject*."""
        self._rate_store.pop(subject, None)

    # ------------------------------------------------------------------
    # JWT helpers (simple implementation, no external deps)
    # ------------------------------------------------------------------

    def _encode_jwt(self, payload: dict[str, Any]) -> str:
        """Encode a JWT with HS256."""
        import base64
        import json

        header = {"alg": "HS256", "typ": "JWT"}
        header_b64 = self._b64url_encode(json.dumps(header).encode())
        payload_b64 = self._b64url_encode(json.dumps(payload).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = hmac.new(
            self._jwt_secret.encode(), signing_input, hashlib.sha256
        ).digest()
        sig_b64 = self._b64url_encode(signature)
        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def _decode_jwt(self, token: str) -> dict[str, Any]:
        """Decode and verify a JWT with HS256."""
        import base64
        import json

        parts = token.split(".")
        if len(parts) != 3:
            raise JWTError("Invalid JWT format")

        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode()
        expected_sig = hmac.new(
            self._jwt_secret.encode(), signing_input, hashlib.sha256
        ).digest()
        try:
            actual_sig = self._b64url_decode(sig_b64)
        except Exception:
            raise JWTError("Invalid signature encoding")

        if not hmac.compare_digest(expected_sig, actual_sig):
            raise JWTError("Signature verification failed")

        payload_bytes = self._b64url_decode(payload_b64)
        return json.loads(payload_bytes)

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        """Base64-URL-encode without padding."""
        import base64

        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    @staticmethod
    def _b64url_decode(data: str) -> bytes:
        """Base64-URL-decode without padding."""
        import base64

        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)
