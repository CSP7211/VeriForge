"""
AuthManager — JWT token generation/validation, RBAC, HMAC-SHA256 API key hashing,
and sliding-window rate limiting.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

import jwt


class Role(enum.Enum):
    """Role-based access control levels."""

    ADMIN = "admin"
    AGENT = "agent"
    VIEWER = "viewer"


class AuthError(Exception):
    """Generic authentication error — no internal details leaked."""

    pass


@dataclass
class RateWindow:
    """Sliding window rate limit tracker per client."""

    max_requests: int = 10
    window_seconds: int = 60
    _requests: deque[float] = field(default_factory=deque, repr=False)

    def is_allowed(self) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        while self._requests and self._requests[0] < cutoff:
            self._requests.popleft()
        if len(self._requests) >= self.max_requests:
            return False
        self._requests.append(now)
        return True

    def reset(self) -> None:
        self._requests.clear()


class AuthManager:
    """JWT + RBAC + HMAC API-key hashing + sliding-window rate limiting."""

    def __init__(
        self,
        jwt_secret: str,
        algorithm: str = "HS256",
        token_ttl_seconds: int = 3600,
        rate_limit: int = 10,
    ) -> None:
        self._jwt_secret = jwt_secret
        self._algorithm = algorithm
        self._token_ttl = token_ttl_seconds
        self._rate_limit = rate_limit
        self._windows: dict[str, RateWindow] = {}
        self._revoked_tokens: set[str] = set()

    # ── JWT ──────────────────────────────────────────────────────────────

    def generate_token(
        self,
        subject: str,
        role: Role,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "sub": subject,
            "role": role.value,
            "iat": now,
            "exp": now + self._token_ttl,
            "jti": secrets.token_hex(16),
        }
        if extra_claims:
            claims.update(extra_claims)
        return jwt.encode(claims, self._jwt_secret, algorithm=self._algorithm)

    def validate_token(self, token: str) -> dict[str, Any]:
        if token in self._revoked_tokens:
            raise AuthError("Invalid or expired token")
        try:
            payload = jwt.decode(
                token,
                self._jwt_secret,
                algorithms=[self._algorithm],
                options={"require": ["exp", "iat", "sub"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthError("Invalid or expired token") from exc
        except jwt.InvalidTokenError as exc:
            raise AuthError("Invalid or expired token") from exc
        return payload

    def revoke_token(self, token: str) -> None:
        self._revoked_tokens.add(token)

    # ── RBAC ─────────────────────────────────────────────────────────────

    @staticmethod
    def has_role(payload: dict[str, Any], required: Role) -> bool:
        """Check if the user's role satisfies the required role.

        Hierarchy: ADMIN > AGENT > VIEWER.
        ADMIN satisfies all required roles.
        AGENT satisfies AGENT and VIEWER.
        VIEWER satisfies only VIEWER.
        """
        role_map = {
            Role.ADMIN: {Role.ADMIN.value},
            Role.AGENT: {Role.ADMIN.value, Role.AGENT.value},
            Role.VIEWER: {Role.ADMIN.value, Role.AGENT.value, Role.VIEWER.value},
        }
        user_role = payload.get("role", "")
        return user_role in role_map.get(required, set())

    def require_role(self, token: str, required: Role) -> dict[str, Any]:
        payload = self.validate_token(token)
        if not self.has_role(payload, required):
            raise AuthError("Insufficient permissions")
        return payload

    # ── HMAC API Key hashing ─────────────────────────────────────────────

    @staticmethod
    def hash_api_key(api_key: str, secret: str) -> str:
        """HMAC-SHA256 hash of the API key — never store raw keys."""
        return hmac.new(
            secret.encode("utf-8"),
            api_key.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def verify_api_key(api_key: str, secret: str, expected_hash: str) -> bool:
        computed = AuthManager.hash_api_key(api_key, secret)
        return hmac.compare_digest(computed, expected_hash)

    @staticmethod
    def generate_api_key() -> str:
        return secrets.token_urlsafe(32)

    # ── Rate Limiting ────────────────────────────────────────────────────

    def check_rate(self, client_id: str) -> bool:
        if client_id not in self._windows:
            self._windows[client_id] = RateWindow(
                max_requests=self._rate_limit,
                window_seconds=60,
            )
        return self._windows[client_id].is_allowed()

    def reset_rate(self, client_id: str) -> None:
        if client_id in self._windows:
            self._windows[client_id].reset()
