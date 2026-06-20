"""SDK configuration and settings management.

All settings follow the precedence:
1. Explicit arguments passed to ``SDKConfig``
2. Environment variables (see ``Environment Variables`` below)
3. Secure defaults

This hierarchy mitigates *CVE-2024-001* — Secure Defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .exceptions import MissingConfigurationError


# ---------------------------------------------------------------------------
# Defaults (secure by design)
# ---------------------------------------------------------------------------

_DEFAULT_BASE_URL = "https://api.veriforge.io/v1"
_DEFAULT_TIMEOUT = 30.0
_DEFAULT_MAX_RETRIES = 3


# ---------------------------------------------------------------------------
# SDKConfig
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SDKConfig:
    """Central configuration object for the VeriForge SDK.

    Fields can be set explicitly or via environment variables:

    Environment Variables:
        VERIFORGE_API_KEY: Authentication token (required).
        VERIFORGE_BASE_URL: API base URL (default: https://api.veriforge.io/v1).
        VERIFORGE_TIMEOUT: Request timeout in seconds (default: 30).
        VERIFORGE_MAX_RETRIES: Retry count for idempotent ops (default: 3).
        VERIFORGE_VERIFY_SSL: Enable TLS cert verification (default: true).
        VERIFORGE_LOG_LEVEL: SDK logging verbosity (default: WARNING).
        VERIFORGE_USER_AGENT: Custom user-agent suffix.
        VERIFORGE_PROJECT_ID: Default project context.
        VERIFORGE_ORG_ID: Organization identifier.
        VERIFORGE_DISABLE_TELEMETRY: Set ``1`` to opt-out of usage metrics.

    Attributes:
        api_key: Bearer token for authentication.
        base_url: Root URL for all API calls.
        timeout: Per-request timeout (seconds).
        max_retries: Retry budget.
        verify_ssl: Validate TLS certificates.
        log_level: Python logging level name.
        user_agent: Optional user-agent suffix.
        project_id: Default project scope.
        org_id: Organization scope.
        disable_telemetry: If ``True``, no usage metrics are sent.
        extra: Arbitrary key/value pairs forwarded to products.
    """

    api_key: Optional[str] = None
    base_url: str = _DEFAULT_BASE_URL
    timeout: float = _DEFAULT_TIMEOUT
    max_retries: int = _DEFAULT_MAX_RETRIES
    verify_ssl: bool = True
    log_level: str = "WARNING"
    user_agent: Optional[str] = None
    project_id: Optional[str] = None
    org_id: Optional[str] = None
    disable_telemetry: bool = False
    extra: Dict[str, Any] = field(default_factory=dict, repr=False)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> "SDKConfig":
        """Create a configuration populated from environment variables.

        Raises:
            MissingConfigurationError: If ``VERIFORGE_API_KEY`` is unset.

        Returns:
            A fully-populated ``SDKConfig`` instance.
        """
        api_key = os.getenv("VERIFORGE_API_KEY")
        if not api_key:
            raise MissingConfigurationError(
                "Environment variable VERIFORGE_API_KEY is required",
                key="VERIFORGE_API_KEY",
            )
        return cls(
            api_key=api_key,
            base_url=os.getenv("VERIFORGE_BASE_URL", _DEFAULT_BASE_URL),
            timeout=float(os.getenv("VERIFORGE_TIMEOUT", _DEFAULT_TIMEOUT)),
            max_retries=int(os.getenv("VERIFORGE_MAX_RETRIES", _DEFAULT_MAX_RETRIES)),
            verify_ssl=os.getenv("VERIFORGE_VERIFY_SSL", "1").lower() in ("1", "true", "yes"),
            log_level=os.getenv("VERIFORGE_LOG_LEVEL", "WARNING").upper(),
            user_agent=os.getenv("VERIFORGE_USER_AGENT"),
            project_id=os.getenv("VERIFORGE_PROJECT_ID"),
            org_id=os.getenv("VERIFORGE_ORG_ID"),
            disable_telemetry=os.getenv("VERIFORGE_DISABLE_TELEMETRY", "0") == "1",
        )

    @classmethod
    def default(cls) -> "SDKConfig":
        """Return a configuration using only secure built-in defaults.

        Note:
            The ``api_key`` will be ``None``; most products will reject
            unauthenticated calls. This factory is useful for offline
            or local-only workflows.
        """
        return cls()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def headers(self) -> Dict[str, str]:
        """Build the HTTP header dict for API requests."""
        h: Dict[str, str] = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.user_agent:
            h["User-Agent"] = f"veriforge-sdk/1.0 {self.user_agent}"
        else:
            h["User-Agent"] = "veriforge-sdk/1.0"
        if self.project_id:
            h["X-Project-ID"] = self.project_id
        if self.org_id:
            h["X-Org-ID"] = self.org_id
        return h

    def merge(self, **overrides: Any) -> "SDKConfig":
        """Return a new config with selective overrides applied.

        Args:
            **overrides: Keyword args matching ``SDKConfig`` fields.

        Returns:
            A new ``SDKConfig`` — the original is unchanged.
        """
        current = {
            "api_key": self.api_key,
            "base_url": self.base_url,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "verify_ssl": self.verify_ssl,
            "log_level": self.log_level,
            "user_agent": self.user_agent,
            "project_id": self.project_id,
            "org_id": self.org_id,
            "disable_telemetry": self.disable_telemetry,
            "extra": dict(self.extra),
        }
        current.update(overrides)
        return SDKConfig(**current)
