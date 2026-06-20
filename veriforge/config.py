"""
SecureConfig — Environment-based configuration with secret management.

All secrets are loaded exclusively from environment variables or
encrypted files.  No hard-coded credentials.
"""

from __future__ import annotations

import os
from typing import Any


class ConfigurationError(RuntimeError):
    """Raised when a required configuration value is missing or invalid."""


class SecureConfig:
    """
    Secure configuration container.

    Secrets are read from environment variables.  A RuntimeError is
    raised if a required secret is missing and no default is provided.
    """

    def __init__(self, **overrides: Any) -> None:
        self._overrides = overrides
        self._cache: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Core helpers
    # ------------------------------------------------------------------

    def _env(self, key: str, default: str | None = None, required: bool = False) -> str:
        """Read a value from the environment (with override support)."""
        if key in self._overrides:
            value = str(self._overrides[key])
        else:
            value = os.environ.get(key, default)

        if required and value is None:
            raise ConfigurationError(f"Required configuration missing: {key}")
        return value or ""

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def secret_key(self) -> str:
        """Primary secret key for HMAC signing."""
        return self._env("VERIFORGE_SECRET", required=True)

    @property
    def jwt_secret(self) -> str:
        """Secret for JWT token signing."""
        return self._env("VERIFORGE_JWT_SECRET", required=True)

    @property
    def audit_secret(self) -> str:
        """Secret for audit log HMAC chain."""
        return self._env("VERIFORGE_AUDIT_SECRET", required=True)

    @property
    def db_url(self) -> str:
        """Database connection URL (used when persistence is enabled)."""
        return self._env("VERIFORGE_DB_URL", default="sqlite:///veriforge.db")

    @property
    def rate_limit_max(self) -> int:
        """Maximum requests per window (default 100)."""
        return int(self._env("VERIFORGE_RATE_LIMIT", default="100"))

    @property
    def rate_limit_window(self) -> int:
        """Rate-limit window in seconds (default 60)."""
        return int(self._env("VERIFORGE_RATE_WINDOW", default="60"))

    @property
    def log_level(self) -> str:
        """Python logging level."""
        return self._env("VERIFORGE_LOG_LEVEL", default="INFO")

    @property
    def compliance_mode(self) -> str:
        """Active compliance standard (soc2, iso27001, pci_dss, or all)."""
        return self._env("VERIFORGE_COMPLIANCE", default="all")

    @property
    def max_file_size(self) -> int:
        """Maximum allowed file size in bytes (default 10 MB)."""
        return int(self._env("VERIFORGE_MAX_FILE_SIZE", default="10485760"))

    @property
    def allowed_extensions(self) -> set[str]:
        """Set of allowed file extensions for scanning."""
        raw = self._env("VERIFORGE_EXTENSIONS", default=".py,.js,.go,.rs,.c,.cpp,.java")
        return {ext.strip() for ext in raw.split(",")}

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> list[str]:
        """
        Validate the current configuration.

        Returns a list of error messages (empty list = configuration is valid).
        """
        errors: list[str] = []
        try:
            _ = self.secret_key
        except ConfigurationError as exc:
            errors.append(str(exc))
        try:
            _ = self.jwt_secret
        except ConfigurationError as exc:
            errors.append(str(exc))
        try:
            _ = self.audit_secret
        except ConfigurationError as exc:
            errors.append(str(exc))
        if self.rate_limit_max < 1:
            errors.append("rate_limit_max must be >= 1")
        if self.rate_limit_window < 1:
            errors.append("rate_limit_window must be >= 1")
        return errors
