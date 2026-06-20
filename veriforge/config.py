"""
SecureConfig — All secrets loaded exclusively from environment variables.
No secrets shall ever be hard-coded. RuntimeError raised if required vars missing.
"""

from __future__ import annotations

import os


class SecureConfig:
    """All secrets loaded from environment variables. RuntimeError if missing."""

    REQUIRED: tuple[str, ...] = ("VERIFORGE_SECRET_KEY",)
    OPTIONAL: tuple[str, ...] = (
        "VERIFORGE_ADMIN_TOKEN",
        "VERIFORGE_API_KEY",
        "VERIFORGE_JWT_SECRET",
    )

    def __init__(self) -> None:
        self.secret_key: str | None = os.environ.get("VERIFORGE_SECRET_KEY")
        self.admin_token: str | None = os.environ.get("VERIFORGE_ADMIN_TOKEN")
        self.api_key: str | None = os.environ.get("VERIFORGE_API_KEY")
        self.jwt_secret: str | None = os.environ.get("VERIFORGE_JWT_SECRET")

        if not self.secret_key:
            raise RuntimeError("VERIFORGE_SECRET_KEY not set")

    def get_jwt_secret(self) -> str:
        """Return the JWT secret, falling back to the main secret_key."""
        secret = self.jwt_secret or self.secret_key
        if not secret:
            raise RuntimeError("No JWT secret available")
        return secret
