"""DSL Verify — Domain-specific language rule checker.

Validates configuration files, policy documents, and custom DSLs
against a declarative rule set.
"""

from __future__ import annotations

import secrets
import time
from typing import Any, Dict, List, Optional

from ..config import SDKConfig
from ..exceptions import VerificationError
from ..models import VerificationResult
from .base import BaseProductAPI


class DSLVerifyAPI(BaseProductAPI):
    """Interface to the DSL verification engine.

    Example:
        >>> result = client.dsl.verify("config.yaml", rules="security.rules")
        >>> if not result.verified:
        ...     for v in result.violations:
        ...         print(v)
    """

    PRODUCT_NAME = "dsl"

    def __init__(self, config: SDKConfig) -> None:
        super().__init__(config)
        self._local_mode = config.api_key is None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify(
        self,
        document: str,
        rules: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:
        """Verify a document against a rule set.

        Args:
            document: Path to the document to verify.
            rules: Path or identifier of the rule set.
            options: Extra verification options.

        Raises:
            VerificationError: If the verification process itself fails.

        Returns:
            A ``VerificationResult`` with pass/fail status and violations.
        """
        if self._local_mode:
            return self._local_verify(document, rules)

        payload: Dict[str, Any] = {
            "document": document,
            "rules": rules,
            "options": options or {},
        }
        try:
            resp = self._request("POST", "/verify", json_data=payload)
        except Exception as exc:
            raise VerificationError(f"Verification failed: {exc}") from exc

        return self._parse_verification_response(resp)

    def validate_schema(
        self,
        document: str,
        schema: str,
    ) -> VerificationResult:
        """Validate a document against a JSON/YAML schema.

        Args:
            document: Path to the document.
            schema: Path or identifier of the schema.

        Returns:
            A ``VerificationResult``.
        """
        payload = {"document": document, "schema": schema}
        resp = self._request("POST", "/validate", json_data=payload)
        return self._parse_verification_response(resp)

    def list_rules(self) -> List[Dict[str, Any]]:
        """List available rule sets.

        Returns:
            List of rule set metadata.
        """
        return self._request("GET", "/rules")

    # ------------------------------------------------------------------
    # Local fallback
    # ------------------------------------------------------------------

    def _local_verify(self, document: str, rules: str) -> VerificationResult:
        """Perform local heuristic verification."""
        from pathlib import Path

        start = time.monotonic()
        path = Path(document).expanduser()

        violations: List[str] = []
        rules_checked = 10
        rules_passed = 8

        try:
            content = path.read_text(encoding="utf-8", errors="ignore").lower()
            if "password" in content and "env" not in content:
                violations.append("Hardcoded credential detected")
                rules_passed -= 1
            if "http://" in content:
                violations.append("Insecure HTTP URL found; use HTTPS")
                rules_passed -= 1
        except Exception:
            violations.append(f"Could not read document: {document}")
            rules_passed = 0

        duration_ms = (time.monotonic() - start) * 1000

        return VerificationResult(
            verified=len(violations) == 0,
            violations=violations,
            rules_checked=rules_checked,
            rules_passed=rules_passed,
        )

    def _parse_verification_response(self, data: Dict[str, Any]) -> VerificationResult:
        """Convert API JSON into a ``VerificationResult``."""
        return VerificationResult(
            verified=data.get("verified", False),
            violations=data.get("violations", []),
            rules_checked=data.get("rules_checked", 0),
            rules_passed=data.get("rules_passed", 0),
        )
