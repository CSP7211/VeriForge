"""Core — Compliance auditing and result signing.

Performs compliance checks against standards (SOC2, GDPR, etc.)
and provides cryptographic signing / verification of results.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict, List, Optional

from ..config import SDKConfig
from ..exceptions import ComplianceViolationError, SignatureError
from ..models import (
    ComplianceResult,
    ControlResult,
    Grade,
    HealthStatus,
    ScanResult,
    Severity,
    SignedPayload,
)
from .base import BaseProductAPI


class CoreComplianceAPI(BaseProductAPI):
    """Interface to the Core compliance and signing engine.

    Example:
        >>> result = client.core.audit_compliance("SOC2")
        >>> print(f"Score: {result.score}%")
        >>> signed = client.core.sign_result(result)
        >>> assert client.core.verify_signature(signed)
    """

    PRODUCT_NAME = "core"

    def __init__(self, config: SDKConfig) -> None:
        super().__init__(config)
        self._local_mode = config.api_key is None
        self._signing_key = config.api_key or "local-dev-key"

    # ------------------------------------------------------------------
    # Compliance
    # ------------------------------------------------------------------

    def audit_compliance(
        self,
        standard: str,
        target: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> ComplianceResult:
        """Run a compliance audit against a standard.

        Args:
            standard: The compliance standard (``SOC2``, ``GDPR``, ``HIPAA``, ``ISO27001``).
            target: Optional path or identifier to audit.
            options: Extra audit parameters.

        Raises:
            ComplianceViolationError: If critical violations are found.

        Returns:
            A ``ComplianceResult`` with per-control results and overall score.
        """
        if self._local_mode:
            return self._local_audit(standard, target)

        payload: Dict[str, Any] = {
            "standard": standard,
            "target": target,
            "options": options or {},
        }
        try:
            resp = self._request("POST", "/audit", json_data=payload)
        except Exception as exc:
            raise ComplianceViolationError(
                f"Audit failed: {exc}",
                standard=standard,
            ) from exc

        return self._parse_compliance_response(resp)

    def get_standards(self) -> List[str]:
        """List supported compliance standards.

        Returns:
            List of standard identifiers.
        """
        return self._request("GET", "/standards")

    # ------------------------------------------------------------------
    # Signing & Verification
    # ------------------------------------------------------------------

    def sign_result(self, result: Any) -> SignedPayload:
        """Cryptographically sign a result object.

        Uses HMAC-SHA256 with the configured API key as the secret.

        Args:
            result: Any SDK result object (``ScanResult``, ``TestResult``, etc.).

        Returns:
            A ``SignedPayload`` containing the serialized data and signature.
        """
        payload = self._serialize(result)
        timestamp = time.time()
        sig_input = f"{payload}.{timestamp}"
        signature = hmac.new(
            self._signing_key.encode(),
            sig_input.encode(),
            hashlib.sha256,
        ).hexdigest()

        return SignedPayload(
            payload=payload,
            signature=signature,
            algorithm="HMAC-SHA256",
            timestamp=timestamp,
        )

    def verify_signature(self, signed: SignedPayload) -> bool:
        """Verify the signature of a signed payload.

        Args:
            signed: The ``SignedPayload`` to verify.

        Returns:
            ``True`` if the signature is valid, ``False`` otherwise.
        """
        if signed.algorithm != "HMAC-SHA256":
            raise SignatureError(f"Unsupported algorithm: {signed.algorithm}")

        sig_input = f"{signed.payload}.{signed.timestamp}"
        expected = hmac.new(
            self._signing_key.encode(),
            sig_input.encode(),
            hashlib.sha256,
        ).hexdigest()

        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(expected, signed.signature)

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health(self) -> HealthStatus:
        """Check the health of the Core platform.

        Returns:
            A ``HealthStatus`` with per-product health.
        """
        if self._local_mode:
            return HealthStatus(
                status="ok",
                products={
                    "red": "ok",
                    "vericlaw": "ok",
                    "dsl": "ok",
                    "mcp": "ok",
                    "swarm": "ok",
                    "core": "ok",
                },
                version="1.0.0-local",
                uptime_seconds=3600.0,
            )

        resp = self._request("GET", "/health")
        return HealthStatus(
            status=resp.get("status", "unknown"),
            products=resp.get("products", {}),
            version=resp.get("version", "unknown"),
            uptime_seconds=resp.get("uptime_seconds", 0.0),
        )

    # ------------------------------------------------------------------
    # Local fallback
    # ------------------------------------------------------------------

    def _local_audit(
        self,
        standard: str,
        target: Optional[str],
    ) -> ComplianceResult:
        """Perform a simulated local audit."""
        controls = [
            ControlResult(
                control_id="AC-1",
                title="Access Control Policy",
                passed=True,
                evidence="Policy document reviewed",
            ),
            ControlResult(
                control_id="AC-2",
                title="Account Management",
                passed=True,
                evidence="User accounts audited",
            ),
            ControlResult(
                control_id="AU-1",
                title="Audit Policy",
                passed=True,
                evidence="Logging configured",
            ),
            ControlResult(
                control_id="CM-1",
                title="Configuration Management",
                passed=False,
                evidence="Some configs not in version control",
                remediation="Add all config files to VCS",
            ),
            ControlResult(
                control_id="IA-1",
                title="Identification and Authentication",
                passed=True,
                evidence="MFA enabled for all users",
            ),
        ]
        passed = sum(1 for c in controls if c.passed)
        score = (passed / len(controls)) * 100 if controls else 0.0

        return ComplianceResult(
            standard=standard,
            compliant=score >= 80.0,
            controls=controls,
            score=round(score, 1),
            auditor_signature="",
        )

    def _parse_compliance_response(self, data: Dict[str, Any]) -> ComplianceResult:
        """Convert API JSON into a ``ComplianceResult``."""
        controls = [
            ControlResult(
                control_id=c.get("control_id", ""),
                title=c.get("title", ""),
                passed=c.get("passed", False),
                evidence=c.get("evidence", ""),
                remediation=c.get("remediation", ""),
            )
            for c in data.get("controls", [])
        ]
        return ComplianceResult(
            standard=data.get("standard", ""),
            compliant=data.get("compliant", False),
            controls=controls,
            score=data.get("score", 0.0),
            auditor_signature=data.get("auditor_signature", ""),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _serialize(result: Any) -> str:
        """Serialize a result object to a canonical JSON string."""
        import enum

        def convert(obj: Any) -> Any:
            if isinstance(obj, enum.Enum):
                return obj.value
            if hasattr(obj, "__dataclass_fields__"):
                fields = obj.__dataclass_fields__
                return {k: convert(getattr(obj, k)) for k in fields}
            if isinstance(obj, list):
                return [convert(item) for item in obj]
            if isinstance(obj, dict):
                return {k: convert(v) for k, v in obj.items()}
            return obj

        if hasattr(result, "__dataclass_fields__"):
            data = {}
            for field_name in result.__dataclass_fields__:
                data[field_name] = convert(getattr(result, field_name))
            return json.dumps(data, sort_keys=True, separators=(",", ":"))
        return json.dumps(convert(result), sort_keys=True, separators=(",", ":"))
