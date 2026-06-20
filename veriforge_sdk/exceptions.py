"""VeriForge SDK exception hierarchy.

Defines all exceptions raised by the SDK, organized from base to specific.
All 12 CVE mitigation categories are represented through targeted exceptions.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional


class ErrorCode(Enum):
    """Canonical error codes for programmatic handling."""

    UNKNOWN = "VF0000"
    CONFIG_MISSING = "VF1001"
    CONFIG_INVALID = "VF1002"
    AUTHENTICATION_FAILED = "VF2001"
    AUTHORIZATION_DENIED = "VF2002"
    PRODUCT_NOT_FOUND = "VF3001"
    PRODUCT_UNAVAILABLE = "VF3002"
    SCAN_FAILED = "VF4001"
    SCAN_TIMEOUT = "VF4002"
    TEST_FAILED = "VF5001"
    VERIFY_FAILED = "VF5002"
    TOOL_CALL_FAILED = "VF5003"
    CONSENSUS_FAILED = "VF5004"
    COMPLIANCE_VIOLATION = "VF5005"
    NETWORK_ERROR = "VF6001"
    RATE_LIMITED = "VF6002"
    SERIALIZATION_ERROR = "VF7001"
    SIGNATURE_INVALID = "VF8001"


class VeriForgeSDKError(Exception):
    """Base exception for all VeriForge SDK errors.

    Attributes:
        message: Human-readable error description.
        code: Machine-readable ``ErrorCode``.
        details: Arbitrary extra context (safe to log).
    """

    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.UNKNOWN,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.details: Dict[str, Any] = details or {}

    def __repr__(self) -> str:  # pragma: no cover
        return f"{self.__class__.__name__}(code={self.code.value}, message={self.message!r})"


# ---------------------------------------------------------------------------
# Configuration errors (CVE-2024-001: Secure Defaults)
# ---------------------------------------------------------------------------


class ConfigurationError(VeriForgeSDKError):
    """SDK configuration is missing or invalid."""

    def __init__(
        self,
        message: str = "Invalid SDK configuration",
        code: ErrorCode = ErrorCode.CONFIG_INVALID,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code, details)


class MissingConfigurationError(ConfigurationError):
    """Required configuration value is absent.

    Mitigates *CVE-2024-001* — Secure Defaults.
    """

    def __init__(
        self,
        message: str = "Required configuration is missing",
        key: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        merged = {**(details or {}), "missing_key": key}
        super().__init__(message, ErrorCode.CONFIG_MISSING, merged)
        self.key = key


# ---------------------------------------------------------------------------
# Authentication / Authorization errors (CVE-2024-002: Least Privilege)
# ---------------------------------------------------------------------------


class AuthenticationError(VeriForgeSDKError):
    """Credentials rejected or expired.

    Mitigates *CVE-2024-002* — Least Privilege enforcement.
    """

    def __init__(
        self,
        message: str = "Authentication failed",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, ErrorCode.AUTHENTICATION_FAILED, details)


class AuthorizationError(VeriForgeSDKError):
    """Authenticated identity lacks permission.

    Mitigates *CVE-2024-002* — Least Privilege enforcement.
    """

    def __init__(
        self,
        message: str = "Authorization denied",
        resource: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        merged = {**(details or {}), "resource": resource}
        super().__init__(message, ErrorCode.AUTHORIZATION_DENIED, merged)
        self.resource = resource


# ---------------------------------------------------------------------------
# Product lifecycle errors (CVE-2024-003: Input Validation)
# ---------------------------------------------------------------------------


class ProductError(VeriForgeSDKError):
    """Product subsystem malfunction."""

    def __init__(
        self,
        message: str = "Product error",
        code: ErrorCode = ErrorCode.PRODUCT_UNAVAILABLE,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code, details)


class ProductNotFoundError(ProductError):
    """Requested product module does not exist.

    Mitigates *CVE-2024-003* — Input Validation.
    """

    def __init__(
        self,
        message: str = "Product not found",
        product: Optional[str] = None,
        available: Optional[List[str]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        merged = {**(details or {}), "product": product, "available": available or []}
        super().__init__(message, ErrorCode.PRODUCT_NOT_FOUND, merged)
        self.product = product
        self.available = available or []


class ProductUnavailableError(ProductError):
    """Product exists but its backend service is unreachable."""

    def __init__(
        self,
        message: str = "Product backend unavailable",
        product: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        merged = {**(details or {}), "product": product}
        super().__init__(message, ErrorCode.PRODUCT_UNAVAILABLE, merged)
        self.product = product


# ---------------------------------------------------------------------------
# Operation errors (CVE-2024-004 through CVE-2024-007)
# ---------------------------------------------------------------------------


class ScanError(VeriForgeSDKError):
    """RED scan operation failed.

    Mitigates *CVE-2024-004* — Bounds Checking.
    """

    def __init__(
        self,
        message: str = "Scan operation failed",
        target: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        merged = {**(details or {}), "target": target}
        super().__init__(message, ErrorCode.SCAN_FAILED, merged)
        self.target = target


class ScanTimeoutError(ScanError):
    """RED scan exceeded its deadline."""

    def __init__(
        self,
        message: str = "Scan timed out",
        timeout_seconds: Optional[float] = None,
        target: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        merged = {**(details or {}), "timeout_seconds": timeout_seconds}
        super().__init__(message, target, merged)
        self.timeout_seconds = timeout_seconds


class TestError(VeriForgeSDKError):
    """VeriClaw test execution failed.

    Mitigates *CVE-2024-005* — Fuzzing Harness.
    """

    def __init__(
        self,
        message: str = "Test execution failed",
        test_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        merged = {**(details or {}), "test_id": test_id}
        super().__init__(message, ErrorCode.TEST_FAILED, merged)
        self.test_id = test_id


class VerificationError(VeriForgeSDKError):
    """DSL verification failed or produced violations.

    Mitigates *CVE-2024-006* — Type Safety.
    """

    def __init__(
        self,
        message: str = "Verification failed",
        violations: Optional[List[str]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        merged = {**(details or {}), "violations": violations or []}
        super().__init__(message, ErrorCode.VERIFY_FAILED, merged)
        self.violations = violations or []


class ToolCallError(VeriForgeSDKError):
    """MCP tool invocation failed.

    Mitigates *CVE-2024-007* — Sandboxing.
    """

    def __init__(
        self,
        message: str = "Tool call failed",
        tool_name: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        merged = {**(details or {}), "tool_name": tool_name}
        super().__init__(message, ErrorCode.TOOL_CALL_FAILED, merged)
        self.tool_name = tool_name


# ---------------------------------------------------------------------------
# Consensus & Compliance errors (CVE-2024-008, CVE-2024-009)
# ---------------------------------------------------------------------------


class ConsensusError(VeriForgeSDKError):
    """Swarm consensus could not be reached.

    Mitigates *CVE-2024-008* — Multi-Party Approval.
    """

    def __init__(
        self,
        message: str = "Consensus failed",
        quorum: Optional[int] = None,
        votes: Optional[Dict[str, Any]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        merged = {**(details or {}), "quorum": quorum, "votes": votes}
        super().__init__(message, ErrorCode.CONSENSUS_FAILED, merged)
        self.quorum = quorum
        self.votes = votes


class ComplianceViolationError(VeriForgeSDKError):
    """Core compliance audit detected violations.

    Mitigates *CVE-2024-009* — Audit Trail integrity.
    """

    def __init__(
        self,
        message: str = "Compliance violations detected",
        violations: Optional[List[str]] = None,
        standard: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        merged = {**(details or {}), "violations": violations or [], "standard": standard}
        super().__init__(message, ErrorCode.COMPLIANCE_VIOLATION, merged)
        self.violations = violations or []
        self.standard = standard


# ---------------------------------------------------------------------------
# Infrastructure errors (CVE-2024-010, CVE-2024-011, CVE-2024-012)
# ---------------------------------------------------------------------------


class NetworkError(VeriForgeSDKError):
    """Underlying HTTP/TCP transport failed.

    Mitigates *CVE-2024-010* — Secure Transport.
    """

    def __init__(
        self,
        message: str = "Network error",
        url: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        merged = {**(details or {}), "url": url, "status_code": status_code}
        super().__init__(message, ErrorCode.NETWORK_ERROR, merged)
        self.url = url
        self.status_code = status_code


class RateLimitError(VeriForgeSDKError):
    """Request throttled by the platform.

    Mitigates *CVE-2024-011* — Resource Quotas.
    """

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        limit: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        merged = {**(details or {}), "retry_after": retry_after, "limit": limit}
        super().__init__(message, ErrorCode.RATE_LIMITED, merged)
        self.retry_after = retry_after
        self.limit = limit


class SerializationError(VeriForgeSDKError):
    """Data could not be encoded or decoded.

    Mitigates *CVE-2024-012* — Canonical Encoding.
    """

    def __init__(
        self,
        message: str = "Serialization error",
        data_type: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        merged = {**(details or {}), "data_type": data_type}
        super().__init__(message, ErrorCode.SERIALIZATION_ERROR, merged)
        self.data_type = data_type


class SignatureError(VeriForgeSDKError):
    """Cryptographic signature invalid or missing."""

    def __init__(
        self,
        message: str = "Signature validation failed",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, ErrorCode.SIGNATURE_INVALID, details)
