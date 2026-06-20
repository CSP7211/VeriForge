"""VeriForge SDK — Unified Developer Kit.

A single SDK providing type-safe, authenticated access to all seven
VeriForge product subsystems:

    RED         — Automated security code scanner
    VeriClaw    — Test generation & execution harness
    DSL Verify  — Domain-specific language rule checker
    MCP Tools   — Model Context Protocol tool sandbox
    Swarm       — Distributed multi-party consensus
    Core        — Compliance auditing & result signing

Quick Start::

    from veriforge_sdk import VeriForgeClient
    client = VeriForgeClient()
    result = client.red.scan("./src")
    print(result.grade.value)

The SDK requires Python 3.9+ and has zero mandatory heavy dependencies.
"""

__version__ = "1.0.0"
__author__ = "VeriForge Engineering"
__license__ = "MIT"

from .client import VeriForgeClient
from .config import SDKConfig
from .exceptions import (
    AuthenticationError,
    AuthorizationError,
    ComplianceViolationError,
    ConfigurationError,
    ConsensusError,
    ErrorCode,
    MissingConfigurationError,
    NetworkError,
    ProductError,
    ProductNotFoundError,
    ProductUnavailableError,
    RateLimitError,
    ScanError,
    ScanTimeoutError,
    SerializationError,
    SignatureError,
    TestError,
    ToolCallError,
    VeriForgeSDKError,
    VerificationError,
)
from .models import (
    ComplianceResult,
    Confidence,
    ConsensusResult,
    ControlResult,
    Finding,
    Grade,
    HealthStatus,
    ScanResult,
    Severity,
    SignedPayload,
    Status,
    TestResult,
    ToolCallResult,
    VerificationResult,
)

__all__ = [
    # Client
    "VeriForgeClient",
    # Config
    "SDKConfig",
    # Exceptions
    "VeriForgeSDKError",
    "ErrorCode",
    "ConfigurationError",
    "MissingConfigurationError",
    "AuthenticationError",
    "AuthorizationError",
    "ProductError",
    "ProductNotFoundError",
    "ProductUnavailableError",
    "ScanError",
    "ScanTimeoutError",
    "TestError",
    "VerificationError",
    "ToolCallError",
    "ConsensusError",
    "ComplianceViolationError",
    "NetworkError",
    "RateLimitError",
    "SerializationError",
    "SignatureError",
    # Models
    "Severity",
    "Grade",
    "Status",
    "Confidence",
    "Finding",
    "ScanResult",
    "TestResult",
    "VerificationResult",
    "ToolCallResult",
    "ConsensusResult",
    "ControlResult",
    "ComplianceResult",
    "HealthStatus",
    "SignedPayload",
    # Version
    "__version__",
]
