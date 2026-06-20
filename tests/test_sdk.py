"""Comprehensive test suite for the VeriForge SDK.

Covers configuration, client initialization, all product APIs, error
handling, models, and cryptographic signing.

Run with::

    pytest tests/test_sdk.py -v
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from veriforge_sdk import (
    ComplianceResult,
    ConsensusResult,
    ControlResult,
    ErrorCode,
    Finding,
    Grade,
    HealthStatus,
    SDKConfig,
    ScanResult,
    Severity,
    SignedPayload,
    TestResult,
    ToolCallResult,
    VeriForgeClient,
    VeriForgeSDKError,
    VerificationResult,
)
from veriforge_sdk.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ComplianceViolationError,
    ConfigurationError,
    ConsensusError,
    MissingConfigurationError,
    NetworkError,
    ProductNotFoundError,
    ProductUnavailableError,
    RateLimitError,
    ScanError,
    ScanTimeoutError,
    SerializationError,
    SignatureError,
    TestError,
    ToolCallError,
    VerificationError,
)


# ============================================================================
# Configuration Tests
# ============================================================================


class TestSDKConfig:
    """Test suite for ``SDKConfig``."""

    def test_default_values(self) -> None:
        """Default config has secure built-in values."""
        config = SDKConfig.default()
        assert config.api_key is None
        assert config.base_url == "https://api.veriforge.io/v1"
        assert config.timeout == 30.0
        assert config.max_retries == 3
        assert config.verify_ssl is True
        assert config.log_level == "WARNING"
        assert config.disable_telemetry is False

    def test_explicit_config(self) -> None:
        """Config fields can be set explicitly."""
        config = SDKConfig(
            api_key="test-key",
            base_url="https://custom.example.com",
            timeout=60.0,
            max_retries=5,
            verify_ssl=False,
            project_id="proj-123",
            org_id="org-456",
        )
        assert config.api_key == "test-key"
        assert config.base_url == "https://custom.example.com"
        assert config.timeout == 60.0
        assert config.max_retries == 5
        assert config.verify_ssl is False
        assert config.project_id == "proj-123"
        assert config.org_id == "org-456"

    def test_headers_contains_auth(self) -> None:
        """"`headers()`` includes the Authorization bearer token."""
        config = SDKConfig(api_key="secret-token")
        headers = config.headers()
        assert headers["Authorization"] == "Bearer secret-token"
        assert headers["Content-Type"] == "application/json"

    def test_headers_with_project_and_org(self) -> None:
        """"`headers()`` includes project and org IDs when set."""
        config = SDKConfig(
            api_key="key",
            project_id="proj-abc",
            org_id="org-xyz",
        )
        headers = config.headers()
        assert headers["X-Project-ID"] == "proj-abc"
        assert headers["X-Org-ID"] == "org-xyz"

    def test_headers_user_agent(self) -> None:
        """"`headers()`` includes the default user-agent."""
        config = SDKConfig(api_key="key")
        headers = config.headers()
        assert "veriforge-sdk/1.0" in headers["User-Agent"]

    def test_headers_custom_user_agent(self) -> None:
        """"`headers()`` appends custom user-agent suffix."""
        config = SDKConfig(api_key="key", user_agent="myapp/2.0")
        headers = config.headers()
        assert "myapp/2.0" in headers["User-Agent"]

    def test_merge_creates_new_instance(self) -> None:
        """"`merge()`` returns a new config without mutating the original."""
        config = SDKConfig(api_key="original")
        new_config = config.merge(timeout=99)
        assert new_config is not config
        assert config.timeout == 30.0  # unchanged
        assert new_config.timeout == 99
        assert new_config.api_key == "original"

    def test_from_env_missing_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """"`from_env()`` raises when VERIFORGE_API_KEY is missing."""
        monkeypatch.delenv("VERIFORGE_API_KEY", raising=False)
        with pytest.raises(MissingConfigurationError) as exc_info:
            SDKConfig.from_env()
        assert exc_info.value.key == "VERIFORGE_API_KEY"
        assert exc_info.value.code == ErrorCode.CONFIG_MISSING

    def test_from_env_reads_all_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """"`from_env()`` populates config from environment variables."""
        monkeypatch.setenv("VERIFORGE_API_KEY", "env-key")
        monkeypatch.setenv("VERIFORGE_BASE_URL", "https://env.example.com")
        monkeypatch.setenv("VERIFORGE_TIMEOUT", "45")
        monkeypatch.setenv("VERIFORGE_MAX_RETRIES", "5")
        monkeypatch.setenv("VERIFORGE_VERIFY_SSL", "0")
        monkeypatch.setenv("VERIFORGE_LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("VERIFORGE_PROJECT_ID", "env-proj")
        monkeypatch.setenv("VERIFORGE_ORG_ID", "env-org")
        monkeypatch.setenv("VERIFORGE_DISABLE_TELEMETRY", "1")

        config = SDKConfig.from_env()
        assert config.api_key == "env-key"
        assert config.base_url == "https://env.example.com"
        assert config.timeout == 45.0
        assert config.max_retries == 5
        assert config.verify_ssl is False
        assert config.log_level == "DEBUG"
        assert config.project_id == "env-proj"
        assert config.org_id == "env-org"
        assert config.disable_telemetry is True


# ============================================================================
# Client Tests
# ============================================================================


class TestVeriForgeClient:
    """Test suite for ``VeriForgeClient``."""

    def test_init_with_default_config(self) -> None:
        """Client initializes with default config in local mode."""
        client = VeriForgeClient()
        assert client.config.api_key is None
        assert client.config.base_url == "https://api.veriforge.io/v1"

    def test_init_with_custom_config(self) -> None:
        """Client initializes with an explicit config."""
        config = SDKConfig(api_key="test-key", timeout=10)
        client = VeriForgeClient(config=config)
        assert client.config.api_key == "test-key"
        assert client.config.timeout == 10

    def test_all_product_accessors(self) -> None:
        """All six product accessors return non-None API instances."""
        client = VeriForgeClient()
        assert client.red is not None
        assert client.vericlaw is not None
        assert client.dsl is not None
        assert client.mcp is not None
        assert client.swarm is not None
        assert client.core is not None

    def test_list_products(self) -> None:
        """"`list_products()`` returns the expected product map."""
        client = VeriForgeClient()
        products = client.list_products()
        assert "red" in products
        assert "vericlaw" in products
        assert "dsl" in products
        assert "mcp" in products
        assert "swarm" in products
        assert "core" in products

    def test_product_accessor_by_name(self) -> None:
        """"`product()`` returns the correct product API by name."""
        client = VeriForgeClient()
        assert client.product("red") is client.red
        assert client.product("vericlaw") is client.vericlaw
        assert client.product("core") is client.core

    def test_product_not_found_raises(self) -> None:
        """"`product()`` raises for unknown product names."""
        client = VeriForgeClient()
        with pytest.raises(ProductNotFoundError) as exc_info:
            client.product("nonexistent")
        assert exc_info.value.product == "nonexistent"
        assert "red" in exc_info.value.available

    def test_with_config_returns_new_client(self) -> None:
        """"`with_config()`` returns a new client without mutating the original."""
        client = VeriForgeClient()
        new_client = client.with_config(timeout=99)
        assert new_client is not client
        assert client.config.timeout == 30.0
        assert new_client.config.timeout == 99

    def test_context_manager(self) -> None:
        """Client works as a context manager."""
        with VeriForgeClient() as client:
            assert client.red is not None

    def test_repr(self) -> None:
        """Client repr is informative."""
        client = VeriForgeClient()
        r = repr(client)
        assert "VeriForgeClient" in r
        assert "local_mode" in r


# ============================================================================
# RED Scan Tests
# ============================================================================


class TestRedScan:
    """Test suite for RED code scanning."""

    def test_scan_nonexistent_target_raises(self) -> None:
        """Scanning a non-existent path raises ScanError."""
        client = VeriForgeClient()
        with pytest.raises(ScanError) as exc_info:
            client.red.scan("/nonexistent/path/that/does/not/exist")
        assert exc_info.value.target is not None

    def test_scan_finds_issues_in_temp_file(self) -> None:
        """Scanning a file with known issues produces findings."""
        client = VeriForgeClient()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("password = 'hunter2'\n")
            f.write("result = eval(user_input)\n")
            temp_path = f.name

        try:
            result = client.red.scan(temp_path)
            assert isinstance(result, ScanResult)
            assert result.scan_id
            assert result.target == temp_path
            assert len(result.findings) > 0
            assert any("password" in f.title.lower() for f in result.findings)
            assert any("eval" in f.title.lower() for f in result.findings)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_scan_result_grade(self) -> None:
        """ScanResult grade is computed from findings."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("# clean file\n")
            f.write("x = 1 + 2\n")
            temp_path = f.name

        client = VeriForgeClient()
        try:
            result = client.red.scan(temp_path)
            assert isinstance(result.grade, Grade)
            assert result.grade in {Grade.A, Grade.A_PLUS, Grade.B}
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_scan_result_fingerprint(self) -> None:
        """ScanResult fingerprint is a hex string."""
        result = ScanResult(
            scan_id="test",
            target="/tmp",
            grade=Grade.A,
            findings=[],
        )
        assert len(result.fingerprint) == 16
        assert all(c in "0123456789abcdef" for c in result.fingerprint)

    def test_list_rules(self) -> None:
        """"`list_rules()`` returns the available rule set."""
        client = VeriForgeClient()
        rules = client.red.list_rules()
        assert isinstance(rules, list)
        assert len(rules) > 0
        assert "id" in rules[0]
        assert "name" in rules[0]


# ============================================================================
# VeriClaw Tests
# ============================================================================


class TestVeriClaw:
    """Test suite for VeriClaw testing."""

    def test_basic_test(self) -> None:
        """Basic test execution returns a valid TestResult."""
        client = VeriForgeClient()
        result = client.vericlaw.test("./tests", coverage=True)
        assert isinstance(result, TestResult)
        assert result.total > 0
        assert result.passed + result.failed + result.skipped == result.total
        assert result.coverage_percent >= 0.0

    def test_test_result_ok(self) -> None:
        """"`TestResult.ok`` is True when no failures."""
        result = TestResult(test_id="t1", passed=10, failed=0, skipped=0)
        assert result.ok is True
        assert result.success_rate == 1.0

    def test_test_result_not_ok(self) -> None:
        """"`TestResult.ok`` is False when failures exist."""
        result = TestResult(test_id="t1", passed=5, failed=3, skipped=0)
        assert result.ok is False
        assert result.success_rate == 5.0 / 8.0


# ============================================================================
# DSL Verify Tests
# ============================================================================


class TestDSLVerify:
    """Test suite for DSL verification."""

    def test_verify_finds_violations(self) -> None:
        """Verifying an insecure config produces violations."""
        client = VeriForgeClient()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("database:\n")
            f.write("  password: 'secret123'\n")
            f.write("  url: http://insecure.example.com\n")
            temp_path = f.name

        try:
            result = client.dsl.verify(temp_path, rules="security.rules")
            assert isinstance(result, VerificationResult)
            assert not result.verified
            assert len(result.violations) > 0
            assert result.rules_checked > 0
            assert result.rules_failed > 0
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_verify_clean_config(self) -> None:
        """Verifying a clean config passes."""
        client = VeriForgeClient()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("app:\n")
            f.write("  name: MyApp\n")
            f.write("  debug: false\n")
            temp_path = f.name

        try:
            result = client.dsl.verify(temp_path, rules="security.rules")
            assert isinstance(result, VerificationResult)
            assert result.verified is True
            assert len(result.violations) == 0
        finally:
            Path(temp_path).unlink(missing_ok=True)


# ============================================================================
# MCP Tools Tests
# ============================================================================


class TestMCPTools:
    """Test suite for MCP tool invocation."""

    def test_call_git_status(self) -> None:
        """"`call_tool()`` returns a valid ToolCallResult."""
        client = VeriForgeClient()
        result = client.mcp.call_tool("git.status", {"path": "/repo"})
        assert isinstance(result, ToolCallResult)
        assert result.tool_name == "git.status"
        assert result.exit_code == 0
        assert result.success is True
        assert "branch" in result.output or "clean" in result.stdout.lower()

    def test_list_tools(self) -> None:
        """"`list_tools()`` returns available tools."""
        client = VeriForgeClient()
        tools = client.mcp.list_tools()
        assert isinstance(tools, list)


# ============================================================================
# Swarm Tests
# ============================================================================


class TestSwarm:
    """Test suite for Swarm consensus."""

    def test_consensus_reaches_agreement(self) -> None:
        """Consensus with sufficient quorum succeeds."""
        client = VeriForgeClient()
        result = client.swarm.consensus(
            topic="test-topic",
            proposal="Test proposal",
            quorum=3,
        )
        assert isinstance(result, ConsensusResult)
        assert result.reached is True
        assert result.outcome == "approve"
        assert result.agreement_ratio >= 0.6
        assert len(result.votes) == 5

    def test_consensus_insufficient_quorum(self) -> None:
        """Consensus with very high quorum may not be reached."""
        client = VeriForgeClient()
        result = client.swarm.consensus(
            topic="test-topic",
            proposal="Test proposal",
            quorum=10,  # More than available voters
        )
        assert isinstance(result, ConsensusResult)
        # Local mode has 5 voters, so quorum=10 should fail
        assert result.reached is False


# ============================================================================
# Core Compliance Tests
# ============================================================================


class TestCoreCompliance:
    """Test suite for Core compliance and signing."""

    def test_audit_compliance(self) -> None:
        """Audit returns a valid ComplianceResult."""
        client = VeriForgeClient()
        result = client.core.audit_compliance("SOC2")
        assert isinstance(result, ComplianceResult)
        assert result.standard == "SOC2"
        assert result.score >= 0.0
        assert result.score <= 100.0
        assert len(result.controls) > 0

    def test_compliance_controls(self) -> None:
        """Control results have correct structure."""
        client = VeriForgeClient()
        result = client.core.audit_compliance("ISO27001")
        for ctrl in result.controls:
            assert ctrl.control_id
            assert ctrl.title
            # Evidence should be present for passed controls
            if ctrl.passed:
                assert ctrl.evidence

    def test_sign_and_verify(self) -> None:
        """Signing produces a verifiable payload."""
        client = VeriForgeClient()
        scan_result = client.red.scan("./tests")  # local scan
        signed = client.core.sign_result(scan_result)
        assert isinstance(signed, SignedPayload)
        assert signed.signature
        assert signed.algorithm == "HMAC-SHA256"
        assert signed.timestamp > 0
        assert client.core.verify_signature(signed) is True

    def test_verify_signature_invalid(self) -> None:
        """Tampered signature fails verification."""
        client = VeriForgeClient()
        signed = client.core.sign_result(
            ScanResult(scan_id="x", target="/tmp", grade=Grade.A)
        )
        # Tamper with the payload
        tampered = SignedPayload(
            payload="tampered",
            signature=signed.signature,
            algorithm=signed.algorithm,
            timestamp=signed.timestamp,
        )
        assert client.core.verify_signature(tampered) is False

    def test_verify_signature_unsupported_algorithm(self) -> None:
        """Unsupported algorithm raises SignatureError."""
        client = VeriForgeClient()
        signed = SignedPayload(
            payload='{}',
            signature="abc",
            algorithm="RSA-SHA256",
            timestamp=0,
        )
        with pytest.raises(SignatureError):
            client.core.verify_signature(signed)


# ============================================================================
# Health Tests
# ============================================================================


class TestHealth:
    """Test suite for health checks."""

    def test_health_returns_status(self) -> None:
        """"`health()`` returns a HealthStatus with all products."""
        client = VeriForgeClient()
        health = client.health()
        assert isinstance(health, HealthStatus)
        assert health.status in ("ok", "degraded", "down")
        assert len(health.products) == 6
        for product_name in ["red", "vericlaw", "dsl", "mcp", "swarm", "core"]:
            assert product_name in health.products

    def test_health_healthy(self) -> None:
        """"`HealthStatus.healthy`` is True when status is ok."""
        hs = HealthStatus(status="ok")
        assert hs.healthy is True
        hs2 = HealthStatus(status="degraded")
        assert hs2.healthy is False


# ============================================================================
# Exception Tests
# ============================================================================


class TestExceptions:
    """Test suite for the exception hierarchy."""

    def test_base_error_attributes(self) -> None:
        """"`VeriForgeSDKError`` has message, code, and details."""
        err = VeriForgeSDKError("test error", code=ErrorCode.SCAN_FAILED)
        assert err.message == "test error"
        assert err.code == ErrorCode.SCAN_FAILED
        assert err.details == {}

    def test_base_error_with_details(self) -> None:
        """"`VeriForgeSDKError`` accepts optional details."""
        err = VeriForgeSDKError("test", details={"key": "value"})
        assert err.details == {"key": "value"}

    def test_missing_configuration_error(self) -> None:
        """"`MissingConfigurationError`` captures the missing key."""
        err = MissingConfigurationError("Missing API key", key="VERIFORGE_API_KEY")
        assert err.key == "VERIFORGE_API_KEY"
        assert err.code == ErrorCode.CONFIG_MISSING

    def test_product_not_found_error(self) -> None:
        """"`ProductNotFoundError`` captures product name and available list."""
        err = ProductNotFoundError(
            "Not found", product="foo", available=["red", "core"]
        )
        assert err.product == "foo"
        assert err.available == ["red", "core"]

    def test_scan_error_with_target(self) -> None:
        """"`ScanError`` captures the target path."""
        err = ScanError("Scan failed", target="/tmp/code")
        assert err.target == "/tmp/code"
        assert err.code == ErrorCode.SCAN_FAILED

    def test_scan_timeout_error(self) -> None:
        """"`ScanTimeoutError`` captures timeout value."""
        err = ScanTimeoutError("Timed out", timeout_seconds=30.0, target="/tmp")
        assert err.timeout_seconds == 30.0
        assert err.target == "/tmp"

    def test_rate_limit_error(self) -> None:
        """"`RateLimitError`` captures retry-after value."""
        err = RateLimitError("Rate limited", retry_after=60, limit=100)
        assert err.retry_after == 60
        assert err.limit == 100

    def test_network_error_with_status(self) -> None:
        """"`NetworkError`` captures URL and status code."""
        err = NetworkError("Server error", url="https://api.example.com", status_code=503)
        assert err.url == "https://api.example.com"
        assert err.status_code == 503

    def test_error_is_instance_of_base(self) -> None:
        """All specific errors are instances of the base."""
        errors = [
            ConfigurationError("cfg"),
            AuthenticationError("auth"),
            ProductNotFoundError("prod", product="x"),
            ScanError("scan"),
            TestError("test"),
            VerificationError("verify"),
            ToolCallError("tool"),
            ConsensusError("consensus"),
            ComplianceViolationError("compliance"),
            NetworkError("net"),
            RateLimitError("rate"),
            SerializationError("serial"),
        ]
        for err in errors:
            assert isinstance(err, VeriForgeSDKError)


# ============================================================================
# Model Tests
# ============================================================================


class TestModels:
    """Test suite for data models."""

    def test_finding_is_critical(self) -> None:
        """"`Finding.is_critical`` is True for CRITICAL severity."""
        f = Finding(title="X", severity=Severity.CRITICAL)
        assert f.is_critical is True
        f2 = Finding(title="Y", severity=Severity.HIGH)
        assert f2.is_critical is False

    def test_finding_immutable(self) -> None:
        """"`Finding`` is a frozen dataclass."""
        f = Finding(title="X")
        with pytest.raises(Exception):
            f.title = "Y"  # type: ignore[misc]

    def test_scan_result_count_by_severity(self) -> None:
        """"`ScanResult.count_by_severity`` returns correct counts."""
        findings = [
            Finding(title="A", severity=Severity.CRITICAL),
            Finding(title="B", severity=Severity.HIGH),
            Finding(title="C", severity=Severity.HIGH),
        ]
        result = ScanResult(
            scan_id="s1",
            target="/tmp",
            grade=Grade.D,
            findings=findings,
        )
        counts = result.count_by_severity
        assert counts[Severity.CRITICAL] == 1
        assert counts[Severity.HIGH] == 2
        assert counts[Severity.MEDIUM] == 0

    def test_scan_result_has_critical(self) -> None:
        """"`ScanResult.has_critical`` reflects findings."""
        result1 = ScanResult(
            scan_id="s1", target="/tmp", grade=Grade.F,
            findings=[Finding(title="X", severity=Severity.CRITICAL)],
        )
        assert result1.has_critical is True

        result2 = ScanResult(
            scan_id="s2", target="/tmp", grade=Grade.A,
            findings=[Finding(title="Y", severity=Severity.LOW)],
        )
        assert result2.has_critical is False

    def test_grade_values(self) -> None:
        """Grade enum has expected values."""
        assert Grade.A_PLUS.value == "A+"
        assert Grade.A.value == "A"
        assert Grade.F.value == "F"

    def test_severity_values(self) -> None:
        """Severity enum has expected values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.INFO.value == "info"

    def test_control_result_defaults(self) -> None:
        """"`ControlResult`` defaults are sensible."""
        ctrl = ControlResult(control_id="AC-1")
        assert ctrl.title == ""
        assert ctrl.passed is False
        assert ctrl.evidence == ""
        assert ctrl.remediation == ""


# ============================================================================
# Integration Tests
# ============================================================================


class TestIntegration:
    """End-to-end integration tests."""

    def test_full_workflow(self) -> None:
        """A complete workflow using multiple products."""
        client = VeriForgeClient()

        # 1. Scan code
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("eval(user_input)\n")
            f.write("password = 'secret'\n")
            temp_path = f.name

        try:
            scan = client.red.scan(temp_path)
            assert isinstance(scan, ScanResult)
        finally:
            Path(temp_path).unlink(missing_ok=True)

        # 2. Run tests
        test = client.vericlaw.test("./src")
        assert isinstance(test, TestResult)

        # 3. Verify config
        verify = client.dsl.verify("config.yaml", rules="rules")
        assert isinstance(verify, VerificationResult)

        # 4. Call tool
        tool = client.mcp.call_tool("git.status")
        assert isinstance(tool, ToolCallResult)

        # 5. Consensus
        consensus = client.swarm.consensus("topic", "proposal", quorum=3)
        assert isinstance(consensus, ConsensusResult)

        # 6. Compliance
        compliance = client.core.audit_compliance("SOC2")
        assert isinstance(compliance, ComplianceResult)

        # 7. Sign scan result
        signed = client.core.sign_result(scan)
        assert isinstance(signed, SignedPayload)
        assert client.core.verify_signature(signed)

        # 8. Health check
        health = client.health()
        assert isinstance(health, HealthStatus)

    def test_client_dynamic_access(self) -> None:
        """"`product()`` provides dynamic access to all modules."""
        client = VeriForgeClient()
        for name in client.list_products():
            api = client.product(name)
            assert api is not None
