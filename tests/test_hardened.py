"""
test_hardened.py — Security regression tests for VeriForge v0.4.0-hardened.

Covers:
  * No-eval guarantee
  * HMAC signature verification
  * Immutable audit chain
  * JWT auth and RBAC
  * Rate limiting
  * Path sanitization
  * Obfuscation detection
  * Compliance auditing
  * Safe JSON serialization
  * Configuration validation

Run with: pytest tests/test_hardened.py -v
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Any

import pytest

from veriforge.engine import VeriForgeEngine, VerificationResult, EvalGuardError, TimeoutError
from veriforge.config import SecureConfig, ConfigurationError
from veriforge.auth import AuthManager, JWTError, RBACError, RateLimitError, Role
from veriforge.audit import ImmutableAuditLog, AuditEntry
from veriforge.semantic import SemanticAnalyzer, ObfuscationFinding
from veriforge.compliance import SOC2Auditor, ISO27001Auditor, PCIDSSAuditor, ComplianceResult
from veriforge.agent import AgentVerifier, AgentAuthError
from veriforge.ide import IDEVerifier, PathSanitizationError
from veriforge.report import ReportGenerator, SafeJSONEncoder


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def secret() -> str:
    return "test-secret-key-32-bytes-long!!"


@pytest.fixture
def config(secret: str) -> SecureConfig:
    return SecureConfig(
        VERIFORGE_SECRET=secret,
        VERIFORGE_JWT_SECRET=secret,
        VERIFORGE_AUDIT_SECRET=secret,
    )


@pytest.fixture
def engine(secret: str, config: SecureConfig) -> VeriForgeEngine:
    return VeriForgeEngine(config=config, secret=secret, timeout_seconds=5)


@pytest.fixture
def auth(secret: str) -> AuthManager:
    return AuthManager(jwt_secret=secret, rate_limit_max=5, rate_limit_window=60)


@pytest.fixture
def audit(secret: str) -> ImmutableAuditLog:
    return ImmutableAuditLog(secret=secret)


@pytest.fixture
def analyzer() -> SemanticAnalyzer:
    return SemanticAnalyzer()


# =============================================================================
# 1. Engine — No-Eval Guarantee
# =============================================================================


class TestNoEvalGuarantee:
    """CVE-2024-XXXX: Ensure eval()/exec() are NEVER called."""

    def test_safe_code_verifies_cleanly(self, engine: VeriForgeEngine) -> None:
        source = "x = 1 + 2\ny = x * 3\n"
        result = engine.verify_code(source)
        assert result.verified is True
        assert len(result.findings) == 0

    def test_eval_call_blocked(self, engine: VeriForgeEngine) -> None:
        source = "eval('1 + 1')\n"
        result = engine.verify_code(source)
        assert result.verified is False
        assert any("eval" in f for f in result.findings)

    def test_exec_call_blocked(self, engine: VeriForgeEngine) -> None:
        source = "exec('print(1)')\n"
        result = engine.verify_code(source)
        assert result.verified is False
        assert any("exec" in f for f in result.findings)

    def test_nested_eval_blocked(self, engine: VeriForgeEngine) -> None:
        source = "getattr(__builtins__, 'eval')('1+1')\n"
        result = engine.verify_code(source)
        assert result.verified is False

    def test_no_eval_in_engine_source(self) -> None:
        """Meta-test: the engine source itself must not contain eval()."""
        import inspect
        import veriforge.engine as engine_mod

        source = inspect.getsource(engine_mod)
        assert " eval(" not in source
        assert " exec(" not in source


# =============================================================================
# 2. Engine — HMAC Signatures
# =============================================================================


class TestHMACSignatures:
    """Verify that every result is cryptographically signed."""

    def test_result_has_signature(self, engine: VeriForgeEngine) -> None:
        result = engine.verify_code("x = 1\n")
        assert result.hmac_signature != ""
        assert len(result.hmac_signature) == 64  # SHA-256 hex

    def test_signature_verifies(self, engine: VeriForgeEngine, secret: str) -> None:
        result = engine.verify_code("x = 1\n")
        assert result.verify_hmac(secret) is True

    def test_signature_fails_with_wrong_secret(self, engine: VeriForgeEngine) -> None:
        result = engine.verify_code("x = 1\n")
        assert result.verify_hmac("wrong-secret") is False

    def test_tampered_result_fails_hmac(self, engine: VeriForgeEngine, secret: str) -> None:
        result = engine.verify_code("x = 1\n")
        # Create a fake result with the same signature but different data
        fake = VerificationResult(
            source="tampered",
            verified=True,
            findings=(),
            hmac_signature=result.hmac_signature,
            timestamp=result.timestamp,
            execution_time_ms=result.execution_time_ms,
        )
        assert fake.verify_hmac(secret) is False


# =============================================================================
# 3. Engine — Frozen/Immutable Results
# =============================================================================


class TestFrozenResults:
    """VerificationResult must be immutable after creation."""

    def test_result_is_frozen(self, engine: VeriForgeEngine) -> None:
        result = engine.verify_code("x = 1\n")
        with pytest.raises(AttributeError):
            result.verified = False  # type: ignore[misc]

    def test_findings_are_tuple(self, engine: VeriForgeEngine) -> None:
        result = engine.verify_code("x = 1\n")
        assert isinstance(result.findings, tuple)


# =============================================================================
# 4. Engine — Input Validation
# =============================================================================


class TestInputValidation:
    """Strict input validation prevents injection attacks."""

    def test_non_string_source_raises(self, engine: VeriForgeEngine) -> None:
        with pytest.raises(TypeError):
            engine.verify_code(12345)  # type: ignore[arg-type]

    def test_oversized_source_raises(self, engine: VeriForgeEngine) -> None:
        with pytest.raises(ValueError):
            engine.verify_code("x\n" * 1_000_001)

    def test_unsupported_extension_raises(self, engine: VeriForgeEngine) -> None:
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"hello")
            path = f.name
        try:
            with pytest.raises(ValueError):
                engine.verify_file(path)
        finally:
            os.unlink(path)


# =============================================================================
# 5. Audit — Immutable Chain
# =============================================================================


class TestAuditChain:
    """Tamper-evident audit log with HMAC chain."""

    def test_empty_chain_is_valid(self, audit: ImmutableAuditLog) -> None:
        assert audit.verify_chain() is True

    def test_entries_are_linked(self, audit: ImmutableAuditLog) -> None:
        e1 = audit.record("scan", "user-1", "file-a.py")
        e2 = audit.record("scan", "user-2", "file-b.py")
        assert e1.prev_hmac == "0" * 64
        assert e2.prev_hmac == e1.entry_hmac

    def test_chain_verifies_after_multiple_entries(self, audit: ImmutableAuditLog) -> None:
        for i in range(10):
            audit.record("scan", f"user-{i}", f"file-{i}.py")
        assert audit.verify_chain() is True

    def test_chain_integrity_detects_tampering(self, audit: ImmutableAuditLog) -> None:
        audit.record("scan", "user-1", "file-a.py")
        audit.record("scan", "user-2", "file-b.py")
        # Tamper with internal state (simulate attack)
        audit._entries[0] = AuditEntry(
            index=0,
            timestamp=time.time(),
            action="TAMPERED",
            subject="attacker",
            detail="",
            prev_hmac="0" * 64,
            entry_hmac="fake" * 16,
        )
        assert audit.verify_chain() is False


# =============================================================================
# 6. Auth — JWT Lifecycle
# =============================================================================


class TestJWTLifecycle:
    """Token issuance, validation, and expiry."""

    def test_token_issued_and_validated(self, auth: AuthManager) -> None:
        token = auth.issue_token("alice", Role.SCANNER)
        payload = auth.validate_token(token)
        assert payload.subject == "alice"
        assert payload.role == Role.SCANNER

    def test_expired_token_rejected(self, secret: str) -> None:
        auth = AuthManager(jwt_secret=secret, token_ttl_seconds=-1)
        token = auth.issue_token("bob", Role.VIEWER)
        with pytest.raises(JWTError):
            auth.validate_token(token)

    def test_invalid_signature_rejected(self, auth: AuthManager) -> None:
        with pytest.raises(JWTError):
            auth.validate_token("header.payload.bad-signature")

    def test_empty_token_rejected(self, auth: AuthManager) -> None:
        with pytest.raises(JWTError):
            auth.validate_token("")


# =============================================================================
# 7. Auth — RBAC
# =============================================================================


class TestRBAC:
    """Role-based access control enforcement."""

    def test_scanner_can_scan(self, auth: AuthManager) -> None:
        token = auth.issue_token("scanner-1", Role.SCANNER)
        auth.check_permission(token, "scan")  # should not raise

    def test_viewer_cannot_scan(self, auth: AuthManager) -> None:
        token = auth.issue_token("viewer-1", Role.VIEWER)
        with pytest.raises(RBACError):
            auth.check_permission(token, "scan")

    def test_admin_can_do_everything(self, auth: AuthManager) -> None:
        token = auth.issue_token("admin-1", Role.ADMIN)
        for action in ("scan", "audit", "config", "admin", "view"):
            auth.check_permission(token, action)

    def test_require_role_enforces_hierarchy(self, auth: AuthManager) -> None:
        viewer_token = auth.issue_token("v1", Role.VIEWER)
        with pytest.raises(RBACError):
            auth.require_role(viewer_token, Role.ADMIN)

    def test_auditor_can_audit_and_view(self, auth: AuthManager) -> None:
        token = auth.issue_token("auditor-1", Role.AUDITOR)
        auth.check_permission(token, "audit")
        auth.check_permission(token, "view")
        with pytest.raises(RBACError):
            auth.check_permission(token, "scan")


# =============================================================================
# 8. Auth — Rate Limiting
# =============================================================================


class TestRateLimiting:
    """Sliding-window rate limit enforcement."""

    def test_within_limit_allowed(self, auth: AuthManager) -> None:
        auth.check_rate_limit("user-1")
        auth.check_rate_limit("user-1")
        auth.check_rate_limit("user-1")

    def test_exceeding_limit_raises(self, auth: AuthManager) -> None:
        # auth is configured with max=5 per 60s
        for _ in range(5):
            auth.check_rate_limit("limited-user")
        with pytest.raises(RateLimitError):
            auth.check_rate_limit("limited-user")

    def test_reset_clears_counter(self, auth: AuthManager) -> None:
        for _ in range(5):
            auth.check_rate_limit("reset-user")
        auth.reset_rate_limit("reset-user")
        auth.check_rate_limit("reset-user")  # should not raise

    def test_different_users_independent(self, auth: AuthManager) -> None:
        for i in range(10):
            auth.check_rate_limit(f"user-{i}")  # each user gets their own counter


# =============================================================================
# 9. Agent — Authenticated Verification
# =============================================================================


class TestAgentVerifier:
    """End-to-end agent verification with auth."""

    def test_agent_register_and_verify(self, auth: AuthManager) -> None:
        verifier = AgentVerifier(auth=auth)
        token = verifier.register_agent("agent-1", Role.SCANNER)
        result = verifier.verify(token, "x = 1\n", "test.py")
        assert isinstance(result, VerificationResult)

    def test_unauthenticated_agent_rejected(self, auth: AuthManager) -> None:
        verifier = AgentVerifier(auth=auth)
        with pytest.raises(AgentAuthError):
            verifier.verify("invalid-token", "x = 1\n")

    def test_viewer_agent_cannot_scan(self, auth: AuthManager) -> None:
        verifier = AgentVerifier(auth=auth)
        token = verifier.register_agent("viewer-agent", Role.VIEWER)
        with pytest.raises(AgentAuthError):
            verifier.verify(token, "x = 1\n")

    def test_revoke_agent(self, auth: AuthManager) -> None:
        verifier = AgentVerifier(auth=auth)
        admin_token = verifier.register_agent("admin-1", Role.ADMIN)
        verifier.revoke_agent(admin_token, "some-agent")
        # After revoke, rate limits are reset


# =============================================================================
# 10. IDE — Path Sanitization
# =============================================================================


class TestPathSanitization:
    """Directory traversal and path injection prevention."""

    def test_safe_path_allowed(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            f.write(b"x = 1\n")
            path = f.name
        try:
            verifier = IDEVerifier(allowed_base_dirs=[os.path.dirname(path)])
            result = verifier.ide_verify(path)
            assert result.verified is True
        finally:
            os.unlink(path)

    def test_traversal_blocked(self) -> None:
        verifier = IDEVerifier()
        with pytest.raises(PathSanitizationError):
            verifier.ide_verify("../../../etc/passwd")

    def test_null_byte_blocked(self) -> None:
        verifier = IDEVerifier()
        with pytest.raises(PathSanitizationError):
            verifier.ide_verify("file.py\x00.txt")

    def test_unsafe_character_blocked(self) -> None:
        verifier = IDEVerifier()
        with pytest.raises(PathSanitizationError):
            verifier.ide_verify("file; rm -rf /")

    def test_outside_allowed_dirs_blocked(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            f.write(b"x = 1\n")
            path = f.name
        try:
            verifier = IDEVerifier(allowed_base_dirs=["/tmp/safe"])
            with pytest.raises(PathSanitizationError):
                verifier.ide_verify(path)
        finally:
            os.unlink(path)

    def test_quick_check_syntax_error(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write("def broken(\n")  # syntax error
            path = f.name
        try:
            verifier = IDEVerifier(allowed_base_dirs=[os.path.dirname(path)])
            result = verifier.quick_check(path)
            assert result["valid"] is False
            assert len(result["errors"]) > 0
        finally:
            os.unlink(path)

    def test_is_safe_path(self) -> None:
        verifier = IDEVerifier()
        assert verifier.is_safe_path("../../../etc/passwd") is False


# =============================================================================
# 11. Semantic — Obfuscation Detection
# =============================================================================


class TestObfuscationDetection:
    """Detection of code obfuscation patterns."""

    def test_clean_code_no_findings(self, analyzer: SemanticAnalyzer) -> None:
        source = "\n".join([
            "def calculate(x, y):",
            "    # Add two numbers",
            "    return x + y",
        ])
        findings = analyzer.analyze(source)
        assert len(findings) == 0

    def test_obfuscated_name_detected(self, analyzer: SemanticAnalyzer) -> None:
        source = "\n".join([
            "def O0lI1(x):",
            "    return x + 1",
        ])
        findings = analyzer.analyze(source)
        obf = [f for f in findings if f.category == "obfuscated_name"]
        assert len(obf) >= 1

    def test_deep_nesting_detected(self, analyzer: SemanticAnalyzer) -> None:
        source = "\n".join([
            "def deep():",
            "    if True:",
            "        if True:",
            "            if True:",
            "                if True:",
            "                    if True:",
            "                        if True:",
            "                            return 1",
        ])
        findings = analyzer.analyze(source)
        nested = [f for f in findings if f.category == "nesting_depth"]
        assert len(nested) >= 1

    def test_string_obfuscation_detected(self, analyzer: SemanticAnalyzer) -> None:
        source = "\n".join([
            "import base64",
            "data = base64.b64decode('cHJpbnQoMSk=')",
        ])
        findings = analyzer.analyze(source)
        obf = [f for f in findings if f.category == "string_obfuscation"]
        assert len(obf) >= 1

    def test_suspicious_import_detected(self, analyzer: SemanticAnalyzer) -> None:
        source = "import marshal\n"
        findings = analyzer.analyze(source)
        susp = [f for f in findings if f.category == "suspicious_import"]
        assert len(susp) >= 1

    def test_is_obfuscated(self, analyzer: SemanticAnalyzer) -> None:
        clean = "x = 1\n"
        dirty = "def O0lI1(): pass\n"
        assert analyzer.is_obfuscated(dirty) is True
        assert analyzer.is_obfuscated(clean) is False


# =============================================================================
# 12. Compliance — SOC2
# =============================================================================


class TestSOC2Compliance:
    """SOC 2 Trust Service Criteria checks."""

    def test_soc2_runs(self) -> None:
        auditor = SOC2Auditor()
        source = "import hashlib\nimport logging\n"
        result = auditor.audit(source)
        assert isinstance(result, ComplianceResult)
        assert result.standard == "SOC 2"
        assert len(result.findings) > 0

    def test_soc2_score_range(self) -> None:
        auditor = SOC2Auditor()
        result = auditor.audit("encrypt = True\n")
        assert 0.0 <= result.score <= 1.0


# =============================================================================
# 13. Compliance — ISO 27001
# =============================================================================


class TestISO27001Compliance:
    """ISO 27001:2022 Annex A checks."""

    def test_iso27001_runs(self) -> None:
        auditor = ISO27001Auditor()
        source = "import pytest\nimport hashlib\n"
        result = auditor.audit(source)
        assert result.standard == "ISO 27001"
        assert len(result.findings) >= 20

    def test_iso27001_detects_access_control(self) -> None:
        auditor = ISO27001Auditor()
        source = "def check_role(user):\n    return user.role\n"
        result = auditor.audit(source)
        ac = [f for f in result.findings if f.control_id == "A.5.15"]
        assert len(ac) == 1


# =============================================================================
# 14. Compliance — PCI DSS
# =============================================================================


class TestPCIDSSCompliance:
    """PCI DSS 4.0 requirement checks."""

    def test_pci_dss_runs(self) -> None:
        auditor = PCIDSSAuditor()
        source = "import tls\nimport audit\n"
        result = auditor.audit(source)
        assert result.standard == "PCI DSS"
        assert len(result.findings) == 12

    def test_pci_dss_requires_encryption(self) -> None:
        auditor = PCIDSSAuditor()
        source = "data = 'plain text'\n"
        result = auditor.audit(source)
        req3 = [f for f in result.findings if f.control_id == "Req 3"][0]
        assert req3.status == "fail"

    def test_pci_dss_passes_with_encryption(self) -> None:
        auditor = PCIDSSAuditor()
        source = "encrypted = aes_encrypt(data)\n"
        result = auditor.audit(source)
        req3 = [f for f in result.findings if f.control_id == "Req 3"][0]
        assert req3.status == "pass"


# =============================================================================
# 15. Report — Safe JSON Serialization
# =============================================================================


class TestSafeJSON:
    """CVE-2024-XXXX: No arbitrary code execution via JSON."""

    def test_verification_result_serializes(self, engine: VeriForgeEngine) -> None:
        gen = ReportGenerator()
        result = engine.verify_code("x = 1\n")
        json_str = gen.result_to_json(result)
        parsed = json.loads(json_str)
        assert parsed["verified"] is True

    def test_audit_entries_serializes(self, audit: ImmutableAuditLog) -> None:
        gen = ReportGenerator()
        audit.record("scan", "user-1", "file.py")
        entries = list(audit._entries)
        json_str = gen.audit_to_json(entries)
        parsed = json.loads(json_str)
        assert len(parsed) == 1

    def test_compliance_results_serializes(self) -> None:
        gen = ReportGenerator()
        results = [SOC2Auditor().audit("x = 1\n")]
        json_str = gen.compliance_to_json(results)
        parsed = json.loads(json_str)
        assert parsed[0]["standard"] == "SOC 2"

    def test_no_pickle_in_encoder(self) -> None:
        """Meta-test: SafeJSONEncoder must not use pickle."""
        import inspect
        import veriforge.report as report_mod

        source = inspect.getsource(report_mod)
        assert "pickle" not in source.lower()

    def test_encoder_rejects_arbitrary_objects(self) -> None:
        gen = ReportGenerator()
        with pytest.raises(TypeError):
            gen.to_json(object())  # plain object has no to_dict

    def test_encoder_handles_datetime(self) -> None:
        from datetime import datetime
        gen = ReportGenerator()
        data = {"created": datetime(2024, 1, 1, 12, 0, 0)}
        json_str = gen.to_json(data)
        parsed = json.loads(json_str)
        assert "2024-01-01" in parsed["created"]

    def test_encoder_handles_bytes(self) -> None:
        gen = ReportGenerator()
        data = {"raw": b"hello world"}
        json_str = gen.to_json(data)
        parsed = json.loads(json_str)
        import base64
        assert parsed["raw"] == base64.b64encode(b"hello world").decode("ascii")


# =============================================================================
# 16. Config — Secure Configuration
# =============================================================================


class TestSecureConfig:
    """Environment-based configuration with no hard-coded secrets."""

    def test_required_secret_raises_when_missing(self) -> None:
        config = SecureConfig(VERIFORGE_SECRET="ok", VERIFORGE_JWT_SECRET="ok")
        with pytest.raises(ConfigurationError):
            _ = config.audit_secret

    def test_all_required_present(self) -> None:
        config = SecureConfig(
            VERIFORGE_SECRET="s1",
            VERIFORGE_JWT_SECRET="s2",
            VERIFORGE_AUDIT_SECRET="s3",
        )
        assert config.secret_key == "s1"
        assert config.jwt_secret == "s2"
        assert config.audit_secret == "s3"

    def test_validation_fails_on_missing(self) -> None:
        config = SecureConfig(VERIFORGE_SECRET="ok")
        errors = config.validate()
        assert len(errors) >= 2  # jwt and audit missing

    def test_defaults(self) -> None:
        config = SecureConfig(
            VERIFORGE_SECRET="s1",
            VERIFORGE_JWT_SECRET="s2",
            VERIFORGE_AUDIT_SECRET="s3",
        )
        assert config.rate_limit_max == 100
        assert config.rate_limit_window == 60
        assert config.log_level == "INFO"

    def test_rate_limit_validation(self) -> None:
        config = SecureConfig(
            VERIFORGE_SECRET="s1",
            VERIFORGE_JWT_SECRET="s2",
            VERIFORGE_AUDIT_SECRET="s3",
            VERIFORGE_RATE_LIMIT="0",
        )
        errors = config.validate()
        assert any("rate_limit_max" in e for e in errors)


# =============================================================================
# 17. Engine — File Operations
# =============================================================================


class TestFileOperations:
    """Verifying files on disk."""

    def test_verify_file(self, engine: VeriForgeEngine) -> None:
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write("x = 1\n")
            path = f.name
        try:
            result = engine.verify_file(path)
            assert result.verified is True
            assert result.source == path
        finally:
            os.unlink(path)

    def test_verify_directory(self, engine: VeriForgeEngine) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "a.py"), "w") as f:
                f.write("x = 1\n")
            with open(os.path.join(tmpdir, "b.py"), "w") as f:
                f.write("y = 2\n")
            results = engine.verify_directory(tmpdir)
            assert len(results) == 2
            assert all(r.verified for r in results)

    def test_verify_directory_skips_unsupported(self, engine: VeriForgeEngine) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "a.py"), "w") as f:
                f.write("x = 1\n")
            with open(os.path.join(tmpdir, "readme.txt"), "w") as f:
                f.write("hello")
            results = engine.verify_directory(tmpdir)
            assert len(results) == 1


# =============================================================================
# 18. Engine — Dangerous Pattern Detection
# =============================================================================


class TestDangerousPatterns:
    """Regex-based dangerous pattern detection."""

    def test_os_system_detected(self, engine: VeriForgeEngine) -> None:
        result = engine.verify_code("os.system('ls')\n")
        assert result.verified is False
        assert any("os.system" in f for f in result.findings)

    def test_subprocess_run_detected(self, engine: VeriForgeEngine) -> None:
        result = engine.verify_code("subprocess.run(['ls'])\n")
        assert result.verified is False

    def test_double_underscore_import_detected(self, engine: VeriForgeEngine) -> None:
        result = engine.verify_code("__import__('os')\n")
        assert result.verified is False


# =============================================================================
# 19. Meta — No Secrets in Code
# =============================================================================


class TestNoSecretsInCode:
    """Ensure the codebase contains no hard-coded secrets."""

    def test_no_hardcoded_passwords(self) -> None:
        import veriforge

        source_file = veriforge.__file__
        with open(source_file, "r") as f:
            source = f.read()
        # __init__ should not have real secrets
        assert "password123" not in source
        assert "AKIA" not in source  # AWS key pattern


# =============================================================================
# 20. Integration — End-to-End Workflow
# =============================================================================


class TestEndToEnd:
    """Full workflow integration test."""

    def test_full_pipeline(self, secret: str) -> None:
        """Engine -> Audit -> Report pipeline."""
        config = SecureConfig(
            VERIFORGE_SECRET=secret,
            VERIFORGE_JWT_SECRET=secret,
            VERIFORGE_AUDIT_SECRET=secret,
        )
        engine = VeriForgeEngine(config=config, secret=secret)
        audit = ImmutableAuditLog(secret=secret)
        reporter = ReportGenerator()

        # Simulate a scan
        source = "x = 1\n"
        result = engine.verify_code(source)
        audit.record("scan", "integration-test", "pipeline.py")

        # Generate report
        report_json = reporter.summary_report([result])
        report = json.loads(report_json)

        assert report["summary"]["total_scanned"] == 1
        assert report["summary"]["verified"] == 1
        assert report["summary"]["failed"] == 0
        assert audit.verify_chain() is True

    def test_compliance_pipeline(self) -> None:
        """Full compliance check pipeline."""
        source = "import hashlib\nimport logging\nencrypted = True\n"
        results = [
            SOC2Auditor().audit(source),
            ISO27001Auditor().audit(source),
            PCIDSSAuditor().audit(source),
        ]
        reporter = ReportGenerator()
        json_str = reporter.compliance_to_json(results)
        parsed = json.loads(json_str)
        assert len(parsed) == 3
        for r in parsed:
            assert 0.0 <= r["score"] <= 1.0
