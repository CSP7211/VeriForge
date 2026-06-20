"""
VeriForge Hardened — Security Regression Tests (20+)

Coverage:
  - SecureConfig raises RuntimeError without env vars
  - Engine verify_code works with valid code
  - No eval() exists in source (AST-based check)
  - HMAC signatures verify correctly
  - Frozen dataclass cannot be modified
  - Audit chain detects tampering
  - JWT auth blocks unauthenticated requests
  - Rate limiting works
  - Path traversal is blocked
  - Timeout decorator works
  - Compliance auditors reject weak code
  - Report serialization handles enums
"""

from __future__ import annotations

import ast
import inspect
import json
import os
import pathlib
import sys
import tempfile
import time
import types

import pytest

# Ensure veriforge is importable
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from veriforge.config import SecureConfig
from veriforge.auth import AuthManager, AuthError, Role
from veriforge.audit import AuditEntry, ImmutableAuditLog
from veriforge.semantic import SemanticAnalyzer, Finding, Severity
from veriforge.engine import (
    VeriForgeEngine,
    VerificationResult,
    ComplianceLevel,
    LimitError,
    TimeoutError,
    _with_timeout,
    MAX_CODE_BYTES,
    MAX_ASSERTIONS,
    MAX_AST_DEPTH,
)
from veriforge.compliance import SOC2Auditor, ISO27001Auditor, PCIDSSAuditor
from veriforge.agent import AgentVerifier
from veriforge.ide import IDEVerifier, IDEVerifierError
from veriforge.report import ReportGenerator


# ─── Fixtures ────────────────────────────────────────────────────────────


@pytest.fixture
def secret() -> str:
    return "test-secret-key-for-hmac-only"


@pytest.fixture
def engine(secret: str) -> VeriForgeEngine:
    return VeriForgeEngine(
        secret=secret,
        semantic=SemanticAnalyzer(),
        compliance_auditors=[
            SOC2Auditor(),
            ISO27001Auditor(),
            PCIDSSAuditor(),
        ],
    )


@pytest.fixture
def auth(secret: str) -> AuthManager:
    return AuthManager(jwt_secret=secret, rate_limit=10)


@pytest.fixture
def verifier(auth: AuthManager, engine: VeriForgeEngine) -> AgentVerifier:
    return AgentVerifier(auth_manager=auth, engine=engine)


@pytest.fixture(autouse=True)
def env_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure required env vars are present for every test."""
    monkeypatch.setenv("VERIFORGE_SECRET_KEY", "test-secret")
    monkeypatch.setenv("VERIFORGE_JWT_SECRET", "test-jwt-secret")


# ═══════════════════════════════════════════════════════════════════════
# 1. SecureConfig
# ═══════════════════════════════════════════════════════════════════════


def test_secure_config_missing_secret_raises() -> None:
    """SecureConfig raises RuntimeError when VERIFORGE_SECRET_KEY is missing."""
    old = os.environ.pop("VERIFORGE_SECRET_KEY", None)
    try:
        with pytest.raises(RuntimeError, match="VERIFORGE_SECRET_KEY not set"):
            SecureConfig()
    finally:
        if old:
            os.environ["VERIFORGE_SECRET_KEY"] = old


def test_secure_config_with_secret_ok() -> None:
    """SecureConfig succeeds when env var is present."""
    os.environ["VERIFORGE_SECRET_KEY"] = "present"
    cfg = SecureConfig()
    assert cfg.secret_key == "present"


def test_secure_config_jwt_fallback() -> None:
    """JWT secret falls back to secret_key when VERIFORGE_JWT_SECRET unset."""
    os.environ.pop("VERIFORGE_JWT_SECRET", None)
    os.environ["VERIFORGE_SECRET_KEY"] = "fallback-secret"
    cfg = SecureConfig()
    assert cfg.get_jwt_secret() == "fallback-secret"


# ═══════════════════════════════════════════════════════════════════════
# 2. Engine — basic verify_code
# ═══════════════════════════════════════════════════════════════════════


def test_engine_verify_valid_code_passes(engine: VeriForgeEngine) -> None:
    """Engine verify_code works with valid, clean code."""
    source = '''
import logging
import re

def greet(name):
    if not name or not re.match(r"^[a-zA-Z0-9_]+$", name):
        logging.error("Invalid name provided")
        raise ValueError("Invalid name")
    logging.info(f"User {name} logged in successfully")
    return f"Hello, {name}"

assert greet("world") == "Hello, world"
'''
    result = engine.verify_code(source)
    assert isinstance(result, VerificationResult)
    assert result.passed is True


def test_engine_detects_eval(engine: VeriForgeEngine) -> None:
    """Engine detects eval() in source code."""
    source = "x = eval('1 + 1')"
    result = engine.verify_code(source)
    assert result.passed is False
    assert any(f.rule == "direct-eval" for f in result.findings)


def test_engine_detects_exec(engine: VeriForgeEngine) -> None:
    """Engine detects exec() in source code."""
    source = "exec('import os')"
    result = engine.verify_code(source)
    assert result.passed is False
    assert any(f.rule == "direct-exec" for f in result.findings)


# ═══════════════════════════════════════════════════════════════════════
# 3. No eval() in source
# ═══════════════════════════════════════════════════════════════════════


def test_no_eval_in_source_code() -> None:
    """AST-based check: no eval() call exists anywhere in veriforge source."""
    veriforge_dir = pathlib.Path(__file__).parent.parent / "veriforge"
    for py_file in veriforge_dir.rglob("*.py"):
        source = py_file.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id == "eval":
                    # Skip test files that intentionally test for eval
                    if "test" in py_file.name:
                        continue
                    pytest.fail(f"eval() found in {py_file}")


# ═══════════════════════════════════════════════════════════════════════
# 4. HMAC signatures
# ═══════════════════════════════════════════════════════════════════════


def test_hmac_signature_verifies(engine: VeriForgeEngine) -> None:
    """HMAC signatures on results verify correctly."""
    source = 'print("hello")'
    result = engine.verify_code(source)
    assert engine.verify_integrity(result) is True


def test_hmac_signature_detects_tampering(engine: VeriForgeEngine, secret: str) -> None:
    """HMAC signature fails after tampering with result data."""
    source = 'print("hello")'
    result = engine.verify_code(source)
    # Tamper by creating a new result with different data but same signature
    tampered = VerificationResult(
        passed=not result.passed,
        code_hash=result.code_hash,
        findings=result.findings,
        compliance=result.compliance,
        signature=result.signature,
        timestamp=result.timestamp,
    )
    assert engine.verify_integrity(tampered) is False


# ═══════════════════════════════════════════════════════════════════════
# 5. Frozen dataclass
# ═══════════════════════════════════════════════════════════════════════


def test_result_is_frozen_dataclass() -> None:
    """VerificationResult is a frozen dataclass — cannot be modified."""
    result = VerificationResult(
        passed=True,
        code_hash="abc123",
        signature="sig",
        timestamp=0.0,
    )
    with pytest.raises(AttributeError):
        result.passed = False


def test_audit_entry_is_frozen() -> None:
    """AuditEntry is a frozen dataclass."""
    entry = AuditEntry(
        timestamp=0.0,
        event="test",
        actor="tester",
        details="",
        prev_hash="0",
        signature="sig",
        entry_hash="hash",
    )
    with pytest.raises(AttributeError):
        entry.event = "tampered"


def test_finding_is_frozen() -> None:
    """Finding is a frozen dataclass."""
    finding = Finding(
        rule="test",
        message="test message",
        severity=Severity.LOW,
        cwe_id="CWE-000",
        line=1,
        column=0,
    )
    with pytest.raises(AttributeError):
        finding.rule = "tampered"


# ═══════════════════════════════════════════════════════════════════════
# 6. Audit chain tamper detection
# ═══════════════════════════════════════════════════════════════════════


def test_audit_chain_intact(secret: str) -> None:
    """A clean audit chain reports no anomalies."""
    log = ImmutableAuditLog(secret)
    log.append("login", "alice", "success")
    log.append("verify", "alice", "file.py")
    assert log.is_intact() is True
    assert len(log.verify_chain()) == 0


def test_audit_chain_detects_tampering(secret: str) -> None:
    """Modifying an entry breaks the chain."""
    log = ImmutableAuditLog(secret)
    log.append("login", "alice", "success")
    log.append("verify", "alice", "file.py")

    # Directly mutate internal state to simulate tampering
    entry = log._entries[0]
    tampered_entry = AuditEntry(
        timestamp=entry.timestamp,
        event="TAMPERED",
        actor=entry.actor,
        details=entry.details,
        prev_hash=entry.prev_hash,
        signature=entry.signature,
        entry_hash=entry.entry_hash,
    )
    log._entries[0] = tampered_entry

    anomalies = log.verify_chain()
    assert len(anomalies) > 0


# ═══════════════════════════════════════════════════════════════════════
# 7. JWT auth blocks unauthenticated requests
# ═══════════════════════════════════════════════════════════════════════


def test_jwt_blocks_invalid_token(auth: AuthManager, verifier: AgentVerifier) -> None:
    """JWT auth blocks unauthenticated requests."""
    with pytest.raises(AuthError):
        verifier.list_agents("invalid-token-string")


def test_jwt_allows_valid_token(auth: AuthManager, verifier: AgentVerifier) -> None:
    """Valid JWT token grants access."""
    token = auth.generate_token("admin1", Role.ADMIN)
    agents = verifier.list_agents(token)
    assert isinstance(agents, list)


def test_jwt_role_enforcement(auth: AuthManager, verifier: AgentVerifier) -> None:
    """VIEWER token cannot access ADMIN-only endpoints."""
    token = auth.generate_token("viewer1", Role.VIEWER)
    with pytest.raises(AuthError):
        verifier.register_agent(token, "agent1", "Test Agent")


# ═══════════════════════════════════════════════════════════════════════
# 8. Rate limiting
# ═══════════════════════════════════════════════════════════════════════


def test_rate_limit_blocks_excess_requests(auth: AuthManager) -> None:
    """Sliding window rate limiting works."""
    auth._rate_limit = 3  # tighten for test
    auth._windows.clear()
    client = "test-client"

    # First 3 requests allowed
    assert auth.check_rate(client) is True
    assert auth.check_rate(client) is True
    assert auth.check_rate(client) is True
    # 4th blocked
    assert auth.check_rate(client) is False


def test_rate_limit_reset(auth: AuthManager) -> None:
    """Rate limit can be reset."""
    auth._rate_limit = 1
    auth._windows.clear()
    client = "reset-client"
    assert auth.check_rate(client) is True
    assert auth.check_rate(client) is False
    auth.reset_rate(client)
    assert auth.check_rate(client) is True


# ═══════════════════════════════════════════════════════════════════════
# 9. Path traversal blocked
# ═══════════════════════════════════════════════════════════════════════


def test_ide_blocks_path_traversal(engine: VeriForgeEngine, tmp_path: pathlib.Path) -> None:
    """IDEVerifier rejects .. path traversal."""
    ide = IDEVerifier(tmp_path, engine)
    with pytest.raises(IDEVerifierError):
        ide.verify_file("../../../etc/passwd")


def test_ide_blocks_absolute_path(engine: VeriForgeEngine, tmp_path: pathlib.Path) -> None:
    """IDEVerifier rejects absolute paths."""
    ide = IDEVerifier(tmp_path, engine)
    with pytest.raises(IDEVerifierError):
        ide.verify_file("/etc/passwd")


def test_ide_allows_valid_relative_path(engine: VeriForgeEngine, tmp_path: pathlib.Path) -> None:
    """IDEVerifier accepts valid relative paths."""
    source = '''
import logging
import re

def process(data):
    if not re.match(r"^[a-zA-Z0-9]+$", data):
        logging.error("Invalid input: security violation")
        raise ValueError("Invalid")
    logging.info(f"Processing {data}")
    return data
'''
    (tmp_path / "main.py").write_text(source, encoding="utf-8")
    ide = IDEVerifier(tmp_path, engine)
    result = ide.verify_file("main.py")
    assert result.passed is True


# ═══════════════════════════════════════════════════════════════════════
# 10. Timeout decorator
# ═══════════════════════════════════════════════════════════════════════


def test_timeout_decorator_raises_on_slow_function() -> None:
    """Timeout decorator raises TimeoutError."""

    @_with_timeout(seconds=1)
    def slow_function() -> str:
        time.sleep(5)
        return "done"

    with pytest.raises(TimeoutError):
        slow_function()


def test_timeout_decorator_allows_fast_function() -> None:
    """Timeout decorator does not interfere with fast functions."""

    @_with_timeout(seconds=5)
    def fast_function() -> str:
        return "done"

    assert fast_function() == "done"


# ═══════════════════════════════════════════════════════════════════════
# 11. Compliance auditors reject weak code
# ═══════════════════════════════════════════════════════════════════════


def test_soc2_rejects_code_without_logging() -> None:
    """SOC2 auditor rejects code with no logging calls."""
    auditor = SOC2Auditor()
    source = 'print("hello")'
    level = auditor.audit(source)
    assert level == ComplianceLevel.FAIL


def test_soc2_accepts_code_with_security_logging() -> None:
    """SOC2 auditor accepts code with proper security event logging."""
    auditor = SOC2Auditor()
    source = '''
import logging

def login(user):
    logging.info(f"User {user} login attempt")
    if not user:
        logging.error("Invalid login: empty user")
        return False
    logging.info(f"User {user} login success")
    return True
'''
    level = auditor.audit(source)
    assert level == ComplianceLevel.PASS


def test_iso27001_rejects_unvalidated_input() -> None:
    """ISO27001 auditor rejects code with tainted input but no validation."""
    auditor = ISO27001Auditor()
    source = '''
def handle_request(request):
    user_input = request.args.get("q")
    return "SELECT * FROM users WHERE name = '" + user_input + "'"
'''
    level = auditor.audit(source)
    assert level == ComplianceLevel.FAIL


def test_iso27001_accepts_validated_input() -> None:
    """ISO27001 auditor accepts code with taint validation."""
    auditor = ISO27001Auditor()
    source = '''
import re

def process(request):
    data = request.args.get("q")
    if not re.match(r"^[a-zA-Z0-9]+$", data):
        raise ValueError("Invalid input")
    return data
'''
    level = auditor.audit(source)
    assert level == ComplianceLevel.PASS


def test_pci_dss_rejects_type_casting_only() -> None:
    """PCI-DSS auditor rejects code with only type casting as 'sanitization'."""
    auditor = PCIDSSAuditor()
    source = '''
def process(user_input):
    x = str(user_input)
    return x
'''
    level = auditor.audit(source)
    # No real user input source, so partial
    assert level in (ComplianceLevel.PARTIAL, ComplianceLevel.FAIL)


def test_pci_dss_accepts_real_sanitization() -> None:
    """PCI-DSS auditor accepts code with real input sanitization."""
    auditor = PCIDSSAuditor()
    source = '''
import re

def process(user_input):
    if not re.match(r"^[a-zA-Z0-9]+$", user_input):
        raise ValueError("Invalid characters")
    if len(user_input) > 100:
        raise ValueError("Input too long")
    return user_input
'''
    level = auditor.audit(source)
    assert level == ComplianceLevel.PASS


# ═══════════════════════════════════════════════════════════════════════
# 12. Report serialization handles enums
# ═══════════════════════════════════════════════════════════════════════


def test_report_serializes_verification_result(engine: VeriForgeEngine) -> None:
    """ReportGenerator correctly serializes a VerificationResult."""
    source = 'print("hello")'
    result = engine.verify_code(source)
    report = ReportGenerator.serialize(result)
    assert isinstance(report, dict)
    assert "passed" in report
    assert "findings" in report
    # Enum values should be strings, not Enum objects
    for key, val in report.get("compliance", {}).items():
        assert not hasattr(val, "value")  # not an Enum


def test_report_json_roundtrip(engine: VeriForgeEngine) -> None:
    """JSON round-trip preserves data correctly."""
    source = 'print("hello")'
    result = engine.verify_code(source)
    json_str = ReportGenerator.to_json(result)
    parsed = json.loads(json_str)
    assert parsed["passed"] == result.passed
    assert parsed["code_hash"] == result.code_hash


def test_report_serialize_finding() -> None:
    """ReportGenerator correctly serializes a Finding."""
    finding = Finding(
        rule="test-rule",
        message="test message",
        severity=Severity.HIGH,
        cwe_id="CWE-89",
        line=5,
        column=10,
        snippet="x = eval(y)",
    )
    serialized = ReportGenerator.serialize(finding)
    assert serialized["severity"] == "high"
    assert serialized["cwe_id"] == "CWE-89"


# ═══════════════════════════════════════════════════════════════════════
# 13. Semantic analyzer — obfuscation detection
# ═══════════════════════════════════════════════════════════════════════


def test_semantic_detects_getattr_builtin_obfuscation() -> None:
    """Analyzer detects getattr(__builtins__, 'eval') obfuscation."""
    analyzer = SemanticAnalyzer()
    source = "getattr(__builtins__, 'eval')('1+1')"
    findings = analyzer.analyze(source)
    assert any(f.rule == "getattr-builtin" for f in findings)


def test_semantic_detects_base64_obfuscation() -> None:
    """Analyzer detects base64-encoded eval patterns."""
    analyzer = SemanticAnalyzer()
    source = "eval(base64.b64decode('cHJpbnQoImhpIik='))"
    findings = analyzer.analyze(source)
    assert any(f.rule == "base64-eval" for f in findings)


def test_semantic_detects_aliased_import() -> None:
    """Analyzer detects aliased imports of dangerous modules."""
    analyzer = SemanticAnalyzer()
    source = "import os as _os"
    findings = analyzer.analyze(source)
    assert any(f.rule == "aliased-import" for f in findings)


# ═══════════════════════════════════════════════════════════════════════
# 14. Resource limits
# ═══════════════════════════════════════════════════════════════════════


def test_code_size_limit(engine: VeriForgeEngine) -> None:
    """Engine rejects code exceeding 1MB."""
    huge = "x = 1\n" * (MAX_CODE_BYTES // 4)
    with pytest.raises(LimitError):
        engine.verify_code(huge)


def test_assertion_limit(engine: VeriForgeEngine) -> None:
    """Engine rejects code with more than 50 assertions."""
    many_asserts = "\n".join(f"assert x == {i}" for i in range(MAX_ASSERTIONS + 1))
    with pytest.raises(LimitError):
        engine.verify_code(many_asserts)


# ═══════════════════════════════════════════════════════════════════════
# 15. AuthManager — HMAC API key operations
# ═══════════════════════════════════════════════════════════════════════


def test_api_key_hashing(auth: AuthManager) -> None:
    """HMAC-SHA256 hashing of API keys is deterministic."""
    key = "my-api-key"
    h1 = auth.hash_api_key(key, "secret")
    h2 = auth.hash_api_key(key, "secret")
    assert h1 == h2
    assert len(h1) == 64  # hex of SHA-256


def test_api_key_verification(auth: AuthManager) -> None:
    """API key verification with HMAC compare_digest works."""
    key = "my-api-key"
    h = auth.hash_api_key(key, "secret")
    assert auth.verify_api_key(key, "secret", h) is True
    assert auth.verify_api_key("wrong-key", "secret", h) is False


# ═══════════════════════════════════════════════════════════════════════
# 16. Token generation and payload
# ═══════════════════════════════════════════════════════════════════════


def test_token_contains_expected_claims(auth: AuthManager) -> None:
    """Generated JWT contains expected claims."""
    token = auth.generate_token("user1", Role.ADMIN)
    payload = auth.validate_token(token)
    assert payload["sub"] == "user1"
    assert payload["role"] == "admin"
    assert "exp" in payload
    assert "iat" in payload
    assert "jti" in payload


def test_token_revocation(auth: AuthManager) -> None:
    """Revoked token is rejected."""
    token = auth.generate_token("user1", Role.ADMIN)
    auth.validate_token(token)  # valid before revocation
    auth.revoke_token(token)
    with pytest.raises(AuthError):
        auth.validate_token(token)


# ═══════════════════════════════════════════════════════════════════════
# 17. IDEVerifier directory scan
# ═══════════════════════════════════════════════════════════════════════


def test_ide_scans_directory(engine: VeriForgeEngine, tmp_path: pathlib.Path) -> None:
    """IDEVerifier scans all .py files in a directory."""
    good_source = '''
import logging
import re

def process(data):
    if not re.match(r"^[a-zA-Z0-9]+$", data):
        logging.error("Invalid input: security violation")
        raise ValueError("Invalid")
    logging.info(f"Processing {data}")
    return data
'''
    (tmp_path / "a.py").write_text(good_source, encoding="utf-8")
    (tmp_path / "b.py").write_text(good_source, encoding="utf-8")
    ide = IDEVerifier(tmp_path, engine)
    results = ide.verify_directory(".")
    assert len(results) == 2
    assert all(r.passed for r in results.values())


# ═══════════════════════════════════════════════════════════════════════
# 18. Audit log append-only
# ═══════════════════════════════════════════════════════════════════════


def test_audit_log_no_clear_method(secret: str) -> None:
    """ImmutableAuditLog has no clear() method."""
    log = ImmutableAuditLog(secret)
    assert not hasattr(log, "clear")


def test_audit_log_entries_grow(secret: str) -> None:
    """Entries grow monotonically."""
    log = ImmutableAuditLog(secret)
    assert len(log.entries) == 0
    log.append("a", "alice")
    assert len(log.entries) == 1
    log.append("b", "bob")
    assert len(log.entries) == 2


# ═══════════════════════════════════════════════════════════════════════
# 19. Engine serialize handles nested structures
# ═══════════════════════════════════════════════════════════════════════


def test_engine_serialize_handles_enum() -> None:
    """serialize() converts Enums to their values."""
    assert VeriForgeEngine.serialize(ComplianceLevel.PASS) == "pass"
    assert VeriForgeEngine.serialize(ComplianceLevel.FAIL) == "fail"
    assert VeriForgeEngine.serialize(Severity.CRITICAL) == "critical"


def test_engine_serialize_handles_dict_with_enums() -> None:
    """serialize() handles dicts containing Enum values."""
    data = {"level": ComplianceLevel.PARTIAL, "sev": Severity.HIGH}
    result = VeriForgeEngine.serialize(data)
    assert result == {"level": "partial", "sev": "high"}


# ═══════════════════════════════════════════════════════════════════════
# 20. Version export
# ═══════════════════════════════════════════════════════════════════════


def test_version_exported() -> None:
    """Package exports a version string."""
    from veriforge import __version__
    assert isinstance(__version__, str)
    assert "hardened" in __version__
