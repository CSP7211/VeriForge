# VeriForge API Reference

## Table of Contents

- [VeriForgeEngine](#veriforgeengine)
- [VerificationResult](#verificationresult)
- [AuthManager](#authmanager)
- [ImmutableAuditLog](#immutableauditlog)
- [SemanticAnalyzer](#semanticanalyzer)
- [Compliance Auditors](#compliance-auditors)
- [AgentVerifier](#agentverifier)
- [IDEVerifier](#ideverifier)
- [ReportGenerator](#reportgenerator)
- [SecureConfig](#secureconfig)
- [Error Handling](#error-handling)

---

## VeriForgeEngine

### `class VeriForgeEngine`

Hardened formal verification engine.

#### Constructor

```python
engine = VeriForgeEngine(
    config=None,           # SecureConfig instance (optional)
    secret=None,           # HMAC signing secret (falls back to VERIFORGE_SECRET env var)
    timeout_seconds=30,    # Analysis timeout in seconds
)
```

#### Methods

##### `verify_code(source: str, filename: str = "<string>") -> VerificationResult`

Verify a single piece of source code.

```python
result = engine.verify_code("x = 1 + 2\n", filename="math.py")
print(result.verified)        # True
print(result.findings)        # ()
print(result.hmac_signature)  # "a1b2c3..."
```

**Parameters:**
- `source` (str): Source code to analyze
- `filename` (str): Logical filename for the source

**Raises:**
- `TypeError`: If source is not a string
- `ValueError`: If source exceeds 1,000,000 characters
- `EvalGuardError`: If target code contains eval()/exec()

##### `verify_file(path: str) -> VerificationResult`

Verify a file on disk.

```python
result = engine.verify_file("/path/to/code.py")
```

**Raises:**
- `FileNotFoundError`: File does not exist
- `ValueError`: Unsupported file extension

##### `verify_directory(path: str) -> list[VerificationResult]`

Recursively verify all supported files in a directory.

```python
results = engine.verify_directory("/path/to/project")
for r in results:
    print(f"{r.source}: {'PASS' if r.verified else 'FAIL'}")
```

---

## VerificationResult

### `class VerificationResult`

Immutable verification result (frozen dataclass).

#### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `source` | `str` | Source filename |
| `verified` | `bool` | Whether verification passed |
| `findings` | `tuple[str, ...]` | Security findings (empty if clean) |
| `hmac_signature` | `str` | HMAC-SHA256 signature (hex) |
| `timestamp` | `float` | Unix timestamp of verification |
| `execution_time_ms` | `float` | Wall-clock time in milliseconds |
| `metadata` | `dict[str, str]` | Additional metadata (not hashed) |

#### Methods

##### `to_dict() -> dict[str, Any]`

Serialize to dictionary (safe for JSON).

##### `verify_hmac(secret: str) -> bool`

Verify the HMAC signature using the given secret.

```python
valid = result.verify_hmac("my-secret")
```

---

## AuthManager

### `class AuthManager`

JWT-based authentication with RBAC and rate limiting.

#### Constructor

```python
auth = AuthManager(
    jwt_secret=None,          # JWT signing secret (auto-generated if None)
    token_ttl_seconds=3600,   # Token expiry time
    rate_limit_max=100,       # Max requests per window
    rate_limit_window=60,     # Rate limit window in seconds
)
```

#### Methods

##### `issue_token(subject: str, role: Role | str = Role.VIEWER) -> str`

Issue a JWT token.

```python
token = auth.issue_token("user-42", Role.SCANNER)
```

##### `validate_token(token: str) -> TokenPayload`

Validate a JWT token.

```python
payload = auth.validate_token(token)
print(payload.subject)     # "user-42"
print(payload.role)        # Role.SCANNER
```

**Raises:** `JWTError` if token is invalid or expired.

##### `check_permission(token: str, action: str) -> None`

Check if the token bearer can perform an action.

```python
auth.check_permission(token, "scan")  # raises RBACError if not allowed
```

##### `require_role(token: str, min_role: Role) -> TokenPayload`

Require a minimum role level.

```python
payload = auth.require_role(token, Role.AUDITOR)
```

##### `check_rate_limit(subject: str) -> None`

Check and record a request for rate limiting.

**Raises:** `RateLimitError` if limit exceeded.

##### `reset_rate_limit(subject: str) -> None`

Reset rate limit counters for a subject.

---

## ImmutableAuditLog

### `class ImmutableAuditLog`

Tamper-evident audit log with HMAC chain.

#### Constructor

```python
audit = ImmutableAuditLog(secret="audit-secret-key")
```

#### Methods

##### `record(action: str, subject: str, detail: str = "") -> AuditEntry`

Append a new audit entry.

```python
entry = audit.record("scan", "user-1", "file.py")
print(entry.entry_hmac)   # Chain-linked HMAC
```

##### `verify_chain() -> bool`

Verify the integrity of the entire chain.

```python
if audit.verify_chain():
    print("Audit log is intact")
else:
    print("AUDIT LOG HAS BEEN TAMPERED WITH!")
```

##### `export_entries() -> list[dict[str, Any]]`

Export all entries as dictionaries.

##### `get_entries_for_subject(subject: str) -> list[AuditEntry]`

Get all entries for a specific subject.

##### `__len__() -> int`

Number of entries in the log.

---

## SemanticAnalyzer

### `class SemanticAnalyzer`

Obfuscation and anti-pattern detection.

#### Constructor

```python
analyzer = SemanticAnalyzer(
    max_nesting_depth=5,      # Maximum allowed nesting depth
    min_comment_ratio=0.05,   # Minimum comment-to-code ratio
)
```

#### Methods

##### `analyze(source: str, filename: str = "<string>") -> list[ObfuscationFinding]`

Run full semantic analysis.

```python
findings = analyzer.analyze("def O0lI1(x): return x\n")
for f in findings:
    print(f"[{f.severity}] {f.category}: {f.message} (line {f.line})")
```

##### `is_obfuscated(source: str, filename: str = "<string>") -> bool`

Quick check for any obfuscation findings.

---

## Compliance Auditors

### `class SOC2Auditor`

SOC 2 Type II compliance auditor.

```python
auditor = SOC2Auditor()
result = auditor.audit(source_code, "file.py")
print(f"Score: {result.score:.1%}")
for finding in result.findings:
    print(f"  {finding.control_id}: {finding.status} - {finding.control_name}")
```

### `class ISO27001Auditor`

ISO/IEC 27001:2022 compliance auditor.

```python
auditor = ISO27001Auditor()
result = auditor.audit(source_code, "file.py")
```

### `class PCIDSSAuditor`

PCI DSS 4.0 compliance auditor.

```python
auditor = PCIDSSAuditor()
result = auditor.audit(source_code, "file.py")
```

### `run_all_auditors(source: str, filename: str = "<string>") -> list[ComplianceResult]`

Run all three auditors at once.

```python
from veriforge.compliance import run_all_auditors
results = run_all_auditors(source_code)
for r in results:
    print(f"{r.standard}: {r.score:.1%}")
```

---

## AgentVerifier

### `class AgentVerifier`

Authenticated code verifier for agent-based workflows.

#### Constructor

```python
verifier = AgentVerifier(
    auth=None,      # AuthManager instance (optional)
    engine=None,    # VeriForgeEngine instance (optional)
    audit=None,     # ImmutableAuditLog instance (optional)
)
```

#### Methods

##### `register_agent(agent_id: str, role: Role | str = Role.SCANNER) -> str`

Register an agent and return a JWT token.

```python
token = verifier.register_agent("agent-42", Role.SCANNER)
```

##### `verify(token: str, source: str, filename: str = "<agent>") -> VerificationResult`

Verify source code on behalf of an authenticated agent.

```python
result = verifier.verify(token, "x = 1\n", "test.py")
```

**Raises:** `AgentAuthError` if authentication or authorization fails.

##### `revoke_agent(admin_token: str, agent_id: str) -> None`

Revoke an agent (admin only).

---

## IDEVerifier

### `class IDEVerifier`

IDE-integrated verifier with path sanitization.

#### Constructor

```python
verifier = IDEVerifier(
    allowed_base_dirs=["/safe/project"],  # Allowed directories
    engine=None,                          # VeriForgeEngine instance (optional)
)
```

#### Methods

##### `ide_verify(file_path: str) -> VerificationResult`

Verify a file with full path sanitization.

```python
result = verifier.ide_verify("/safe/project/main.py")
```

**Raises:** `PathSanitizationError` if path fails any check.

##### `quick_check(file_path: str) -> dict[str, Any]`

Quick syntax-only check for real-time IDE feedback.

```python
result = verifier.quick_check("/safe/project/main.py")
print(result["valid"], result["errors"])
```

##### `is_safe_path(file_path: str) -> bool`

Check if a path passes sanitization.

---

## ReportGenerator

### `class ReportGenerator`

Safe JSON report generation.

#### Constructor

```python
generator = ReportGenerator(indent=2)
```

#### Methods

##### `to_json(obj: Any) -> str`

Safely serialize any supported object to JSON.

##### `result_to_json(result: VerificationResult) -> str`

Serialize a VerificationResult.

##### `summary_report(results: list[VerificationResult], compliance: list[ComplianceResult] | None = None) -> str`

Generate a comprehensive summary report.

```python
json_report = generator.summary_report(results, compliance_results)
```

---

## SecureConfig

### `class SecureConfig`

Environment-based configuration.

#### Constructor

```python
config = SecureConfig(
    VERIFORGE_SECRET="secret",         # Override env var
    VERIFORGE_JWT_SECRET="jwt-secret",
    VERIFORGE_AUDIT_SECRET="audit-secret",
)
```

#### Properties

| Property | Type | Description | Env Var |
|----------|------|-------------|---------|
| `secret_key` | `str` | Primary HMAC secret | `VERIFORGE_SECRET` |
| `jwt_secret` | `str` | JWT signing secret | `VERIFORGE_JWT_SECRET` |
| `audit_secret` | `str` | Audit log secret | `VERIFORGE_AUDIT_SECRET` |
| `db_url` | `str` | Database URL | `VERIFORGE_DB_URL` |
| `rate_limit_max` | `int` | Max requests/window | `VERIFORGE_RATE_LIMIT` |
| `rate_limit_window` | `int` | Window in seconds | `VERIFORGE_RATE_WINDOW` |
| `log_level` | `str` | Logging level | `VERIFORGE_LOG_LEVEL` |
| `compliance_mode` | `str` | Active compliance | `VERIFORGE_COMPLIANCE` |

#### Methods

##### `validate() -> list[str]`

Validate configuration and return list of errors.

```python
errors = config.validate()
if errors:
    for e in errors:
        print(f"Config error: {e}")
```

---

## Error Handling

| Exception | Module | Description |
|-----------|--------|-------------|
| `EvalGuardError` | `engine` | Target code contains eval()/exec() |
| `TimeoutError` | `engine` | Analysis exceeded time limit |
| `JWTError` | `auth` | JWT token validation failure |
| `RBACError` | `auth` | Permission denied |
| `RateLimitError` | `auth` | Rate limit exceeded |
| `ConfigurationError` | `config` | Missing or invalid configuration |
| `AgentAuthError` | `agent` | Agent authentication failure |
| `PathSanitizationError` | `ide` | Unsafe file path detected |

All exceptions inherit from `RuntimeError` (except `TypeError`/`ValueError` for input validation).
