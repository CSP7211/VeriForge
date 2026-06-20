# Changelog

## 0.4.0-hardened — 2024-XX-XX

### Security
- Hardened core platform with 12 CVE-class vulnerabilities patched
- All secrets now loaded exclusively from environment variables (`SecureConfig`)
- JWT token generation/validation with RBAC (ADMIN, AGENT, VIEWER roles)
- HMAC-SHA256 signing on every `VerificationResult` and `AuditEntry`
- Immutable append-only audit log with HMAC-chain tamper detection
- NO `eval()` anywhere in the codebase — safe regex + AST walker only
- Sliding-window rate limiting (10 requests/minute default)
- 30-second timeout decorator on all verification operations
- Path-sanitized IDE verifier (`Path.relative_to()` blocks traversal)
- Frozen dataclasses on all result types (immutable by design)
- Generic error messages — no internal path or stack disclosure

### Compliance
- **SOC2Auditor**: Verifies actual logging calls for security events (not just imports)
- **ISO27001Auditor**: Verifies taint validation on user inputs
- **PCIDSSAuditor**: Verifies real input sanitization (regex, allow-list, parameterized queries)

### Features
- `SemanticAnalyzer` detects: eval/exec, getattr obfuscation, base64-encoded payloads,
  string-concat eval formation, aliased imports, dangerous imports
- `ReportGenerator` with custom JSON serialization handling Enum and dataclass types
- CLI entry point via `python -m veriforge`
- 20+ security regression tests

### Infrastructure
- CI workflow for Python 3.10, 3.11, 3.12
- Security workflow with Bandit, Safety, and CodeQL
