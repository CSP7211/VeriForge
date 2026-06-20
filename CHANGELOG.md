# Changelog

All notable changes to VeriForge will be documented in this file.

## [0.4.0-hardened] — 2024-01-15

### Security
- Hardened against 12 CVEs (CVE-2024-001 through CVE-2024-012)
- Replaced all dynamic code execution with static AST analysis
- Added HMAC-SHA256 signing to all verification results
- Implemented immutable frozen dataclasses for results
- Added constant-time HMAC comparison to prevent timing attacks
- Added per-subject sliding-window rate limiting
- Implemented HMAC-chained tamper-evident audit logging
- Added multi-layer path sanitization (null bytes, traversal, unsafe chars, allow-lists)
- Implemented JWT authentication with HS256 and RBAC
- Added SafeJSONEncoder to prevent serialization-based RCE
- Moved all secrets to environment variable configuration

### Added
- `VeriForgeEngine` — Hardened verification engine with no-eval guarantee
- `AuthManager` — JWT authentication with RBAC and rate limiting
- `ImmutableAuditLog` — Tamper-evident HMAC-chained audit log
- `SemanticAnalyzer` — Obfuscation and anti-pattern detection
- `AgentVerifier` — Authenticated agent verification
- `IDEVerifier` — Path-sanitized IDE integration
- `SecureConfig` — Environment-based configuration management
- `ReportGenerator` — Safe JSON serialization
- SOC2Auditor, ISO27001Auditor, PCIDSSAuditor — Compliance auditors
- CLI with `scan`, `audit`, and `dashboard` subcommands
- 20+ comprehensive security regression tests
- Docker and Kubernetes deployment manifests
- GitHub Actions CI/CD for Python 3.10–3.12

### Changed
- All result types now use `frozen=True, slots=True` dataclasses
- HMAC secrets must be provided via environment variables
- Default timeout changed from infinite to 30 seconds

### Removed
- Removed all uses of `eval()`, `exec()`, and `compile()`
- Removed hard-coded default secrets
- Removed arbitrary object serialization in reports

## [0.3.0] — 2023-11-01

### Added
- Basic verification engine with AST analysis
- Simple audit logging
- Initial compliance checks

## [0.2.0] — 2023-08-15

### Added
- Initial project scaffolding
- Basic code parsing capabilities

## [0.1.0] — 2023-06-01

### Added
- Project initialization
- Proof-of-concept verification engine
