# Changelog

All notable changes to VeriClaw will be documented in this file.

## [0.5.0] - 2026-06-19

### Added
- **VeriClawEngine** — Main orchestrator with `scan()`, `red_team()`, and `certify()` pipeline
- **AttackSurfaceAnalyzer** — AST-based entry point discovery with risk scoring (0.0-10.0)
- **AdversarialMutator** — 8 mutation strategies: boundary, injection, encoding, semantic, resource, null, empty, type confusion
- **PayloadGenerator** — Context-aware payloads for SQLi, XSS, command injection, path traversal, format string, deserialization, prototype pollution
- **SecurityProver** — Formal proofs for type safety, memory safety, and injection resistance
- **SecurityCertifier** — HMAC-SHA256 signed certificates with letter grades (A+ to F) and 90-day expiration
- **RedTeamSwarm** — Multi-agent red teaming with 5 specialist agents and attack chain construction
- **FuzzingSwarm** — Distributed mutation-based fuzzing
- **VerificationSwarm** — Parallel property proving
- **PolicyEngine** — CI/CD security gates with strict/standard/permissive levels
- **ReportGenerator** — Interactive HTML, SARIF v2.1.0, and Markdown output
- **MCP Tools** — 4 tools for Claude/Cursor/Copilot integration
- **GitHub Action** — CI/CD workflow for automated security scanning
- **Certificate Template** — Professional HTML certificate rendering
- **319 tests** — Comprehensive test coverage across all modules

### Architecture
- Centralized `models.py` for all shared dataclasses
- Clean relative imports with no circular dependencies
- Built on hardened VeriForge v0.4.0 platform (12 CVEs patched)

## [0.4.0] - 2026-06-19

### Security
- **VF-001** Fixed — Hardcoded secrets removed, env-based config
- **VF-002** Fixed — RCE via eval() eliminated, safe regex parser
- **VF-003** Fixed — Path traversal protected with Path.relative_to()
- **VF-004** Fixed — JWT + RBAC + rate limiting on all endpoints
- **VF-005** Fixed — Semantic analyzer with obfuscation detection
- **VF-006** Fixed — Timeouts + size/depth/assertion limits
- **VF-007** Fixed — Deep compliance checks (not just imports)
- **VF-008** Fixed — Custom JSON serialization
- **VF-009** Fixed — Frozen dataclasses + HMAC signatures
- **VF-010** Fixed — Generic error messages (no info disclosure)
- **VF-011** Fixed — Safe setup.py with context managers
- **VF-012** Fixed — Immutable audit log with HMAC chain
