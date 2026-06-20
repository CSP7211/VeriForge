# VeriForge Hardened v0.4.0

A hardened code verification platform with immutable audit trails, JWT-based authentication, HMAC integrity checks, and deep compliance auditing for SOC2 / ISO27001 / PCI-DSS.

## Security Model

| Control | Implementation |
|---------|---------------|
| Secrets | Environment variables only (`VERIFORGE_SECRET_KEY`) |
| Auth | JWT tokens with RBAC (ADMIN / AGENT / VIEWER) |
| Integrity | HMAC-SHA256 on every audit entry and verification result |
| Audit | Append-only HMAC-chained log; tamper detection via `verify_chain()` |
| Code Parsing | NO `eval()` — safe regex + AST walker only |
| Rate Limiting | Sliding window (10 req/min default) |
| Timeout | 30s per verification via signal-based decorator |
| Path Safety | `Path.relative_to()` validation; no traversal |

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Set required environment variable
export VERIFORGE_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export VERIFORGE_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"

# Run tests
pytest tests/ -v

# Verify a file
python -m veriforge verify myscript.py
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VERIFORGE_SECRET_KEY` | Yes | Master secret for HMAC signing |
| `VERIFORGE_JWT_SECRET` | No | JWT signing secret (falls back to SECRET_KEY) |
| `VERIFORGE_ADMIN_TOKEN` | No | Static admin API token |
| `VERIFORGE_API_KEY` | No | Service API key |

## Architecture

```
veriforge/
  config.py    — SecureConfig (env-only secrets)
  auth.py      — AuthManager (JWT, RBAC, rate limiting)
  audit.py     — ImmutableAuditLog (HMAC chain)
  semantic.py  — SemanticAnalyzer (obfuscation detection)
  engine.py    — VeriForgeEngine (frozen, signed results)
  compliance.py — SOC2 / ISO27001 / PCI-DSS auditors
  agent.py     — AgentVerifier (JWT + RBAC)
  ide.py       — IDEVerifier (path-sanitized)
  report.py    — ReportGenerator (fixed JSON serialization)
```

## Compliance Auditors

- **SOC2Auditor**: Requires actual `logging.info/error` calls covering security events, not just `import logging`
- **ISO27001Auditor**: Requires taint validation on user inputs before use
- **PCIDSSAuditor**: Requires real input sanitization (regex, allow-list, parameterized queries) — type casting alone is insufficient

## Security Testing

The test suite includes 20+ security regression tests covering:

- Configuration hardening
- Engine verification (valid code + attack detection)
- Source-code audit (no eval anywhere)
- HMAC integrity verification
- Frozen dataclass immutability
- Audit chain tamper detection
- JWT authentication enforcement
- Rate limiting behavior
- Path traversal blocking
- Timeout handling
- Compliance auditor accuracy
- JSON serialization correctness

## License

MIT License — see [LICENSE](LICENSE) file.
