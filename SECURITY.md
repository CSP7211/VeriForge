# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.5.x   | :white_check_mark: |
| < 0.5   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in VeriClaw, please report it responsibly:

1. **Email**: security@veriforge.dev
2. **Subject**: `[SECURITY] VeriClaw — Brief description`
3. **Include**:
   - Steps to reproduce
   - Expected vs actual behavior
   - Impact assessment
   - Suggested fix (if any)

We will respond within 48 hours and aim to release a patch within 7 days.

## Security Features

- No `eval()` or `exec()` on user input
- HMAC-SHA256 signed certificates
- Immutable audit logs with hash chaining
- JWT-based authentication for agent endpoints
- RBAC with role-based capability enforcement
- Rate limiting on all endpoints
- Path traversal protection via `Path.relative_to()`
- Resource limits and timeouts on all operations

## Security Hardening History

VeriClaw is built on VeriForge v0.4.0-hardened which patched 12 CVEs:
- 2 Critical (hardcoded secrets, RCE via eval)
- 3 High (path traversal, unauthenticated endpoints, semantic bypass)
- 6 Medium (DoS, weak compliance, JSON bugs, mutable results, supply chain, audit log)
- 1 Low (information disclosure)
