# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.4.0-hardened | Yes |
| 0.3.0 | No (upgrade to 0.4.0-hardened) |
| < 0.3.0 | No |

## Reporting a Vulnerability

If you discover a security vulnerability in VeriForge, please report it responsibly:

1. **Do NOT** open a public issue
2. Email **security@veriforge.dev** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if available)

We will respond within **48 hours** and work with you to coordinate disclosure.

## Security Features

VeriForge implements defense-in-depth security:

- **No-eval guarantee**: All analysis is static AST-based; `eval()`/`exec()` are detected and blocked
- **HMAC-signed results**: Every verification result is cryptographically signed
- **Immutable audit chain**: Tamper-evident HMAC-chained audit logging
- **JWT + RBAC**: Full authentication and role-based access control
- **Rate limiting**: Per-subject sliding-window rate limiting
- **Path sanitization**: Multi-layer directory traversal protection
- **Safe JSON serialization**: Controlled serialization without pickle/eval

## 12 Patched CVEs

| CVE | Severity | Description |
|-----|----------|-------------|
| CVE-2024-001 | Critical | Eval code execution in verification engine |
| CVE-2024-002 | High | Mutable verification results |
| CVE-2024-003 | High | Missing HMAC signatures |
| CVE-2024-004 | High | Path traversal in IDE integration |
| CVE-2024-005 | High | JWT signature bypass |
| CVE-2024-006 | Medium | Audit log tampering |
| CVE-2024-007 | Medium | Rate limit bypass |
| CVE-2024-008 | Critical | JSON serialization RCE |
| CVE-2024-009 | High | Configuration secret exposure |
| CVE-2024-010 | Low | Obfuscation detection bypass |
| CVE-2024-011 | Medium | Timeout bypass |
| CVE-2024-012 | High | Privilege escalation in agent |

## Security Best Practices

1. Always use strong, randomly generated secrets (min 32 bytes)
2. Store secrets in environment variables or a secrets manager
3. Run VeriForge with the principle of least privilege
4. Enable audit logging in production
5. Regularly review compliance audit results
6. Keep VeriForge and dependencies up to date
