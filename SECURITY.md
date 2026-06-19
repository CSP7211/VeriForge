# Security Policy

## Reporting a Vulnerability

Email: security@veriforge.dev
Subject: [SECURITY] VeriForge Red — Brief description

We respond within 48 hours and aim to release a patch within 7 days.

## Security Architecture

- No eval() or exec() on user input
- AES-256 (Fernet) for quarantine encryption
- PBKDF2 + Fernet for vault encryption
- All processing is local — zero network
- HMAC-SHA256 for certificate signing
- Immutable audit logs with hash chaining
