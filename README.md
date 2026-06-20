# VeriForge

![CI](https://github.com/veriforge/veriforge/workflows/CI/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-20%2B-brightgreen)
![Security](https://img.shields.io/badge/security-hardened-red)

**Hardened Formal Verification Platform** with defense-in-depth security, immutable audit trails, and multi-standard compliance auditing.

> VeriForge has been hardened against **12 CVEs** (CVE-2024-001 through CVE-2024-012), replacing dynamic code execution with static AST analysis, adding HMAC-signed immutable results, and implementing full RBAC, rate limiting, and tamper-evident audit logging.

---

## Features

- **No-eval guarantee** — Pure static AST analysis, never `eval()` or `exec()`
- **HMAC-signed results** — Every verification result is cryptographically signed
- **Immutable audit chain** — Tamper-evident HMAC-chained audit log
- **JWT + RBAC** — Full authentication and role-based access control
- **Rate limiting** — Per-subject sliding-window rate limiting
- **Path sanitization** — Multi-layer directory traversal protection
- **Obfuscation detection** — Semantic analysis for code obfuscation
- **Compliance auditing** — SOC 2, ISO 27001, and PCI-DSS automated checks
- **Safe JSON serialization** — Controlled serialization without pickle/eval
- **Environment-only secrets** — No hard-coded credentials

---

## Quick Start

### Environment Setup

```bash
# Required secrets (generate strong random values)
export VERIFORGE_SECRET="$(openssl rand -hex 32)"
export VERIFORGE_JWT_SECRET="$(openssl rand -hex 32)"
export VERIFORGE_AUDIT_SECRET="$(openssl rand -hex 32)"
```

### Installation

```bash
pip install veriforge
```

Or from source:

```bash
git clone https://github.com/veriforge/veriforge.git
cd veriforge
pip install -e ".[dev]"
```

### Example Usage

```python
from veriforge.engine import VeriForgeEngine
from veriforge.config import SecureConfig

config = SecureConfig()
engine = VeriForgeEngine(config=config)

# Verify clean code
result = engine.verify_code("x = 1 + 2\n")
print(result.verified)  # True

# Detect dangerous code
result = engine.verify_code("eval(user_input)\n")
print(result.verified)  # False
print(result.findings)  # ('SECURITY: Dangerous pattern...',)
```

### CLI Usage

```bash
# Scan a file
veriforge scan file.py

# Scan a directory
veriforge scan ./project --output report.json

# Verify audit chain
veriforge audit --verify-chain

# Export audit log
veriforge audit --export audit.json
```

---

## Architecture

```
+--------------------------------------------------+
| LAYER 5 | SOC2 / ISO27001 / PCI-DSS auditors     |
+---------+----------------------------------------+
| LAYER 4 | Immutable HMAC-chained audit log       |
+---------+----------------------------------------+
| LAYER 3 | JWT authentication + RBAC + rate limit |
+---------+----------------------------------------+
| LAYER 2 | Path sanitization + input validation   |
+---------+----------------------------------------+
| LAYER 1 | No-eval engine + frozen HMAC results   |
+--------------------------------------------------+
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the complete security architecture.

---

## Security Features

| Feature | Implementation |
|---------|---------------|
| No dynamic execution | `ast.parse()` + `ast.walk()` only |
| Result immutability | `@dataclass(frozen=True, slots=True)` |
| Cryptographic signing | HMAC-SHA256 with constant-time verification |
| Directory traversal | Null byte + `../` + unsafe char + allow-list checks |
| Authentication | HS256 JWT with configurable expiry |
| Authorization | 4-level RBAC (admin/auditor/scanner/viewer) |
| Rate limiting | Sliding-window per-subject counters |
| Audit integrity | HMAC-chained entries with forward linkage |
| JSON safety | `SafeJSONEncoder` — no pickle, no eval |

---

## Project Structure

```
veriforge_github/
├── veriforge/          # Core package (11 modules)
│   ├── engine.py       # VeriForgeEngine (no eval, HMAC)
│   ├── auth.py         # AuthManager (JWT, RBAC)
│   ├── audit.py        # ImmutableAuditLog (HMAC chain)
│   ├── semantic.py     # SemanticAnalyzer (obfuscation)
│   ├── config.py       # SecureConfig (env vars)
│   ├── compliance.py   # SOC2/ISO27001/PCI-DSS
│   ├── agent.py        # AgentVerifier (auth)
│   ├── ide.py          # IDEVerifier (path sanitize)
│   └── report.py       # ReportGenerator (safe JSON)
├── tests/              # 20+ security regression tests
├── examples/           # Runnable usage examples
├── docs/               # Architecture, API, Deployment
└── .github/workflows/  # CI/CD (Python 3.10-3.12)
```

---

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — 5-layer defense-in-depth model
- [API Reference](docs/API.md) — All public classes and methods
- [Deployment](docs/DEPLOYMENT.md) — Docker and Kubernetes guides

---

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=veriforge --cov-report=term-missing

# Lint
black --check veriforge/
mypy veriforge/
bandit -r veriforge/

# Format
black veriforge/ tests/ examples/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
