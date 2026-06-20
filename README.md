# VeriClaw

**Adversarial Security Testing Framework built on VeriForge**

[![CI](https://github.com/veriforge/vericlaw/actions/workflows/ci.yml/badge.svg)](https://github.com/veriforge/vericlaw/actions)
[![PyPI](https://img.shields.io/pypi/v/vericlaw)](https://pypi.org/project/vericlaw/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-319%20passing-brightgreen)]()

---

## What is VeriClaw?

VeriClaw transforms VeriForge's formal verification engine into an **active, continuous security validation platform**. While traditional security tools passively scan for known vulnerabilities, VeriClaw actively generates adversarial mutations, proves security properties formally, and runs autonomous red team simulations — all backed by cryptographically signed security certificates.

### Key Capabilities

| Capability | What It Does |
|-----------|-------------|
| **Attack Surface Analysis** | AST-based discovery of entry points, data flows, and trust boundaries |
| **Adversarial Mutation** | 8 mutation strategies — boundary, injection, encoding, semantic, resource, null, empty, type confusion |
| **Payload Generation** | Context-aware payloads for SQLi, XSS, command injection, path traversal, deserialization, prototype pollution |
| **Formal Property Proving** | Proves type safety, memory safety, and injection resistance via AST inspection |
| **Security Certification** | HMAC-SHA256 signed certificates with letter grades (A+ to F) and 90-day expiration |
| **Red Team Swarm** | Multi-agent autonomous red teaming with 5 specialist agents and attack chain construction |
| **CI/CD Security Gate** | Configurable strict/standard/permissive policy enforcement |
| **MCP Integration** | Native Model Context Protocol tools for Claude, Cursor, GitHub Copilot |

---

## Quick Start

### Installation

```bash
pip install vericlaw
```

### Set Environment Variables

```bash
export VERIFORGE_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export VERIFORGE_ADMIN_TOKEN="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export VERIFORGE_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

### Run a Scan

```python
from vericlaw import VeriClawEngine

engine = VeriClawEngine(config={"policy_level": "standard"})

# Scan a file
result = engine.scan("my_app.py")
print(f"Grade: {result.grade}")
print(f"Risk Score: {result.risk_score}/10")
print(f"Findings: {len(result.findings)}")

# Generate a certificate
cert = engine.certify("my_app.py")
print(f"Certificate signature verified: {certifier.verify(cert)}")
```

### Run Red Team

```python
from vericlaw import VeriClawEngine

engine = VeriClawEngine()
result = engine.red_team("my_app.py", rounds=5)

for step in result.attack_chain:
    print(f"{step['phase']}: {step['finding']}")
```

### CI/CD Gate

```python
from vericlaw import VeriClawEngine, PolicyEngine

engine = VeriClawEngine()
policy = PolicyEngine(level="strict")

result = engine.scan(".")
decision = policy.check(result)

if not decision.passed:
    print("SECURITY GATE FAILED:")
    for v in decision.violations:
        print(f"  - {v}")
    exit(1)
```

---

## Architecture

```
Your Code
    |
    v
+---------------------------------------+
|  VeriClaw Engine                      |
|  (scan / red_team / certify)          |
+---------------------------------------+
    |           |           |
    v           v           v
+--------+ +--------+ +-----------+
|Analyzer| |Mutator | | Prover    |
|+Payload| |+Fuzzer | |+Certifier |
+--------+ +--------+ +-----------+
    |           |           |
    v           v           v
+--------+ +--------+ +-----------+
|  CI/CD | | Swarms | |  MCP      |
|  Gate  | |RedTeam | |  Tools    |
+--------+ +--------+ +-----------+
    |           |           |
    v           v           v
+--------+ +--------+ +-----------+
|Policy  | |Attack  | |Claude/    |
|Engine  | |Chain   | |Cursor/    |
+--------+ +--------+ |Copilot    |
                      +-----------+
```

---

## Built on VeriForge

VeriClaw is built on top of the hardened VeriForge platform:

- **12 CVEs patched** — No eval(), immutable audit logs, HMAC signatures, JWT + RBAC
- **Formal verification engine** — Syntax, semantic, formal, and compliance layers
- **Immutable audit chain** — HMAC-chained, tamper-evident logging
- **Agent swarm support** — Byzantine fault tolerant consensus

---

## Security Grades

| Grade | Risk Score | Meaning |
|-------|-----------|---------|
| **A+** | 0.0 | Zero findings — all properties proven |
| **A** | 0.1 - 2.0 | Excellent — minimal surface, all proofs pass |
| **B** | 2.1 - 4.0 | Good — some findings, key proofs pass |
| **C** | 4.1 - 6.0 | Fair — moderate risk, partial proofs |
| **D** | 6.1 - 8.0 | Poor — significant findings, proofs fail |
| **F** | 8.1 - 10.0 | Critical — immediate action required |

---

## GitHub Actions Integration

Add to `.github/workflows/security.yml`:

```yaml
name: VeriClaw Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install vericlaw
      - run: python -m vericlaw.scan --target . --format sarif --output results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
      - run: python -m vericlaw.gate --target . --policy standard
```

---

## MCP Integration

VeriClaw exposes 4 tools via Model Context Protocol for any MCP-compatible AI:

| Tool | Description |
|------|-------------|
| `vericlaw_scan` | Full adversarial scan with grade and certificate |
| `vericlaw_red_team` | Autonomous red team with attack chain |
| `vericlaw_certify` | Generate signed security certificate |
| `vericlaw_explain` | Explain any finding with remediation |

### Claude Desktop Config

```json
{
  "mcpServers": {
    "vericlaw": {
      "command": "python",
      "args": ["-m", "veriforge_mcp.server", "--transport", "stdio"],
      "env": {
        "VERIFORGE_SECRET_KEY": "your-secret-key"
      }
    }
  }
}
```

---

## Documentation

- [API Reference](vericlaw/docs/API.md) — Full API documentation
- [Deployment Guide](vericlaw/docs/DEPLOYMENT.md) — Docker, K8s, CI/CD
- [Architecture](vericlaw/docs/ARCHITECTURE.md) — Design principles

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

MIT License — see [LICENSE](LICENSE).
