# VeriForge SDK -- Unified Developer Kit

[![PyPI](https://img.shields.io/pypi/v/veriforge-sdk)](https://pypi.org/project/veriforge-sdk/)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> **One SDK. Seven products. Infinite confidence.**

The **VeriForge SDK** is a unified, type-safe Python client for the entire
VeriForge security platform. With a single import you get authenticated access
to code scanning, test generation, DSL verification, tool sandboxing,
distributed consensus, and compliance auditing.

---

## Overview

VeriForge is a modular security platform composed of seven specialized products:

| # | Product | Purpose |
|---|---------|---------|
| 1 | **RED** | Automated security code scanner |
| 2 | **VeriClaw** | Test generation & execution harness |
| 3 | **DSL Verify** | Domain-specific language rule checker |
| 4 | **MCP Tools** | Model Context Protocol tool sandbox |
| 5 | **Swarm** | Distributed multi-party consensus |
| 6 | **Core** | Compliance auditing & result signing |

The SDK abstracts authentication, retry logic, error handling, and result
parsing so you can focus on shipping secure code.

---

## Installation

### From PyPI (recommended)

```bash
pip install veriforge-sdk
```

### From Source

```bash
git clone https://github.com/veriforge/veriforge-sdk.git
cd veriforge-sdk
pip install -e ".[dev]"
```

### Requirements

- Python 3.9 or newer
- No mandatory heavy dependencies (stdlib + dataclasses)

---

## Quick Start

### 1. RED -- Security Code Scan

```python
from veriforge_sdk import VeriForgeClient

client = VeriForgeClient()
result = client.red.scan("/path/to/code")

print(f"Grade: {result.grade.value}")
print(f"Scan ID: {result.scan_id}")
print(f"Duration: {result.duration_ms:.1f}ms")

for f in result.findings:
    print(f"  [{f.severity.value}] {f.title}")
    if f.remediation:
        print(f"      -> {f.remediation}")
```

### 2. VeriClaw -- Automated Testing

```python
result = client.vericlaw.test("/path/to/tests", coverage=True)

print(f"Passed: {result.passed}/{result.total}")
print(f"Coverage: {result.coverage_percent:.1f}%")
print(f"Success rate: {result.success_rate:.1%}")

if not result.ok:
    for err in result.errors:
        print(f"  ERROR: {err}")
```

### 3. DSL Verify -- Policy & Config Validation

```python
result = client.dsl.verify("config.yaml", rules="security.rules")

if result.verified:
    print("All rules passed!")
else:
    print(f"Failed {result.rules_failed}/{result.rules_checked} rules")
    for v in result.violations:
        print(f"  [VIOLATION] {v}")
```

### 4. MCP Tools -- Sandboxed Tool Calls

```python
result = client.mcp.call_tool("git.status", {"path": "/repo"})

print(f"Tool: {result.tool_name}")
print(f"Exit code: {result.exit_code}")
print(f"Output:\n{result.stdout}")

if result.stderr:
    print(f"Errors:\n{result.stderr}")
```

### 5. Swarm -- Distributed Consensus

```python
result = client.swarm.consensus(
    topic="deploy-v2",
    proposal="Approve deployment of v2.0.0",
    quorum=3,
)

if result.reached:
    print(f"Consensus reached! Outcome: {result.outcome}")
    print(f"Agreement: {result.agreement_ratio:.0%}")
    print(f"Confidence: {result.confidence.value}")
else:
    print("Consensus not reached")
    print(f"Votes: {result.votes}")
```

### 6. Core -- Compliance Audit

```python
result = client.core.audit_compliance("SOC2")

print(f"Standard: {result.standard}")
print(f"Compliant: {result.compliant}")
print(f"Score: {result.score}%")

for ctrl in result.controls:
    status = "PASS" if ctrl.passed else "FAIL"
    print(f"  [{status}] {ctrl.control_id}: {ctrl.title}")
    if not ctrl.passed:
        print(f"       Remediation: {ctrl.remediation}")
```

### 7. Platform Health Check

```python
health = client.health()

print(f"Status: {health.status}")
print(f"Version: {health.version}")
print(f"Uptime: {health.uptime_seconds:.0f}s")

for product, status in health.products.items():
    print(f"  {product}: {status}")
```

---

## API Reference

### `VeriForgeClient`

The central entry point. Initialize once and reuse across your application.

```python
from veriforge_sdk import VeriForgeClient, SDKConfig

# From environment variables (VERIFORGE_API_KEY required)
client = VeriForgeClient()

# With explicit configuration
config = SDKConfig(api_key="vf_key_xxx", timeout=60)
client = VeriForgeClient(config=config)

# Context manager
with VeriForgeClient() as client:
    result = client.red.scan("./src")
```

### Configuration

```python
from veriforge_sdk import SDKConfig

# From environment (raises if VERIFORGE_API_KEY is missing)
config = SDKConfig.from_env()

# With defaults (offline mode)
config = SDKConfig.default()

# Merge to create a modified copy
fast_config = config.merge(timeout=5, max_retries=1)
```

### Error Handling

All SDK errors inherit from `VeriForgeSDKError`:

```python
from veriforge_sdk import (
    VeriForgeClient,
    VeriForgeSDKError,
    ScanError,
    ScanTimeoutError,
    ProductNotFoundError,
    NetworkError,
    RateLimitError,
)

client = VeriForgeClient()

try:
    result = client.red.scan("./src")
except ScanTimeoutError as exc:
    print(f"Scan timed out after {exc.timeout_seconds}s")
except ScanError as exc:
    print(f"Scan failed: {exc.message}")
except RateLimitError as exc:
    print(f"Rate limited. Retry after {exc.retry_after}s")
except VeriForgeSDKError as exc:
    print(f"SDK error {exc.code.value}: {exc.message}")
```

### Signing & Verification

```python
from veriforge_sdk import VeriForgeClient

client = VeriForgeClient()

# Sign any result
result = client.red.scan("./src")
signed = client.core.sign_result(result)

print(f"Signature: {signed.signature}")
print(f"Algorithm: {signed.algorithm}")

# Verify later
assert client.core.verify_signature(signed), "Signature invalid!"
```

---

## Product Reference

| Product | Module | Key Methods | Description |
|---------|--------|-------------|-------------|
| **RED** | `client.red` | `scan()`, `get_scan()`, `list_rules()` | Static code security analysis |
| **VeriClaw** | `client.vericlaw` | `test()`, `get_test()`, `fuzz()` | Property-based test generation |
| **DSL Verify** | `client.dsl` | `verify()`, `validate_schema()`, `list_rules()` | Policy & DSL rule checking |
| **MCP Tools** | `client.mcp` | `call_tool()`, `list_tools()`, `describe_tool()` | Sandboxed tool invocation |
| **Swarm** | `client.swarm` | `consensus()`, `get_round()`, `vote()` | Distributed consensus |
| **Core** | `client.core` | `audit_compliance()`, `sign_result()`, `verify_signature()`, `health()` | Compliance & signing |

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VERIFORGE_API_KEY` | Yes* | None | Authentication bearer token |
| `VERIFORGE_BASE_URL` | No | `https://api.veriforge.io/v1` | API base URL |
| `VERIFORGE_TIMEOUT` | No | `30` | Request timeout (seconds) |
| `VERIFORGE_MAX_RETRIES` | No | `3` | Retry count |
| `VERIFORGE_VERIFY_SSL` | No | `true` | TLS certificate validation |
| `VERIFORGE_LOG_LEVEL` | No | `WARNING` | SDK logging verbosity |
| `VERIFORGE_USER_AGENT` | No | None | Custom user-agent suffix |
| `VERIFORGE_PROJECT_ID` | No | None | Default project context |
| `VERIFORGE_ORG_ID` | No | None | Organization identifier |
| `VERIFORGE_DISABLE_TELEMETRY` | No | `0` | Set to `1` to opt out |

*Required for full platform access. The SDK falls back to local mode if absent.

---

## Security & CVE Mitigations

The VeriForge SDK implements defense-in-depth mitigations for the
following CVE categories:

| CVE | Category | Mitigation |
|-----|----------|------------|
| CVE-2024-001 | Secure Defaults | All settings default to secure values; missing required config raises |
| CVE-2024-002 | Least Privilege | Authentication & authorization errors are distinct and informative |
| CVE-2024-003 | Input Validation | Product names and parameters are validated before dispatch |
| CVE-2024-004 | Bounds Checking | Scan targets are validated for existence and accessibility |
| CVE-2024-005 | Fuzzing Harness | Test execution is sandboxed with timeout and case limits |
| CVE-2024-006 | Type Safety | DSL verification enforces schema constraints |
| CVE-2024-007 | Sandboxing | MCP tool calls run in isolated subprocesses |
| CVE-2024-008 | Multi-Party Approval | Swarm consensus requires configurable quorum |
| CVE-2024-009 | Audit Trail | All results are cryptographically signed with HMAC-SHA256 |
| CVE-2024-010 | Secure Transport | TLS verification enabled by default; no plaintext fallback |
| CVE-2024-011 | Resource Quotas | Rate-limit errors expose Retry-After for backoff |
| CVE-2024-012 | Canonical Encoding | Results use deterministic JSON serialization |

---

## Development

```bash
# Install dev dependencies
make install

# Run tests
make test

# Lint and format
make lint

# Build distribution
make build
```

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

*VeriForge SDK v1.0.0 -- Built with security in mind.*
