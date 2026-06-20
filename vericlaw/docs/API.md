# VeriClaw API Reference

**Version:** 0.5.0

This document describes the public API surface of the VeriClaw adversarial security testing framework. All types are fully type-hinted and runtime-checkable.

---

## Table of Contents

1. [Data Types](#data-types)
   - [EntryPoint](#entrypoint)
   - [DataFlow](#dataflow)
   - [Boundary](#boundary)
   - [AttackVector](#attackvector)
   - [AttackSurface](#attacksurface)
   - [Mutation](#mutation)
   - [Payload](#payload)
   - [PropertyProof](#propertyproof)
   - [Finding](#finding)
   - [SecurityCertificate](#securitycertificate)
   - [ScanResult](#scanresult)
   - [RedTeamResult](#redteamresult)
2. [ReportGenerator](#reportgenerator)
   - [generate_html](#generate_html)
   - [generate_sarif](#generate_sarif)
   - [generate_markdown](#generate_markdown)
   - [render_certificate](#render_certificate)
3. [Helper Functions](#helper-functions)
4. [Configuration](#configuration)
5. [Error Handling](#error-handling)

---

## Data Types

All data types are implemented as `@dataclass` and live in the `vericlaw` package root. They can be imported with:

```python
from vericlaw import (
    EntryPoint, DataFlow, Boundary, AttackVector,
    AttackSurface, Mutation, Payload, PropertyProof,
    Finding, SecurityCertificate, ScanResult, RedTeamResult,
)
```

---

### EntryPoint

```python
@dataclass
class EntryPoint:
    name: str
    type: str                     # "function" | "class" | "method" | "endpoint"
    line: int
    parameters: list[str] = []
    returns: Optional[str] = None
    decorators: list[str] = []
    docstring: Optional[str] = None
    risk_indicators: list[str] = []
```

Represents a single entry point into the application's attack surface.

**Example:**

```python
ep = EntryPoint(
    name="process_user_input",
    type="function",
    line=42,
    parameters=["data: str", "opts: dict"],
    returns="Response",
    risk_indicators=["accepts user input", "no type validation"],
)
```

---

### DataFlow

```python
@dataclass
class DataFlow:
    source: str                   # Where untrusted data enters
    sink: str                     # Where it's used dangerously
    path: list[str] = []
    taint_level: str = "low"      # "high" | "medium" | "low"
```

Models a taint flow from a source to a sink.

**Example:**

```python
df = DataFlow(
    source="request.body.username",
    sink="execute_query()",
    path=["validate_input", "build_query"],
    taint_level="high",
)
```

---

### Boundary

```python
@dataclass
class Boundary:
    name: str
    type: str                     # "network" | "filesystem" | "database" | "process"
    protections: list[str] = []
    gaps: list[str] = []
```

A trust boundary in the system architecture.

**Example:**

```python
b = Boundary(
    name="API Gateway",
    type="network",
    protections=["TLS 1.3", "mTLS"],
    gaps=["no rate limiting"],
)
```

---

### AttackVector

```python
@dataclass
class AttackVector:
    type: str                     # OWASP category, e.g. "Injection"
    entry_point: str
    confidence: float             # 0.0 - 1.0
    evidence: str
    cwe_id: Optional[str] = None
```

A classified attack vector with confidence scoring.

**Example:**

```python
av = AttackVector(
    type="SQL Injection",
    entry_point="process_user_input",
    confidence=0.92,
    evidence="User input concatenated into SQL query at line 55",
    cwe_id="89",
)
```

---

### AttackSurface

```python
@dataclass
class AttackSurface:
    entry_points: list[EntryPoint] = []
    data_flows: list[DataFlow] = []
    trust_boundaries: list[Boundary] = []
    attack_vectors: list[AttackVector] = []
    risk_score: float = 0.0       # 0.0 - 10.0
```

Complete attack surface discovered for a target.

**Example:**

```python
surface = AttackSurface(
    entry_points=[ep],
    data_flows=[df],
    trust_boundaries=[b],
    attack_vectors=[av],
    risk_score=6.5,
)
```

---

### Mutation

```python
@dataclass
class Mutation:
    original: str
    mutated: str
    mutation_type: str            # "boundary" | "injection" | "encoding" | "semantic" | "resource"
    description: str
    severity: str                 # "critical" | "high" | "medium" | "low"
```

A single adversarial code mutation produced by the mutator.

**Example:**

```python
m = Mutation(
    original="user_input = request.args.get('q')",
    mutated="user_input = request.args.get('q') + ' OR 1=1'",
    mutation_type="injection",
    description="Append tautology to test SQL injection",
    severity="high",
)
```

---

### Payload

```python
@dataclass
class Payload:
    content: str
    payload_type: str             # "sql_injection" | "xss" | "command_injection" | ...
    context: str                  # Where this payload triggers
    encoding: str                 # "raw" | "base64" | "urlencode" | "hex" | "unicode"
    severity: str
```

An attack payload generated for a specific vulnerability context.

**Example:**

```python
p = Payload(
    content="<script>alert(1)</script>",
    payload_type="xss",
    context="Reflected in search results page",
    encoding="raw",
    severity="high",
)
```

---

### PropertyProof

```python
@dataclass
class PropertyProof:
    property_name: str
    status: str                   # "proven" | "violated" | "timeout" | "error"
    counterexample: Optional[str] = None
    verification_time_ms: int = 0
    confidence: float = 0.0       # 0.0 - 1.0
```

Result of an attempt to formally prove a security property.

**Example:**

```python
proof = PropertyProof(
    property_name="type_safety",
    status="proven",
    counterexample=None,
    verification_time_ms=1200,
    confidence=0.99,
)
```

---

### Finding

```python
@dataclass
class Finding:
    id: str
    title: str
    severity: str                 # "critical" | "high" | "medium" | "low"
    category: str
    description: str
    evidence: str
    remediation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
```

A security finding produced by the scan pipeline.

**Example:**

```python
f = Finding(
    id="VC-SQLI-001",
    title="SQL Injection in login handler",
    severity="critical",
    category="Injection",
    description="User-supplied username is concatenated into SQL without parameterisation.",
    evidence="Line 55: query = f\"SELECT * FROM users WHERE name = '{username}'\"",
    remediation="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE name = ?', (username,))",
    cwe_id="89",
    cvss_score=9.8,
)
```

---

### SecurityCertificate

```python
@dataclass(frozen=True)
class SecurityCertificate:
    target: str
    timestamp: str                # ISO-8601
    findings: list[Finding]
    proofs: list[PropertyProof]
    risk_score: float             # 0.0 - 10.0
    grade: str                    # "A+" | "A" | "B" | "C" | "D" | "F"
    signature: str                # HMAC-SHA256 hex digest
    expires: str                  # ISO-8601
```

An **immutable**, cryptographically signed security certificate. Because it is
`frozen=True`, instances are hashable and suitable for use as cache keys.

**Example:**

```python
cert = SecurityCertificate(
    target="src/app.py",
    timestamp="2025-06-19T12:00:00Z",
    findings=[f],
    proofs=[proof],
    risk_score=3.2,
    grade="B",
    signature="a3f7c2...9e4b",
    expires="2025-09-19T12:00:00Z",
)
```

---

### ScanResult

```python
@dataclass
class ScanResult:
    target: str
    timestamp: str
    attack_surface: AttackSurface
    mutations: list[Mutation]
    payloads: list[Payload]
    proofs: list[PropertyProof]
    findings: list[Finding]
    certificate: Optional[SecurityCertificate] = None
    risk_score: float = 0.0
    grade: str = "F"
```

Top-level result produced by `VeriClawEngine.scan()`. This is the primary
input to `ReportGenerator`.

**Example:**

```python
result = ScanResult(
    target="src/app.py",
    timestamp="2025-06-19T12:00:00Z",
    attack_surface=surface,
    mutations=[m],
    payloads=[p],
    proofs=[proof],
    findings=[f],
    certificate=cert,
    risk_score=3.2,
    grade="B",
)
```

---

### RedTeamResult

```python
@dataclass
class RedTeamResult:
    target: str
    rounds: int
    findings: list[Finding]
    attack_chain: list[dict] = []
    success_rate: float = 0.0
    time_elapsed_ms: int = 0
```

Result of an autonomous red-team simulation.

---

## ReportGenerator

```python
class ReportGenerator:
    def generate_html(self, result: ScanResult) -> str: ...
    def generate_sarif(self, result: ScanResult) -> dict: ...
    def generate_markdown(self, result: ScanResult) -> str: ...
    def render_certificate(self, certificate: SecurityCertificate, template_path: Optional[str] = None) -> str: ...
```

The primary reporting interface. All methods accept a `ScanResult` and return
strings (or a dict for SARIF). No external network calls are made.

**Construction:**

```python
from vericlaw.report import ReportGenerator

gen = ReportGenerator()
```

`ReportGenerator` has no configuration options and is stateless. A single
instance can safely be shared across threads.

---

### generate_html

```python
def generate_html(self, result: ScanResult) -> str
```

Produce a self-contained HTML report string.

| Parameter | Type | Description |
|-----------|------|-------------|
| `result` | `ScanResult` | Scan result to render. |

**Returns:** `str` — complete HTML document with inline CSS and a small
embedded JavaScript table sorter.

**Raises:**
- `TypeError` — if *result* is not a `ScanResult`.

**Features:**
- Executive summary with colour-coded grade badge.
- SVG-free risk-score gauge (pure CSS conic-gradient).
- Sortable findings table (click column headers).
- Attack-surface breakdown (entry points, data flows, trust boundaries).
- Property-proofs table with pass/fail icons.
- Side-by-side original → mutated code blocks.
- Syntax-highlighted payload cards.
- Certificate / signature-verification block.
- Attack-chain flow diagram.
- Remediation recommendations grouped by finding.
- Dark theme via `prefers-color-scheme: dark`.
- Fully responsive down to 320 px.

**Example:**

```python
html = gen.generate_html(result)
Path("report.html").write_text(html, encoding="utf-8")
```

---

### generate_sarif

```python
def generate_sarif(self, result: ScanResult) -> dict[str, Any]
```

Produce a SARIF v2.1.0 dictionary.

| Parameter | Type | Description |
|-----------|------|-------------|
| `result` | `ScanResult` | Scan result to export. |

**Returns:** `dict` — SARIF document ready for `json.dump(...)`.

**Raises:**
- `TypeError` — if *result* is not a `ScanResult`.

**Mapping conventions:**

| VeriClaw field | SARIF field |
|----------------|-------------|
| `Finding.id` | `result.properties.id` |
| `Finding.category` | `rule.id` (normalised) |
| `Finding.severity` | `result.level` |
| `Finding.title` | `rule.shortDescription.text` |
| `Finding.description` | `result.message.text` |
| `Finding.cwe_id` | `result.properties.cwe` |
| `Finding.cvss_score` | `result.properties.cvssScore` |
| `PropertyProof.violated` | Additional `VC-PROPERTY_VIOLATION` result |
| `ScanResult.grade` | `run.properties.veriClaw.grade` |

**Example:**

```python
import json

sarif = gen.generate_sarif(result)
Path("results.sarif").write_text(
    json.dumps(sarif, indent=2), encoding="utf-8"
)
```

---

### generate_markdown

```python
def generate_markdown(self, result: ScanResult) -> str
```

Produce a concise Markdown summary suitable for GitHub PR comments.

| Parameter | Type | Description |
|-----------|------|-------------|
| `result` | `ScanResult` | Scan result to summarise. |

**Returns:** `str` — Markdown text.

**Raises:**
- `TypeError` — if *result* is not a `ScanResult`.

**Output includes:**
- Grade badge with colour span.
- Risk score.
- Finding count with severity breakdown.
- Table of top 10 findings.
- Property-proof summary.
- Mutation & payload counts.
- Certificate signature status.

**Example:**

```python
md = gen.generate_markdown(result)
print(md)   # paste into GitHub PR comment
```

---

### render_certificate

```python
def render_certificate(
    self,
    certificate: SecurityCertificate,
    template_path: Optional[str] = None,
) -> str
```

Render a `SecurityCertificate` through the bundled Jinja2 template (or a
custom one).

| Parameter | Type | Description |
|-----------|------|-------------|
| `certificate` | `SecurityCertificate` | Certificate to render. |
| `template_path` | `Optional[str]` | Filesystem path to a custom `.html` template. If `None`, the bundled `vericlaw/templates/certificate.html` is used. |

**Returns:** `str` — rendered HTML document.

**Raises:**
- `jinja2.TemplateNotFound` — if the specified template cannot be located.
- `TypeError` — propagated from Jinja2 if template variables are missing.

**Template variables available:**

| Variable | Type | Description |
|----------|------|-------------|
| `target` | `str` | Certificate target path/name. |
| `grade` | `str` | Letter grade (A+, A, B, C, D, F). |
| `grade_colour` | `str` | Hex colour code for the grade. |
| `risk_score` | `float` | Numeric risk score 0.0–10.0. |
| `risk_percentage` | `float` | Risk score as percentage 0–100. |
| `findings` | `list[dict]` | List of finding dicts. |
| `proofs` | `list[dict]` | List of proof dicts. |
| `signature` | `str` | HMAC-SHA256 signature string. |
| `signature_verified` | `bool` | Whether signature is present and non-empty. |
| `timestamp` | `str` | ISO-8601 issue timestamp. |
| `expires` | `str` | ISO-8601 expiry timestamp. |
| `version` | `str` | VeriClaw version string. |

**Example (bundled template):**

```python
html_cert = gen.render_certificate(cert)
Path("certificate.html").write_text(html_cert, encoding="utf-8")
```

**Example (custom template):**

```python
html_cert = gen.render_certificate(
    cert,
    template_path="/path/to/my_certificate.html",
)
```

---

## Helper Functions

The `vericlaw.report` module exposes a small number of internal helpers that
may be useful when building custom reports:

| Function | Signature | Purpose |
|----------|-----------|---------|
| `_grade_colour` | `(grade: str) -> str` | Map grade letter to hex colour. |
| `_severity_sort_key` | `(severity: str) -> int` | Numeric rank for severity (critical=0, low=3). |
| `_h` | `(v: str) -> str` | HTML-escape a value. |

These are prefixed with an underscore by convention but are stable and tested.

---

## Configuration

`ReportGenerator` itself requires no configuration. Behaviour is controlled
through the `ScanResult` data passed to each method.

If you need to customise the certificate appearance, supply your own Jinja2
template via `render_certificate(..., template_path=...)`.

Environment variables consumed by the wider VeriClaw system (not
`ReportGenerator` directly):

| Variable | Default | Purpose |
|----------|---------|---------|
| `VERIFORGE_SECRET_KEY` | `""` | Secret key used by `SecurityCertifier` for HMAC-SHA256 signing. |
| `VERICLAW_TIMEOUT` | `300` | Default scan timeout in seconds. |
| `VERICLAW_POLICY_LEVEL` | `"standard"` | Policy strictness (`strict`, `standard`, `permissive`). |

---

## Error Handling

All `ReportGenerator` methods validate their inputs and raise specific
exceptions on misuse:

| Scenario | Exception | Message |
|----------|-----------|---------|
| `generate_html` called with non-`ScanResult` | `TypeError` | `"result must be a ScanResult instance"` |
| `generate_sarif` called with non-`ScanResult` | `TypeError` | `"result must be a ScanResult instance"` |
| `generate_markdown` called with non-`ScanResult` | `TypeError` | `"result must be a ScanResult instance"` |
| Missing Jinja2 template | `jinja2.TemplateNotFound` | Template name |

No method raises exceptions for empty findings lists or missing certificates;
all gracefully render placeholder / omitted sections.

---

## Complete Example

```python
from pathlib import Path
from vericlaw import ScanResult, AttackSurface, Finding, PropertyProof, SecurityCertificate
from vericlaw.report import ReportGenerator

# Assume result comes from VeriClawEngine.scan(...)
result = ScanResult(
    target="src/app.py",
    timestamp="2025-06-19T12:00:00Z",
    attack_surface=AttackSurface(risk_score=2.5),
    mutations=[],
    payloads=[],
    proofs=[
        PropertyProof("type_safety", "proven", confidence=0.98),
        PropertyProof("memory_safety", "proven", confidence=0.95),
    ],
    findings=[
        Finding(
            id="VC-001", title="Weak hash algorithm",
            severity="medium", category="Cryptography",
            description="MD5 is used for password hashing.",
            evidence="Line 12: hashlib.md5(pwd)",
            remediation="Switch to bcrypt or Argon2.",
        ),
    ],
    certificate=None,
    risk_score=2.5,
    grade="A",
)

gen = ReportGenerator()

# Generate all three formats
Path("report.html").write_text(gen.generate_html(result), encoding="utf-8")
Path("report.sarif").write_text(
    json.dumps(gen.generate_sarif(result), indent=2),
    encoding="utf-8",
)
Path("report.md").write_text(gen.generate_markdown(result), encoding="utf-8")
```
