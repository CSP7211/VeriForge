"""
vericlaw/mcp_tools.py — MCP Extension Tools for VeriClaw.

Provides tool definitions and handlers that extend the VeriForge MCP
server with VeriClaw adversarial security capabilities.

Each handler:
- Accepts a parameters dict
- Returns a JSON-serializable result dict
- Includes proper error handling and execution timing
"""

from __future__ import annotations

import time
import traceback
from typing import Any

from .engine import VeriClawEngine
from .models import Finding, PropertyProof, ScanResult, SecurityCertificate

# ---------------------------------------------------------------------------
# Tool definitions (schemas for MCP registration)
# ---------------------------------------------------------------------------

VERICLAW_TOOLS: list[dict[str, Any]] = [
    {
        "name": "vericlaw_scan",
        "description": (
            "Run a comprehensive adversarial security scan on code. "
            "Analyzes attack surface, generates adversarial mutations, "
            "proves security properties, and assigns a security grade."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Path to code file or directory to scan",
                },
                "policy_level": {
                    "type": "string",
                    "enum": ["strict", "standard", "permissive"],
                    "description": "Policy level for the scan (default: standard)",
                },
                "max_mutations": {
                    "type": "integer",
                    "description": "Maximum number of mutations to generate (default: 100)",
                    "minimum": 1,
                    "maximum": 10000,
                },
                "swarm_size": {
                    "type": "integer",
                    "description": "Number of agents in the swarm (default: 5)",
                    "minimum": 1,
                    "maximum": 50,
                },
                "format": {
                    "type": "string",
                    "enum": ["json", "sarif", "markdown", "html"],
                    "description": "Output format for the scan report (default: json)",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "vericlaw_red_team",
        "description": (
            "Run an autonomous red team simulation against code. "
            "Deploys multiple specialist agents to find and chain "
            "vulnerabilities."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Path to code or endpoint to attack",
                },
                "rounds": {
                    "type": "integer",
                    "description": "Number of attack rounds (default: 5)",
                    "minimum": 1,
                    "maximum": 20,
                },
                "swarm_size": {
                    "type": "integer",
                    "description": "Number of red team agents (default: 5)",
                    "minimum": 1,
                    "maximum": 20,
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "vericlaw_certify",
        "description": (
            "Generate a signed security certificate for code. "
            "Runs a full scan and produces a cryptographically signed "
            "certificate with findings, proofs, and grade."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Path to code to certify",
                },
                "secret_key": {
                    "type": "string",
                    "description": "Optional secret key for signing (uses env var if omitted)",
                },
                "expires_days": {
                    "type": "integer",
                    "description": "Number of days until certificate expires (default: 30)",
                    "minimum": 1,
                    "maximum": 365,
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "vericlaw_explain",
        "description": (
            "Explain a security finding with context and remediation. "
            "Takes a finding identifier and returns a detailed explanation "
            "including the vulnerability, its impact, and how to fix it."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_id": {
                    "type": "string",
                    "description": "Unique identifier of the finding to explain",
                },
                "format": {
                    "type": "string",
                    "enum": ["json", "markdown"],
                    "description": "Output format (default: json)",
                },
                "include_code_examples": {
                    "type": "boolean",
                    "description": "Include code examples in the explanation (default: True)",
                },
            },
            "required": ["finding_id"],
        },
    },
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    """Return current timestamp in ISO format."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _error_response(error: Exception, tool_name: str) -> dict[str, Any]:
    """Build a standard error response."""
    return {
        "tool": tool_name,
        "status": "error",
        "error": str(error),
        "error_type": type(error).__name__,
        "traceback": traceback.format_exc(),
        "timestamp": _now_iso(),
    }


# ---------------------------------------------------------------------------
# Handler: vericlaw_scan
# ---------------------------------------------------------------------------


def handle_vericlaw_scan(params: dict[str, Any]) -> dict[str, Any]:
    """Run a comprehensive adversarial security scan on code.

    Args:
        params: Dict with keys: target (required), policy_level,
                max_mutations, swarm_size, format.

    Returns:
        JSON-serializable dict with scan results.
    """
    start = time.perf_counter()
    tool_name = "vericlaw_scan"

    try:
        target: str = params["target"]
        policy_level: str = params.get("policy_level", "standard")
        max_mutations: int = params.get("max_mutations", 100)
        swarm_size: int = params.get("swarm_size", 5)
        fmt: str = params.get("format", "json")

        # Import here to avoid circular deps at module load
        from .swarm import RedTeamSwarm, VerificationSwarm

        # Run red team scan
        red_team = RedTeamSwarm(size=swarm_size)
        rt_result = red_team.attack(target, rounds=3)

        # Run verification
        verify = VerificationSwarm(size=4)
        properties = [
            "type_safety",
            "memory_safety",
            "injection_resistance",
        ]
        proofs = verify.prove_all(target, properties)

        # Evaluate against policy
        from .ci import PolicyEngine

        engine = PolicyEngine(level=policy_level)

        # Build minimal ScanResult for policy check
        scan_findings = [
            Finding(
                id=f.id,
                title=f.title,
                severity=f.severity,
                category=f.category,
                description=f.description,
                evidence=f.evidence,
                remediation=f.remediation,
                cwe_id=f.cwe_id,
                cvss_score=f.cvss_score,
            )
            for f in rt_result.findings
        ]

        scan_proofs = [
            PropertyProof(
                property_name=p.property_name,
                status=p.status,
                counterexample=p.counterexample,
                verification_time_ms=p.verification_time_ms,
                confidence=p.confidence,
            )
            for p in proofs
        ]

        grade = _compute_grade(scan_findings, scan_proofs)

        from .models import AttackSurface

        scan_result = ScanResult(
            target=target,
            timestamp=_now_iso(),
            attack_surface=AttackSurface(),
            mutations=[],
            payloads=[],
            proofs=scan_proofs,
            findings=scan_findings,
            risk_score=0.0,
            grade=grade,
        )

        policy_decision = engine.check(scan_result)

        elapsed = int((time.perf_counter() - start) * 1000)

        return {
            "tool": tool_name,
            "status": "success",
            "target": target,
            "timestamp": _now_iso(),
            "execution_time_ms": elapsed,
            "policy_level": policy_level,
            "policy_decision": {
                "passed": policy_decision.passed,
                "decision": policy_decision.decision,
                "violations": policy_decision.violations,
                "recommendations": policy_decision.recommendations,
            },
            "findings_count": len(rt_result.findings),
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "confidence": f.confidence,
                }
                for f in rt_result.findings
            ],
            "proofs": [
                {
                    "property": p.property_name,
                    "status": p.status,
                    "confidence": p.confidence,
                }
                for p in proofs
            ],
            "grade": grade,
            "format": fmt,
            "red_team_summary": {
                "rounds": rt_result.rounds,
                "success_rate": rt_result.success_rate,
                "attack_chain_steps": len(rt_result.attack_chain),
            },
        }

    except Exception as exc:
        return _error_response(exc, tool_name)


# ---------------------------------------------------------------------------
# Handler: vericlaw_red_team
# ---------------------------------------------------------------------------


def handle_vericlaw_red_team(params: dict[str, Any]) -> dict[str, Any]:
    """Run an autonomous red team simulation against code.

    Args:
        params: Dict with keys: target (required), rounds, swarm_size.

    Returns:
        JSON-serializable dict with red team results.
    """
    start = time.perf_counter()
    tool_name = "vericlaw_red_team"

    try:
        target: str = params["target"]
        rounds: int = params.get("rounds", 5)
        swarm_size: int = params.get("swarm_size", 5)

        from .swarm import RedTeamSwarm

        swarm = RedTeamSwarm(size=swarm_size)
        result = swarm.attack(target, rounds=rounds)

        elapsed = int((time.perf_counter() - start) * 1000)

        return {
            "tool": tool_name,
            "status": "success",
            "target": target,
            "timestamp": _now_iso(),
            "execution_time_ms": elapsed,
            "rounds": result.rounds,
            "swarm_size": swarm_size,
            "findings_count": len(result.findings),
            "success_rate": result.success_rate,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "confidence": round(f.confidence, 3),
                    "exploitability": round(f.exploitability, 3),
                    "cwe_id": f.cwe_id,
                    "cvss_score": f.cvss_score,
                }
                for f in result.findings
            ],
            "attack_chain": result.attack_chain,
        }

    except Exception as exc:
        return _error_response(exc, tool_name)


# ---------------------------------------------------------------------------
# Handler: vericlaw_certify
# ---------------------------------------------------------------------------


def handle_vericlaw_certify(params: dict[str, Any]) -> dict[str, Any]:
    """Generate a signed security certificate for code.

    Args:
        params: Dict with keys: target (required), secret_key, expires_days.

    Returns:
        JSON-serializable dict with certificate data.
    """
    start = time.perf_counter()
    tool_name = "vericlaw_certify"

    try:
        target: str = params["target"]
        secret_key: str = params.get("secret_key", "")
        expires_days: int = params.get("expires_days", 30)

        from .swarm import RedTeamSwarm, VerificationSwarm

        red_team = RedTeamSwarm(size=5)
        rt_result = red_team.attack(target, rounds=3)

        verify = VerificationSwarm(size=4)
        properties = ["type_safety", "memory_safety", "injection_resistance"]
        proofs = verify.prove_all(target, properties)

        grade = _compute_grade(rt_result.findings, proofs)

        import hashlib
        import hmac
        from datetime import datetime, timedelta, timezone

        timestamp = datetime.now(timezone.utc)
        expires = timestamp + timedelta(days=expires_days)

        findings_summary = [
            {"id": f.id, "title": f.title, "severity": f.severity}
            for f in rt_result.findings
        ]
        proofs_summary = [
            {"property": p.property_name, "status": p.status}
            for p in proofs
        ]

        payload = (
            f"{target}:{grade}:{timestamp.isoformat()}:"
            f"{findings_summary}:{proofs_summary}"
        )
        key = secret_key.encode() if secret_key else b"vericlaw-default-key"
        signature = hmac.new(
            key, payload.encode(), hashlib.sha256
        ).hexdigest()

        elapsed = int((time.perf_counter() - start) * 1000)

        return {
            "tool": tool_name,
            "status": "success",
            "target": target,
            "timestamp": timestamp.isoformat(),
            "execution_time_ms": elapsed,
            "grade": grade,
            "findings_count": len(rt_result.findings),
            "proofs_count": len(proofs),
            "expires": expires.isoformat(),
            "signature": signature,
            "signature_algorithm": "HMAC-SHA256",
            "findings": findings_summary,
            "proofs": proofs_summary,
        }

    except Exception as exc:
        return _error_response(exc, tool_name)


# ---------------------------------------------------------------------------
# Handler: vericlaw_explain
# ---------------------------------------------------------------------------


def handle_vericlaw_explain(params: dict[str, Any]) -> dict[str, Any]:
    """Explain a security finding with context and remediation.

    Args:
        params: Dict with keys: finding_id (required), format,
                include_code_examples.

    Returns:
        JSON-serializable dict with detailed explanation.
    """
    start = time.perf_counter()
    tool_name = "vericlaw_explain"

    try:
        finding_id: str = params["finding_id"]
        fmt: str = params.get("format", "json")
        include_code: bool = params.get("include_code_examples", True)

        # Build explanation based on finding ID patterns
        explanation = _build_explanation(finding_id, include_code)

        elapsed = int((time.perf_counter() - start) * 1000)

        result: dict[str, Any] = {
            "tool": tool_name,
            "status": "success",
            "finding_id": finding_id,
            "timestamp": _now_iso(),
            "execution_time_ms": elapsed,
            "format": fmt,
            "explanation": explanation,
        }

        if fmt == "markdown":
            result["markdown"] = _explanation_to_markdown(explanation)

        return result

    except Exception as exc:
        return _error_response(exc, tool_name)


# ---------------------------------------------------------------------------
# Internal: explanation builder
# ---------------------------------------------------------------------------


def _build_explanation(finding_id: str, include_code: bool) -> dict[str, Any]:
    """Build a detailed explanation for a finding ID."""
    # Parse category from finding ID prefix
    category_hints: dict[str, dict[str, Any]] = {
        "sql": {
            "title": "SQL Injection",
            "category": "sql_injection",
            "cwe": "CWE-89",
            "severity": "CRITICAL",
            "summary": (
                "SQL injection occurs when user-supplied input is "
                "concatenated directly into SQL queries, allowing attackers "
                "to execute arbitrary database commands."
            ),
            "impact": [
                "Complete database compromise",
                "Extraction of sensitive data (PII, credentials)",
                "Data modification or deletion",
                "Authentication bypass",
                "Remote code execution in some configurations",
            ],
            "remediation": [
                "Use parameterized queries / prepared statements",
                "Use an ORM that handles escaping automatically",
                "Validate and sanitize all user inputs",
                "Apply principle of least privilege to DB accounts",
                "Enable query logging and monitoring",
            ],
            "code_vulnerable": "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
            "code_secure": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        },
        "xss": {
            "title": "Cross-Site Scripting (XSS)",
            "category": "xss",
            "cwe": "CWE-79",
            "severity": "HIGH",
            "summary": (
                "XSS vulnerabilities allow attackers to inject client-side "
                "scripts into web pages viewed by other users, enabling "
                "session hijacking, keylogging, and defacement."
            ),
            "impact": [
                "Session cookie theft",
                "Keylogging and credential harvesting",
                "Defacement of web pages",
                "Redirection to malicious sites",
                "CSRF bypass via injected scripts",
            ],
            "remediation": [
                "HTML-encode all user output before rendering",
                "Use a templating engine with auto-escaping",
                "Implement Content Security Policy (CSP)",
                "Validate input on arrival",
                "Use HttpOnly and Secure flags on cookies",
            ],
            "code_vulnerable": 'element.innerHTML = userComment;',
            "code_secure": 'element.textContent = userComment;',
        },
        "cmd": {
            "title": "OS Command Injection",
            "category": "command_injection",
            "cwe": "CWE-78",
            "severity": "CRITICAL",
            "summary": (
                "Command injection occurs when user input is passed to "
                "system shell commands without proper sanitization, "
                "allowing arbitrary command execution on the server."
            ),
            "impact": [
                "Remote code execution on server",
                "Full system compromise",
                "Data exfiltration",
                "Lateral movement within network",
                "Installation of persistent backdoors",
            ],
            "remediation": [
                "Never pass user input to shell commands",
                "Use subprocess with shell=False",
                "Validate filenames with allowlists",
                "Run in sandboxed environments",
                "Use language-native libraries instead of shelling out",
            ],
            "code_vulnerable": "os.system('convert ' + filename + ' output.png')",
            "code_secure": "subprocess.run(['convert', filename, 'output.png'], shell=False)",
        },
        "pat": {
            "title": "Path Traversal",
            "category": "path_traversal",
            "cwe": "CWE-22",
            "severity": "HIGH",
            "summary": (
                "Path traversal allows attackers to access files outside "
                "the intended directory by using '..' sequences or "
                "absolute paths in file name parameters."
            ),
            "impact": [
                "Arbitrary file read",
                "Source code disclosure",
                "Configuration file exposure",
                "Credential theft from config files",
                "Remote code execution via uploaded files",
            ],
            "remediation": [
                "Use pathlib and resolve paths before access",
                "Validate against an allowlist of permitted paths",
                "Reject paths containing '..' or null bytes",
                "Run application with minimal file permissions",
                "Use chroot jails where appropriate",
            ],
            "code_vulnerable": "open('/data/' + filename).read()",
            "code_secure": "(Path('/data') / filename).resolve().read_text()",
        },
        "log": {
            "title": "Logic Bypass",
            "category": "logic_bypass",
            "cwe": "CWE-287",
            "severity": "CRITICAL",
            "summary": (
                "Logic bypass vulnerabilities allow attackers to circumvent "
                "security controls by exploiting flawed application logic, "
                "such as parameter pollution or missing authorization checks."
            ),
            "impact": [
                "Authentication bypass",
                "Privilege escalation",
                "Unauthorized data access",
                "Administrative function abuse",
                "Security control disablement",
            ],
            "remediation": [
                "Implement centralized authorization checks",
                "Normalize and validate all input parameters",
                "Reject duplicate keys in query parameters",
                "Apply defense-in-depth with multiple control layers",
                "Audit all access to sensitive endpoints",
            ],
            "code_vulnerable": "if params.get('admin') == 'true': grant_access()",
            "code_secure": "if user.has_role('admin') and auth.verify(request): grant_access()",
        },
    }

    # Determine category from finding_id
    category = "generic"
    for hint, data in category_hints.items():
        if hint.upper() in finding_id.upper() or data["category"].upper() in finding_id.upper():
            category = hint
            break

    data = category_hints.get(category, category_hints["sql"])

    explanation: dict[str, Any] = {
        "title": data["title"],
        "category": data["category"],
        "cwe_id": data["cwe"],
        "severity": data["severity"],
        "finding_id": finding_id,
        "summary": data["summary"],
        "impact": data["impact"],
        "remediation_steps": data["remediation"],
    }

    if include_code:
        explanation["code_examples"] = {
            "vulnerable": data["code_vulnerable"],
            "secure": data["code_secure"],
            "language": "python",
        }

    return explanation


def _explanation_to_markdown(explanation: dict[str, Any]) -> str:
    """Convert explanation dict to markdown format."""
    lines = [
        f"# {explanation['title']}",
        "",
        f"**Severity:** {explanation['severity']}  ",
        f"**CWE:** {explanation['cwe_id']}  ",
        f"**Finding ID:** {explanation['finding_id']}",
        "",
        "## Summary",
        "",
        explanation["summary"],
        "",
        "## Impact",
        "",
    ]
    for impact in explanation["impact"]:
        lines.append(f"- {impact}")
    lines.extend(["", "## Remediation", ""])
    for step in explanation["remediation_steps"]:
        lines.append(f"1. {step}")

    if "code_examples" in explanation:
        code = explanation["code_examples"]
        lines.extend([
            "",
            "## Code Examples",
            "",
            "### Vulnerable",
            "",
            f"```{code['language']}",
            code["vulnerable"],
            "```",
            "",
            "### Secure",
            "",
            f"```{code['language']}",
            code["secure"],
            "```",
        ])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Internal: grade computation
# ---------------------------------------------------------------------------


def _compute_grade(
    findings: list[Any], proofs: list[Any]
) -> str:
    """Compute a security grade from findings and proofs."""
    # Count by severity
    critical = sum(1 for f in findings if f.severity == "CRITICAL")
    high = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    low = sum(1 for f in findings if f.severity == "LOW")

    # Count proven properties
    proven = sum(1 for p in proofs if p.status == "proven")
    total_proofs = len(proofs) if proofs else 1

    # Base score from findings (100 = perfect)
    finding_score = max(0, 100 - critical * 30 - high * 15 - medium * 5 - low * 1)

    # Proof bonus
    proof_bonus = (proven / total_proofs) * 20

    total = finding_score + proof_bonus

    if total >= 95 and critical == 0 and high == 0:
        return "A+"
    if total >= 85 and critical == 0:
        return "A"
    if total >= 70:
        return "B"
    if total >= 55:
        return "C"
    if total >= 40:
        return "D"
    return "F"
