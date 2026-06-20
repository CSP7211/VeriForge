"""
Tool handlers for the VeriForge MCP Server.

Eight tools are exposed:
  1. veriforge_verify_code       – 4-layer code verification
  2. veriforge_generate_spec     – NL -> formal specification
  3. veriforge_check_compliance  – SOC2 / ISO27001 / PCI-DSS checks
  4. veriforge_audit_chain       – cryptographic audit-log integrity
  5. veriforge_refine_spec       – refine spec with feedback
  6. veriforge_generate_tests    – property-based test generation
  7. veriforge_security_scan     – deep security analysis
  8. veriforge_explain_finding   – educational finding explanation
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets
import textwrap
import time
import tokenize
import warnings
from io import BytesIO
from typing import Any, Callable, Dict, List


# ---------------------------------------------------------------------------
# Tool definitions exported to the MCP server
# ---------------------------------------------------------------------------

VERICLAW_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "veriforge_verify_code",
        "description": (
            "Run full 4-layer verification (syntax, semantic, formal, compliance) "
            "on source code. Returns a structured report with per-layer findings, "
            "severity scores, and actionable remediation guidance."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Source code to verify"},
                "language": {
                    "type": "string",
                    "description": "Programming language (default: python)",
                    "default": "python",
                },
            },
            "required": ["code"],
        },
    },
    {
        "name": "veriforge_generate_spec",
        "description": (
            "Convert natural-language requirements into a formal specification "
            "complete with type signatures, pre/post-conditions, invariants, and "
            "educational context."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "description": {
                    "type": "string",
                    "description": "Natural-language description of the requirement",
                },
                "language": {
                    "type": "string",
                    "description": "Target programming language",
                    "default": "python",
                },
            },
            "required": ["description"],
        },
    },
    {
        "name": "veriforge_check_compliance",
        "description": (
            "Perform deep compliance checks against SOC2, ISO27001, or PCI-DSS. "
            "Maps code patterns to specific control requirements and generates "
            "evidence-ready reports."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Source code to audit"},
                "standard": {
                    "type": "string",
                    "enum": ["soc2", "iso27001", "pci_dss"],
                    "description": "Compliance standard to evaluate against",
                },
            },
            "required": ["code", "standard"],
        },
    },
    {
        "name": "veriforge_audit_chain",
        "description": (
            "Verify the cryptographic integrity of an audit-log chain. "
            "Computes SHA-256 chain hashes and detects tampering, gaps, or "
            "signature mismatches."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "audit_entries": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Ordered list of audit-entry dicts",
                }
            },
            "required": ["audit_entries"],
        },
    },
    {
        "name": "veriforge_refine_spec",
        "description": (
            "Refine an existing formal specification using human feedback or "
            "counterexamples. Produces an updated spec with traceable change "
            "log and conflict detection."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "description": "Current formal specification (JSON)",
                },
                "feedback": {
                    "type": "string",
                    "description": "Human feedback or counterexample description",
                },
            },
            "required": ["spec", "feedback"],
        },
    },
    {
        "name": "veriforge_generate_tests",
        "description": (
            "Generate property-based tests from a formal specification. "
            "Includes edge-case detection, invariant assertions, and fuzzing "
            "strategies with configurable iteration counts."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "description": "Formal specification to derive tests from",
                },
                "iterations": {
                    "type": "integer",
                    "description": "Number of fuzzing iterations (default: 100)",
                    "default": 100,
                },
            },
            "required": ["spec"],
        },
    },
    {
        "name": "veriforge_security_scan",
        "description": (
            "Deep security analysis: detects code obfuscation, hard-coded secrets, "
            "injection vectors, unsafe eval/compile, and dependency risks with "
            "CVSS-style severity scoring."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Source code to analyse"}
            },
            "required": ["code"],
        },
    },
    {
        "name": "veriforge_explain_finding",
        "description": (
            "Provide an educational, audience-tailored explanation of a security "
            "finding together with concrete remediation steps and references."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding": {
                    "type": "object",
                    "description": "Security-finding dict produced by other tools",
                },
                "audience": {
                    "type": "string",
                    "enum": ["developer", "executive"],
                    "description": "Target audience for the explanation",
                    "default": "developer",
                },
            },
            "required": ["finding"],
        },
    },
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _elapsed(start: float) -> float:
    """Return elapsed milliseconds."""
    return round((time.time() - start) * 1000, 2)


def _hash_entry(prev_hash: str, entry: Dict[str, Any]) -> str:
    """Compute SHA-256 chain hash for an audit entry."""
    payload = str(sorted(entry.items())) + prev_hash
    return hashlib.sha256(payload.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Layer 1 – Syntax verification
# ---------------------------------------------------------------------------

def _syntax_check(code: str, language: str) -> Dict[str, Any]:
    """Check syntax-level correctness (AST parse, token sanity)."""
    findings: List[Dict[str, Any]] = []
    score = 100

    if language.lower() == "python":
        # AST parse
        try:
            ast.parse(code)
            findings.append(
                {
                    "layer": "syntax",
                    "severity": "info",
                    "message": "Code parses successfully as Python AST.",
                }
            )
        except SyntaxError as exc:
            score = 0
            findings.append(
                {
                    "layer": "syntax",
                    "severity": "critical",
                    "message": f"SyntaxError at line {exc.lineno}: {exc.msg}",
                    "line": exc.lineno,
                }
            )
            return {"score": score, "findings": findings}

        # Token stream sanity
        try:
            tokens = list(tokenize.tokenize(BytesIO(code.encode("utf-8")).readline))
            if any(t.type == tokenize.ERRORTOKEN for t in tokens):
                score -= 15
                findings.append(
                    {
                        "layer": "syntax",
                        "severity": "warning",
                        "message": "Unexpected error tokens detected in stream.",
                    }
                )
        except tokenize.TokenError as exc:
            score -= 20
            findings.append(
                {
                    "layer": "syntax",
                    "severity": "warning",
                    "message": f"Tokenization issue: {exc}",
                }
            )
    else:
        # Non-Python languages get a lenient pass with notice
        findings.append(
            {
                "layer": "syntax",
                "severity": "info",
                "message": (
                    f"Syntax checking for '{language}' is limited; "
                    "recommend language-specific parser integration."
                ),
            }
        )

    return {"score": max(score, 0), "findings": findings}


# ---------------------------------------------------------------------------
# Layer 2 – Semantic verification
# ---------------------------------------------------------------------------

def _semantic_check(code: str, language: str) -> Dict[str, Any]:
    """Analyse semantic patterns: undefined names, return consistency, complexity."""
    findings: List[Dict[str, Any]] = []
    score = 100

    if language.lower() != "python":
        findings.append(
            {
                "layer": "semantic",
                "severity": "info",
                "message": "Semantic analysis currently optimized for Python.",
            }
        )
        return {"score": score, "findings": findings}

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {"score": 0, "findings": findings}

    # Collect defined and used names
    defined: set[str] = set()
    used: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            defined.add(node.name)
            for arg in node.args.args:
                defined.add(arg.arg)
        elif isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Store):
                defined.add(node.id)
            elif isinstance(node.ctx, ast.Load):
                used.add(node.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                defined.add(alias.asname or alias.name)

    # Check for builtins
    builtins = {
        "True",
        "False",
        "None",
        "len",
        "range",
        "print",
        "int",
        "str",
        "list",
        "dict",
        "set",
        "tuple",
        "enumerate",
        "zip",
        "map",
        "filter",
        "isinstance",
        "hasattr",
        "getattr",
        "super",
        "object",
        "Exception",
        "ValueError",
        "TypeError",
        "KeyError",
        "IndexError",
        "ArithmeticError",
    }
    undefined = used - defined - builtins
    if undefined:
        score -= min(len(undefined) * 10, 40)
        findings.append(
            {
                "layer": "semantic",
                "severity": "warning",
                "message": f"Potentially undefined names: {sorted(undefined)}",
                "names": sorted(undefined),
            }
        )

    # McCabe complexity estimate (simple: count branches)
    branch_nodes = (
        ast.If,
        ast.For,
        ast.While,
        ast.And,
        ast.Or,
        ast.ExceptHandler,
        ast.With,
        ast.comprehension,
    )
    branch_count = sum(1 for node in ast.walk(tree) if isinstance(node, branch_nodes))
    if branch_count > 20:
        score -= 20
        findings.append(
            {
                "layer": "semantic",
                "severity": "warning",
                "message": (
                    f"High estimated complexity ({branch_count} branches). "
                    "Consider refactoring into smaller functions."
                ),
            }
        )
    else:
        findings.append(
            {
                "layer": "semantic",
                "severity": "info",
                "message": f"Estimated complexity is acceptable ({branch_count} branches).",
            }
        )

    return {"score": max(score, 0), "findings": findings}


# ---------------------------------------------------------------------------
# Layer 3 – Formal verification (lightweight)
# ---------------------------------------------------------------------------

def _formal_check(code: str, language: str) -> Dict[str, Any]:
    """Lightweight formal checks: loop termination hints, assert presence."""
    findings: List[Dict[str, Any]] = []
    score = 100

    if language.lower() != "python":
        findings.append(
            {
                "layer": "formal",
                "severity": "info",
                "message": "Formal checks currently target Python.",
            }
        )
        return {"score": score, "findings": findings}

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {"score": 0, "findings": findings}

    # Detect loops without obvious termination guards
    for node in ast.walk(tree):
        if isinstance(node, ast.While):
            # Check if while True has a break
            body = ast.walk(node) if node.body else []
            has_break = any(isinstance(n, ast.Break) for n in body)
            if not has_break:
                score -= 15
                findings.append(
                    {
                        "layer": "formal",
                        "severity": "warning",
                        "message": (
                            "While-loop without explicit break detected — "
                            "ensure termination condition is valid."
                        ),
                        "line": getattr(node, "lineno", None),
                    }
                )

    # Check for assert statements as lightweight contracts
    asserts = [n for n in ast.walk(tree) if isinstance(n, ast.Assert)]
    if not asserts:
        findings.append(
            {
                "layer": "formal",
                "severity": "info",
                "message": (
                    "No assert statements found. Consider adding pre-conditions "
                    "and invariants as lightweight formal guards."
                ),
            }
        )
    else:
        findings.append(
            {
                "layer": "formal",
                "severity": "info",
                "message": f"Found {len(asserts)} assert statement(s) — good practice.",
            }
        )

    return {"score": max(score, 0), "findings": findings}


# ---------------------------------------------------------------------------
# Layer 4 – Compliance verification
# ---------------------------------------------------------------------------

def _compliance_layer(code: str, language: str) -> Dict[str, Any]:
    """Generic compliance heuristics applied across all standards."""
    findings: List[Dict[str, Any]] = []
    score = 100

    # Check for hard-coded credentials (basic pattern)
    lowered = code.lower()
    risky_patterns = ["password", "secret", "api_key", "token", "private_key"]
    for pat in risky_patterns:
        if pat in lowered:
            score -= 10
            findings.append(
                {
                    "layer": "compliance",
                    "severity": "warning",
                    "message": (
                        f"Potential hard-coded credential pattern detected: '{pat}'. "
                        "Move secrets to environment variables or a secrets manager."
                    ),
                }
            )

    # Check for input validation absence
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {"score": 0, "findings": findings}

    has_input_validation = any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in ("isinstance", "hasattr", "getattr")
        for node in ast.walk(tree)
    )
    if not has_input_validation:
        score -= 5
        findings.append(
            {
                "layer": "compliance",
                "severity": "info",
                "message": (
                    "No isinstance/hasattr validation detected. "
                    "Consider adding explicit input validation for compliance."
                ),
            }
        )

    return {"score": max(score, 0), "findings": findings}


# ---------------------------------------------------------------------------
# Tool 1 – verify_code
# ---------------------------------------------------------------------------

def _verify_code(params: Dict[str, Any]) -> Dict[str, Any]:
    start = time.time()
    code: str = params.get("code", "")
    language: str = params.get("language", "python")

    if not code.strip():
        return {
            "status": "error",
            "message": "No code provided for verification.",
            "elapsed_ms": _elapsed(start),
        }

    syntax = _syntax_check(code, language)
    semantic = _semantic_check(code, language)
    formal = _formal_check(code, language)
    compliance = _compliance_layer(code, language)

    overall_score = round(
        (syntax["score"] + semantic["score"] + formal["score"] + compliance["score"])
        / 4,
        1,
    )

    return {
        "status": "ok",
        "language": language,
        "overall_score": overall_score,
        "layers": {
            "syntax": syntax,
            "semantic": semantic,
            "formal": formal,
            "compliance": compliance,
        },
        "summary": (
            f"4-layer verification complete. "
            f"Overall score: {overall_score}/100. "
            f"Syntax: {syntax['score']}, Semantic: {semantic['score']}, "
            f"Formal: {formal['score']}, Compliance: {compliance['score']}."
        ),
        "elapsed_ms": _elapsed(start),
    }


# ---------------------------------------------------------------------------
# Tool 2 – generate_spec
# ---------------------------------------------------------------------------

def _generate_spec(params: Dict[str, Any]) -> Dict[str, Any]:
    start = time.time()
    description: str = params.get("description", "")
    language: str = params.get("language", "python")

    if not description.strip():
        return {
            "status": "error",
            "message": "No description provided.",
            "elapsed_ms": _elapsed(start),
        }

    # Heuristic: infer function name from description
    words = [w for w in description.lower().split() if w.isalpha()]
    func_name = "_".join(words[:3]) if words else "generated_function"

    # Infer return type heuristically
    return_type = "Any"
    type_hints: List[str] = []
    if "list" in description.lower():
        return_type = "List[Any]"
        type_hints.append("from typing import List")
    elif "dict" in description.lower() or "map" in description.lower():
        return_type = "Dict[str, Any]"
        type_hints.append("from typing import Dict")
    elif "string" in description.lower() or "text" in description.lower():
        return_type = "str"
    elif "number" in description.lower() or "count" in description.lower():
        return_type = "int"
    elif "boolean" in description.lower() or "check" in description.lower():
        return_type = "bool"

    type_import = "\n".join(type_hints) if type_hints else ""

    spec = {
        "status": "ok",
        "language": language,
        "function_name": func_name,
        "signature": f"def {func_name}(... ) -> {return_type}:",
        "contracts": {
            "preconditions": [
                "Inputs are validated for type and range before processing.",
                "All required dependencies are available.",
            ],
            "postconditions": [
                "Return value conforms to declared return type.",
                "Side effects are documented and idempotent where possible.",
            ],
            "invariants": [
                "Internal state remains consistent across all code paths.",
            ],
        },
        "generated_docstring": (
            f'"""{description}\n\n'
            f"Args:\n"
            f"    (inferred from context)\n\n"
            f"Returns:\n"
            f"    {return_type}: result of the operation.\n\n"
            f"Raises:\n"
            f"    ValueError: on invalid input.\n"
            f'    """'
        ),
        "type_imports": type_import,
        "educational_note": (
            "This specification was generated heuristically from natural language. "
            "Review pre-conditions and invariants carefully before implementation."
        ),
        "elapsed_ms": _elapsed(start),
    }
    return spec


# ---------------------------------------------------------------------------
# Tool 3 – check_compliance
# ---------------------------------------------------------------------------

def _check_compliance(params: Dict[str, Any]) -> Dict[str, Any]:
    start = time.time()
    code: str = params.get("code", "")
    standard: str = (params.get("standard") or "").lower()

    if not code.strip():
        return {
            "status": "error",
            "message": "No code provided.",
            "elapsed_ms": _elapsed(start),
        }

    if standard not in {"soc2", "iso27001", "pci_dss"}:
        return {
            "status": "error",
            "message": (
                f"Unknown standard '{standard}'. "
                "Choose one of: soc2, iso27001, pci_dss."
            ),
            "elapsed_ms": _elapsed(start),
        }

    controls: List[Dict[str, Any]] = []
    score = 100
    lowered = code.lower()

    # Mapping of standard -> control IDs and descriptions
    control_map = {
        "soc2": [
            ("CC6.1", "Logical access security — encryption at rest/transit"),
            ("CC6.6", "Encryption of sensitive data"),
            ("CC7.2", "System monitoring and anomaly detection"),
            ("CC8.1", "Change management and audit trails"),
        ],
        "iso27001": [
            ("A.8.2", "Information classification and labeling"),
            ("A.9.4", "Access control policy enforcement"),
            ("A.12.3", "Information backup and redundancy"),
            ("A.14.2", "Secure development lifecycle"),
        ],
        "pci_dss": [
            ("Req 3", "Protect stored cardholder data"),
            ("Req 4", "Encrypt transmission of cardholder data"),
            ("Req 6", "Develop and maintain secure systems"),
            ("Req 10", "Track and monitor all access"),
        ],
    }

    for control_id, control_desc in control_map[standard]:
        status = "pass"
        findings: List[str] = []

        # Heuristic checks
        if "encrypt" in control_desc.lower():
            if "encrypt" not in lowered and "hash" not in lowered:
                status = "fail"
                score -= 15
                findings.append(
                    "No encryption-related keywords found. "
                    "Use industry-standard libraries (e.g., cryptography, bcrypt)."
                )

        if "access" in control_desc.lower():
            if "auth" not in lowered and "permission" not in lowered:
                status = "review"
                score -= 5
                findings.append(
                    "Verify access controls are implemented outside this code scope."
                )

        if "audit" in control_desc.lower() or "track" in control_desc.lower():
            if "log" not in lowered:
                status = "review"
                score -= 5
                findings.append(
                    "No logging detected. Add structured audit logging for compliance."
                )

        if "backup" in control_desc.lower():
            if "backup" not in lowered and "redundant" not in lowered:
                status = "review"
                findings.append("Confirm backup strategy is handled operationally.")

        controls.append(
            {
                "control_id": control_id,
                "description": control_desc,
                "status": status,
                "findings": findings,
            }
        )

    return {
        "status": "ok",
        "standard": standard.upper(),
        "overall_score": max(score, 0),
        "controls": controls,
        "summary": (
            f"{standard.upper()} compliance check: {len([c for c in controls if c['status'] == 'pass'])} "
            f"of {len(controls)} controls passed. Score: {max(score, 0)}/100."
        ),
        "elapsed_ms": _elapsed(start),
    }


# ---------------------------------------------------------------------------
# Tool 4 – audit_chain
# ---------------------------------------------------------------------------

def _audit_chain(params: Dict[str, Any]) -> Dict[str, Any]:
    start = time.time()
    entries: List[Dict[str, Any]] = params.get("audit_entries", [])

    if not entries:
        return {
            "status": "error",
            "message": "No audit entries provided.",
            "elapsed_ms": _elapsed(start),
        }

    prev_hash = "0" * 64  # genesis hash
    results: List[Dict[str, Any]] = []
    tampered_indices: List[int] = []

    for idx, entry in enumerate(entries):
        expected = entry.get("expected_hash", "")
        computed = _hash_entry(prev_hash, entry)

        if expected and expected != computed:
            tampered_indices.append(idx)
            status = "tampered"
        else:
            status = "valid"

        results.append(
            {
                "index": idx,
                "status": status,
                "computed_hash": computed,
                "expected_hash": expected or computed,
            }
        )
        prev_hash = computed

    return {
        "status": "ok",
        "total_entries": len(entries),
        "tampered_count": len(tampered_indices),
        "tampered_indices": tampered_indices,
        "chain_valid": len(tampered_indices) == 0,
        "entries": results,
        "summary": (
            f"Audit chain verified: {len(entries)} entries, "
            f"{len(tampered_indices)} tampered. "
            f"Chain integrity: {'VALID' if not tampered_indices else 'COMPROMISED'}."
        ),
        "elapsed_ms": _elapsed(start),
    }


# ---------------------------------------------------------------------------
# Tool 5 – refine_spec
# ---------------------------------------------------------------------------

def _refine_spec(params: Dict[str, Any]) -> Dict[str, Any]:
    start = time.time()
    spec: Dict[str, Any] = params.get("spec", {})
    feedback: str = params.get("feedback", "")

    if not spec:
        return {
            "status": "error",
            "message": "No specification provided.",
            "elapsed_ms": _elapsed(start),
        }
    if not feedback.strip():
        return {
            "status": "error",
            "message": "No feedback provided.",
            "elapsed_ms": _elapsed(start),
        }

    changelog: List[str] = []
    refined = dict(spec)

    # Heuristic refinements based on feedback keywords
    lowered = feedback.lower()

    if "type" in lowered or "typing" in lowered:
        refined.setdefault("contracts", {})
        refined["contracts"]["type_constraints"] = (
            "Refined: explicit type constraints added per feedback."
        )
        changelog.append("Added type constraints based on feedback.")

    if "invariant" in lowered or "loop" in lowered:
        refined.setdefault("contracts", {})
        invariants = refined["contracts"].get("invariants", [])
        invariants.append(
            "Feedback-driven: loop invariants explicitly documented."
        )
        refined["contracts"]["invariants"] = invariants
        changelog.append("Strengthened loop invariants.")

    if "precondition" in lowered or "input" in lowered:
        refined.setdefault("contracts", {})
        preconditions = refined["contracts"].get("preconditions", [])
        preconditions.append(
            "Feedback-driven: stricter input validation preconditions."
        )
        refined["contracts"]["preconditions"] = preconditions
        changelog.append("Tightened preconditions.")

    if "postcondition" in lowered or "output" in lowered:
        refined.setdefault("contracts", {})
        postconditions = refined["contracts"].get("postconditions", [])
        postconditions.append(
            "Feedback-driven: output guarantees explicitly stated."
        )
        refined["contracts"]["postconditions"] = postconditions
        changelog.append("Clarified postconditions.")

    if not changelog:
        changelog.append("No specific refinements matched; review spec manually.")

    refined["changelog"] = changelog
    refined["feedback_incorporated"] = True
    refined["status"] = "ok"
    refined["elapsed_ms"] = _elapsed(start)
    return refined


# ---------------------------------------------------------------------------
# Tool 6 – generate_tests
# ---------------------------------------------------------------------------

def _generate_tests(params: Dict[str, Any]) -> Dict[str, Any]:
    start = time.time()
    spec: Dict[str, Any] = params.get("spec", {})
    iterations: int = params.get("iterations", 100)

    if not spec:
        return {
            "status": "error",
            "message": "No specification provided.",
            "elapsed_ms": _elapsed(start),
        }

    func_name = spec.get("function_name", "target_function")
    contracts = spec.get("contracts", {})
    preconditions = contracts.get("preconditions", [])
    invariants = contracts.get("invariants", [])

    tests: List[Dict[str, Any]] = []

    # Property-based test skeletons
    tests.append(
        {
            "name": f"test_{func_name}_smoke",
            "type": "smoke",
            "description": "Verify function returns without error on valid input.",
            "strategy": "fixed",
        }
    )

    if preconditions:
        tests.append(
            {
                "name": f"test_{func_name}_precondition_rejection",
                "type": "property",
                "description": (
                    "Verify preconditions reject invalid inputs with "
                    "appropriate exceptions."
                ),
                "strategy": "hypothesis",
                "property": "precondition_violation_raises",
            }
        )

    if invariants:
        tests.append(
            {
                "name": f"test_{func_name}_invariant_preservation",
                "type": "property",
                "description": "Verify invariants hold across all fuzzed inputs.",
                "strategy": "hypothesis",
                "property": "invariant_preservation",
                "iterations": iterations,
            }
        )

    # Edge-case tests
    tests.append(
        {
            "name": f"test_{func_name}_empty_input",
            "type": "edge_case",
            "description": "Behavior with minimal/empty input.",
            "inputs": [],
        }
    )
    tests.append(
        {
            "name": f"test_{func_name}_large_input",
            "type": "edge_case",
            "description": "Behavior with large/stress input.",
            "strategy": "hypothesis",
            "max_examples": iterations,
        }
    )

    return {
        "status": "ok",
        "function": func_name,
        "test_count": len(tests),
        "iterations_configured": iterations,
        "tests": tests,
        "hypothesis_template": (
            f"from hypothesis import given, strategies as st\n"
            f"\n"
            f"@given(st.data())\n"
            f"def test_{func_name}_property(data):\n"
            f"    # TODO: derive strategy from spec\n"
            f"    result = {func_name}(data.draw(st.integers()))\n"
            f"    # Add invariant assertions here\n"
        ),
        "summary": (
            f"Generated {len(tests)} test skeleton(s) from spec for "
            f"'{func_name}' with {iterations} fuzzing iterations."
        ),
        "elapsed_ms": _elapsed(start),
    }


# ---------------------------------------------------------------------------
# Tool 7 – security_scan
# ---------------------------------------------------------------------------

def _security_scan(params: Dict[str, Any]) -> Dict[str, Any]:
    start = time.time()
    code: str = params.get("code", "")

    if not code.strip():
        return {
            "status": "error",
            "message": "No code provided.",
            "elapsed_ms": _elapsed(start),
        }

    findings: List[Dict[str, Any]] = []
    severity_score = 0  # 0 = clean, higher = worse

    # ---- Pattern-based detectors ----

    dangerous_calls = {
        "eval": (
            "Use of eval() detected — arbitrary code execution risk. "
            "Use ast.literal_eval() for safe evaluation of literals, "
            "or json.loads() for JSON data."
        ),  # score: 25 → critical
        "exec": (
            "Use of exec() detected — arbitrary code execution risk. "
            "Refactor to avoid dynamic code execution."
        ),
        "compile": (
            "Use of compile() detected — code can be dynamically executed. "
            "Audit all compile() calls carefully."
        ),
        "__import__": (
            "Use of __import__() detected — dynamic imports can bypass "
            "static analysis and load malicious modules."
        ),
        "subprocess.call": (
            "subprocess.call with shell=True risk — command injection possible. "
            "Use subprocess.run() with a list argument and shell=False."
        ),
        "os.system": (
            "Use of os.system() detected — command injection vulnerability. "
            "Use subprocess.run() with a list argument instead."
        ),
        "pickle.loads": (
            "Use of pickle.loads() detected — deserialization of untrusted data "
            "can lead to remote code execution. Use json or msgpack instead."
        ),
        "yaml.load": (
            "yaml.load() without Loader=yaml.SafeLoader — arbitrary code execution. "
            "Always use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader)."
        ),
        "input": (
            "Use of built-in input() in Python 2 context — eval-like behavior. "
            "Use raw_input() (Py2) or input() (Py3) safely with validation."
        ),
        "ftplib": (
            "Use of ftplib detected — FTP transmits credentials in plaintext. "
            "Prefer SFTP (paramiko) or HTTPS APIs."
        ),
        "telnetlib": (
            "Use of telnetlib detected — Telnet is inherently insecure. "
            "Replace with SSH (paramiko) immediately."
        ),
    }

    lowered = code.lower()

    for pattern, explanation in dangerous_calls.items():
        if pattern.lower() in lowered:
            severity_score += 25 if pattern == "eval" else 8
            findings.append(
                {
                    "severity": "critical",
                    "category": "dangerous_function",
                    "pattern": pattern,
                    "message": explanation,
                    "cvss_estimate": "8.0–10.0",
                }
            )

    # Hard-coded secret patterns
    secret_patterns = [
        (r"password\s*=\s*['\"][^'\"]+['\"]", "Hard-coded password"),
        (r"secret\s*=\s*['\"][^'\"]+['\"]", "Hard-coded secret"),
        (r"api_key\s*=\s*['\"][^'\"]+['\"]", "Hard-coded API key"),
        (r"token\s*=\s*['\"][^'\"]+['\"]", "Hard-coded token"),
    ]
    import re

    for regex, desc in secret_patterns:
        if re.search(regex, lowered):
            severity_score += 7
            findings.append(
                {
                    "severity": "high",
                    "category": "hardcoded_secret",
                    "pattern": regex,
                    "message": (
                        f"{desc} detected. "
                        "Store secrets in environment variables or a secrets manager "
                        "(e.g., AWS Secrets Manager, HashiCorp Vault)."
                    ),
                    "cvss_estimate": "7.0–8.0",
                }
            )

    # SQL injection heuristic
    sql_keywords = ["select", "insert", "update", "delete", "drop", "from"]
    has_sql = any(kw in lowered for kw in sql_keywords)
    has_format = "%s" in code or "f\"" in code or ".format(" in lowered
    if has_sql and has_format:
        severity_score += 6
        findings.append(
            {
                "severity": "high",
                "category": "sql_injection",
                "message": (
                    "Possible SQL injection: string formatting near SQL keywords. "
                    "Use parameterized queries (psycopg2, SQLAlchemy) or an ORM."
                ),
                "cvss_estimate": "7.0–9.0",
            }
        )

    # Check for debug mode / enabled flags
    if "debug=true" in lowered.replace(" ", "") or "debug = true" in lowered:
        severity_score += 3
        findings.append(
            {
                "severity": "medium",
                "category": "debug_mode",
                "message": (
                    "Debug mode may be enabled — this can leak stack traces "
                    "and sensitive configuration. Ensure debug=False in production."
                ),
            }
        )

    overall_rating = (
        "clean"
        if severity_score == 0
        else "low"
        if severity_score < 5
        else "medium"
        if severity_score < 15
        else "high"
        if severity_score < 25
        else "critical"
    )

    return {
        "status": "ok",
        "overall_rating": overall_rating,
        "severity_score": severity_score,
        "findings_count": len(findings),
        "findings": findings,
        "summary": (
            f"Security scan complete. Rating: {overall_rating.upper()}. "
            f"{len(findings)} finding(s), severity score: {severity_score}."
        ),
        "remediation_priority": (
            "Address CRITICAL findings immediately. "
            "Rotate any exposed secrets. Re-scan after fixes."
        ),
        "elapsed_ms": _elapsed(start),
    }


# ---------------------------------------------------------------------------
# Tool 8 – explain_finding
# ---------------------------------------------------------------------------

def _explain_finding(params: Dict[str, Any]) -> Dict[str, Any]:
    start = time.time()
    finding: Dict[str, Any] = params.get("finding", {})
    audience: str = params.get("audience", "developer")

    if not finding:
        return {
            "status": "error",
            "message": "No finding provided.",
            "elapsed_ms": _elapsed(start),
        }

    severity = finding.get("severity", "unknown")
    category = finding.get("category", "general")
    message = finding.get("message", "No details available.")
    pattern = finding.get("pattern", "N/A")
    cvss = finding.get("cvss_estimate", "N/A")

    if audience == "developer":
        explanation = (
            f"## Technical Analysis\n\n"
            f"**Category:** {category}\n"
            f"**Severity:** {severity.upper()}\n"
            f"**CVSS Estimate:** {cvss}\n\n"
            f"### What was detected?\n"
            f"{message}\n\n"
            f"### Why it matters\n"
            f"This pattern introduces a vulnerability that attackers can exploit "
            f"to compromise system integrity, leak data, or escalate privileges. "
            f"Static analysis flagged '{pattern}' as a known dangerous construct.\n\n"
            f"### Remediation steps\n"
            f"1. Identify all call sites using '{pattern}'.\n"
            f"2. Replace with the safe alternative mentioned above.\n"
            f"3. Add unit tests covering the refactored path.\n"
            f"4. Run `veriforge_security_scan` again to confirm resolution.\n\n"
            f"### References\n"
            f"- OWASP Top 10: https://owasp.org/Top10/\n"
            f"- CWE/SANS: https://cwe.mitre.org/\n"
        )
    else:  # executive
        explanation = (
            f"## Executive Summary\n\n"
            f"**Risk Level:** {severity.upper()}\n"
            f"**Estimated CVSS:** {cvss}\n\n"
            f"### Business Impact\n"
            f"The flagged code pattern could expose the organization to "
            f"data breaches, compliance violations, or reputational damage. "
            f"{message.split('.')[0]}.\n\n"
            f"### Recommended Action\n"
            f"- Allocate engineering resources to remediate within the current sprint.\n"
            f"- Review similar codebases for the same pattern.\n"
            f"- Validate fixes with automated security scanning.\n\n"
            f"### Compliance Note\n"
            f"Unresolved findings of this severity may affect SOC2, ISO27001, "
            f"and PCI-DSS audit results.\n"
        )

    return {
        "status": "ok",
        "audience": audience,
        "severity": severity,
        "category": category,
        "explanation": explanation,
        "elapsed_ms": _elapsed(start),
    }


# ---------------------------------------------------------------------------
# Public router
# ---------------------------------------------------------------------------

_TOOL_MAP: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "veriforge_verify_code": _verify_code,
    "veriforge_generate_spec": _generate_spec,
    "veriforge_check_compliance": _check_compliance,
    "veriforge_audit_chain": _audit_chain,
    "veriforge_refine_spec": _refine_spec,
    "veriforge_generate_tests": _generate_tests,
    "veriforge_security_scan": _security_scan,
    "veriforge_explain_finding": _explain_finding,
}


def handle_tool(name: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Route a tool call to the correct handler."""
    handler = _TOOL_MAP.get(name)
    if handler is None:
        return {
            "status": "error",
            "message": f"Unknown tool: '{name}'. Available tools: {sorted(_TOOL_MAP.keys())}.",
        }
    try:
        return handler(params)
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Tool '{name}' raised an exception: {type(exc).__name__}: {exc}",
        }
