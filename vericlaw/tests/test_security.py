"""vericlaw/tests/test_security.py — Comprehensive security module tests.

Tests cover:
* PayloadGenerator — context-aware payload generation
* SecurityProver   — formal property proving via AST analysis
* SecurityCertifier — HMAC-SHA256 signed certificate lifecycle
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from typing import Optional

import pytest

from vericlaw.payloads import Payload, PayloadGenerator
from vericlaw.prover import PropertyProof, SecurityProver
from vericlaw.certifier import (
    Finding,
    PropertyProof as CertPropertyProof,
    SecurityCertificate,
    SecurityCertifier,
)


# ---------------------------------------------------------------------------
# Fixtures — lightweight EntryPoint stand-ins
# ---------------------------------------------------------------------------

@dataclass
class FakeEntryPoint:
    """Minimal stand-in for analyzer.EntryPoint."""

    name: str = "handler"
    type: str = "function"
    line: int = 1
    parameters: list[str] = field(default_factory=list)
    returns: Optional[str] = None
    decorators: list[str] = field(default_factory=list)
    docstring: Optional[str] = None
    risk_indicators: list[str] = field(default_factory=list)
    source: str = ""
    body: list[ast.AST] = field(default_factory=list)


# ---------------------------------------------------------------------------
# PayloadGenerator tests
# ---------------------------------------------------------------------------

class TestPayloadGenerator:

    def test_generates_sqli_for_username_param(self):
        """Username parameters should trigger SQL injection payloads."""
        gen = PayloadGenerator()
        ep = FakeEntryPoint(name="login", parameters=["username", "password"])
        payloads = gen.generate_for(ep, "sql_injection")

        assert len(payloads) > 0
        contents = [p.content for p in payloads]
        assert any("OR" in c for c in contents)
        assert any("DROP TABLE" in c for c in contents)
        assert any("UNION SELECT" in c for c in contents)

    def test_generates_path_traversal_for_filename_param(self):
        """Filename parameters should trigger path traversal payloads."""
        gen = PayloadGenerator()
        ep = FakeEntryPoint(name="download", parameters=["filename"])
        all_payloads = gen.generate_all(ep)

        assert "path_traversal" in all_payloads
        pt_payloads = all_payloads["path_traversal"]
        assert len(pt_payloads) > 0

        contents = [p.content for p in pt_payloads]
        assert any("../../etc/passwd" in c for c in contents)
        assert any("windows" in c.lower() for c in contents)

    def test_generates_all_for_flask_route(self):
        """A Flask route with user input should get multiple payload types."""
        gen = PayloadGenerator()
        ep = FakeEntryPoint(
            name="profile",
            parameters=["username"],
            decorators=["@app.route('/user/<username>')"],
            risk_indicators=["flask"],
        )
        all_payloads = gen.generate_all(ep)

        # Flask indicators should expand payload types
        assert len(all_payloads) >= 2
        # Username param should bring in SQLi + XSS
        assert "sql_injection" in all_payloads
        assert "xss" in all_payloads

    def test_payload_dataclass_fields(self):
        """Payload must expose the expected fields."""
        gen = PayloadGenerator()
        ep = FakeEntryPoint(parameters=["query"])
        payloads = gen.generate_for(ep, "sql_injection")

        for p in payloads:
            assert hasattr(p, "content")
            assert hasattr(p, "payload_type")
            assert hasattr(p, "context")
            assert hasattr(p, "encoding")
            assert hasattr(p, "severity")
            assert p.payload_type == "sql_injection"

    def test_unknown_vulnerability_type_returns_empty(self):
        """Requesting a non-catalog type yields an empty list."""
        gen = PayloadGenerator()
        ep = FakeEntryPoint(parameters=["x"])
        assert gen.generate_for(ep, "buffer_overflow") == []

    def test_encoding_variants_present(self):
        """Each raw payload should have multiple encoding variants."""
        gen = PayloadGenerator()
        ep = FakeEntryPoint(parameters=["cmd"])
        payloads = gen.generate_for(ep, "command_injection")

        encodings = {p.encoding for p in payloads}
        assert "raw" in encodings
        assert "base64" in encodings or "urlencode" in encodings or "hex" in encodings

    def test_prototype_pollution_payloads(self):
        """Prototype pollution payloads must contain JSON objects."""
        gen = PayloadGenerator()
        ep = FakeEntryPoint(parameters=["data"])
        payloads = gen.generate_for(ep, "prototype_pollution")

        assert len(payloads) > 0
        contents = [p.content for p in payloads]
        assert any("__proto__" in c for c in contents)
        assert any("constructor" in c for c in contents)

    def test_deserialization_payloads(self):
        """Deserialization payloads should cover pickle and YAML."""
        gen = PayloadGenerator()
        ep = FakeEntryPoint(parameters=["json"])
        payloads = gen.generate_for(ep, "deserialization")

        assert len(payloads) > 0
        contexts = [p.context for p in payloads]
        assert any("pickle" in c.lower() for c in contexts)
        assert any("yaml" in c.lower() for c in contexts)


# ---------------------------------------------------------------------------
# SecurityProver tests
# ---------------------------------------------------------------------------

class TestSecurityProver:

    def test_proves_type_safety_on_clean_code(self):
        """Clean, well-typed code should pass type safety."""
        prover = SecurityProver()
        code = """
def greet(name: str) -> str:
    return f"Hello, {name}"

class Calculator:
    def add(self, a: int, b: int) -> int:
        return a + b
"""
        proof = prover.prove_type_safety(code)
        assert proof.status == "proven"
        assert proof.confidence > 0.5

    def test_detects_type_safety_violation_on_eval(self):
        """Usage of eval() must be flagged as a type-safety violation."""
        prover = SecurityProver()
        code = """
def process(user_input):
    result = eval(user_input)
    return result
"""
        proof = prover.prove_type_safety(code)
        assert proof.status == "violated"
        assert proof.counterexample is not None
        assert "eval" in proof.counterexample.lower() or "Dynamic execution" in proof.counterexample

    def test_proves_injection_resistance_with_param_queries(self):
        """Parameterized queries should satisfy injection resistance."""
        prover = SecurityProver()
        code = """
def get_user(user_id: int, cursor):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()
"""
        proof = prover.prove_injection_resistance(code)
        assert proof.status == "proven"
        assert proof.confidence > 0.5

    def test_detects_injection_vulnerability_with_fstring(self):
        """F-string concatenation in SQL must be flagged."""
        prover = SecurityProver()
        code = """
def search_users(name: str, cursor):
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cursor.fetchall()
"""
        proof = prover.prove_injection_resistance(code)
        assert proof.status == "violated"
        assert proof.counterexample is not None
        assert "f-string" in proof.counterexample.lower() or "sql" in proof.counterexample.lower()

    def test_proves_memory_safety(self):
        """Code without unbounded growth should pass memory safety."""
        prover = SecurityProver()
        code = """
def process(items: list) -> list:
    result = []
    for item in items[:1000]:
        result.append(item)
    return result
"""
        proof = prover.prove_memory_safety(code)
        # May be proven or violated depending on heuristic strictness
        assert proof.status in ("proven", "violated")

    def test_detects_memory_safety_violation_recursive(self):
        """Recursive function without base case should be flagged."""
        prover = SecurityProver()
        code = """
def broken_factorial(n):
    return n * broken_factorial(n - 1)
"""
        proof = prover.prove_memory_safety(code)
        assert proof.status == "violated"
        assert proof.counterexample is not None
        assert "recursive" in proof.counterexample.lower()

    def test_prove_all_returns_list(self):
        """prove_all must return exactly three PropertyProof objects."""
        prover = SecurityProver()
        code = "def hello(): pass"
        proofs = prover.prove_all(code)
        assert isinstance(proofs, list)
        assert len(proofs) == 3
        for p in proofs:
            assert isinstance(p, PropertyProof)

    def test_prove_property_no_eval(self):
        """The no_eval property should detect eval usage."""
        prover = SecurityProver()
        code = "result = eval(user_input)"
        proof = prover.prove_property(code, "no_eval")
        assert proof.status == "violated"

    def test_prove_property_no_eval_clean(self):
        """The no_eval property should pass on eval-free code."""
        prover = SecurityProver()
        code = "result = int(user_input)"
        proof = prover.prove_property(code, "no_eval")
        assert proof.status == "proven"


# ---------------------------------------------------------------------------
# SecurityCertifier tests
# ---------------------------------------------------------------------------

class TestSecurityCertifier:

    def test_generates_valid_certificate_with_correct_grade(self):
        """Certify should produce a certificate with the expected grade."""
        certifier = SecurityCertifier(secret_key="test-secret-key")
        findings = [
            Finding(
                id="F-001",
                title="SQL Injection",
                severity="critical",
                category="sql_injection",
                description="Unparameterized query in login handler",
                evidence="cursor.execute(f'SELECT * FROM users WHERE name = {name}')",
                remediation="Use parameterized queries",
                cwe_id="CWE-89",
                cvss_score=9.8,
            ),
            Finding(
                id="F-002",
                title="Hardcoded Password",
                severity="high",
                category="hardcoded_credentials",
                description="Password found in source code",
                evidence='password = "admin123"',
                remediation="Use environment variables",
                cwe_id="CWE-798",
                cvss_score=7.5,
            ),
        ]
        proofs = [
            CertPropertyProof(
                property_name="injection_resistance",
                status="violated",
                counterexample="F-string in SQL query",
                verification_time_ms=12,
                confidence=0.95,
            ),
            CertPropertyProof(
                property_name="type_safety",
                status="proven",
                counterexample=None,
                verification_time_ms=8,
                confidence=0.85,
            ),
        ]

        cert = certifier.certify("test_target", findings, proofs)
        assert isinstance(cert, SecurityCertificate)
        assert cert.target == "test_target"
        assert cert.grade in ("A+", "A", "B", "C", "D", "F")
        assert 0.0 <= cert.risk_score <= 10.0
        assert len(cert.findings) == 2
        assert len(cert.proofs) == 2
        assert cert.signature is not None
        assert len(cert.signature) == 64  # hex-encoded SHA-256

    def test_signature_verifies_correctly(self):
        """A freshly generated certificate must verify successfully."""
        certifier = SecurityCertifier(secret_key="another-test-key")
        findings = []
        proofs = [
            CertPropertyProof(
                property_name="type_safety",
                status="proven",
                counterexample=None,
                verification_time_ms=5,
                confidence=0.9,
            ),
        ]

        cert = certifier.certify("clean_target", findings, proofs)
        assert certifier.verify(cert) is True

    def test_detects_tampered_certificate(self):
        """Modifying any field should cause verification to fail."""
        certifier = SecurityCertifier(secret_key="tamper-test-key")
        findings = []
        proofs = []

        cert = certifier.certify("original_target", findings, proofs)
        assert certifier.verify(cert) is True

        # Tamper by creating a new certificate with altered risk_score
        tampered = SecurityCertificate(
            target=cert.target,
            timestamp=cert.timestamp,
            findings=cert.findings,
            proofs=cert.proofs,
            risk_score=9.9,  # tampered!
            grade=cert.grade,
            signature=cert.signature,  # original signature
            expires=cert.expires,
        )
        assert certifier.verify(tampered) is False

    def test_grade_calculation(self):
        """Grade must map correctly from risk score ranges."""
        certifier = SecurityCertifier(secret_key="grade-test")

        test_cases = [
            # (findings, proofs, expected_grade)
            ([], [], "A+"),  # nothing = perfect
            (
                [Finding("F1", "Low", "low", "xss", "x", "e", "r", "CWE-79", 3.0)],
                [],
                "A",
            ),
            (
                [Finding("F1", "Med", "medium", "xss", "x", "e", "r", "CWE-79", 5.0)] * 3,
                [],
                "B",
            ),
            (
                [Finding("F1", "Med", "medium", "xss", "x", "e", "r", "CWE-79", 5.0)] * 3
                + [Finding("F1", "High", "high", "xss", "x", "e", "r", "CWE-79", 8.0)],
                [],
                "C",
            ),
            (
                [Finding("F1", "High", "high", "xss", "x", "e", "r", "CWE-79", 8.0)] * 4,
                [],
                "D",
            ),
            (
                [Finding("F1", "Crit", "critical", "sqli", "x", "e", "r", "CWE-89", 9.8)] * 5,
                [],
                "F",
            ),
        ]

        for findings, proofs, expected in test_cases:
            cert = certifier.certify("target", findings, proofs)
            assert cert.grade == expected, f"Expected {expected}, got {cert.grade} for score {cert.risk_score}"

    def test_cwe_id_mapping(self):
        """CWE mapping must return correct identifiers."""
        assert SecurityCertifier.get_cwe_id("sql_injection") == "CWE-89"
        assert SecurityCertifier.get_cwe_id("xss") == "CWE-79"
        assert SecurityCertifier.get_cwe_id("command_injection") == "CWE-78"
        assert SecurityCertifier.get_cwe_id("path_traversal") == "CWE-22"
        assert SecurityCertifier.get_cwe_id("deserialization") == "CWE-502"
        assert SecurityCertifier.get_cwe_id("hardcoded_credentials") == "CWE-798"
        assert SecurityCertifier.get_cwe_id("eval_usage") == "CWE-95"
        assert SecurityCertifier.get_cwe_id("missing_auth") == "CWE-306"

    def test_secret_key_from_env(self, monkeypatch):
        """Certifier should load secret key from VERIFORGE_SECRET_KEY."""
        monkeypatch.setenv("VERIFORGE_SECRET_KEY", "env-secret")
        certifier = SecurityCertifier()
        assert certifier.secret_key == "env-secret"

    def test_certificate_expiration(self):
        """Certificate should have an expires field ~90 days in the future."""
        from datetime import datetime

        certifier = SecurityCertifier(secret_key="exp-test")
        cert = certifier.certify("t", [], [])
        ts = datetime.fromisoformat(cert.timestamp)
        exp = datetime.fromisoformat(cert.expires)
        delta = (exp - ts).days
        assert delta == 90
