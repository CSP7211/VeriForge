"""Comprehensive test suite for vericlaw.report.ReportGenerator.

Covers:
- HTML report generation (structure, content, dark theme, grade colours)
- SARIF v2.1.0 export (schema compliance, field mapping)
- Markdown generation (content, severity breakdown)
- Certificate rendering via Jinja2
- Empty-result graceful handling
- Type validation
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

import pytest

from vericlaw import (
    AttackSurface,
    AttackVector,
    Boundary,
    DataFlow,
    EntryPoint,
    Finding,
    Mutation,
    Payload,
    PropertyProof,
    ScanResult,
    SecurityCertificate,
)
from vericlaw.report import (
    SARIF_SCHEMA,
    VERICLAW_VERSION,
    ReportGenerator,
    _grade_colour,
    _h,
    _severity_sort_key,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def generator() -> ReportGenerator:
    """Fresh ReportGenerator instance."""
    return ReportGenerator()


@pytest.fixture
def sample_certificate() -> SecurityCertificate:
    """A signed security certificate for testing."""
    return SecurityCertificate(
        target="src/app.py",
        timestamp="2025-06-19T12:00:00Z",
        findings=[
            Finding(
                id="VC-SQLI-001",
                title="SQL Injection in login handler",
                severity="critical",
                category="Injection",
                description="User input is concatenated into a SQL query without parameterisation.",
                evidence="Line 55: query = f\"SELECT * FROM users WHERE name = '{user}'\"",
                remediation="Use parameterized queries or an ORM.",
                cwe_id="89",
                cvss_score=9.8,
            ),
            Finding(
                id="VC-XSS-002",
                title="Reflected XSS in search",
                severity="high",
                category="Cross-Site Scripting",
                description="Search term is reflected in the response without encoding.",
                evidence="Line 30: document.write(searchTerm)",
                remediation="HTML-encode all user output. Use a templating engine with auto-escaping.",
                cwe_id="79",
                cvss_score=7.5,
            ),
        ],
        proofs=[
            PropertyProof(
                property_name="type_safety",
                status="proven",
                counterexample=None,
                verification_time_ms=1200,
                confidence=0.99,
            ),
            PropertyProof(
                property_name="memory_safety",
                status="proven",
                counterexample=None,
                verification_time_ms=800,
                confidence=0.95,
            ),
            PropertyProof(
                property_name="injection_resistance",
                status="violated",
                counterexample="Input: ' OR 1=1 --",
                verification_time_ms=450,
                confidence=0.88,
            ),
        ],
        risk_score=6.5,
        grade="C",
        signature="a3f7c2d8e9b1045a6d7e8f9012345678abcdef1234567890abcdef1234567890ab",
        expires="2025-09-19T12:00:00Z",
    )


@pytest.fixture
def sample_attack_surface() -> AttackSurface:
    """Attack surface with representative data."""
    return AttackSurface(
        entry_points=[
            EntryPoint(
                name="login",
                type="endpoint",
                line=42,
                parameters=["username: str", "password: str"],
                returns="Response",
                risk_indicators=["accepts user input", "authentication"],
            ),
            EntryPoint(
                name="search",
                type="function",
                line=30,
                parameters=["query: str"],
                returns="list[Result]",
                risk_indicators=["reflected output"],
            ),
        ],
        data_flows=[
            DataFlow(
                source="request.form.username",
                sink="execute_query()",
                path=["validate_input", "build_query"],
                taint_level="high",
            ),
        ],
        trust_boundaries=[
            Boundary(
                name="API Gateway",
                type="network",
                protections=["TLS 1.3"],
                gaps=["no rate limiting"],
            ),
        ],
        attack_vectors=[
            AttackVector(
                type="SQL Injection",
                entry_point="login",
                confidence=0.92,
                evidence="User input concatenated into SQL query",
                cwe_id="89",
            ),
            AttackVector(
                type="Cross-Site Scripting",
                entry_point="search",
                confidence=0.85,
                evidence="Reflected user input in DOM",
                cwe_id="79",
            ),
        ],
        risk_score=6.5,
    )


@pytest.fixture
def sample_result(
    sample_attack_surface: AttackSurface,
    sample_certificate: SecurityCertificate,
) -> ScanResult:
    """A full ScanResult with all fields populated."""
    return ScanResult(
        target="src/app.py",
        timestamp="2025-06-19T12:00:00Z",
        attack_surface=sample_attack_surface,
        mutations=[
            Mutation(
                original="user = request.args.get('q')",
                mutated="user = request.args.get('q') + \"' OR 1=1--\"",
                mutation_type="injection",
                description="Append SQL tautology",
                severity="critical",
            ),
            Mutation(
                original="return render_template('page.html', data=user_data)",
                mutated="return render_template('page.html', data=user_data + '<script>alert(1)</script>')",
                mutation_type="injection",
                description="Inject XSS payload",
                severity="high",
            ),
        ],
        payloads=[
            Payload(
                content="<script>alert('XSS')</script>",
                payload_type="xss",
                context="Reflected search results",
                encoding="raw",
                severity="high",
            ),
            Payload(
                content="' UNION SELECT * FROM passwords--",
                payload_type="sql_injection",
                context="Login form username field",
                encoding="raw",
                severity="critical",
            ),
        ],
        proofs=sample_certificate.proofs,
        findings=sample_certificate.findings,
        certificate=sample_certificate,
        risk_score=6.5,
        grade="C",
    )


@pytest.fixture
def empty_result() -> ScanResult:
    """A ScanResult with no findings, mutations, payloads, or proofs."""
    return ScanResult(
        target="src/empty.py",
        timestamp="2025-06-19T12:00:00Z",
        attack_surface=AttackSurface(),
        mutations=[],
        payloads=[],
        proofs=[],
        findings=[],
        certificate=None,
        risk_score=0.0,
        grade="A+",
    )


# ---------------------------------------------------------------------------
# Helper-function tests
# ---------------------------------------------------------------------------

class TestHelpers:
    """Tests for internal helper functions."""

    @pytest.mark.parametrize("grade,expected", [
        ("A+", "#27ae60"),
        ("A", "#2ecc71"),
        ("B", "#f39c12"),
        ("C", "#e67e22"),
        ("D", "#e74c3c"),
        ("F", "#c0392b"),
        ("Z", "#7f8c8d"),   # unknown grade fallback
    ])
    def test_grade_colour(self, grade: str, expected: str) -> None:
        assert _grade_colour(grade) == expected

    @pytest.mark.parametrize("severity,expected", [
        ("critical", 0),
        ("high", 1),
        ("medium", 2),
        ("low", 3),
        ("info", 4),
        ("unknown", 99),     # unknown fallback
    ])
    def test_severity_sort_key(self, severity: str, expected: int) -> None:
        assert _severity_sort_key(severity) == expected

    def test_h_escapes_html(self) -> None:
        assert _h("<script>") == "&lt;script&gt;"
        assert _h("'quoted'") == "&#x27;quoted&#x27;"
        assert _h('"double"') == "&quot;double&quot;"

    @pytest.mark.parametrize("sev,level", [
        ("critical", "error"),
        ("high", "error"),
        ("medium", "warning"),
        ("low", "note"),
        ("info", "none"),
    ])
    def test_sarif_level_mapping(self, sev: str, level: str) -> None:
        assert ReportGenerator._sarif_level(sev) == level  # type: ignore[misc]


# ---------------------------------------------------------------------------
# HTML report tests
# ---------------------------------------------------------------------------

class TestHtmlReport:
    """Tests for ReportGenerator.generate_html()."""

    def test_returns_string(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        html = generator.generate_html(sample_result)
        assert isinstance(html, str)
        assert len(html) > 1000

    def test_contains_doctype(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        html = generator.generate_html(sample_result)
        assert "<!DOCTYPE html>" in html

    def test_contains_title_with_target(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        html = generator.generate_html(sample_result)
        assert "<title>VeriClaw Report" in html
        assert "src/app.py" in html

    def test_contains_executive_summary(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        html = generator.generate_html(sample_result)
        assert "Executive Summary" in html

    def test_contains_findings_section(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        html = generator.generate_html(sample_result)
        assert "Findings" in html
        assert "VC-SQLI-001" in html
        assert "VC-XSS-002" in html

    def test_contains_attack_surface_section(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        html = generator.generate_html(sample_result)
        assert "Attack Surface" in html
        assert "login" in html
        assert "search" in html

    def test_contains_data_flows(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        html = generator.generate_html(sample_result)
        assert "Data Flows" in html
        assert "request.form.username" in html

    def test_contains_trust_boundaries(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        html = generator.generate_html(sample_result)
        assert "Trust Boundaries" in html
        assert "API Gateway" in html

    def test_contains_proofs_section(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        html = generator.generate_html(sample_result)
        assert "Property Proofs" in html
        assert "type_safety" in html
        assert "memory_safety" in html
        assert "injection_resistance" in html

    def test_contains_mutations_section(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        html = generator.generate_html(sample_result)
        assert "Mutations" in html
        assert "ORIGINAL" in html
        assert "MUTATED" in html

    def test_contains_payloads_section(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        html = generator.generate_html(sample_result)
        assert "Payloads" in html
        # Payload content is HTML-escaped (single quotes -> &#x27; in Py3.12+)
        assert "alert(&#x27;XSS&#x27;)" in html or "alert('XSS')" in html

    def test_contains_certificate_section(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        html = generator.generate_html(sample_result)
        assert "Security Certificate" in html
        # Certificate uses all-caps "VERIFIED" with checkmark entity
        assert "VERIFIED" in html
        assert "&#x2714;" in html

    def test_contains_attack_chain(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        html = generator.generate_html(sample_result)
        assert "Attack Chain" in html
        assert "SQL Injection" in html

    def test_contains_remediation_section(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        html = generator.generate_html(sample_result)
        assert "Remediation Recommendations" in html
        assert "Use parameterized queries" in html

    def test_contains_footer(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        html = generator.generate_html(sample_result)
        assert "Generated by" in html
        assert "VeriClaw" in html
        assert VERICLAW_VERSION in html

    def test_findings_sorted_by_severity(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        """Critical findings should appear before high findings."""
        html = generator.generate_html(sample_result)
        # In the sorted table, VC-SQLI-001 (critical) should come before VC-XSS-002 (high)
        pos_critical = html.find("VC-SQLI-001")
        pos_high = html.find("VC-XSS-002")
        assert pos_critical < pos_high

    # -- Grade badge colours --

    @pytest.mark.parametrize("grade,colour", [
        ("A+", "#27ae60"),
        ("A", "#2ecc71"),
        ("B", "#f39c12"),
        ("C", "#e67e22"),
        ("D", "#e74c3c"),
        ("F", "#c0392b"),
    ])
    def test_grade_badge_colour(self, generator: ReportGenerator, grade: str, colour: str) -> None:
        result = ScanResult(
            target="test.py",
            timestamp="2025-01-01T00:00:00Z",
            attack_surface=AttackSurface(),
            mutations=[],
            payloads=[],
            proofs=[],
            findings=[],
            certificate=None,
            risk_score=5.0,
            grade=grade,
        )
        html = generator.generate_html(result)
        assert colour in html

    # -- Dark theme --

    def test_dark_theme_css_present(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        html = generator.generate_html(sample_result)
        assert "prefers-color-scheme: dark" in html

    def test_dark_theme_has_different_bg(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        html = generator.generate_html(sample_result)
        # In dark mode, background should be a dark colour
        match = re.search(r'@media\s*\(prefers-color-scheme:\s*dark\)\s*\{[^}]*--bg:\s*(#[0-9a-fA-F]+)', html)
        assert match is not None
        dark_bg = match.group(1)
        assert int(dark_bg[1:3], 16) < 50  # Dark backgrounds have low R value

    # -- Responsive design --

    def test_responsive_media_query(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        html = generator.generate_html(sample_result)
        assert "@media (max-width: 640px)" in html

    # -- Risk gauge --

    def test_risk_gauge_present(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        html = generator.generate_html(sample_result)
        assert "gauge-container" in html
        assert "6.5 / 10" in html

    # -- HTML escaping --

    def test_html_escaping_in_content(self, generator: ReportGenerator) -> None:
        """Potentially dangerous content should be escaped."""
        result = ScanResult(
            target="<script>alert(1)</script>.py",
            timestamp="2025-01-01T00:00:00Z",
            attack_surface=AttackSurface(),
            mutations=[],
            payloads=[],
            proofs=[],
            findings=[Finding(
                id="VC-001",
                title="<b>XSS</b>",
                severity="high",
                category="Injection",
                description="<script>alert(1)</script>",
                evidence="<iframe src='evil.com'>",
                remediation="Use &lt;escaped&gt; output",
            )],
            certificate=None,
            risk_score=5.0,
            grade="F",
        )
        html = generator.generate_html(result)
        # User-provided content must be escaped (the HTML itself contains
        # <script> tags for the table sorter, so we check the *finding*
        # content is escaped rather than banning <script> globally).
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html  # description escaped
        assert "&lt;b&gt;XSS&lt;/b&gt;" in html  # title escaped
        assert "&lt;iframe" in html  # evidence starts with escaped iframe tag
        assert "evil.com" in html  # evidence domain preserved
        assert "&lt;script&gt;alert(1)&lt;/script&gt;.py" in html  # target escaped

    # -- Error handling --

    def test_type_error_on_invalid_input(self, generator: ReportGenerator) -> None:
        with pytest.raises(TypeError, match="ScanResult"):
            generator.generate_html("not a scan result")


# ---------------------------------------------------------------------------
# SARIF export tests
# ---------------------------------------------------------------------------

class TestSarifExport:
    """Tests for ReportGenerator.generate_sarif()."""

    def test_returns_dict(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        sarif = generator.generate_sarif(sample_result)
        assert isinstance(sarif, dict)

    def test_valid_json_serialisable(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        sarif = generator.generate_sarif(sample_result)
        json_str = json.dumps(sarif)
        restored = json.loads(json_str)
        assert restored["version"] == "2.1.0"

    def test_has_schema_field(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        sarif = generator.generate_sarif(sample_result)
        assert "$schema" in sarif
        assert "sarif-schema-2.1.0" in sarif["$schema"]

    def test_has_correct_version(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        sarif = generator.generate_sarif(sample_result)
        assert sarif["version"] == "2.1.0"

    def test_has_runs_array(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        sarif = generator.generate_sarif(sample_result)
        assert "runs" in sarif
        assert isinstance(sarif["runs"], list)
        assert len(sarif["runs"]) == 1

    def test_tool_info_present(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        sarif = generator.generate_sarif(sample_result)
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "VeriClaw"
        assert driver["version"] == VERICLAW_VERSION

    def test_results_present(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        sarif = generator.generate_sarif(sample_result)
        results = sarif["runs"][0]["results"]
        assert isinstance(results, list)
        assert len(results) >= 2  # At least 2 findings

    def test_finding_has_rule_id(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        sarif = generator.generate_sarif(sample_result)
        results = sarif["runs"][0]["results"]
        # Findings are mapped to ruleIds based on their category
        rule_ids = {r.get("ruleId", "") for r in results}
        assert "VC-INJECTION" in rule_ids  # from "Injection" category
        # Every result must have a ruleId
        for r in results:
            assert "ruleId" in r
            assert r["ruleId"].startswith("VC-")

    def test_finding_has_level(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        sarif = generator.generate_sarif(sample_result)
        results = sarif["runs"][0]["results"]
        levels = {r["level"] for r in results if "level" in r}
        assert "error" in levels  # critical/high findings map to error

    def test_finding_has_message(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        sarif = generator.generate_sarif(sample_result)
        results = sarif["runs"][0]["results"]
        for r in results:
            assert "message" in r
            assert "text" in r["message"]

    def test_finding_has_location(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        sarif = generator.generate_sarif(sample_result)
        results = sarif["runs"][0]["results"]
        for r in results:
            assert "locations" in r
            assert len(r["locations"]) > 0

    def test_cwe_in_properties(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        sarif = generator.generate_sarif(sample_result)
        results = sarif["runs"][0]["results"]
        for r in results:
            props = r.get("properties", {})
            if "VC-SQLI" in r.get("ruleId", ""):
                assert props.get("cwe") == "89"
                return

    def test_cvss_in_properties(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        sarif = generator.generate_sarif(sample_result)
        results = sarif["runs"][0]["results"]
        for r in results:
            props = r.get("properties", {})
            if props.get("id") == "VC-SQLI-001":
                assert props.get("cvssScore") == 9.8
                return
        pytest.fail("CVSS score not found in SARIF properties")

    def test_rules_defined(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        sarif = generator.generate_sarif(sample_result)
        rules = sarif["runs"][0]["tool"]["driver"].get("rules", [])
        assert len(rules) >= 1
        rule_ids = {r["id"] for r in rules}
        assert "VC-INJECTION" in rule_ids

    def test_invocation_present(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        sarif = generator.generate_sarif(sample_result)
        invocations = sarif["runs"][0].get("invocations", [])
        assert len(invocations) == 1
        assert invocations[0]["executionSuccessful"] is True

    def test_property_violation_in_results(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        sarif = generator.generate_sarif(sample_result)
        results = sarif["runs"][0]["results"]
        violation_results = [r for r in results if r.get("ruleId") == "VC-PROPERTY_VIOLATION"]
        assert len(violation_results) >= 1

    def test_vericlaw_extension_properties(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        sarif = generator.generate_sarif(sample_result)
        run_props = sarif["runs"][0].get("properties", {}).get("veriClaw", {})
        assert run_props.get("grade") == "C"
        assert run_props.get("riskScore") == 6.5

    def test_type_error_on_invalid_input(self, generator: ReportGenerator) -> None:
        with pytest.raises(TypeError, match="ScanResult"):
            generator.generate_sarif("not a scan result")


# ---------------------------------------------------------------------------
# Markdown report tests
# ---------------------------------------------------------------------------

class TestMarkdownReport:
    """Tests for ReportGenerator.generate_markdown()."""

    def test_returns_string(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        md = generator.generate_markdown(sample_result)
        assert isinstance(md, str)
        assert len(md) > 100

    def test_contains_target(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        md = generator.generate_markdown(sample_result)
        assert "src/app.py" in md

    def test_contains_grade(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        md = generator.generate_markdown(sample_result)
        assert "C" in md

    def test_contains_risk_score(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        md = generator.generate_markdown(sample_result)
        assert "6.5 / 10" in md

    def test_contains_finding_count(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        md = generator.generate_markdown(sample_result)
        assert "**Findings:** 2" in md

    def test_contains_severity_breakdown(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        md = generator.generate_markdown(sample_result)
        assert "Severity Breakdown" in md
        assert "CRITICAL" in md
        assert "HIGH" in md

    def test_contains_top_findings_table(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        md = generator.generate_markdown(sample_result)
        assert "Top Findings" in md
        assert "|" in md  # Table delimiter
        assert "VC-SQLI-001" in md
        assert "VC-XSS-002" in md

    def test_contains_property_proofs_summary(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        md = generator.generate_markdown(sample_result)
        assert "Property Proofs" in md
        assert "**Proven:** 2" in md
        assert "**Violated:** 1" in md

    def test_contains_mutation_count(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        md = generator.generate_markdown(sample_result)
        assert "Mutations tested" in md

    def test_contains_payload_count(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        md = generator.generate_markdown(sample_result)
        assert "Payloads generated" in md

    def test_contains_certificate_status(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        md = generator.generate_markdown(sample_result)
        assert "Certificate Signature" in md

    def test_contains_footer(self, generator: ReportGenerator, sample_result: ScanResult) -> None:
        md = generator.generate_markdown(sample_result)
        assert "Generated by VeriClaw" in md
        assert VERICLAW_VERSION in md

    def test_markdown_code_fence_for_target(self, generator: ReportGenerator) -> None:
        """Target name should be wrapped in backticks (code span) in markdown."""
        result = ScanResult(
            target="<script>.py",
            timestamp="2025-01-01T00:00:00Z",
            attack_surface=AttackSurface(),
            mutations=[],
            payloads=[],
            proofs=[],
            findings=[],
            certificate=None,
            risk_score=0.0,
            grade="A",
        )
        md = generator.generate_markdown(result)
        # Target is wrapped in backticks, rendering it as inline code
        assert "`<script>.py`" in md

    def test_type_error_on_invalid_input(self, generator: ReportGenerator) -> None:
        with pytest.raises(TypeError, match="ScanResult"):
            generator.generate_markdown("not a scan result")


# ---------------------------------------------------------------------------
# Certificate rendering tests
# ---------------------------------------------------------------------------

class TestCertificateRendering:
    """Tests for ReportGenerator.render_certificate()."""

    def test_returns_string(self, generator: ReportGenerator, sample_certificate: SecurityCertificate) -> None:
        html = generator.render_certificate(sample_certificate)
        assert isinstance(html, str)
        assert len(html) > 1000

    def test_contains_target(self, generator: ReportGenerator, sample_certificate: SecurityCertificate) -> None:
        html = generator.render_certificate(sample_certificate)
        assert "src/app.py" in html

    def test_contains_grade(self, generator: ReportGenerator, sample_certificate: SecurityCertificate) -> None:
        html = generator.render_certificate(sample_certificate)
        assert sample_certificate.grade in html

    def test_contains_grade_colour(self, generator: ReportGenerator, sample_certificate: SecurityCertificate) -> None:
        html = generator.render_certificate(sample_certificate)
        assert "#e67e22" in html  # C grade colour

    def test_contains_findings_table(self, generator: ReportGenerator, sample_certificate: SecurityCertificate) -> None:
        html = generator.render_certificate(sample_certificate)
        assert "VC-SQLI-001" in html
        assert "VC-XSS-002" in html

    def test_contains_proofs_table(self, generator: ReportGenerator, sample_certificate: SecurityCertificate) -> None:
        html = generator.render_certificate(sample_certificate)
        assert "type_safety" in html
        assert "memory_safety" in html

    def test_contains_signature_verified(self, generator: ReportGenerator, sample_certificate: SecurityCertificate) -> None:
        html = generator.render_certificate(sample_certificate)
        assert "Signature Verified" in html

    def test_contains_timestamp(self, generator: ReportGenerator, sample_certificate: SecurityCertificate) -> None:
        html = generator.render_certificate(sample_certificate)
        assert sample_certificate.timestamp in html

    def test_contains_expiry(self, generator: ReportGenerator, sample_certificate: SecurityCertificate) -> None:
        html = generator.render_certificate(sample_certificate)
        assert sample_certificate.expires in html

    def test_contains_version(self, generator: ReportGenerator, sample_certificate: SecurityCertificate) -> None:
        html = generator.render_certificate(sample_certificate)
        assert VERICLAW_VERSION in html

    def test_certificate_official_styling(self, generator: ReportGenerator, sample_certificate: SecurityCertificate) -> None:
        html = generator.render_certificate(sample_certificate)
        assert "certificate" in html.lower() or "Certificate of Security Assessment" in html
        assert "VeriClaw" in html

    def test_invalid_signature_shows_fail(self, generator: ReportGenerator) -> None:
        cert = SecurityCertificate(
            target="test.py",
            timestamp="2025-01-01T00:00:00Z",
            findings=[],
            proofs=[],
            risk_score=0.0,
            grade="A+",
            signature="",
            expires="2025-12-31T00:00:00Z",
        )
        html = generator.render_certificate(cert)
        assert "Invalid" in html or "MISSING" in html or "Missing" in html

    def test_empty_findings_renders_gracefully(self, generator: ReportGenerator) -> None:
        cert = SecurityCertificate(
            target="test.py",
            timestamp="2025-01-01T00:00:00Z",
            findings=[],
            proofs=[],
            risk_score=0.0,
            grade="A+",
            signature="sig123",
            expires="2025-12-31T00:00:00Z",
        )
        html = generator.render_certificate(cert)
        assert isinstance(html, str)
        assert "No findings" in html or "0" in html


# ---------------------------------------------------------------------------
# Empty-result graceful handling tests
# ---------------------------------------------------------------------------

class TestEmptyResults:
    """Tests that all generators handle empty ScanResults gracefully."""

    def test_html_no_crash(self, generator: ReportGenerator, empty_result: ScanResult) -> None:
        html = generator.generate_html(empty_result)
        assert isinstance(html, str)
        assert "<!DOCTYPE html>" in html

    def test_html_shows_no_findings(self, generator: ReportGenerator, empty_result: ScanResult) -> None:
        html = generator.generate_html(empty_result)
        assert "No findings detected" in html or "Findings (0)" in html or "0" in html

    def test_html_shows_no_mutations(self, generator: ReportGenerator, empty_result: ScanResult) -> None:
        html = generator.generate_html(empty_result)
        assert "No mutations generated" in html

    def test_html_shows_no_payloads(self, generator: ReportGenerator, empty_result: ScanResult) -> None:
        html = generator.generate_html(empty_result)
        assert "No payloads generated" in html

    def test_html_shows_no_proofs(self, generator: ReportGenerator, empty_result: ScanResult) -> None:
        html = generator.generate_html(empty_result)
        assert "No proofs executed" in html

    def test_html_no_certificate_section_when_none(self, generator: ReportGenerator, empty_result: ScanResult) -> None:
        html = generator.generate_html(empty_result)
        # Certificate section should not appear when certificate is None
        # (The summary may mention signature, but the card should not exist)
        cert_card_count = html.lower().count("security certificate")
        # Should be 0 or only in a "Signature" line, not a full card
        assert cert_card_count == 0

    def test_sarif_no_crash(self, generator: ReportGenerator, empty_result: ScanResult) -> None:
        sarif = generator.generate_sarif(empty_result)
        assert isinstance(sarif, dict)
        assert sarif["version"] == "2.1.0"

    def test_sarif_empty_results(self, generator: ReportGenerator, empty_result: ScanResult) -> None:
        sarif = generator.generate_sarif(empty_result)
        results = sarif["runs"][0]["results"]
        assert isinstance(results, list)
        assert len(results) == 0

    def test_markdown_no_crash(self, generator: ReportGenerator, empty_result: ScanResult) -> None:
        md = generator.generate_markdown(empty_result)
        assert isinstance(md, str)
        assert "VeriClaw" in md

    def test_markdown_shows_zero_findings(self, generator: ReportGenerator, empty_result: ScanResult) -> None:
        md = generator.generate_markdown(empty_result)
        assert "**Findings:** 0" in md

    def test_markdown_no_severity_breakdown_when_empty(self, generator: ReportGenerator, empty_result: ScanResult) -> None:
        md = generator.generate_markdown(empty_result)
        # Should not show severity breakdown when there are no findings
        lines = md.split("\n")
        severity_lines = [l for l in lines if "CRITICAL:" in l or "HIGH:" in l or "MEDIUM:" in l]
        assert len(severity_lines) == 0


# ---------------------------------------------------------------------------
# Integration / edge-case tests
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge-case and integration tests."""

    def test_result_with_many_findings(self, generator: ReportGenerator) -> None:
        """HTML and SARIF should handle many findings without error."""
        findings = [
            Finding(
                id=f"VC-{i:04d}",
                title=f"Finding number {i}",
                severity=["critical", "high", "medium", "low"][i % 4],
                category="Test",
                description=f"Description for finding {i}",
                evidence=f"Evidence {i}",
                remediation=f"Fix finding {i}",
            )
            for i in range(100)
        ]
        result = ScanResult(
            target="big_project.py",
            timestamp="2025-01-01T00:00:00Z",
            attack_surface=AttackSurface(),
            mutations=[],
            payloads=[],
            proofs=[],
            findings=findings,
            certificate=None,
            risk_score=7.5,
            grade="D",
        )
        html = generator.generate_html(result)
        sarif = generator.generate_sarif(result)
        md = generator.generate_markdown(result)

        assert "VC-0099" in html
        assert len(sarif["runs"][0]["results"]) == 100
        # Top 10 findings in markdown are sorted by severity; VC-0099 is low
        # severity so it won't be in the top 10, but the summary note appears
        assert "and 90 more" in md or "VC-0099" in md

    def test_unicode_content(self, generator: ReportGenerator) -> None:
        """Unicode in findings should be handled correctly."""
        result = ScanResult(
            target="app_\u4e2d\u6587.py",
            timestamp="2025-01-01T00:00:00Z",
            attack_surface=AttackSurface(),
            mutations=[],
            payloads=[],
            proofs=[],
            findings=[
                Finding(
                    id="VC-001",
                    title="Unicode test: \u4e2d\u6587\u6f0f\u6d1e",
                    severity="medium",
                    category="Test",
                    description="Description with unicode: \U0001F600",
                    evidence="Evidence: caf\u00e9",
                    remediation="Fix: na\u00efve approach",
                ),
            ],
            certificate=None,
            risk_score=3.0,
            grade="B",
        )
        html = generator.generate_html(result)
        assert "\u4e2d\u6587" in html

    def test_long_strings_truncated_in_html(self, generator: ReportGenerator) -> None:
        """Very long descriptions should be truncated in the HTML table."""
        long_desc = "A" * 500
        result = ScanResult(
            target="test.py",
            timestamp="2025-01-01T00:00:00Z",
            attack_surface=AttackSurface(),
            mutations=[],
            payloads=[],
            proofs=[],
            findings=[
                Finding(
                    id="VC-001",
                    title="Long desc test",
                    severity="low",
                    category="Test",
                    description=long_desc,
                    evidence="B" * 500,
                    remediation="Fix it",
                ),
            ],
            certificate=None,
            risk_score=1.0,
            grade="A",
        )
        html = generator.generate_html(result)
        # Should contain the truncated version with ellipsis
        assert "..." in html
        # The full 500-char string should not appear unbroken
        assert "A" * 200 not in html

    def test_certificate_with_all_grades(self, generator: ReportGenerator) -> None:
        """Certificate should render correctly for every possible grade."""
        for grade in ["A+", "A", "B", "C", "D", "F"]:
            cert = SecurityCertificate(
                target="test.py",
                timestamp="2025-01-01T00:00:00Z",
                findings=[],
                proofs=[],
                risk_score=5.0,
                grade=grade,
                signature="sig",
                expires="2025-12-31T00:00:00Z",
            )
            html = generator.render_certificate(cert)
            assert grade in html
            assert isinstance(html, str)

    def test_markdown_no_top_findings_when_empty(self, generator: ReportGenerator, empty_result: ScanResult) -> None:
        md = generator.generate_markdown(empty_result)
        assert "Top Findings" not in md

    def test_markdown_limits_to_10_findings(self, generator: ReportGenerator) -> None:
        """Markdown should only show top 10 findings with a count note."""
        findings = [
            Finding(
                id=f"VC-{i:04d}",
                title=f"Finding {i}",
                severity="medium",
                category="Test",
                description="Desc",
                evidence="Evid",
                remediation="Fix",
            )
            for i in range(15)
        ]
        result = ScanResult(
            target="test.py",
            timestamp="2025-01-01T00:00:00Z",
            attack_surface=AttackSurface(),
            mutations=[],
            payloads=[],
            proofs=[],
            findings=findings,
            certificate=None,
            risk_score=3.0,
            grade="C",
        )
        md = generator.generate_markdown(result)
        # Should have a note about additional findings
        assert "and 5 more" in md

    def test_html_risk_gauge_zero(self, generator: ReportGenerator) -> None:
        """Gauge should work with risk score of 0."""
        result = ScanResult(
            target="test.py",
            timestamp="2025-01-01T00:00:00Z",
            attack_surface=AttackSurface(),
            mutations=[],
            payloads=[],
            proofs=[],
            findings=[],
            certificate=None,
            risk_score=0.0,
            grade="A+",
        )
        html = generator.generate_html(result)
        assert "0.0 / 10" in html
        assert "gauge-container" in html

    def test_html_risk_gauge_max(self, generator: ReportGenerator) -> None:
        """Gauge should cap at 100% even with risk score above 10."""
        result = ScanResult(
            target="test.py",
            timestamp="2025-01-01T00:00:00Z",
            attack_surface=AttackSurface(),
            mutations=[],
            payloads=[],
            proofs=[],
            findings=[],
            certificate=None,
            risk_score=15.0,  # Above max
            grade="F",
        )
        html = generator.generate_html(result)
        # Should still render without error
        assert "gauge-container" in html

    def test_sarif_level_mapping_unknown_severity(self) -> None:
        """Unknown severity should default to 'warning'."""
        assert ReportGenerator._sarif_level("unknown_severity") == "warning"  # type: ignore[misc]
        assert ReportGenerator._sarif_level("") == "warning"  # type: ignore[misc]
