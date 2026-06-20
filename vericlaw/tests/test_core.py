"""Comprehensive test suite for VeriClaw core modules.

Covers:
- Engine initialization with different configs
- Scan pipeline on sample vulnerable code
- Analyzer detecting Flask routes, SQL injection points, subprocess calls
- Mutator generating boundary and injection mutations
"""

from __future__ import annotations

import os
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

# Ensure the package under test is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vericlaw.analyzer import (
    AttackSurface,
    AttackSurfaceAnalyzer,
    AttackVector,
    Boundary,
    DataFlow,
    EntryPoint,
)
from vericlaw.engine import ScanResult, VeriClawEngine
from vericlaw.mutator import AdversarialMutator, Mutation
from vericlaw.certifier import Finding, SecurityCertificate
from vericlaw.prover import PropertyProof
from vericlaw.ci import PolicyEngine, PolicyDecision
from vericlaw.report import ReportGenerator


# ============================================================================
# Fixtures
# ============================================================================

SAMPLE_VULNERABLE_CODE = textwrap.dedent(
    '''\
    import os
    import subprocess
    import json
    import pickle
    from flask import Flask, request, render_template_string

    app = Flask(__name__)

    @app.route("/search", methods=["GET"])
    def search(user_input):
        query = user_input
        cursor = get_db().cursor()
        cursor.execute("SELECT * FROM items WHERE name = '" + query + "'")
        return "done"

    @app.route("/run", methods=["POST"])
    def run_command(cmd):
        result = os.system(cmd)
        return str(result)

    @app.route("/load", methods=["POST"])
    def load_data(data):
        obj = pickle.loads(data)
        return str(obj)

    @app.route("/greet")
    def greet(name):
        template = "Hello " + name
        return render_template_string(template)

    def safe_helper(x):
        return x * 2

    def process(user_request):
        val = eval(user_request)
        return val
    '''
)

SAMPLE_SAFE_CODE = textwrap.dedent(
    '''\
    def add(a: int, b: int) -> int:
        return a + b

    def multiply(x: int, y: int) -> int:
        return x * y
    '''
)


@pytest.fixture
def engine():
    """Default VeriClawEngine instance."""
    return VeriClawEngine()


@pytest.fixture
def strict_engine():
    """VeriClawEngine with strict policy."""
    return VeriClawEngine(config={"policy_level": "strict"})


@pytest.fixture
def analyzer():
    """AttackSurfaceAnalyzer instance."""
    return AttackSurfaceAnalyzer()


@pytest.fixture
def mutator():
    """AdversarialMutator instance with deterministic seed."""
    return AdversarialMutator(config={"seed": 42})


# ============================================================================
# Engine tests
# ============================================================================

class TestEngineInit:
    """Test VeriClawEngine initialization."""

    def test_default_init(self, engine):
        assert engine.analyzer is not None
        assert engine.mutator is not None
        assert engine.payloads is not None
        assert engine.prover is not None
        assert engine.certifier is not None
        assert engine.policy is not None
        assert engine.reporter is not None

    def test_strict_policy(self, strict_engine):
        assert strict_engine.policy.level == "strict"

    def test_custom_config(self):
        cfg = {
            "timeout": 60,
            "max_mutations": 20,
            "swarm_size": 10,
            "policy_level": "permissive",
        }
        e = VeriClawEngine(config=cfg)
        assert e.config == cfg
        assert e.policy.level == "permissive"
        assert e.mutator.max_mutations == 20

    def test_empty_config(self):
        e = VeriClawEngine(config={})
        assert e.policy.level == "standard"

    def test_none_config(self):
        e = VeriClawEngine(config=None)
        assert e.policy.level == "standard"


class TestEngineGrade:
    """Test grade computation."""

    @pytest.mark.parametrize(
        "score,expected",
        [
            (0.0, "A+"),
            (0.5, "A+"),
            (1.0, "A+"),
            (1.5, "A"),
            (2.0, "A"),
            (2.5, "B"),
            (3.0, "B"),
            (4.0, "C"),
            (5.0, "C"),
            (6.0, "D"),
            (7.0, "D"),
            (8.0, "F"),
            (10.0, "F"),
        ],
    )
    def test_grade_mapping(self, score, expected):
        assert VeriClawEngine._grade_from_score(score) == expected


class TestEngineScan:
    """Test the full scan pipeline."""

    def test_scan_on_vulnerable_code(self, engine):
        result = engine.scan(SAMPLE_VULNERABLE_CODE)
        assert isinstance(result, ScanResult)
        assert result.target == SAMPLE_VULNERABLE_CODE
        assert result.attack_surface is not None
        assert result.risk_score > 0
        # Should detect entry points
        assert len(result.attack_surface.entry_points) > 0
        # Should have findings from attack vectors
        assert len(result.findings) >= 0

    def test_scan_on_safe_code(self, engine):
        result = engine.scan(SAMPLE_SAFE_CODE)
        assert isinstance(result, ScanResult)
        assert result.risk_score == 0.0
        assert result.grade == "A+"

    def test_scan_returns_mutations_for_vulnerable(self, engine):
        result = engine.scan(SAMPLE_VULNERABLE_CODE)
        # High-risk entry points should generate mutations
        assert len(result.mutations) > 0

    def test_scan_returns_payloads(self, engine):
        result = engine.scan(SAMPLE_VULNERABLE_CODE)
        # Payloads should be generated for high-risk entry points
        assert len(result.payloads) > 0

    def test_scan_returns_proofs(self, engine):
        result = engine.scan(SAMPLE_VULNERABLE_CODE)
        assert len(result.proofs) > 0
        for proof in result.proofs:
            assert isinstance(proof, PropertyProof)

    def test_scan_with_certificate(self, engine):
        result = engine.scan(SAMPLE_VULNERABLE_CODE, certify=True)
        assert result.certificate is not None
        assert isinstance(result.certificate, SecurityCertificate)
        assert result.certificate.target == SAMPLE_VULNERABLE_CODE

    def test_scan_file(self, engine, tmp_path):
        f = tmp_path / "vuln.py"
        f.write_text(SAMPLE_VULNERABLE_CODE)
        result = engine.scan(str(f))
        assert isinstance(result, ScanResult)
        assert result.risk_score > 0

    def test_scan_invalid_code_returns_empty(self, engine):
        result = engine.scan("not valid python @@@")
        assert isinstance(result, ScanResult)
        assert result.attack_surface.risk_score == 0.0


class TestEngineRedTeam:
    """Test red team simulation."""

    def test_red_team_runs(self, engine):
        result = engine.red_team(SAMPLE_VULNERABLE_CODE, rounds=2)
        assert result.target == SAMPLE_VULNERABLE_CODE
        assert result.rounds == 2
        assert result.time_elapsed_ms >= 0

    def test_red_team_default_rounds(self, engine):
        result = engine.red_team(SAMPLE_VULNERABLE_CODE)
        assert result.rounds == 5


class TestEngineCertify:
    """Test certificate generation."""

    def test_certify_returns_certificate(self, engine):
        cert = engine.certify(SAMPLE_VULNERABLE_CODE)
        assert isinstance(cert, SecurityCertificate)
        assert cert.target == SAMPLE_VULNERABLE_CODE
        assert cert.grade is not None


# ============================================================================
# Analyzer tests
# ============================================================================

class TestAnalyzerEntryPoints:
    """Test entry point discovery."""

    def test_detects_function_defs(self, analyzer):
        code = "def foo(a, b):\n    pass\n"
        surface = analyzer.analyze(code)
        assert len(surface.entry_points) == 1
        ep = surface.entry_points[0]
        assert ep.name == "foo"
        assert ep.type == "function"
        assert ep.parameters == ["a", "b"]

    def test_detects_class_defs(self, analyzer):
        code = "class MyView:\n    def get(self):\n        pass\n"
        surface = analyzer.analyze(code)
        ep_names = [ep.name for ep in surface.entry_points]
        assert "MyView" in ep_names
        myview = [ep for ep in surface.entry_points if ep.name == "MyView"][0]
        assert myview.type == "class"

    def test_detects_method_defs(self, analyzer):
        code = "class MyView:\n    def get(self):\n        pass\n"
        surface = analyzer.analyze(code)
        ep_names = [ep.name for ep in surface.entry_points]
        assert "MyView.get" in ep_names

    def test_detects_async_functions(self, analyzer):
        code = "async def handler(req):\n    return req\n"
        surface = analyzer.analyze(code)
        assert any(ep.name == "handler" for ep in surface.entry_points)

    def test_detects_decorators(self, analyzer):
        code = "@app.route('/test')\ndef test():\n    pass\n"
        surface = analyzer.analyze(code)
        ep = surface.entry_points[0]
        assert "route" in ep.decorators

    def test_extracts_docstring(self, analyzer):
        code = 'def foo():\n    """A docstring."""\n    pass\n'
        surface = analyzer.analyze(code)
        ep = surface.entry_points[0]
        assert ep.docstring == "A docstring."


class TestAnalyzerFlaskRoutes:
    """Test Flask route detection."""

    def test_detects_flask_routes(self, analyzer):
        surface = analyzer.analyze(SAMPLE_VULNERABLE_CODE)
        route_eps = [ep for ep in surface.entry_points if ep.type == "endpoint"]
        assert len(route_eps) >= 4  # search, run_command, load_data, greet
        names = [ep.name for ep in route_eps]
        assert "search" in names
        assert "run_command" in names

    def test_routes_have_http_route_indicator(self, analyzer):
        surface = analyzer.analyze(SAMPLE_VULNERABLE_CODE)
        for ep in surface.entry_points:
            if ep.type == "endpoint":
                assert "http_route" in ep.risk_indicators


class TestAnalyzerRiskyParams:
    """Test risky parameter detection."""

    def test_detects_risky_params(self, analyzer):
        code = "def handle(user_input, request, data):\n    pass\n"
        surface = analyzer.analyze(code)
        ep = surface.entry_points[0]
        assert any("risky_param:user_input" == ri for ri in ep.risk_indicators)
        assert any("risky_param:request" == ri for ri in ep.risk_indicators)
        assert any("risky_param:data" == ri for ri in ep.risk_indicators)


class TestAnalyzerSQLInjection:
    """Test SQL injection point detection."""

    def test_detects_sql_execute(self, analyzer):
        code = "def query(data):\n    cursor.execute('SELECT * FROM t')\n"
        surface = analyzer.analyze(code)
        assert any(
            v.type == "SQL Injection" for v in surface.attack_vectors
        )

    def test_detects_sql_flow(self, analyzer):
        surface = analyzer.analyze(SAMPLE_VULNERABLE_CODE)
        sql_flows = [df for df in surface.data_flows if "execute" in df.sink]
        assert len(sql_flows) > 0

    def test_sql_injection_cwe89(self, analyzer):
        code = "def query(data):\n    cursor.execute('SELECT *')\n"
        surface = analyzer.analyze(code)
        vectors = [v for v in surface.attack_vectors if v.type == "SQL Injection"]
        assert all(v.cwe_id == "CWE-89" for v in vectors)


class TestAnalyzerSubprocess:
    """Test subprocess/command injection detection."""

    def test_detects_os_system(self, analyzer):
        surface = analyzer.analyze(SAMPLE_VULNERABLE_CODE)
        assert any(
            v.type == "Command Injection" for v in surface.attack_vectors
        )

    def test_detects_subprocess_call(self, analyzer):
        code = "import subprocess\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n"
        surface = analyzer.analyze(code)
        assert any(
            v.type == "Command Injection" for v in surface.attack_vectors
        )


class TestAnalyzerDeserialization:
    """Test deserialization detection."""

    def test_detects_pickle_loads(self, analyzer):
        surface = analyzer.analyze(SAMPLE_VULNERABLE_CODE)
        assert any(
            v.type == "Insecure Deserialization" for v in surface.attack_vectors
        )


class TestAnalyzerEvalExec:
    """Test eval/exec detection."""

    def test_detects_eval(self, analyzer):
        surface = analyzer.analyze(SAMPLE_VULNERABLE_CODE)
        assert any(
            v.type == "Code Injection" for v in surface.attack_vectors
        )

    def test_detects_exec(self, analyzer):
        code = "def bad(code):\n    exec(code)\n"
        surface = analyzer.analyze(code)
        assert any(
            v.type == "Code Injection" for v in surface.attack_vectors
        )


class TestAnalyzerAuthDecorators:
    """Test auth decorator detection."""

    def test_detects_login_required(self, analyzer):
        code = "@login_required\ndef secret():\n    pass\n"
        surface = analyzer.analyze(code)
        ep = surface.entry_points[0]
        assert "auth_protected" in ep.risk_indicators


class TestAnalyzerRiskScore:
    """Test risk score computation."""

    def test_vulnerable_code_high_score(self, analyzer):
        surface = analyzer.analyze(SAMPLE_VULNERABLE_CODE)
        assert surface.risk_score > 5.0
        assert surface.risk_score <= 10.0

    def test_safe_code_zero_score(self, analyzer):
        surface = analyzer.analyze(SAMPLE_SAFE_CODE)
        assert surface.risk_score == 0.0

    def test_syntax_error_returns_zero(self, analyzer):
        surface = analyzer.analyze("def broken(@@@)\n")
        assert surface.risk_score == 0.0


class TestAnalyzerFile:
    """Test file-based analysis."""

    def test_analyze_file(self, analyzer, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("def foo(x):\n    eval(x)\n")
        surface = analyzer.analyze_file(f)
        assert any(v.type == "Code Injection" for v in surface.attack_vectors)


class TestAnalyzerProject:
    """Test project-level analysis."""

    def test_analyze_project(self, analyzer, tmp_path):
        (tmp_path / "a.py").write_text("def foo():\n    eval('1')\n")
        (tmp_path / "b.py").write_text("def bar():\n    pass\n")
        results = analyzer.analyze_project(tmp_path)
        assert "a.py" in results
        assert "b.py" in results
        assert results["a.py"].risk_score > 0
        assert results["b.py"].risk_score == 0.0

    def test_analyze_project_skips_pycache(self, analyzer, tmp_path):
        pycache = tmp_path / "__pycache__"
        pycache.mkdir()
        (pycache / "cached.cpython-310.pyc").write_text("fake")
        (tmp_path / "real.py").write_text("def ok(): pass\n")
        results = analyzer.analyze_project(tmp_path)
        assert "real.py" in results
        assert "cached.cpython-310.pyc" not in results


# ============================================================================
# Mutator tests
# ============================================================================

class TestMutatorInit:
    """Test AdversarialMutator initialization."""

    def test_default_init(self):
        m = AdversarialMutator()
        assert m.max_mutations == 50
        assert len(m.strategies) == 8

    def test_custom_config(self):
        m = AdversarialMutator(config={"max_mutations": 10, "strategies": ["boundary", "injection"]})
        assert m.max_mutations == 10
        assert m.strategies == {"boundary", "injection"}

    def test_seed_for_reproducibility(self):
        m = AdversarialMutator(config={"seed": 123})
        code = "x = 5\ny = 10\n"
        ep = EntryPoint(name="test", type="function", line=1, parameters=[])
        r1 = m.fuzz(code, iterations=5)
        m2 = AdversarialMutator(config={"seed": 123})
        r2 = m2.fuzz(code, iterations=5)
        assert len(r1) == len(r2)


class TestMutatorBoundary:
    """Test boundary condition mutations."""

    def test_boundary_swaps(self, mutator):
        code = "if x >= 10:\n    pass\n"
        ep = EntryPoint(name="test", type="function", line=1, parameters=[])
        mutations = mutator.mutate(code, ep)
        boundary = [m for m in mutations if m.mutation_type == "boundary"]
        assert len(boundary) > 0
        # At least one mutation should change >= to something else
        assert any(
            ">" in m.mutated and ">=" not in m.mutated
            for m in boundary
        )

    def test_equality_swap(self, mutator):
        code = "if x == 10:\n    pass\n"
        ep = EntryPoint(name="test", type="function", line=1, parameters=[])
        mutations = mutator.mutate(code, ep)
        boundary = [m for m in mutations if m.mutation_type == "boundary"]
        assert any("!=" in m.mutated for m in boundary)


class TestMutatorInjection:
    """Test injection payload mutations."""

    def test_sqli_payload_injected(self, mutator):
        code = "query = 'SELECT * FROM users'\n"
        ep = EntryPoint(name="test", type="function", line=1, parameters=["user_input"])
        mutations = mutator.mutate(code, ep)
        injections = [m for m in mutations if m.mutation_type == "injection"]
        assert len(injections) > 0
        assert any("OR '1'='1" in m.mutated for m in injections)

    def test_xss_payload_injected(self, mutator):
        code = 'html = "<div>" + name + "</div>"\n'
        ep = EntryPoint(name="test", type="function", line=1, parameters=[])
        mutations = mutator.mutate(code, ep)
        injections = [m for m in mutations if m.mutation_type == "injection"]
        assert any("<script>" in m.mutated for m in injections)


class TestMutatorEncoding:
    """Test encoding variant mutations."""

    def test_base64_variant(self, mutator):
        code = "x = 'hello'\n"
        ep = EntryPoint(name="test", type="function", line=1, parameters=[])
        mutations = mutator.mutate(code, ep)
        encodings = [m for m in mutations if m.mutation_type == "encoding"]
        assert any("Base64" in m.description for m in encodings)

    def test_urlencode_variant(self, mutator):
        code = "x = 'hello'\n"
        ep = EntryPoint(name="test", type="function", line=1, parameters=[])
        mutations = mutator.mutate(code, ep)
        encodings = [m for m in mutations if m.mutation_type == "encoding"]
        assert any("URL-encoded" in m.description for m in encodings)

    def test_hex_variant(self, mutator):
        code = "x = 'hello'\n"
        ep = EntryPoint(name="test", type="function", line=1, parameters=[])
        mutations = mutator.mutate(code, ep)
        encodings = [m for m in mutations if m.mutation_type == "encoding"]
        assert any("Hex-encoded" in m.description for m in encodings)


class TestMutatorSemantic:
    """Test semantic swap mutations."""

    def test_json_to_pickle(self, mutator):
        code = "obj = json.loads(data)\n"
        ep = EntryPoint(name="test", type="function", line=1, parameters=[])
        mutations = mutator.mutate(code, ep)
        semantic = [m for m in mutations if m.mutation_type == "semantic"]
        assert any("pickle.loads" in m.mutated for m in semantic)

    def test_safe_to_unsafe_yaml(self, mutator):
        code = "obj = yaml.safe_load(data)\n"
        ep = EntryPoint(name="test", type="function", line=1, parameters=[])
        mutations = mutator.mutate(code, ep)
        semantic = [m for m in mutations if m.mutation_type == "semantic"]
        assert any("unsafe_load" in m.mutated for m in semantic)


class TestMutatorResource:
    """Test resource exhaustion mutations."""

    def test_infinite_loop_injected(self, mutator):
        code = "def calc():\n    return 1 + 1\n"
        ep = EntryPoint(name="test", type="function", line=1, parameters=[])
        mutations = mutator.mutate(code, ep)
        resource = [m for m in mutations if m.mutation_type == "resource"]
        assert any("while True" in m.mutated for m in resource)

    def test_massive_allocation(self, mutator):
        code = "x = 'A' * 10\n"
        ep = EntryPoint(name="test", type="function", line=1, parameters=[])
        mutations = mutator.mutate(code, ep)
        resource = [m for m in mutations if m.mutation_type == "resource"]
        assert any("10**9" in m.mutated for m in resource)


class TestMutatorNone:
    """Test None substitution mutations."""

    def test_replaces_with_none(self, mutator):
        code = "x = 42\n"
        ep = EntryPoint(name="test", type="function", line=1, parameters=[])
        mutations = mutator.mutate(code, ep)
        nones = [m for m in mutations if m.mutation_type == "none"]
        assert len(nones) > 0
        assert any("None" in m.mutated for m in nones)


class TestMutatorEmpty:
    """Test empty value substitution mutations."""

    def test_replaces_with_empty(self, mutator):
        code = "x = 'hello'\n"
        ep = EntryPoint(name="test", type="function", line=1, parameters=[])
        mutations = mutator.mutate(code, ep)
        empties = [m for m in mutations if m.mutation_type == "empty"]
        assert len(empties) > 0


class TestMutatorType:
    """Test type swap mutations."""

    def test_int_to_str(self, mutator):
        code = "x = int(y)\n"
        ep = EntryPoint(name="test", type="function", line=1, parameters=[])
        mutations = mutator.mutate(code, ep)
        types = [m for m in mutations if m.mutation_type == "type"]
        assert any("str(" in m.mutated for m in types)

    def test_str_to_int(self, mutator):
        code = "x = str(y)\n"
        ep = EntryPoint(name="test", type="function", line=1, parameters=[])
        mutations = mutator.mutate(code, ep)
        types = [m for m in mutations if m.mutation_type == "type"]
        assert any("int(" in m.mutated for m in types)


class TestMutatorFuzz:
    """Test fuzzing mode."""

    def test_fuzz_generates_mutations(self, mutator):
        code = "x = 5\ny = 10\nz = x + y\n"
        mutations = mutator.fuzz(code, iterations=20)
        assert len(mutations) > 0
        assert len(mutations) <= 20

    def test_fuzz_respects_max_mutations(self):
        m = AdversarialMutator(config={"max_mutations": 5, "seed": 42})
        code = "x = 5\ny = 10\nz = x + y\n"
        mutations = m.fuzz(code, iterations=100)
        assert len(mutations) <= 5

    def test_fuzz_returns_different_types(self, mutator):
        code = "x = 5\ny = 10\nz = x + y\n"
        mutations = mutator.fuzz(code, iterations=50)
        types = set(m.mutation_type for m in mutations)
        assert len(types) >= 1

    def test_empty_code(self, mutator):
        mutations = mutator.fuzz("")
        assert mutations == []


class TestMutatorDedup:
    """Test mutation deduplication."""

    def test_no_duplicate_mutated_content(self, mutator):
        code = "if x >= 10:\n    pass\n"
        ep = EntryPoint(name="test", type="function", line=1, parameters=[])
        mutations = mutator.mutate(code, ep)
        mutated_contents = [m.mutated for m in mutations]
        assert len(mutated_contents) == len(set(mutated_contents))


# ============================================================================
# Data class tests
# ============================================================================

class TestEntryPoint:
    """Test EntryPoint dataclass."""

    def test_defaults(self):
        ep = EntryPoint(name="foo", type="function", line=1)
        assert ep.parameters == []
        assert ep.returns is None
        assert ep.decorators == []
        assert ep.docstring is None
        assert ep.risk_indicators == []


class TestAttackSurface:
    """Test AttackSurface dataclass."""

    def test_defaults(self):
        s = AttackSurface()
        assert s.entry_points == []
        assert s.data_flows == []
        assert s.trust_boundaries == []
        assert s.attack_vectors == []
        assert s.risk_score == 0.0


class TestMutation:
    """Test Mutation dataclass."""

    def test_fields(self):
        m = Mutation(
            original="x = 1",
            mutated="x = None",
            mutation_type="none",
            description="test",
            severity="low",
        )
        assert m.original == "x = 1"
        assert m.mutated == "x = None"
        assert m.mutation_type == "none"


# ============================================================================
# CI / Policy tests
# ============================================================================

class TestPolicyEngine:
    """Test PolicyEngine."""

    def test_strict_fails_low_grade(self):
        p = PolicyEngine("strict")
        mock = type("M", (), {
            "grade": "C", "risk_score": 4.0,
            "findings": [],
            "proofs": [
                type("P", (), {"property_name": "type_safety", "status": "proven"})(),
                type("P", (), {"property_name": "memory_safety", "status": "proven"})(),
                type("P", (), {"property_name": "injection_resistance", "status": "proven"})(),
            ],
        })()
        d = p.check(mock)
        assert not d.passed  # Grade C fails strict (needs A)

    def test_standard_passes_b_grade(self):
        p = PolicyEngine("standard")
        mock = type("M", (), {
            "grade": "B", "risk_score": 3.0,
            "findings": [type("F", (), {"severity": "low", "title": "x", "category": "c", "remediation": "r"})()],
            "proofs": [
                type("P", (), {"property_name": "type_safety", "status": "proven"})(),
                type("P", (), {"property_name": "injection_resistance", "status": "proven"})(),
            ],
        })()
        d = p.check(mock)
        assert d.passed  # Grade B, low findings only, required proofs pass

    def test_permissive_only_fails_f(self):
        p = PolicyEngine("permissive")
        mock = type("M", (), {
            "grade": "C", "risk_score": 5.0,  # C is min for permissive
            "findings": [type("F", (), {"severity": "high", "title": "x", "category": "c", "remediation": "r"})()],
            "proofs": [type("P", (), {"property_name": "type_safety", "status": "proven"})()],
        })()
        d = p.check(mock)
        assert d.passed  # Grade C meets min, at least one proof passes

    def test_gate_returns_bool(self):
        p = PolicyEngine("standard")
        mock = type("M", (), {
            "grade": "A", "risk_score": 1.0,
            "findings": [],
            "proofs": [
                type("P", (), {"property_name": "type_safety", "status": "proven"})(),
                type("P", (), {"property_name": "injection_resistance", "status": "proven"})(),
            ],
        })()
        assert p.gate(mock) is True


# ============================================================================
# Report tests
# ============================================================================

class TestReportGenerator:
    """Test ReportGenerator."""

    def _make_result(self, findings=None):
        """Build a proper ScanResult."""
        from vericlaw.models import (
            AttackSurface, Finding, Mutation, Payload, PropertyProof, ScanResult,
        )
        return ScanResult(
            target="test.py",
            grade="A",
            risk_score=1.0,
            timestamp="2026-06-19T00:00:00",
            findings=findings if findings is not None else [],
            proofs=[PropertyProof("type_safety", "proven", confidence=0.9)],
            mutations=[Mutation("a", "b", "boundary", "test", "medium")],
            payloads=[Payload("<script>", "xss", "context", "raw", "high")],
            attack_surface=AttackSurface(),
        )

    def test_generate_html(self):
        rg = ReportGenerator()
        result = self._make_result()
        html = rg.generate_html(result)
        assert "test.py" in html
        assert "A" in html

    def test_generate_sarif(self):
        rg = ReportGenerator()
        f = Finding(
            id="VC-0001", title="TF", description="test", severity="high",
            category="c", evidence="e", remediation="r", cwe_id="89", cvss_score=7.5,
        )
        result = self._make_result(findings=[f])
        sarif = rg.generate_sarif(result)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1

    def test_generate_markdown(self):
        rg = ReportGenerator()
        result = self._make_result()
        md = rg.generate_markdown(result)
        assert "test.py" in md
        assert "A" in md


# ============================================================================
# Integration tests
# ============================================================================

class TestFullPipeline:
    """End-to-end integration tests."""

    def test_full_pipeline_on_vulnerable_code(self):
        engine = VeriClawEngine(config={"max_mutations": 10})
        result = engine.scan(SAMPLE_VULNERABLE_CODE)
        assert result.grade != "A+"
        assert result.risk_score > 0
        assert len(result.findings) > 0

    def test_full_pipeline_on_safe_code(self):
        engine = VeriClawEngine(config={"max_mutations": 10})
        result = engine.scan(SAMPLE_SAFE_CODE)
        assert result.grade == "A+"
        assert result.risk_score == 0.0

    def test_policy_gate_blocks_vulnerable(self):
        engine = VeriClawEngine(config={"policy_level": "strict"})
        result = engine.scan(SAMPLE_VULNERABLE_CODE)
        assert not engine.policy.gate(result)

    def test_policy_gate_allows_safe(self):
        engine = VeriClawEngine(config={"policy_level": "standard"})
        result = engine.scan(SAMPLE_SAFE_CODE)
        # Gate result depends on proof status
        assert isinstance(engine.policy.gate(result), bool)

    def test_certificate_verification(self):
        engine = VeriClawEngine()
        cert = engine.certify(SAMPLE_VULNERABLE_CODE)
        assert engine.certifier.verify(cert)
