"""Attack surface analysis via AST-based static analysis.

Discovers attack surfaces in Python code by detecting entry points,
data flows, trust boundaries, and attack vectors.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Optional

from .models import AttackSurface, AttackVector, Boundary, DataFlow, EntryPoint


# ---------------------------------------------------------------------------
# Risk indicators
# ---------------------------------------------------------------------------

_RISKY_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "user_input",
        "request",
        "data",
        "payload",
        "cmd",
        "command",
        "query",
        "sql",
        "filename",
        "path",
        "url",
        "body",
        "headers",
        "cookies",
        "form",
        "args",
        "kwargs",
        "input",
        "raw",
        "untrusted",
        "external",
    }
)

_SQL_SINKS: frozenset[str] = frozenset(
    {
        "execute",
        "executemany",
        "executescript",
        "raw",
        "raw_query",
    }
)

_SUBPROCESS_CALLS: frozenset[str] = frozenset(
    {
        "system",
        "popen",
        "call",
        "run",
        "check_output",
        "check_call",
    }
)

_DESER_CALLS: frozenset[str] = frozenset(
    {
        "loads",
        "load",
        "unsafe_load",
    }
)

_EVAL_EXEC: frozenset[str] = frozenset({"eval", "exec", "compile"})

_HTTP_CLIENTS: frozenset[str] = frozenset(
    {
        "get",
        "post",
        "put",
        "delete",
        "patch",
        "request",
    }
)

_TEMPLATE_RENDERS: frozenset[str] = frozenset(
    {
        "render_template",
        "render",
        "render_to_response",
        "Template",
    }
)

_AUTH_DECORATORS: frozenset[str] = frozenset(
    {
        "login_required",
        "requires_auth",
        "authenticate",
        "jwt_required",
        "oauth_required",
        "permission_required",
        "staff_member_required",
        "user_passes_test",
    }
)

_FILE_OPS: frozenset[str] = frozenset(
    {
        "open",
        "read",
        "write",
        "readlines",
        "writelines",
    }
)


# ---------------------------------------------------------------------------
# AST visitor
# ---------------------------------------------------------------------------

class _AttackSurfaceVisitor(ast.NodeVisitor):
    """AST visitor that collects entry points, sinks, and data flows."""

    def __init__(self, filepath: str = "<string>") -> None:
        self.filepath = filepath
        self.entry_points: list[EntryPoint] = []
        self.data_flows: list[DataFlow] = []
        self.boundaries: list[Boundary] = []
        self.vectors: list[AttackVector] = []
        self._current_class: Optional[str] = None
        self._import_aliases: dict[str, str] = {}  # alias -> real_name

    # -- helpers -----------------------------------------------------------

    def _location(self, node: ast.AST) -> str:
        return f"{self.filepath}:{getattr(node, 'lineno', 0)}"

    def _node_str(self, node: ast.AST) -> str:
        """Best-effort string representation of an AST node."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Constant):
            return repr(node.value)
        if isinstance(node, ast.Attribute):
            return f"{self._node_str(node.value)}.{node.attr}"
        if isinstance(node, ast.Call):
            return f"{self._node_str(node.func)}(...)"
        if isinstance(node, ast.BinOp):
            return "<binop>"
        if isinstance(node, ast.JoinedStr):
            return "<f-string>"
        return "<expr>"

    def _is_risky_param(self, name: str) -> bool:
        return name.lower() in _RISKY_PARAM_NAMES

    def _get_decorator_names(self, decorators: list[ast.expr]) -> list[str]:
        names: list[str] = []
        for d in decorators:
            if isinstance(d, ast.Name):
                names.append(d.id)
            elif isinstance(d, ast.Attribute):
                names.append(d.attr)
            elif isinstance(d, ast.Call):
                if isinstance(d.func, ast.Name):
                    names.append(d.func.id)
                elif isinstance(d.func, ast.Attribute):
                    names.append(d.func.attr)
        return names

    # -- visit methods -----------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            asname = alias.asname or alias.name
            self._import_aliases[asname] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        module = node.module or ""
        for alias in node.names:
            asname = alias.asname or alias.name
            self._import_aliases[asname] = f"{module}.{alias.name}"
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        prev = self._current_class
        self._current_class = node.name

        risk_indicators: list[str] = []
        for base in node.bases:
            base_name = self._node_str(base)
            if any(
                base_name.endswith(s)
                for s in ("View", "APIView", "Resource", "Handler")
            ):
                risk_indicators.append(f"inherits_{base_name}")

        ep = EntryPoint(
            name=node.name,
            type="class",
            line=node.lineno,
            decorators=self._get_decorator_names(node.decorator_list),
            docstring=ast.get_docstring(node),
            risk_indicators=risk_indicators,
        )
        self.entry_points.append(ep)
        self.generic_visit(node)
        self._current_class = prev

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._process_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._process_function(node, is_async=True)
        self.generic_visit(node)

    def _process_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        is_async: bool = False,
    ) -> None:
        params = [arg.arg for arg in node.args.args]
        params += [arg.arg for arg in node.args.kwonlyargs]
        if node.args.vararg:
            params.append(node.args.vararg.arg)
        if node.args.kwarg:
            params.append(node.args.kwarg.arg)

        dec_names = self._get_decorator_names(node.decorator_list)

        risk_indicators: list[str] = []
        for p in params:
            if self._is_risky_param(p):
                risk_indicators.append(f"risky_param:{p}")

        # Detect Flask / FastAPI / Django route decorators
        route_decorators = {"route", "get", "post", "put", "delete", "patch", "api_view"}
        if any(d in route_decorators for d in dec_names):
            risk_indicators.append("http_route")

        # Detect auth decorators
        if any(d in _AUTH_DECORATORS for d in dec_names):
            risk_indicators.append("auth_protected")

        # Detect template rendering
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._node_str(child.func)
                if any(call_name.endswith(r) for r in _TEMPLATE_RENDERS):
                    risk_indicators.append("template_render")
                    self.vectors.append(
                        AttackVector(
                            type="Server-Side Template Injection",
                            entry_point=f"{self.filepath}:{node.lineno}",
                            confidence=0.6,
                            evidence=f"Template render call: {call_name}",
                            cwe_id="CWE-1336",
                        )
                    )

        ep_type = "method" if self._current_class else "function"
        if any(d in route_decorators for d in dec_names):
            ep_type = "endpoint"

        name = node.name
        if self._current_class:
            name = f"{self._current_class}.{name}"

        ep = EntryPoint(
            name=name,
            type=ep_type,
            line=node.lineno,
            parameters=params,
            decorators=dec_names,
            docstring=ast.get_docstring(node),
            risk_indicators=risk_indicators,
        )
        self.entry_points.append(ep)

        # Walk body for sinks
        self._scan_body_for_sinks(node, name)

    def _scan_body_for_sinks(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        func_name: str,
    ) -> None:
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            call_name = self._node_str(child.func)
            loc = f"{self.filepath}:{getattr(child, 'lineno', 0)}"

            # SQL injection sinks
            if any(call_name.endswith(f".{s}") or call_name == s for s in _SQL_SINKS):
                self.data_flows.append(
                    DataFlow(
                        source=func_name,
                        sink=call_name,
                        path=[loc],
                        taint_level="high",
                    )
                )
                self.vectors.append(
                    AttackVector(
                        type="SQL Injection",
                        entry_point=loc,
                        confidence=0.8,
                        evidence=f"SQL sink: {call_name}",
                        cwe_id="CWE-89",
                    )
                )
                self.boundaries.append(
                    Boundary(
                        name=f"db_boundary_{func_name}",
                        type="database",
                        gaps=["unsanitized_query"],
                    )
                )

            # Subprocess / command injection
            if any(call_name.endswith(f".{s}") or call_name == s for s in _SUBPROCESS_CALLS):
                self.data_flows.append(
                    DataFlow(
                        source=func_name,
                        sink=call_name,
                        path=[loc],
                        taint_level="high",
                    )
                )
                self.vectors.append(
                    AttackVector(
                        type="Command Injection",
                        entry_point=loc,
                        confidence=0.85,
                        evidence=f"Subprocess call: {call_name}",
                        cwe_id="CWE-78",
                    )
                )
                self.boundaries.append(
                    Boundary(
                        name=f"process_boundary_{func_name}",
                        type="process",
                        gaps=["command_injection"],
                    )
                )

            # Deserialization
            if any(call_name.endswith(f".{s}") or call_name == s for s in _DESER_CALLS):
                self.vectors.append(
                    AttackVector(
                        type="Insecure Deserialization",
                        entry_point=loc,
                        confidence=0.75,
                        evidence=f"Deserialization: {call_name}",
                        cwe_id="CWE-502",
                    )
                )

            # Eval / exec
            if any(call_name == s or call_name.endswith(f".{s}") for s in _EVAL_EXEC):
                self.vectors.append(
                    AttackVector(
                        type="Code Injection",
                        entry_point=loc,
                        confidence=0.9,
                        evidence=f"Dangerous eval/exec: {call_name}",
                        cwe_id="CWE-94",
                    )
                )

            # File operations
            if call_name in _FILE_OPS or call_name.endswith(f".open"):
                self.boundaries.append(
                    Boundary(
                        name=f"file_boundary_{func_name}",
                        type="filesystem",
                        gaps=["unrestricted_file_access"],
                    )
                )

            # HTTP client calls (SSRF indicator)
            if any(call_name.endswith(f".{s}") for s in _HTTP_CLIENTS):
                self.vectors.append(
                    AttackVector(
                        type="Server-Side Request Forgery",
                        entry_point=loc,
                        confidence=0.6,
                        evidence=f"HTTP client call: {call_name}",
                        cwe_id="CWE-918",
                    )
                )


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class AttackSurfaceAnalyzer:
    """Discover attack surfaces in Python code via AST analysis."""

    def analyze(self, code: str, filepath: str = "<string>") -> AttackSurface:
        """Run static analysis on *code* and return the discovered attack surface."""
        try:
            tree = ast.parse(code, filename=filepath)
        except SyntaxError:
            return AttackSurface(risk_score=0.0)

        visitor = _AttackSurfaceVisitor(filepath=filepath)
        visitor.visit(tree)

        risk_score = self._compute_risk(visitor)
        return AttackSurface(
            entry_points=visitor.entry_points,
            data_flows=visitor.data_flows,
            trust_boundaries=visitor.boundaries,
            attack_vectors=visitor.vectors,
            risk_score=risk_score,
        )

    def analyze_file(self, path: Path | str) -> AttackSurface:
        """Analyze a single file on disk."""
        p = Path(path)
        code = p.read_text(encoding="utf-8")
        return self.analyze(code, filepath=str(p))

    def analyze_project(self, path: Path | str) -> dict[str, AttackSurface]:
        """Analyze every *.py file under *path*."""
        results: dict[str, AttackSurface] = {}
        root = Path(path)
        if root.is_file() and root.suffix == ".py":
            results[str(root)] = self.analyze_file(root)
            return results
        for py_file in root.rglob("*.py"):
            if "__pycache__" in py_file.parts:
                continue
            key = str(py_file.relative_to(root))
            results[key] = self.analyze_file(py_file)
        return results

    # -- risk scoring ------------------------------------------------------

    @staticmethod
    def _compute_risk(visitor: _AttackSurfaceVisitor) -> float:
        score = 0.0
        # Entry points with risky params
        for ep in visitor.entry_points:
            for ri in ep.risk_indicators:
                if ri.startswith("risky_param"):
                    score += 0.5
                elif ri == "http_route":
                    score += 1.0
                elif ri == "template_render":
                    score += 1.5
                elif ri == "auth_protected":
                    score += 0.3

        # Data flows
        for df in visitor.data_flows:
            score += 1.0 if df.taint_level == "high" else 0.5

        # Attack vectors
        for vec in visitor.vectors:
            score += vec.confidence * 1.5

        # Boundaries
        score += len(visitor.boundaries) * 0.5

        return min(round(score, 2), 10.0)
