"""
SemanticAnalyzer — Detects code obfuscation and semantic anti-patterns.

Provides static analysis capabilities to identify:
  * String obfuscation (concatenation, encoding tricks)
  * Excessive nesting depth
  * Comment-to-code ratio anomalies
  * Suspicious identifier patterns
  * Mixed-encoding identifiers
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True, frozen=True)
class ObfuscationFinding:
    """A single obfuscation detection finding."""

    category: str
    message: str
    line: int
    severity: str  # "low", "medium", "high", "critical"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "message": self.message,
            "line": self.line,
            "severity": self.severity,
        }


class SemanticAnalyzer:
    """
    Semantic code analyzer for obfuscation and anti-pattern detection.

    All analysis is static — no code execution is ever performed.
    """

    # Patterns used to detect obfuscated identifiers
    OBFUSCATED_NAME_PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"^[Oo0lI1]{3,}$"),           # Repeated look-alike chars
        re.compile(r"^_{3,}$"),                   # Excessive underscores
        re.compile(r"^[a-zA-Z]_[a-zA-Z]_[a-zA-Z]_"),  # Repeated single-char
    ]

    # String functions that may indicate obfuscation
    OBFUSCATION_FUNCTIONS: set[str] = {
        "encode", "decode", "chr", "ord", "hex", "unhex", "b64encode",
        "b64decode", "translate", "join", "replace",
    }

    def __init__(self, max_nesting_depth: int = 5, min_comment_ratio: float = 0.05) -> None:
        self._max_nesting = max_nesting_depth
        self._min_comment_ratio = min_comment_ratio

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, source: str, filename: str = "<string>") -> list[ObfuscationFinding]:
        """
        Perform full semantic analysis on *source*.

        Returns a list of ObfuscationFinding objects (may be empty).
        """
        findings: list[ObfuscationFinding] = []

        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError:
            # Cannot analyze syntactically invalid code
            return findings

        findings.extend(self._check_nesting_depth(tree))
        findings.extend(self._check_obfuscated_names(tree))
        findings.extend(self._check_string_obfuscation(tree))
        findings.extend(self._check_comment_ratio(source))
        findings.extend(self._check_suspicious_imports(tree))
        return findings

    def is_obfuscated(self, source: str, filename: str = "<string>") -> bool:
        """Return True if the source contains any obfuscation findings."""
        return len(self.analyze(source, filename)) > 0

    # ------------------------------------------------------------------
    # Internal checks
    # ------------------------------------------------------------------

    def _check_nesting_depth(self, tree: ast.AST) -> list[ObfuscationFinding]:
        """Flag functions/classes with excessive nesting depth."""
        findings: list[ObfuscationFinding] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                depth = self._compute_nesting(node)
                if depth > self._max_nesting:
                    findings.append(
                        ObfuscationFinding(
                            category="nesting_depth",
                            message=f"Excessive nesting depth ({depth} > {self._max_nesting})",
                            line=node.lineno,
                            severity="medium",
                        )
                    )
        return findings

    def _check_obfuscated_names(self, tree: ast.AST) -> list[ObfuscationFinding]:
        """Flag identifiers that appear obfuscated."""
        findings: list[ObfuscationFinding] = []
        for node in ast.walk(tree):
            name: str | None = None
            if isinstance(node, ast.Name):
                name = node.id
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = node.name

            if name:
                for pattern in self.OBFUSCATED_NAME_PATTERNS:
                    if pattern.match(name):
                        findings.append(
                            ObfuscationFinding(
                                category="obfuscated_name",
                                message=f"Suspicious identifier: {name}",
                                line=getattr(node, "lineno", 0),
                                severity="high",
                            )
                        )
                        break
        return findings

    def _check_string_obfuscation(self, tree: ast.AST) -> list[ObfuscationFinding]:
        """Flag chains of string/encoding manipulation calls."""
        findings: list[ObfuscationFinding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if self._is_obfuscation_call(node):
                    findings.append(
                        ObfuscationFinding(
                            category="string_obfuscation",
                            message="Potential string obfuscation detected",
                            line=getattr(node, "lineno", 0),
                            severity="medium",
                        )
                    )
        return findings

    def _check_comment_ratio(self, source: str) -> list[ObfuscationFinding]:
        """Flag files with anomalous comment-to-code ratios."""
        lines = source.splitlines()
        total = len(lines)
        if total == 0:
            return []
        comments = sum(1 for line in lines if line.strip().startswith("#"))
        ratio = comments / total
        if ratio < self._min_comment_ratio and total > 20:
            return [
                ObfuscationFinding(
                    category="comment_ratio",
                    message=f"Low comment ratio ({ratio:.2%} < {self._min_comment_ratio:.0%})",
                    line=0,
                    severity="low",
                )
            ]
        return []

    def _check_suspicious_imports(self, tree: ast.AST) -> list[ObfuscationFinding]:
        """Flag imports of modules commonly used for obfuscation."""
        findings: list[ObfuscationFinding] = []
        suspicious_modules = {"marshal", "types", "codeop", "compileall"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in suspicious_modules:
                        findings.append(
                            ObfuscationFinding(
                                category="suspicious_import",
                                message=f"Suspicious module imported: {alias.name}",
                                line=node.lineno,
                                severity="high",
                            )
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module in suspicious_modules:
                    findings.append(
                        ObfuscationFinding(
                            category="suspicious_import",
                            message=f"Suspicious module imported: {node.module}",
                            line=node.lineno,
                            severity="high",
                        )
                    )
        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _compute_nesting(self, node: ast.AST) -> int:
        """Compute maximum nesting depth inside a node."""
        max_depth = 0
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.With, ast.Try, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                depth = 1 + self._compute_nesting(child)
                max_depth = max(max_depth, depth)
        return max_depth

    def _is_obfuscation_call(self, node: ast.Call) -> bool:
        """Check if a call node matches known obfuscation patterns."""
        func = node.func
        if isinstance(func, ast.Attribute):
            return func.attr in self.OBFUSCATION_FUNCTIONS
        if isinstance(func, ast.Name):
            return func.id in self.OBFUSCATION_FUNCTIONS
        return False
