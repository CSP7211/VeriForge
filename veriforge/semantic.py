"""
SemanticAnalyzer — AST walker that detects dangerous patterns:
  - direct eval/exec
  - getattr(__builtins__, 'eval')
  - __import__('os').system
  - compile() with mode='single' or mode='exec'
  - base64-encoded eval strings
  - string concatenation to form 'eval'
  - aliased imports of dangerous modules

Returns structured findings with severity and CWE ID.
"""

from __future__ import annotations

import ast
import base64
import enum
import re
from dataclasses import dataclass
from typing import Any


class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    """A single security finding from semantic analysis."""

    rule: str
    message: str
    severity: Severity
    cwe_id: str
    line: int
    column: int
    snippet: str = ""


class SemanticAnalyzer:
    """Static AST analysis to detect code obfuscation and dangerous patterns."""

    DANGEROUS_NAMES: set[str] = {
        "eval",
        "exec",
        "compile",
        "__import__",
        "system",
        "popen",
        "subprocess",
        "os.system",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.run",
    }

    BASE64_EVAL_PATTERNS: list[re.Pattern[str]] = [
        re.compile(r'eval\s*\(\s*base64\.b64decode\s*\(', re.IGNORECASE),
        re.compile(r'exec\s*\(\s*base64\.b64decode\s*\(', re.IGNORECASE),
        re.compile(r'eval\s*\(\s*__[\w]*__\s*\(', re.IGNORECASE),
    ]

    CONCAT_EVAL_PATTERNS: list[re.Pattern[str]] = [
        re.compile(r'["\']e["\']\s*\+\s*["\']v["\']\s*\+\s*["\']a["\']\s*\+\s*["\']l["\']'),
        re.compile(r'["\']e["\']\s*\+\s*["\']x["\']\s*\+\s*["\']e["\']\s*\+\s*["\']c["\']'),
    ]

    def __init__(self, max_findings: int = 100) -> None:
        self.max_findings = max_findings

    def analyze(self, source: str) -> list[Finding]:
        """Run all detection heuristics and return a list of findings."""
        findings: list[Finding] = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings

        findings.extend(self._walk_ast(tree, source))
        findings.extend(self._regex_checks(source))
        findings.extend(self._detect_base64_exec(source))
        findings.extend(self._detect_concat_eval(source))

        return findings[: self.max_findings]

    # ── AST Walker ───────────────────────────────────────────────────────

    def _walk_ast(self, tree: ast.AST, source: str) -> list[Finding]:
        findings: list[Finding] = []
        source_lines = source.splitlines()

        for node in ast.walk(tree):
            # Direct eval() / exec() calls
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name):
                    if func.id == "eval":
                        findings.append(
                            Finding(
                                rule="direct-eval",
                                message="Direct eval() call detected — arbitrary code execution",
                                severity=Severity.CRITICAL,
                                cwe_id="CWE-95",
                                line=node.lineno or 0,
                                column=node.col_offset or 0,
                                snippet=self._get_snippet(source_lines, node.lineno or 0),
                            )
                        )
                    elif func.id == "exec":
                        findings.append(
                            Finding(
                                rule="direct-exec",
                                message="Direct exec() call detected — arbitrary code execution",
                                severity=Severity.CRITICAL,
                                cwe_id="CWE-95",
                                line=node.lineno or 0,
                                column=node.col_offset or 0,
                                snippet=self._get_snippet(source_lines, node.lineno or 0),
                            )
                        )
                    elif func.id == "compile":
                        findings.append(
                            Finding(
                                rule="compile-call",
                                message="compile() call detected — possible dynamic code execution",
                                severity=Severity.HIGH,
                                cwe_id="CWE-95",
                                line=node.lineno or 0,
                                column=node.col_offset or 0,
                                snippet=self._get_snippet(source_lines, node.lineno or 0),
                            )
                        )
                    elif func.id == "__import__":
                        findings.append(
                            Finding(
                                rule="dunder-import",
                                message="__import__() call detected — dynamic module loading",
                                severity=Severity.HIGH,
                                cwe_id="CWE-78",
                                line=node.lineno or 0,
                                column=node.col_offset or 0,
                                snippet=self._get_snippet(source_lines, node.lineno or 0),
                            )
                        )

                # getattr(__builtins__, 'eval') pattern
                is_getattr = (
                    (isinstance(func, ast.Name) and func.id == "getattr")
                    or (isinstance(func, ast.Attribute) and func.attr == "getattr")
                )
                if is_getattr:
                    findings.append(
                        Finding(
                            rule="getattr-builtin",
                            message="getattr() on builtins — potential eval/exec obfuscation",
                            severity=Severity.HIGH,
                            cwe_id="CWE-94",
                            line=node.lineno or 0,
                            column=node.col_offset or 0,
                            snippet=self._get_snippet(source_lines, node.lineno or 0),
                        )
                    )

                # os.system / subprocess.* pattern via attribute access
                if isinstance(func, ast.Attribute):
                    if func.attr in {"system", "popen", "call", "run"}:
                        findings.append(
                            Finding(
                                rule="os-command",
                                message=f"{func.attr}() detected — OS command execution",
                                severity=Severity.CRITICAL,
                                cwe_id="CWE-78",
                                line=node.lineno or 0,
                                column=node.col_offset or 0,
                                snippet=self._get_snippet(source_lines, node.lineno or 0),
                            )
                        )

            # Aliased imports: import os as _os; import subprocess as sp
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in {"os", "subprocess", "sys"} and alias.asname:
                        findings.append(
                            Finding(
                                rule="aliased-import",
                                message=f"Suspicious aliased import: {alias.name} as {alias.asname}",
                                severity=Severity.MEDIUM,
                                cwe_id="CWE-78",
                                line=node.lineno or 0,
                                column=node.col_offset or 0,
                                snippet=self._get_snippet(source_lines, node.lineno or 0),
                            )
                        )

            # from os import system; from subprocess import call
            if isinstance(node, ast.ImportFrom):
                if node.module in {"os", "subprocess", "sys"}:
                    for alias in node.names:
                        if alias.name in {"system", "popen", "call", "run", "execv", "execve"}:
                            findings.append(
                                Finding(
                                    rule="dangerous-import-from",
                                    message=f"Dangerous import: from {node.module} import {alias.name}",
                                    severity=Severity.CRITICAL,
                                    cwe_id="CWE-78",
                                    line=node.lineno or 0,
                                    column=node.col_offset or 0,
                                    snippet=self._get_snippet(source_lines, node.lineno or 0),
                                )
                            )

            # Check for f-string or string concat patterns that form 'eval'
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                if self._is_eval_concat(node):
                    findings.append(
                        Finding(
                            rule="string-concat-eval",
                            message="String concatenation forming 'eval' detected",
                            severity=Severity.HIGH,
                            cwe_id="CWE-94",
                            line=node.lineno or 0,
                            column=node.col_offset or 0,
                            snippet=self._get_snippet(source_lines, node.lineno or 0),
                        )
                    )

        return findings

    # ── Helper: detect string concat forming 'eval' or 'exec' ────────────

    def _is_eval_concat(self, node: ast.BinOp) -> bool:
        """Heuristic: check if a BinOp chain of string adds forms 'eval' or 'exec'."""
        parts: list[str] = []
        self._collect_str_parts(node, parts)
        joined = "".join(parts).lower().strip()
        return joined in {"eval", "exec", "compile"}

    def _collect_str_parts(self, node: ast.AST, parts: list[str]) -> None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            parts.append(node.value)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            self._collect_str_parts(node.left, parts)
            self._collect_str_parts(node.right, parts)

    # ── Regex checks on raw source ───────────────────────────────────────

    def _regex_checks(self, source: str) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            if "__builtins__" in line.lower() and "eval" in line.lower():
                findings.append(
                    Finding(
                        rule="builtins-eval-obfuscation",
                        message="__builtins__ combined with eval — obfuscation attempt",
                        severity=Severity.CRITICAL,
                        cwe_id="CWE-94",
                        line=lineno,
                        column=0,
                        snippet=line.strip(),
                    )
                )
        return findings

    def _detect_base64_exec(self, source: str) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            for pattern in self.BASE64_EVAL_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            rule="base64-eval",
                            message="Base64-encoded payload passed to eval/exec — likely obfuscated malware",
                            severity=Severity.CRITICAL,
                            cwe_id="CWE-94",
                            line=lineno,
                            column=0,
                            snippet=line.strip(),
                        )
                    )
        return findings

    def _detect_concat_eval(self, source: str) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            for pattern in self.CONCAT_EVAL_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            rule="concat-eval-string",
                            message="String concatenation forming eval/exec detected in source",
                            severity=Severity.HIGH,
                            cwe_id="CWE-94",
                            line=lineno,
                            column=0,
                            snippet=line.strip(),
                        )
                    )
        return findings

    @staticmethod
    def _get_snippet(lines: list[str], lineno: int) -> str:
        if 1 <= lineno <= len(lines):
            return lines[lineno - 1].strip()
        return ""
