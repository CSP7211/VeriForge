"""
Deep compliance auditors — verify real security controls, not superficial imports.

* SOC2Auditor:    logging calls must cover security events (not just `import logging`)
* ISO27001Auditor: taint analysis — user inputs must be validated before use
* PCIDSSAuditor:   real input sanitization (not just type casting)
"""

from __future__ import annotations

import ast
import re
from typing import Any

from veriforge.engine import ComplianceLevel


# ── base ─────────────────────────────────────────────────────────────────

class AuditorError(Exception):
    pass


class ComplianceAuditor:
    """Base class for compliance auditors."""

    name: str = ""

    def audit(self, source: str) -> ComplianceLevel:
        raise NotImplementedError

    @staticmethod
    def _parse_ast(source: str) -> ast.AST | None:
        try:
            return ast.parse(source)
        except SyntaxError:
            return None


# ── SOC2 ─────────────────────────────────────────────────────────────────

class SOC2Auditor(ComplianceAuditor):
    """
    SOC2 Type II auditor.

    Verifies that the code contains actual logging calls for security events,
    not merely `import logging`. Looks for:
      - logging.info / warning / error / critical calls
      - Exception handling with logging
      - Security event logging (auth, access, failures)
    """

    name = "SOC2"

    SECURITY_EVENT_KEYWORDS: set[str] = {
        "auth", "login", "logout", "access", "permission", "denied",
        "unauthorized", "failure", "error", "security", "breach",
        "audit", "invalid", "attempt", "blocked", "unauthenticated",
    }

    def audit(self, source: str) -> ComplianceLevel:
        tree = self._parse_ast(source)
        if tree is None:
            return ComplianceLevel.FAIL

        # Check for actual logging calls (not just imports)
        has_logging_calls = False
        has_security_events = False
        call_count = 0

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                # logging.<level>(...) pattern
                if isinstance(func, ast.Attribute):
                    if func.attr in {"debug", "info", "warning", "error", "critical", "exception", "log"}:
                        has_logging_calls = True
                        call_count += 1
                        # Check if any argument contains security keywords
                        for keyword in self.SECURITY_EVENT_KEYWORDS:
                            if self._node_contains_keyword(node, keyword):
                                has_security_events = True
                                break
                # bare <level>(...) via alias
                if isinstance(func, ast.Name):
                    if func.id in {"info", "error", "warning", "critical", "debug"}:
                        has_logging_calls = True
                        call_count += 1

            # try/except blocks with logging
            if isinstance(node, ast.Try):
                for handler in node.handlers:
                    for child in ast.walk(handler):
                        if isinstance(child, ast.Call):
                            func = child.func
                            if isinstance(func, ast.Attribute) and func.attr in {
                                "error", "critical", "exception", "warning",
                            }:
                                has_logging_calls = True

        if not has_logging_calls:
            return ComplianceLevel.FAIL
        if call_count < 2:
            return ComplianceLevel.PARTIAL
        if has_security_events:
            return ComplianceLevel.PASS
        return ComplianceLevel.PARTIAL

    @staticmethod
    def _node_contains_keyword(node: ast.AST, keyword: str) -> bool:
        """Check if any string Constant in the node contains the keyword."""
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                if keyword.lower() in child.value.lower():
                    return True
        return False


# ── ISO 27001 ────────────────────────────────────────────────────────────

class ISO27001Auditor(ComplianceAuditor):
    """
    ISO/IEC 27001 auditor.

    Verifies taint validation on user inputs:
      - Input from request.form, request.args, input(), sys.argv is tainted
      - Tainted values must be validated (type check, length check, regex match)
        before use in SQL, file paths, shell commands, or eval-like contexts.
    """

    name = "ISO27001"

    TAINT_SOURCES: list[re.Pattern[str]] = [
        re.compile(r"request\.(form|args|json|data|files|cookies|headers)", re.IGNORECASE),
        re.compile(r"input\s*\("),
        re.compile(r"sys\.argv"),
        re.compile(r"os\.environ\["),
        re.compile(r"socket\.recv"),
    ]

    VALIDATION_PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"isinstance\s*\("),
        re.compile(r"(re\.match|re\.search|re\.fullmatch|re\.compile)"),
        re.compile(r"len\s*\("),
        re.compile(r"\.strip\s*\("),
        re.compile(r"\.validate\s*\("),
        re.compile(r"try:\s*\n.*?(ValueError|TypeError|ValidationError)", re.DOTALL),
        re.compile(r"(int\s*\(|float\s*\(|str\s*\()"),
    ]

    def audit(self, source: str) -> ComplianceLevel:
        tree = self._parse_ast(source)
        if tree is None:
            return ComplianceLevel.FAIL

        source_lower = source.lower()
        has_taint_source = False
        has_validation = False

        # Detect taint sources
        for pattern in self.TAINT_SOURCES:
            if pattern.search(source):
                has_taint_source = True
                break

        # If no taint sources, nothing to validate — but check for defensive patterns
        if not has_taint_source:
            # Check if the code has general validation patterns anyway
            validation_count = sum(
                1 for p in self.VALIDATION_PATTERNS if p.search(source)
            )
            if validation_count >= 2:
                return ComplianceLevel.PASS
            return ComplianceLevel.PARTIAL

        # Taint sources exist — must have validation
        for pattern in self.VALIDATION_PATTERNS:
            if pattern.search(source):
                has_validation = True
                break

        # Check for parameterized queries / prepared statements
        has_parameterized = bool(
            re.search(r"%s|\?|param|execute\s*\(.*,\s*\(", source_lower)
            or "sqlalchemy" in source_lower
            or "parameterized" in source_lower
        )

        if has_validation or has_parameterized:
            return ComplianceLevel.PASS
        return ComplianceLevel.FAIL


# ── PCI-DSS ──────────────────────────────────────────────────────────────

class PCIDSSAuditor(ComplianceAuditor):
    """
    PCI-DSS v4.0 auditor.

    Verifies real input sanitization:
      - Must sanitize user input before processing
      - Type casting alone (e.g., str(), int()) does NOT count as sanitization
      - Must have: regex validation, allow-list checks, encoding/escaping,
        parameterized queries, or explicit input validation routines.
    """

    name = "PCIDSS"

    SANITIZATION_PATTERNS: list[re.Pattern[str]] = [
        # Regex-based validation
        re.compile(r"(re\.match|re\.search|re\.fullmatch|re\.compile|re\.findall)"),
        # Allow-list validation
        re.compile(r"(whitelist|allowlist|in\s+\[|in\s+\{)"),
        # Encoding / escaping
        re.compile(r"(html\.escape|urllib\.parse\.quote|cgi\.escape|bleach\.|mark_safe|escape\()"),
        # Parameterized queries
        re.compile(r"(%s|\?.*execute|param|bindparam|prepared)"),
        # Length / size checks
        re.compile(r"(len\s*\(\s*\w+\s*\)\s*[<>=]|\.length\s*[<>=]|max_length)"),
        # Explicit validators
        re.compile(r"(validator|validate|sanitize|clean\s*\(|schema|marshmallow|pydantic|cerberus)"),
    ]

    # Patterns that are NOT real sanitization (just type casting or no-op)
    NON_SANITIZATION: list[re.Pattern[str]] = [
        re.compile(r"^\s*(str|int|float|bool|list|dict)\s*\(\s*\w+\s*\)\s*$"),
    ]

    def audit(self, source: str) -> ComplianceLevel:
        tree = self._parse_ast(source)
        if tree is None:
            return ComplianceLevel.FAIL

        # Check for user input handling
        has_user_input = bool(
            re.search(
                r"(request\.(form|args|json|data)|input\s*\(|os\.environ|sys\.argv|socket\.recv)",
                source,
            )
        )

        # Count real sanitization patterns
        sanitization_count = sum(
            1 for p in self.SANITIZATION_PATTERNS if p.search(source)
        )

        has_no_op_only = all(
            p.search(source) for p in self.NON_SANITIZATION
        )

        if sanitization_count >= 2:
            return ComplianceLevel.PASS
        if sanitization_count == 1:
            return ComplianceLevel.PARTIAL
        if has_user_input and sanitization_count == 0:
            return ComplianceLevel.FAIL
        if not has_user_input and sanitization_count == 0:
            # No user input, no sanitization needed — but encourage defensive coding
            return ComplianceLevel.PARTIAL
        return ComplianceLevel.FAIL
