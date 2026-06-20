import ast
import hmac
import hashlib
import re
from dataclasses import dataclass, field
from typing import Tuple

@dataclass(frozen=True, slots=True)
class VerificationResult:
    verified: bool
    findings: Tuple[str, ...] = field(default_factory=tuple)
    signature: str = ""
    code_hash: str = ""

DANGEROUS_PATTERNS = [
    (r"\beval\b", "SECURITY: Dangerous pattern 'eval' detected"),
    (r"\bexec\b", "SECURITY: Dangerous pattern 'exec' detected"),
    (r"\bcompile\b", "SECURITY: Dangerous pattern 'compile' detected"),
    (r"\b__import__\b", "SECURITY: Dangerous pattern '__import__' detected"),
    (r"\bos\.system\b", "SECURITY: Dangerous pattern 'os.system' detected"),
    (r"\bsubprocess\b", "SECURITY: Dangerous pattern 'subprocess' detected"),
    (r"\bopen\s*\(", "SECURITY: Uncontrolled file open detected"),
    (r"\binput\s*\(", "SECURITY: Uncontrolled input detected"),
]

SAFE_BUILTINS = frozenset({
    "abs", "all", "any", "ascii", "bin", "bool", "bytearray", "bytes",
    "chr", "complex", "dict", "dir", "divmod", "enumerate", "filter",
    "float", "format", "frozenset", "getattr", "hasattr", "hash", "hex",
    "id", "int", "isinstance", "issubclass", "iter", "len", "list",
    "map", "max", "memoryview", "min", "next", "object", "oct", "ord",
    "pow", "print", "property", "range", "repr", "reversed", "round",
    "set", "setattr", "slice", "sorted", "staticmethod", "str", "sum",
    "super", "tuple", "type", "vars", "zip", "__build_class__",
    "True", "False", "None", "NotImplemented", "Ellipsis",
})

class VeriForgeEngine:
    def __init__(self, config):
        self.config = config

    def verify_code(self, code: str) -> VerificationResult:
        findings = []
        code_hash = hashlib.sha256(code.encode()).hexdigest()[:16]

        for pattern, msg in DANGEROUS_PATTERNS:
            if re.search(pattern, code):
                findings.append(msg)

        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            findings.append(f"SYNTAX: {e}")
            return self._sign(VerificationResult(verified=False, findings=tuple(findings), code_hash=code_hash))

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ("eval", "exec", "compile"):
                        findings.append(f"SECURITY: Call to '{node.func.id}' blocked")
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("system", "popen", "call"):
                        findings.append(f"SECURITY: Call to '{node.func.attr}' blocked")
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "__import__":
                    findings.append("SECURITY: Call to '__import__' blocked")
            if isinstance(node, ast.ImportFrom):
                if node.names and any(n.name == "*" for n in node.names):
                    findings.append("SECURITY: Wildcard import blocked")

        verified = len(findings) == 0
        return self._sign(VerificationResult(verified=verified, findings=tuple(findings), code_hash=code_hash))

    def _sign(self, result: VerificationResult) -> VerificationResult:
        payload = f"{result.verified}:{result.code_hash}:{':'.join(result.findings)}"
        sig = hmac.new(self.config.secret.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
        return VerificationResult(verified=result.verified, findings=result.findings, signature=sig, code_hash=result.code_hash)

    def verify_signature(self, result: VerificationResult) -> bool:
        payload = f"{result.verified}:{result.code_hash}:{':'.join(result.findings)}"
        expected = hmac.new(self.config.secret.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
        return hmac.compare_digest(expected, result.signature)
