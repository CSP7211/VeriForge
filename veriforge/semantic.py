import ast
import re

class SemanticAnalyzer:
    def analyze(self, code: str) -> dict:
        findings = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return {"obfuscated": False, "findings": ["syntax_error"]}
        hex_strings = re.findall(r'["\']\\x[0-9a-fA-F]{2,}["\']', code)
        if hex_strings:
            findings.append(f"OBFUSCATION: {len(hex_strings)} hex-encoded strings")
        b64_like = re.findall(r'["\'][A-Za-z0-9+/]{40,}={0,2}["\']', code)
        if b64_like:
            findings.append(f"OBFUSCATION: {len(b64_like)} base64-like strings")
        max_depth = 0
        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.For, ast.While, ast.Try, ast.With)):
                depth = self._node_depth(node, tree)
                max_depth = max(max_depth, depth)
        if max_depth > 5:
            findings.append(f"COMPLEXITY: Excessive nesting depth {max_depth}")
        return {"obfuscated": len(findings) > 0, "findings": findings}

    def _node_depth(self, target, tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.AST):
                for child in ast.iter_child_nodes(node):
                    if child is target:
                        return 1 + self._node_depth(node, tree)
        return 0
