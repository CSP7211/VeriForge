"""Adversarial code mutation engine.

Generates targeted and random code mutations for security testing,
including boundary condition changes, injection payloads, encoding
variants, semantic swaps, and resource-exhaustion attacks.
"""

from __future__ import annotations

import base64
import random
import urllib.parse
from typing import Optional

from .models import EntryPoint, Mutation


# ---------------------------------------------------------------------------
# Mutator
# ---------------------------------------------------------------------------

class AdversarialMutator:
    """Generate adversarial code mutations for security testing."""

    # All supported mutation strategies
    _ALL_STRATEGIES: frozenset[str] = frozenset(
        {
            "boundary",
            "injection",
            "encoding",
            "semantic",
            "resource",
            "none",
            "empty",
            "type",
        }
    )

    def __init__(self, config: Optional[dict] = None) -> None:
        """Initialise the mutator.

        *config* may contain:
        - ``max_mutations`` (int): cap on mutations per call.
        - ``strategies`` (list[str]): subset of strategy names to enable.
        - ``seed`` (int | None): RNG seed for reproducible fuzzing.
        """
        cfg = config or {}
        self.max_mutations: int = cfg.get("max_mutations", 50)
        self.strategies: frozenset[str] = frozenset(
            cfg.get("strategies", list(self._ALL_STRATEGIES))
        )
        seed = cfg.get("seed")
        self._rng = random.Random(seed)

    # -- public API --------------------------------------------------------

    def mutate(self, code: str, entry_point: EntryPoint) -> list[Mutation]:
        """Generate targeted adversarial mutations for *entry_point*."""
        mutations: list[Mutation] = []
        lines = code.splitlines(keepends=True)

        if not lines:
            return mutations

        # Strategy: boundary
        if "boundary" in self.strategies:
            mutations.extend(self._boundary_mutations(code, lines, entry_point))

        # Strategy: injection
        if "injection" in self.strategies:
            mutations.extend(self._injection_mutations(code, lines, entry_point))

        # Strategy: encoding
        if "encoding" in self.strategies:
            mutations.extend(self._encoding_mutations(code, lines, entry_point))

        # Strategy: semantic
        if "semantic" in self.strategies:
            mutations.extend(self._semantic_mutations(code, lines, entry_point))

        # Strategy: resource
        if "resource" in self.strategies:
            mutations.extend(self._resource_mutations(code, lines, entry_point))

        # Strategy: none
        if "none" in self.strategies:
            mutations.extend(self._none_mutations(code, lines, entry_point))

        # Strategy: empty
        if "empty" in self.strategies:
            mutations.extend(self._empty_mutations(code, lines, entry_point))

        # Strategy: type
        if "type" in self.strategies:
            mutations.extend(self._type_mutations(code, lines, entry_point))

        # De-duplicate by mutated content
        seen: set[str] = set()
        unique: list[Mutation] = []
        for m in mutations:
            if m.mutated not in seen:
                seen.add(m.mutated)
                unique.append(m)

        return unique[: self.max_mutations]

    def fuzz(self, code: str, iterations: int = 100) -> list[Mutation]:
        """Pure fuzzing mode -- apply random mutations."""
        mutations: list[Mutation] = []
        lines = code.splitlines(keepends=True)
        if not lines:
            return mutations

        strategies = list(self.strategies)
        if not strategies:
            return mutations

        for _ in range(min(iterations, self.max_mutations)):
            strategy = self._rng.choice(strategies)
            line_idx = self._rng.randint(0, len(lines) - 1)
            original_line = lines[line_idx]

            mutated_line = self._apply_random_mutation(original_line, strategy)
            if mutated_line and mutated_line != original_line:
                new_lines = list(lines)
                new_lines[line_idx] = mutated_line
                mutations.append(
                    Mutation(
                        original=original_line.rstrip("\n"),
                        mutated="".join(new_lines),
                        mutation_type=strategy,
                        description=f"Fuzz: {strategy} on line {line_idx + 1}",
                        severity=self._rng.choice(["low", "medium", "high"]),
                    )
                )

        return mutations

    # -- strategy implementations ------------------------------------------

    def _boundary_mutations(
        self, code: str, lines: list[str], ep: EntryPoint
    ) -> list[Mutation]:
        """Flip boundary operators (>= to >, == to !=, etc.)."""
        swaps = {
            ">=": ">",
            ">": ">=",
            "<=": "<",
            "<": "<=",
            "==": "!=",
            "!=": "==",
        }
        mutations: list[Mutation] = []
        for i, line in enumerate(lines):
            for old, new in swaps.items():
                if old in line:
                    mutated = line.replace(old, new, 1)
                    new_code = "".join(lines[:i] + [mutated] + lines[i + 1 :])
                    mutations.append(
                        Mutation(
                            original=line.rstrip("\n"),
                            mutated=new_code,
                            mutation_type="boundary",
                            description=f"Swapped '{old}' to '{new}' on line {i + 1}",
                            severity="medium",
                        )
                    )
        return mutations

    def _injection_mutations(
        self, code: str, lines: list[str], ep: EntryPoint
    ) -> list[Mutation]:
        """Inject SQLi, XSS, and command-injection payloads into string literals."""
        payloads = [
            ("' OR '1'='1", "SQL injection payload"),
            ("<script>alert('XSS')</script>", "XSS payload"),
            ("; cat /etc/passwd;", "Command injection payload"),
            ("../../../etc/passwd", "Path traversal payload"),
            ("{{ 7*7 }}", "SSTI payload"),
            ("%s%n", "Format string payload"),
        ]
        mutations: list[Mutation] = []
        for i, line in enumerate(lines):
            for payload, desc in payloads:
                # Append payload after string literals or bare variable references
                if "'" in line or '"' in line:
                    mutated = line.rstrip("\n") + f" + '{payload}'\n"
                    new_code = "".join(lines[:i] + [mutated] + lines[i + 1 :])
                    mutations.append(
                        Mutation(
                            original=line.rstrip("\n"),
                            mutated=new_code,
                            mutation_type="injection",
                            description=f"{desc} on line {i + 1}",
                            severity="critical",
                        )
                    )
        return mutations

    def _encoding_mutations(
        self, code: str, lines: list[str], ep: EntryPoint
    ) -> list[Mutation]:
        """Generate Base64, URL-encoded, and hex-escaped variants."""
        mutations: list[Mutation] = []
        sample = code.strip()
        if not sample:
            return mutations

        # Base64 variant
        b64 = base64.b64encode(sample.encode()).decode()
        mutations.append(
            Mutation(
                original=code,
                mutated=f"# Base64-encoded variant\n# {b64}\n{code}",
                mutation_type="encoding",
                description="Base64-encoded payload variant",
                severity="low",
            )
        )

        # URL-encoded variant
        urlenc = urllib.parse.quote(sample)
        mutations.append(
            Mutation(
                original=code,
                mutated=f"# URL-encoded variant\n# {urlenc}\n{code}",
                mutation_type="encoding",
                description="URL-encoded payload variant",
                severity="low",
            )
        )

        # Hex-escaped variant
        hexenc = sample.encode().hex()
        mutations.append(
            Mutation(
                original=code,
                mutated=f"# Hex-encoded variant\n# {hexenc}\n{code}",
                mutation_type="encoding",
                description="Hex-encoded payload variant",
                severity="low",
            )
        )

        return mutations

    def _semantic_mutations(
        self, code: str, lines: list[str], ep: EntryPoint
    ) -> list[Mutation]:
        """Swap safe functions for unsafe alternatives."""
        swaps = {
            "json.loads": "pickle.loads",
            "pickle.loads": "json.loads",
            "yaml.safe_load": "yaml.unsafe_load",
            "subprocess.run": "os.system",
            "os.system": "subprocess.run",
            "re.match": "eval",
            "ast.literal_eval": "eval",
        }
        mutations: list[Mutation] = []
        for i, line in enumerate(lines):
            for safe, unsafe in swaps.items():
                if safe in line:
                    mutated = line.replace(safe, unsafe, 1)
                    new_code = "".join(lines[:i] + [mutated] + lines[i + 1 :])
                    mutations.append(
                        Mutation(
                            original=line.rstrip("\n"),
                            mutated=new_code,
                            mutation_type="semantic",
                            description=f"Swapped '{safe}' -> '{unsafe}' on line {i + 1}",
                            severity="high",
                        )
                    )
        return mutations

    def _resource_mutations(
        self, code: str, lines: list[str], ep: EntryPoint
    ) -> list[Mutation]:
        """Inject resource-exhaustion patterns."""
        exhaustion_snippets = [
            ("while True:\n    pass\n", "infinite loop"),
            ("x = 'A' * 10**9\n", "massive allocation"),
            ("def _deep(n):\n    return _deep(n+1)\n_deep(0)\n", "deep recursion"),
        ]
        mutations: list[Mutation] = []
        for snippet, desc in exhaustion_snippets:
            mutated = code + "\n" + snippet
            mutations.append(
                Mutation(
                    original=code,
                    mutated=mutated,
                    mutation_type="resource",
                    description=desc,
                    severity="high",
                )
            )
        return mutations

    def _none_mutations(
        self, code: str, lines: list[str], ep: EntryPoint
    ) -> list[Mutation]:
        """Replace literal values with None."""
        mutations: list[Mutation] = []
        for i, line in enumerate(lines):
            # Simple heuristic: replace assignments of literals with None
            stripped = line.strip()
            if "=" in stripped and not stripped.startswith("#"):
                parts = stripped.split("=", 1)
                if len(parts) == 2:
                    lhs = parts[0].strip()
                    rhs = parts[1].strip()
                    # Only replace non-None right-hand sides
                    if rhs and not rhs.startswith("None"):
                        mutated_line = f"{lhs} = None\n"
                        new_lines = list(lines)
                        new_lines[i] = " " * (len(line) - len(line.lstrip())) + mutated_line
                        mutations.append(
                            Mutation(
                                original=line.rstrip("\n"),
                                mutated="".join(new_lines),
                                mutation_type="none",
                                description=f"Replaced assignment with None on line {i + 1}",
                                severity="medium",
                            )
                        )
        return mutations

    def _empty_mutations(
        self, code: str, lines: list[str], ep: EntryPoint
    ) -> list[Mutation]:
        """Replace literals with empty strings, lists, or dicts."""
        mutations: list[Mutation] = []
        for i, line in enumerate(lines):
            stripped = line.strip()
            if "=" in stripped and not stripped.startswith("#"):
                parts = stripped.split("=", 1)
                if len(parts) == 2:
                    lhs = parts[0].strip()
                    empties = ["''", "[]", "{}"]
                    for empty_val in empties:
                        mutated_line = f"{lhs} = {empty_val}\n"
                        indent = " " * (len(line) - len(line.lstrip()))
                        new_lines = list(lines)
                        new_lines[i] = indent + mutated_line
                        mutations.append(
                            Mutation(
                                original=line.rstrip("\n"),
                                mutated="".join(new_lines),
                                mutation_type="empty",
                                description=f"Replaced with {empty_val} on line {i + 1}",
                                severity="low",
                            )
                        )
        return mutations

    def _type_mutations(
        self, code: str, lines: list[str], ep: EntryPoint
    ) -> list[Mutation]:
        """Swap types (int <-> str, list <-> dict)."""
        type_swaps = {
            "int(": "str(",
            "str(": "int(",
            "list(": "dict(",
            "dict(": "list(",
        }
        mutations: list[Mutation] = []
        for i, line in enumerate(lines):
            for old, new in type_swaps.items():
                if old in line:
                    mutated = line.replace(old, new, 1)
                    new_code = "".join(lines[:i] + [mutated] + lines[i + 1 :])
                    mutations.append(
                        Mutation(
                            original=line.rstrip("\n"),
                            mutated=new_code,
                            mutation_type="type",
                            description=f"Swapped type '{old}' -> '{new}' on line {i + 1}",
                            severity="medium",
                        )
                    )
        return mutations

    # -- helpers -----------------------------------------------------------

    def _apply_random_mutation(self, line: str, strategy: str) -> Optional[str]:
        """Apply a single random mutation of *strategy* to *line*."""
        if strategy == "boundary":
            swaps = [(">=", ">"), (">=", "<"), ("==", "!="), ("<=", "<")]
            old, new = self._rng.choice(swaps)
            return line.replace(old, new, 1) if old in line else None
        if strategy == "injection":
            payloads = ["XSS", "SQLi", "CMD"]
            return line.rstrip("\n") + f"  # injection:{self._rng.choice(payloads)}\n"
        if strategy == "encoding":
            if line.strip():
                return line.rstrip("\n") + "  # encoded\n"
        if strategy == "semantic":
            swaps = [("json.loads", "pickle.loads"), ("safe_load", "load")]
            old, new = self._rng.choice(swaps)
            return line.replace(old, new, 1) if old in line else None
        if strategy == "resource":
            return line + "while True: pass\n"
        if strategy == "none":
            if "=" in line and not line.strip().startswith("#"):
                parts = line.split("=", 1)
                if len(parts) == 2:
                    return parts[0] + "= None\n"
        if strategy == "empty":
            if "=" in line and not line.strip().startswith("#"):
                parts = line.split("=", 1)
                if len(parts) == 2:
                    return parts[0] + "= []\n"
        if strategy == "type":
            swaps = [("int(", "str("), ("str(", "int(")]
            old, new = self._rng.choice(swaps)
            return line.replace(old, new, 1) if old in line else None
        return None
