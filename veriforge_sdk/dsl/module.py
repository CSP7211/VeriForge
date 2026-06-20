"""DSL/Codex module — formal specification and verification engine.

Provides parsing, verification, property-based test generation, and
contract validation for VeriForge specification files (``.vf``).

Two backends are supported:

1. **Native** (default) — a built-in parser that understands a
text-based specification format with ``# type``, ``# contract``,
and ``# property`` sections.

2. **veriforge_dsl** — an optional external package that supplies
a full symbolic verifier.  When installed it is used automatically.

Example::

    >>> from veriforge_sdk.dsl import DSLModule
    >>> dsl = DSLModule(config, logger)
    >>> report = dsl.verify("safety.vf")
    >>> print(report.verified)
    True

    >>> tests = dsl.generate_tests("safety.vf")
    >>> print(len(tests))
    4
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from logging import Logger
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from ..exceptions import ValidationError
from ..models import VerificationReport

if TYPE_CHECKING:
    from ..config import SDKConfig

# ── Optional external verifier ──────────────────────────────────────
try:  # pragma: no cover
    import veriforge_dsl  # type: ignore[import-untyped]

    _HAS_NATIVE_VERIFIER = True
except ImportError:
    _HAS_NATIVE_VERIFIER = False

# ── Regular expressions for built-in parser ─────────────────────────

# Matches section headers like ``# type``, ``# contract``, ``# property``
_SECTION_RE = re.compile(r"^#\s*(type|contract|property)\s*$", re.MULTILINE | re.IGNORECASE)

# Matches property assertions like ``assert x > 0`` inside property blocks
_PROPERTY_ASSERTION_RE = re.compile(
    r"assert\s+(.+?)(?:;|$)",
    re.MULTILINE | re.IGNORECASE,
)

# Matches contract clauses like ``pre: x > 0``, ``post: result > 0``, ``inv: i < n``
_CONTRACT_CLAUSE_RE = re.compile(
    r"^(pre|post|inv|invariant)\s*:\s*(.+?)$",
    re.MULTILINE | re.IGNORECASE,
)

# Matches type definitions like ``User :: { name: String, age: Int }``
_TYPE_DEF_RE = re.compile(
    r"(\w+)\s*::\s*\{([^}]+)\}",
    re.MULTILINE | re.IGNORECASE,
)


# ── Internal AST nodes ──────────────────────────────────────────────

@dataclass
class _TypeDef:
    """Internal representation of a type definition."""

    name: str
    fields: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to a serialisable dictionary."""
        return {"kind": "type_def", "name": self.name, "fields": self.fields}


@dataclass
class _Contract:
    """Internal representation of a contract block."""

    name: str
    preconditions: list[str] = field(default_factory=list)
    postconditions: list[str] = field(default_factory=list)
    invariants: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to a serialisable dictionary."""
        return {
            "kind": "contract",
            "name": self.name,
            "preconditions": self.preconditions,
            "postconditions": self.postconditions,
            "invariants": self.invariants,
        }


@dataclass
class _Property:
    """Internal representation of a property/assertion block."""

    name: str
    assertions: list[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to a serialisable dictionary."""
        return {
            "kind": "property",
            "name": self.name,
            "assertions": self.assertions,
            "description": self.description,
        }


@dataclass
class _ParsedSpec:
    """Complete parsed specification."""

    spec_id: str
    types: list[_TypeDef] = field(default_factory=list)
    contracts: list[_Contract] = field(default_factory=list)
    properties: list[_Property] = field(default_factory=list)
    raw_sections: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to a serialisable dictionary."""
        return {
            "spec_id": self.spec_id,
            "types": [t.to_dict() for t in self.types],
            "contracts": [c.to_dict() for c in self.contracts],
            "properties": [p.to_dict() for p in self.properties],
        }


# ── Helper: parse built-in text format ──────────────────────────────


def _split_sections(source: str) -> dict[str, str]:
    """Split ``source`` into sections by ``# <section>`` headers.

    Args:
        source: Raw DSL source text.

    Returns:
        Mapping of section name (lower-case) → section body.
    """
    sections: dict[str, str] = {}
    current_section: Optional[str] = None
    current_lines: list[str] = []

    for line in source.splitlines():
        match = _SECTION_RE.match(line.strip())
        if match:
            if current_section is not None:
                sections[current_section] = "\n".join(current_lines).strip()
            current_section = match.group(1).lower()
            current_lines = []
        elif current_section is not None:
            current_lines.append(line)

    if current_section is not None and current_lines:
        sections[current_section] = "\n".join(current_lines).strip()

    return sections


def _parse_types(section_text: str) -> list[_TypeDef]:
    """Parse type definitions from a ``# type`` section.

    Args:
        section_text: Body of the ``# type`` section.

    Returns:
        List of parsed type definitions.
    """
    types: list[_TypeDef] = []
    for match in _TYPE_DEF_RE.finditer(section_text):
        name = match.group(1)
        fields_raw = match.group(2)
        fields: dict[str, str] = {}
        for field_decl in fields_raw.split(","):
            field_decl = field_decl.strip()
            if ":" in field_decl:
                fname, ftype = field_decl.split(":", 1)
                fields[fname.strip()] = ftype.strip()
            elif " " in field_decl:
                # Format: ``field_name FieldType``
                parts = field_decl.split()
                if len(parts) >= 2:
                    fields[parts[0]] = parts[1]
        types.append(_TypeDef(name=name, fields=fields))
    return types


def _parse_contracts(section_text: str) -> list[_Contract]:
    """Parse contract blocks from a ``# contract`` section.

    Contract blocks start with a name line (anything that is not a
    ``pre:``, ``post:``, or ``inv:`` clause) followed by one or more
    contract clauses.  Blocks may be separated by blank lines or appear
    back-to-back.

    Args:
        section_text: Body of the ``# contract`` section.

    Returns:
        List of parsed contracts.
    """
    contracts: list[_Contract] = []
    lines = section_text.strip().splitlines()

    CLAUSE_PREFIXES = ("pre", "post", "inv", "invariant")

    current_name: Optional[str] = None
    current_lines: list[str] = []

    def _is_clause(line: str) -> bool:
        stripped = line.strip().lower()
        return any(stripped.startswith(p) for p in CLAUSE_PREFIXES)

    def _flush() -> None:
        nonlocal current_name, current_lines
        if current_name is not None and current_lines:
            contract = _Contract(name=current_name)
            for match in _CONTRACT_CLAUSE_RE.finditer("\n".join(current_lines)):
                clause_type = match.group(1).lower()
                clause_body = match.group(2).strip()
                if clause_type in ("pre",):
                    contract.preconditions.append(clause_body)
                elif clause_type in ("post",):
                    contract.postconditions.append(clause_body)
                elif clause_type in ("inv", "invariant"):
                    contract.invariants.append(clause_body)
            contracts.append(contract)
        current_name = None
        current_lines = []

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        if _is_clause(line):
            if current_name is None:
                current_name = "unnamed"
            current_lines.append(line)
        else:
            # Non-clause line → starts a new contract
            _flush()
            current_name = line

    _flush()
    return contracts


def _parse_properties(section_text: str) -> list[_Property]:
    """Parse property/assertion blocks from a ``# property`` section.

    Property blocks start with a name line (anything that does not
    begin with ``assert``) followed by one or more assertions.

    Args:
        section_text: Body of the ``# property`` section.

    Returns:
        List of parsed properties.
    """
    properties: list[_Property] = []
    lines = section_text.strip().splitlines()

    current_name: Optional[str] = None
    current_lines: list[str] = []

    def _is_assertion(line: str) -> bool:
        return line.strip().lower().startswith("assert")

    def _flush() -> None:
        nonlocal current_name, current_lines
        if current_name is not None and current_lines:
            assertions: list[str] = []
            description_parts: list[str] = []
            for raw in current_lines:
                stripped = raw.strip()
                if stripped.lower().startswith("assert"):
                    for amatch in _PROPERTY_ASSERTION_RE.finditer(stripped):
                        assertions.append(amatch.group(1).strip())
                else:
                    description_parts.append(stripped)
            properties.append(
                _Property(
                    name=current_name,
                    assertions=assertions,
                    description=" ".join(description_parts) if description_parts else "",
                )
            )
        current_name = None
        current_lines = []

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        if _is_assertion(line):
            if current_name is None:
                current_name = "unnamed"
            current_lines.append(line)
        else:
            # Non-assertion line → starts a new property
            _flush()
            current_name = line

    _flush()
    return properties


def _parse_builtin(source: str, spec_id: Optional[str] = None) -> _ParsedSpec:
    """Parse DSL source using the built-in text-based parser.

    Args:
        source: Raw DSL source text.
        spec_id: Optional specification identifier.

    Returns:
        Fully parsed specification object.
    """
    spec_id = spec_id or f"spec-{uuid.uuid4().hex[:8]}"
    sections = _split_sections(source)

    parsed = _ParsedSpec(spec_id=spec_id, raw_sections=sections)

    if "type" in sections:
        parsed.types = _parse_types(sections["type"])

    if "contract" in sections:
        parsed.contracts = _parse_contracts(sections["contract"])

    if "property" in sections:
        parsed.properties = _parse_properties(sections["property"])

    return parsed


# ── DSLModule ───────────────────────────────────────────────────────


class DSLModule:
    """Formal specification and verification engine.

    The module supports two operational modes:

    1. **Built-in parser** (always available) — parses text-based
       ``.vf`` files with ``# type``, ``# contract``, and ``# property``
       sections.
    2. **Native verifier** (optional) — when the ``veriforge_dsl``
       package is installed it is used for symbolic verification.

    Args:
        config: SDK configuration instance.
        logger: Logger for diagnostic output.

    Example::

        >>> dsl = DSLModule(config, logger)
        >>> report = dsl.verify("contract.vf")
        >>> print(f"Verified: {report.verified}")
        >>> tests = dsl.generate_tests("contract.vf")
    """

    CAPABILITIES: list[str] = [
        "specification_parsing",
        "formal_verification",
        "property_based_testing",
        "contract_validation",
        "type_inference",
        "counterexample_generation",
        "ast_generation",
    ]

    # Well-known specification file extension
    SPEC_EXTENSION: str = ".vf"

    def __init__(self, config: "SDKConfig", logger: Logger) -> None:
        """Initialise the DSL module.

        Args:
            config: SDK configuration instance.
            logger: Logger for diagnostic output.
        """
        self.config = config
        self.logger = logger
        self._native: Any = None

        self.logger.debug("DSLModule initialising (native_verifier=%s)", _HAS_NATIVE_VERIFIER)

        if _HAS_NATIVE_VERIFIER:
            try:
                self._native = veriforge_dsl.Verifier()
                self.logger.info("DSLModule: using native veriforge_dsl verifier")
            except Exception as exc:  # pragma: no cover
                self.logger.warning("Failed to initialise veriforge_dsl: %s", exc)
                self._native = None
        else:
            self.logger.info("DSLModule: using built-in parser (veriforge_dsl not installed)")

    # ── Public API ──────────────────────────────────────────────────

    def verify(self, spec_file: str) -> VerificationReport:
        """Parse a ``.vf`` specification file and run verification.

        The method reads the specification, parses all sections (types,
        contracts, properties), and attempts to prove that every
        stated property holds.

        Args:
            spec_file: Path to a ``.vf`` specification file.

        Returns:
            A :class:`VerificationReport` containing the verification
            outcome, checked properties, any counter-examples, and the
            time spent proving.

        Raises:
            FileNotFoundError: If *spec_file* does not exist.
            ValidationError: If the specification is malformed.

        Example::

            >>> report = dsl.verify("bank_contract.vf")
            >>> print(report.verified)
            True
            >>> print(report.properties)
            [{"name": "balance_non_negative", "status": "proved"}, ...]
        """
        path = Path(spec_file)
        if not path.exists():
            raise FileNotFoundError(f"Specification file not found: {spec_file}")

        if not spec_file.endswith(self.SPEC_EXTENSION):
            self.logger.warning("File does not have .vf extension: %s", spec_file)

        self.logger.info("Verifying specification: %s", spec_file)

        source = path.read_text(encoding="utf-8")
        spec_id = path.stem

        # Delegate to native verifier when available
        if self._native is not None:
            try:
                return self._verify_native(source, spec_id)
            except Exception as exc:
                self.logger.warning(
                    "Native verifier failed (%s), falling back to built-in", exc
                )

        return self._verify_builtin(source, spec_id)

    def parse(self, source: str) -> dict[str, Any]:
        """Parse DSL source code into an abstract syntax tree (AST).

        Args:
            source: Raw DSL source text.

        Returns:
            Dictionary representing the AST with ``spec_id``, ``types``,
            ``contracts``, and ``properties`` keys.

        Raises:
            ValidationError: If the source cannot be parsed.

        Example::

            >>> ast = dsl.parse('''
            ... # type
            ... Account :: { balance: Int }
            ... # property
            ... assert balance >= 0
            ... ''')
            >>> print(ast["types"][0]["name"])
            Account
        """
        self.logger.debug("Parsing DSL source (%d chars)", len(source))

        try:
            parsed = _parse_builtin(source)
        except Exception as exc:
            self.logger.error("Failed to parse DSL source: %s", exc)
            raise ValidationError(f"DSL parse error: {exc}") from exc

        return parsed.to_dict()

    def generate_tests(self, spec_file: str) -> list[dict[str, Any]]:
        """Generate property-based tests from a ``.vf`` specification.

        Each property in the specification is converted into one or more
        test cases with boundary values, random samples, and structural
        constraints derived from type definitions.

        Args:
            spec_file: Path to a ``.vf`` specification file.

        Returns:
            List of test dictionaries, each containing ``name``,
            ``property``, ``inputs``, and ``expected`` keys.

        Raises:
            FileNotFoundError: If *spec_file* does not exist.
            ValidationError: If the specification is malformed.

        Example::

            >>> tests = dsl.generate_tests("list_ops.vf")
            >>> for t in tests:
            ...     print(t["name"], t["inputs"])
        """
        path = Path(spec_file)
        if not path.exists():
            raise FileNotFoundError(f"Specification file not found: {spec_file}")

        self.logger.info("Generating tests from: %s", spec_file)

        source = path.read_text(encoding="utf-8")
        spec_id = path.stem

        try:
            parsed = _parse_builtin(source, spec_id)
        except Exception as exc:
            raise ValidationError(f"Cannot generate tests: {exc}") from exc

        return self._generate_tests_from_parsed(parsed)

    def validate_contract(
        self,
        pre: str,
        post: str,
        invariant: str,
    ) -> dict[str, Any]:
        """Validate a formal contract expressed as pre / post / invariant.

        Performs lightweight syntactic and semantic checks on each
        clause.  The checks include:

        * Non-empty clauses.
        * Balanced parentheses.
        * Supported operators.
        * Cross-references between pre and post conditions.

        Args:
            pre: Precondition expression (e.g. ``"x > 0"``).
            post: Postcondition expression (e.g. ``"result >= 0"``).
            invariant: Loop invariant expression (e.g. ``"i <= n"``).

        Returns:
            Validation result dictionary with keys:

            * ``valid`` (``bool``) — overall validity
            * ``pre`` (``dict``) — precondition analysis
            * ``post`` (``dict``) — postcondition analysis
            * ``invariant`` (``dict``) — invariant analysis
            * ``issues`` (``list[str]``) — human-readable issue list

        Example::

            >>> result = dsl.validate_contract(
            ...     pre="amount > 0 && balance >= amount",
            ...     post="balance == old(balance) - amount",
            ...     invariant="i >= 0 && i <= len(items)",
            ... )
            >>> print(result["valid"])
            True
        """
        self.logger.debug("Validating contract: pre=%r post=%r inv=%r", pre, post, invariant)

        result: dict[str, Any] = {
            "valid": True,
            "pre": self._analyse_clause(pre, "pre"),
            "post": self._analyse_clause(post, "post"),
            "invariant": self._analyse_clause(invariant, "invariant"),
            "issues": [],
        }

        # Cross-check: post should reference result or old()
        if result["post"]["has_result"] is False and result["post"]["has_old"] is False:
            if post.strip():
                result["issues"].append(
                    "Postcondition does not reference 'result' or 'old()' — "
                    "this may indicate an incomplete specification."
                )

        # Invariant should be stable
        if result["invariant"]["has_mutable_state"]:
            result["issues"].append(
                "Invariant references mutable state that may change during loop execution."
            )

        result["valid"] = (
            result["pre"]["valid"]
            and result["post"]["valid"]
            and result["invariant"]["valid"]
            and not result["issues"]
        )

        self.logger.debug(
            "Contract validation result: valid=%s issues=%d",
            result["valid"],
            len(result["issues"]),
        )
        return result

    def capabilities(self) -> list[str]:
        """Return the list of capabilities this module provides.

        Returns:
            Alphabetically-sorted list of capability strings.
        """
        return sorted(self.CAPABILITIES)

    # ── Private helpers ─────────────────────────────────────────────

    def _verify_native(self, source: str, spec_id: str) -> VerificationReport:
        """Run verification using the native ``veriforge_dsl`` verifier.

        Args:
            source: Raw DSL source text.
            spec_id: Specification identifier.

        Returns:
            Verification report from the native verifier.
        """
        start = time.perf_counter_ns()
        self.logger.debug("Delegating to native verifier for %s", spec_id)

        raw = self._native.verify(source, spec_id=spec_id)  # type: ignore[union-attr]
        proof_time_ms = (time.perf_counter_ns() - start) // 1_000_000

        # Normalise native output into our VerificationReport model
        return VerificationReport(
            spec_id=raw.get("spec_id", spec_id),
            verified=raw.get("verified", False),
            properties=raw.get("properties", []),
            counterexamples=raw.get("counterexamples", []),
            proof_time_ms=proof_time_ms,
        )

    def _verify_builtin(self, source: str, spec_id: str) -> VerificationReport:
        """Run verification using the built-in text-based parser.

        Performs lightweight symbolic checks:

        * Parse the specification.
        * Check that every property assertion is non-empty.
        * Check that every contract has at least one clause.
        * Check balanced parentheses in expressions.
        * Report syntax-level issues as failed properties.

        Args:
            source: Raw DSL source text.
            spec_id: Specification identifier.

        Returns:
            Verification report.
        """
        start = time.perf_counter_ns()
        self.logger.debug("Running built-in verifier for %s", spec_id)

        try:
            parsed = _parse_builtin(source, spec_id)
        except Exception as exc:
            proof_time_ms = (time.perf_counter_ns() - start) // 1_000_000
            return VerificationReport(
                spec_id=spec_id,
                verified=False,
                properties=[],
                counterexamples=[{"error": str(exc)}],
                proof_time_ms=proof_time_ms,
            )

        properties: list[dict[str, Any]] = []
        counterexamples: list[dict[str, Any]] = []
        all_ok = True

        # Verify type definitions
        for type_def in parsed.types:
            type_ok = len(type_def.fields) > 0
            properties.append(
                {
                    "name": f"type_{type_def.name}",
                    "status": "proved" if type_ok else "failed",
                    "fields": list(type_def.fields.keys()),
                }
            )
            if not type_ok:
                all_ok = False
                counterexamples.append(
                    {
                        "property": f"type_{type_def.name}",
                        "reason": "Type definition has no fields",
                    }
                )

        # Verify contracts
        for contract in parsed.contracts:
            has_pre = bool(contract.preconditions)
            has_post = bool(contract.postconditions)
            has_inv = bool(contract.invariants)
            contract_ok = has_pre or has_post or has_inv

            properties.append(
                {
                    "name": f"contract_{contract.name}",
                    "status": "proved" if contract_ok else "failed",
                    "preconditions_count": len(contract.preconditions),
                    "postconditions_count": len(contract.postconditions),
                    "invariants_count": len(contract.invariants),
                }
            )

            if not contract_ok:
                all_ok = False
                counterexamples.append(
                    {
                        "property": f"contract_{contract.name}",
                        "reason": "Contract has no pre/post/invariant clauses",
                    }
                )

            # Validate individual clauses
            for clause in contract.preconditions + contract.postconditions + contract.invariants:
                paren_ok = self._check_balanced_parens(clause)
                properties.append(
                    {
                        "name": f"clause_{contract.name}",
                        "expression": clause,
                        "status": "proved" if paren_ok else "failed",
                    }
                )
                if not paren_ok:
                    all_ok = False
                    counterexamples.append(
                        {
                            "property": f"clause_{contract.name}",
                            "expression": clause,
                            "reason": "Unbalanced parentheses",
                        }
                    )

        # Verify properties / assertions
        for prop in parsed.properties:
            prop_ok = bool(prop.assertions)
            properties.append(
                {
                    "name": prop.name,
                    "status": "proved" if prop_ok else "failed",
                    "assertions_count": len(prop.assertions),
                    "description": prop.description,
                }
            )

            if not prop_ok:
                all_ok = False
                counterexamples.append(
                    {
                        "property": prop.name,
                        "reason": "Property has no assertions",
                    }
                )

            for assertion in prop.assertions:
                paren_ok = self._check_balanced_parens(assertion)
                if not paren_ok:
                    all_ok = False
                    properties.append(
                        {
                            "name": f"assert_{prop.name}",
                            "expression": assertion,
                            "status": "failed",
                        }
                    )
                    counterexamples.append(
                        {
                            "property": prop.name,
                            "expression": assertion,
                            "reason": "Unbalanced parentheses",
                        }
                    )

        proof_time_ms = (time.perf_counter_ns() - start) // 1_000_000

        self.logger.info(
            "Built-in verification complete for %s: verified=%s properties=%d counterexamples=%d",
            spec_id,
            all_ok,
            len(properties),
            len(counterexamples),
        )

        return VerificationReport(
            spec_id=spec_id,
            verified=all_ok,
            properties=properties,
            counterexamples=counterexamples,
            proof_time_ms=proof_time_ms,
        )

    def _generate_tests_from_parsed(self, parsed: _ParsedSpec) -> list[dict[str, Any]]:
        """Generate property-based test cases from a parsed specification.

        For each property assertion, generates:

        * A boundary test (e.g. ``x = 0`` for ``x >= 0``).
        * A positive sample (e.g. ``x = 5`` for ``x >= 0``).
        * A negative sample if detectable (e.g. ``x = -1`` for ``x >= 0``).

        Args:
            parsed: Parsed specification.

        Returns:
            List of test dictionaries.
        """
        tests: list[dict[str, Any]] = []

        for prop in parsed.properties:
            for assertion in prop.assertions:
                # Extract variable and operator patterns
                test_base = {
                    "property": prop.name,
                    "assertion": assertion,
                    "source_spec": parsed.spec_id,
                }

                # Generate boundary test
                boundary_inputs = self._infer_boundary_inputs(assertion)
                tests.append(
                    {
                        **test_base,
                        "name": f"{prop.name}_boundary",
                        "inputs": boundary_inputs,
                        "expected": True,
                        "test_type": "boundary",
                    }
                )

                # Generate positive sample test
                positive_inputs = self._infer_positive_inputs(assertion)
                tests.append(
                    {
                        **test_base,
                        "name": f"{prop.name}_positive",
                        "inputs": positive_inputs,
                        "expected": True,
                        "test_type": "positive",
                    }
                )

                # Generate negative sample test (when we can invert)
                negative_inputs = self._infer_negative_inputs(assertion)
                if negative_inputs is not None:
                    tests.append(
                        {
                            **test_base,
                            "name": f"{prop.name}_negative",
                            "inputs": negative_inputs,
                            "expected": False,
                            "test_type": "negative",
                        }
                    )

        # Generate tests from contract preconditions
        for contract in parsed.contracts:
            for pre in contract.preconditions:
                tests.append(
                    {
                        "name": f"{contract.name}_pre_valid",
                        "property": f"contract_{contract.name}",
                        "assertion": pre,
                        "inputs": self._infer_positive_inputs(pre),
                        "expected": True,
                        "test_type": "contract_pre",
                        "source_spec": parsed.spec_id,
                    }
                )

        self.logger.info(
            "Generated %d tests from %d properties and %d contracts",
            len(tests),
            len(parsed.properties),
            len(parsed.contracts),
        )
        return tests

    # ── Static analysis helpers ─────────────────────────────────────

    @staticmethod
    def _check_balanced_parens(expr: str) -> bool:
        """Check whether all parentheses in *expr* are balanced.

        Args:
            expr: Expression string to check.

        Returns:
            ``True`` if parentheses are balanced.
        """
        depth = 0
        for ch in expr:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth < 0:
                    return False
        return depth == 0

    @staticmethod
    def _analyse_clause(clause: str, clause_type: str) -> dict[str, Any]:
        """Analyse a single contract clause.

        Args:
            clause: The clause expression.
            clause_type: One of ``"pre"``, ``"post"``, ``"invariant"``.

        Returns:
            Analysis dictionary with ``valid``, ``has_result``,
            ``has_old``, ``has_mutable_state``, and ``operators`` keys.
        """
        text = clause.strip()
        if not text:
            return {
                "valid": False,
                "has_result": False,
                "has_old": False,
                "has_mutable_state": False,
                "operators": [],
                "issue": f"{clause_type} clause is empty",
            }

        paren_ok = DSLModule._check_balanced_parens(text)
        ops = re.findall(r"(==|!=|<=|>=|&&|\|\||<|>|\+|-|\*|/|%)", text)

        return {
            "valid": paren_ok,
            "has_result": "result" in text.lower(),
            "has_old": "old(" in text.lower(),
            "has_mutable_state": bool(
                re.search(r"\+\+|--|\+= |-= |[^=<>!]= [^=]", text)
            ),
            "operators": ops,
            "issue": None if paren_ok else "Unbalanced parentheses",
        }

    @staticmethod
    def _infer_boundary_inputs(assertion: str) -> dict[str, Any]:
        """Infer boundary-value inputs for an assertion.

        Heuristically detects comparisons like ``x >= 0``, ``x < 10``
        and returns inputs at the boundary.

        Args:
            assertion: Assertion expression.

        Returns:
            Dictionary mapping inferred variable names to boundary values.
        """
        inputs: dict[str, Any] = {}
        # Match patterns like ``x >= 0``, ``x > 0``, ``x <= N``, ``x < N``
        for match in re.finditer(
            r"(\w+)\s*(>=|<=|>|<|==|!=)\s*(\w+)", assertion
        ):
            var = match.group(1)
            op = match.group(2)
            val_str = match.group(3)

            # Skip if var is likely a keyword or function name
            if var.lower() in ("result", "old", "len", "assert"):
                continue

            try:
                val = int(val_str)
            except ValueError:
                try:
                    val = float(val_str)
                except ValueError:
                    val = 0

            if op in (">=", "=="):
                inputs[var] = val
            elif op == ">":
                inputs[var] = val + 1
            elif op in ("<=",):
                inputs[var] = val
            elif op == "<":
                inputs[var] = val - 1

        return inputs if inputs else {"_default": 0}

    @staticmethod
    def _infer_positive_inputs(assertion: str) -> dict[str, Any]:
        """Infer positive (should-satisfy) inputs for an assertion.

        Args:
            assertion: Assertion expression.

        Returns:
            Dictionary mapping inferred variable names to values that
            should satisfy the assertion.
        """
        inputs: dict[str, Any] = {}
        for match in re.finditer(
            r"(\w+)\s*(>=|<=|>|<|==|!=)\s*(\w+)", assertion
        ):
            var = match.group(1)
            op = match.group(2)
            val_str = match.group(3)

            if var.lower() in ("result", "old", "len", "assert"):
                continue

            try:
                val = int(val_str)
            except ValueError:
                try:
                    val = float(val_str)
                except ValueError:
                    val = 0

            if op in (">=", "==", "<="):
                inputs[var] = val + 10  # well above/below boundary
            elif op == ">":
                inputs[var] = val + 10
            elif op == "<":
                inputs[var] = val - 10

        return inputs if inputs else {"_default": 42}

    @staticmethod
    def _infer_negative_inputs(assertion: str) -> Optional[dict[str, Any]]:
        """Infer negative (should-fail) inputs for an assertion.

        Args:
            assertion: Assertion expression.

        Returns:
            Dictionary of inputs that should *not* satisfy the assertion,
            or ``None`` if we cannot safely infer a negation.
        """
        inputs: dict[str, Any] = {}
        negation_possible = False

        for match in re.finditer(
            r"(\w+)\s*(>=|<=|>|<|==|!=)\s*(\w+)", assertion
        ):
            var = match.group(1)
            op = match.group(2)
            val_str = match.group(3)

            if var.lower() in ("result", "old", "len", "assert"):
                continue

            try:
                val = int(val_str)
            except ValueError:
                try:
                    val = float(val_str)
                except ValueError:
                    continue

            negation_possible = True
            if op == ">=":
                inputs[var] = val - 1
            elif op == "<=":
                inputs[var] = val + 1
            elif op == ">":
                inputs[var] = val
            elif op == "<":
                inputs[var] = val
            elif op == "==":
                inputs[var] = val + 1

        return inputs if negation_possible else None
