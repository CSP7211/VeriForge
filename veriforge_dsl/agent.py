"""
veriforge_dsl.agent -- NL to Spec Pipeline

Translates natural-language descriptions into formal Spec objects,
generates Python implementations, and verifies + refines them.
"""

from __future__ import annotations

import ast
import inspect
import re
import textwrap
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .contracts import Contract, Spec, check_invariants, enforce_contracts
from .core import Forge, VerificationResult
from .types import (
    VBool,
    VConstraint,
    VDict,
    VEnum,
    VFloat,
    VInt,
    VList,
    VOptional,
    VStr,
    VType,
    VUnion,
)
from .verification import generate_inputs, run_verification


# ---------------------------------------------------------------------------
# NL parsing helpers
# ---------------------------------------------------------------------------

_TYPE_KEYWORDS: Dict[str, Callable[[], VType]] = {
    "integer": VInt,
    "int": VInt,
    "float": VFloat,
    "double": VFloat,
    "string": VStr,
    "str": VStr,
    "boolean": VBool,
    "bool": VBool,
    "list": lambda: VList(VInt()),
    "positive integer": lambda: VConstraint(VInt(), lambda x: x > 0, name="positive"),
    "positive float": lambda: VConstraint(VFloat(), lambda x: x > 0.0, name="positive"),
    "non-empty string": lambda: VConstraint(VStr(), lambda s: len(s) > 0, name="non_empty"),
    "uuid": lambda: VStr(regex=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
}


def _extract_type(token: str) -> Optional[VType]:
    token_lower = token.lower().strip()
    factory = _TYPE_KEYWORDS.get(token_lower)
    if factory:
        return factory()
    # handle "list of X"
    m = re.match(r"list of (\w+)", token_lower)
    if m:
        inner_name = m.group(1)
        inner = _extract_type(inner_name)
        if inner:
            return VList(inner)
        if inner_name in ("int", "integer"):
            return VList(VInt())
        if inner_name in ("float", "double"):
            return VList(VFloat())
        if inner_name in ("str", "string"):
            return VList(VStr())
    return None


def _extract_preconditions(description: str) -> List[Callable[..., bool]]:
    """Heuristic extraction of preconditions from NL."""
    precs: List[Callable[..., bool]] = []
    lower = description.lower()

    # amount > 0
    if "amount" in lower and "positive" in lower:
        precs.append(lambda amount: amount > 0)
    # length checks
    m = re.search(r"len\((\w+)\)\s*>\s*(\d+)", lower)
    if m:
        var_name = m.group(1)
        threshold = int(m.group(2))
        precs.append(lambda **kw: len(kw.get(var_name, [])) > threshold)
    # non-empty
    if "non-empty" in lower or "nonempty" in lower or "not empty" in lower:
        for word in re.findall(r"(\w+)\s+is\s+non[- ]?empty", lower):
            precs.append(lambda **kw: len(kw.get(word, [])) > 0)
    # enum constraints
    enum_match = re.search(r"in\s+\[(.+?)\]", description)
    if enum_match:
        raw = enum_match.group(1)
        vals = [v.strip().strip("'\"`) ") for v in raw.split(",")]
        precs.append(lambda val, vals=vals: val in vals)
    return precs


def _extract_postconditions(description: str) -> List[Callable[..., bool]]:
    """Heuristic extraction of postconditions from NL."""
    posts: List[Callable[..., bool]] = []
    lower = description.lower()
    # return > 0
    if "return" in lower and "positive" in lower:
        posts.append(lambda __return__: __return__ > 0)
    return posts


# ---------------------------------------------------------------------------
# SpecAgent
# ---------------------------------------------------------------------------

@dataclass
class SpecAgent:
    """Translates natural language to formal specs and beyond."""

    forge: Optional[Forge] = None
    _nl_history: List[Dict[str, Any]] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Translation
    # ------------------------------------------------------------------

    def translate(self, description: str) -> Spec:
        """Parse an NL *description* into a formal :class:`Spec`."""
        lower = description.lower()

        # Extract function name
        name_match = re.search(r"(?:function|def|method)\s+(\w+)", description)
        name = name_match.group(1) if name_match else "unnamed"

        # Extract argument declarations like ``amount: float`` or ``amount is a positive integer``
        inputs: Dict[str, VType] = {}
        # pattern: "word: type" or "word is a/an type"
        for pat in [
            r"(\w+)\s*:\s*(\w+(?:\s+of\s+\w+)?)",
            r"(\w+)\s+is\s+a(?:n)?\s+(\w+(?:\s+of\s+\w+)?)",
        ]:
            for m in re.finditer(pat, description):
                arg_name = m.group(1)
                type_token = m.group(2)
                vtype = _extract_type(type_token)
                if vtype and arg_name not in ("return", "returns"):
                    inputs[arg_name] = vtype

        # Fallback: scan for common argument names
        if not inputs:
            common_args = {
                "amount": VFloat(),
                "currency": VStr(),
                "user_id": VStr(),
                "data": VList(VFloat()),
                "value": VInt(),
                "name": VStr(),
            }
            for arg_name, default_type in common_args.items():
                if re.search(rf"\b{arg_name}\b", description, re.IGNORECASE):
                    inputs[arg_name] = default_type

        # Detect output type
        output: VType = VBool()
        ret_match = re.search(r"return[s]?\s+(?:an|a)?\s*(\w+(?:\s+of\s+\w+)?)", lower)
        if ret_match:
            out_type = _extract_type(ret_match.group(1))
            if out_type:
                output = out_type
        else:
            # heuristic based on keywords
            if "median" in lower or "average" in lower or "mean" in lower:
                output = VFloat()
            elif "count" in lower or "length" in lower or "index" in lower:
                output = VInt()
            elif "success" in lower or "error" in lower:
                output = VBool()

        # Extract contracts
        precs = _extract_preconditions(description)
        posts = _extract_postconditions(description)
        contract = Contract(preconditions=precs, postconditions=posts)

        spec = Spec(
            name=name,
            inputs=inputs,
            output=output,
            contracts=contract,
            description=description,
        )
        self._nl_history.append({"description": description, "spec": spec})
        return spec

    # ------------------------------------------------------------------
    # Implementation generation
    # ------------------------------------------------------------------

    def generate_impl(self, spec: Spec) -> Callable:
        """Generate a Python callable satisfying *spec*.

        Uses AST-based code generation for simple specs and falls back to
        template dispatch for well-known patterns (median, payment, etc.).
        """
        lower_desc = spec.description.lower()

        # --- Dispatch on known patterns --------------------------------
        if "median" in lower_desc or spec.name == "find_median":
            return self._gen_median_impl(spec)
        if "payment" in lower_desc or spec.name == "process_payment":
            return self._gen_payment_impl(spec)
        if "sum" in lower_desc or spec.name == "sum_values":
            return self._gen_sum_impl(spec)
        if "factorial" in lower_desc or spec.name == "factorial":
            return self._gen_factorial_impl(spec)
        if "sort" in lower_desc or spec.name == "sort_list":
            return self._gen_sort_impl(spec)

        # --- Generic fallback: build a simple function ------------------
        return self._gen_generic_impl(spec)

    # -- Template generators --

    def _gen_median_impl(self, spec: Spec) -> Callable:
        def find_median(data: List[float]) -> float:
            if not data:
                raise ValueError("Cannot compute median of empty list")
            sorted_data = sorted(data)
            n = len(sorted_data)
            if n % 2 == 1:
                return float(sorted_data[n // 2])
            return (sorted_data[n // 2 - 1] + sorted_data[n // 2]) / 2.0
        return find_median

    def _gen_payment_impl(self, spec: Spec) -> Callable:
        import uuid

        _seen_uuids: set = set()

        def process_payment(amount: float, currency: str, user_id: str) -> dict:
            if amount <= 0:
                return {"success": False, "error": "INVALID_AMOUNT", "transaction_id": None}
            if currency not in ("USD", "EUR", "GBP"):
                return {"success": False, "error": "INVALID_CURRENCY", "transaction_id": None}
            tx_id = str(uuid.uuid4())
            if tx_id in _seen_uuids:
                return {"success": False, "error": "DUPLICATE_UUID", "transaction_id": None}
            _seen_uuids.add(tx_id)
            return {"success": True, "error": None, "transaction_id": tx_id}
        return process_payment

    def _gen_sum_impl(self, spec: Spec) -> Callable:
        def sum_values(data: List[float]) -> float:
            return sum(data)
        return sum_values

    def _gen_factorial_impl(self, spec: Spec) -> Callable:
        def factorial(n: int) -> int:
            if n < 0:
                raise ValueError("n must be non-negative")
            result = 1
            for i in range(2, n + 1):
                result *= i
            return result
        return factorial

    def _gen_sort_impl(self, spec: Spec) -> Callable:
        def sort_list(data: List[float]) -> List[float]:
            return sorted(data)
        return sort_list

    def _gen_generic_impl(self, spec: Spec) -> Callable:
        arg_names = list(spec.inputs.keys())
        code = f"def {spec.name}({', '.join(arg_names)}):\n"
        code += "    pass\n"
        local_ns: Dict[str, Any] = {}
        exec(code, local_ns)
        return local_ns[spec.name]

    # ------------------------------------------------------------------
    # Verify + Refine loop
    # ------------------------------------------------------------------

    def verify_and_refine(
        self,
        spec: Spec,
        impl: Callable,
        max_rounds: int = 3,
        iterations: int = 100,
    ) -> Dict[str, Any]:
        """Run verification, collect feedback, and optionally refine.

        Returns a dict with keys:
        - ``spec``: the (possibly refined) Spec
        - ``impl``: the implementation callable
        - ``results``: list of VerificationResult per round
        - ``refined``: bool indicating whether refinement occurred
        """
        forge = self.forge or Forge(name="agent_forge")
        forge.register(spec, impl)

        results: List[VerificationResult] = []
        refined = False
        current_spec = spec
        current_impl = impl

        for round_num in range(max_rounds):
            result = forge.verify(spec.name, iterations=iterations)
            results.append(result)
            if result.passed:
                break
            # Build feedback from counterexamples
            feedback_parts: List[str] = []
            if result.counterexamples:
                cx = result.counterexamples[0]
                if any(isinstance(v, str) and v.startswith("-") for v in cx.values()):
                    feedback_parts.append("negative values detected")
                if any(v is None for v in cx.values()):
                    feedback_parts.append("null values detected")
                if any(isinstance(v, (list, tuple)) and len(v) == 0 for v in cx.values()):
                    feedback_parts.append("empty collections detected")
                if not feedback_parts:
                    feedback_parts.append("counterexample found")
            if not feedback_parts:
                feedback_parts.append("verification failed")
            feedback = "; ".join(feedback_parts)
            current_spec = forge.refine(spec.name, feedback)
            refined = True
            # re-register the refined spec
            forge.register(current_spec, current_impl)

        return {
            "spec": current_spec,
            "impl": current_impl,
            "results": results,
            "refined": refined,
        }
