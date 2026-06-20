"""
veriforge_dsl.verification -- Property-Based Testing & Edge Cases

Generates random inputs within type constraints, detects boundary values,
and produces detailed verification reports.
"""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple

from .contracts import Contract, Spec
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

if TYPE_CHECKING:
    from .core import Forge, VerificationResult


# ---------------------------------------------------------------------------
# Input generation
# ---------------------------------------------------------------------------

def _random_float(rng: random.Random, vtype: VFloat) -> float:
    lo = vtype.min if vtype.min is not None else -1e6
    hi = vtype.max if vtype.max is not None else 1e6
    return rng.uniform(lo, hi)


def _random_int(rng: random.Random, vtype: VInt) -> int:
    lo = vtype.min if vtype.min is not None else -1_000_000
    hi = vtype.max if vtype.max is not None else 1_000_000
    # clamp to avoid overflow in randint
    lo = max(lo, -(2**31))
    hi = min(hi, 2**31 - 1)
    return rng.randint(lo, hi)


def _random_str(rng: random.Random, vtype: VStr) -> str:
    min_l = vtype.min_len if vtype.min_len is not None else 0
    max_l = vtype.max_len if vtype.max_len is not None else 20
    length = rng.randint(min_l, max_l)
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
    return "".join(rng.choice(chars) for _ in range(length))


def _random_bool(rng: random.Random, vtype: VBool) -> bool:
    return rng.choice([True, False])


def _random_enum(rng: random.Random, vtype: VEnum) -> str:
    return rng.choice(vtype.values)


def _generate_value(rng: random.Random, vtype: VType) -> Any:
    """Recursively generate a random value satisfying *vtype*."""
    if isinstance(vtype, VConstraint):
        # First try full-range generation (few attempts)
        for _ in range(100):
            val = _generate_value(rng, vtype.inner)
            if vtype.predicate(val):
                return val
        # Fallback: use narrower range for numeric types to help rejection sampling
        if isinstance(vtype.inner, (VFloat, VInt)):
            for _ in range(5000):
                if isinstance(vtype.inner, VFloat):
                    val = rng.uniform(-10.0, 10.0)
                else:
                    val = rng.randint(-100, 100)
                if vtype.predicate(val):
                    return val
        raise RuntimeError(f"Failed to generate value for constrained type {vtype}")
    if isinstance(vtype, VOptional):
        if rng.random() < 0.1:
            return None
        return _generate_value(rng, vtype.inner)
    if isinstance(vtype, VUnion):
        chosen = rng.choice(vtype.types)
        return _generate_value(rng, chosen)
    if isinstance(vtype, VList):
        min_l = vtype.min_len if vtype.min_len is not None else 0
        max_l = vtype.max_len if vtype.max_len is not None else 20
        length = rng.randint(min_l, max_l)
        return [_generate_value(rng, vtype.element_type) for _ in range(length)]
    if isinstance(vtype, VDict):
        length = rng.randint(0, 10)
        return {
            _generate_value(rng, vtype.key_type): _generate_value(rng, vtype.value_type)
            for _ in range(length)
        }
    if isinstance(vtype, VFloat):
        return _random_float(rng, vtype)
    if isinstance(vtype, VInt):
        return _random_int(rng, vtype)
    if isinstance(vtype, VStr):
        return _random_str(rng, vtype)
    if isinstance(vtype, VBool):
        return _random_bool(rng, vtype)
    if isinstance(vtype, VEnum):
        return _random_enum(rng, vtype)
    raise TypeError(f"Unsupported type for generation: {vtype!r}")


def generate_inputs(
    spec: Spec, iterations: int = 100, seed: Optional[int] = None
) -> List[Dict[str, Any]]:
    """Generate *iterations* random input dicts satisfying *spec.inputs*."""
    rng = random.Random(seed)
    results: List[Dict[str, Any]] = []
    for _ in range(iterations):
        sample: Dict[str, Any] = {}
        for arg_name, vtype in spec.inputs.items():
            sample[arg_name] = _generate_value(rng, vtype)
        results.append(sample)
    return results


# ---------------------------------------------------------------------------
# Edge case generation
# ---------------------------------------------------------------------------

def _edge_cases_for_type(vtype: VType) -> List[Any]:
    """Return canonical edge-case values for *vtype*."""
    if isinstance(vtype, VConstraint):
        inner_edges = _edge_cases_for_type(vtype.inner)
        return [v for v in inner_edges if vtype.predicate(v)]
    if isinstance(vtype, VOptional):
        return [None] + _edge_cases_for_type(vtype.inner)
    if isinstance(vtype, VUnion):
        edges: List[Any] = []
        for t in vtype.types:
            edges.extend(_edge_cases_for_type(t))
        return edges
    if isinstance(vtype, VList):
        et = vtype.element_type
        inner = _edge_cases_for_type(et)
        return [
            [],
            [_generate_value(random.Random(42), et)],
            inner[:3] if inner else [],
        ]
    if isinstance(vtype, VFloat):
        edges = [-1e9, -1.0, -0.0, 0.0, 0.5, 1.0, 1e9, float("inf"), float("-inf")]
        if vtype.min is not None:
            edges.extend([vtype.min, math.nextafter(vtype.min, float("inf"))])
        if vtype.max is not None:
            edges.extend([vtype.max, math.nextafter(vtype.max, float("-inf"))])
        return edges
    if isinstance(vtype, VInt):
        edges = [-2_147_483_648, -1, 0, 1, 2_147_483_647]
        if vtype.min is not None:
            edges.extend([vtype.min, vtype.min + 1])
        if vtype.max is not None:
            edges.extend([vtype.max, vtype.max - 1])
        return edges
    if isinstance(vtype, VStr):
        edges = ["", "a", " " * 100, "\x00", "unicode:\u00e9\u00e0"]
        if vtype.min_len is not None and vtype.min_len > 0:
            edges.append("x" * vtype.min_len)
        if vtype.max_len is not None:
            edges.append("x" * vtype.max_len)
        return edges
    if isinstance(vtype, VBool):
        return [True, False]
    if isinstance(vtype, VEnum):
        return vtype.values[:1] + (vtype.values[-1:] if len(vtype.values) > 1 else [])
    return []


def find_edge_cases(spec: Spec) -> List[Dict[str, Any]]:
    """Return a list of edge-case input dicts for *spec*."""
    per_arg: Dict[str, List[Any]] = {}
    for arg_name, vtype in spec.inputs.items():
        per_arg[arg_name] = _edge_cases_for_type(vtype)
    # Cartesian product (bounded)
    from itertools import product

    arg_names = list(per_arg.keys())
    edge_lists = [per_arg[k] for k in arg_names]
    cases: List[Dict[str, Any]] = []
    for combo in product(*edge_lists):
        cases.append(dict(zip(arg_names, combo)))
    return cases


# ---------------------------------------------------------------------------
# Property checking
# ---------------------------------------------------------------------------

def check_property(
    func: Callable, property_fn: Callable[[Any], bool], inputs: Dict[str, Any]
) -> Tuple[bool, Optional[str]]:
    """Run *func* with *inputs* and test *property_fn* on the result.

    Returns ``(passed, error_message)``.
    """
    try:
        result = func(**inputs)
    except Exception as exc:
        return False, f"Exception: {type(exc).__name__}: {exc}"
    try:
        ok = property_fn(result)
    except Exception as exc:
        return False, f"Property exception: {type(exc).__name__}: {exc}"
    if not ok:
        return False, f"Property failed for result {result!r}"
    return True, None


# ---------------------------------------------------------------------------
# Full verification run
# ---------------------------------------------------------------------------

def run_verification(
    forge: "Forge",
    spec_name: str,
    iterations: int = 100,
    seed: Optional[int] = None,
) -> "VerificationResult":
    """Run the full verification pipeline for *spec_name* inside *forge*."""
    from .core import VerificationResult

    spec = forge.specs[spec_name]
    impl = forge.implementations[spec_name]

    start = time.perf_counter()
    rng = random.Random(seed)

    # --- Phase 1: Edge cases ------------------------------------------
    edge_cases = find_edge_cases(spec)
    edge_passed = 0
    for case in edge_cases:
        try:
            result = impl(**case)
            # validate output type
            spec.output.validate(result)
            edge_passed += 1
        except Exception as exc:
            pass  # counted as failed

    # --- Phase 2: Random generative tests -----------------------------
    generative_passed = 0
    counterexamples: List[Dict[str, Any]] = []
    messages: List[str] = []

    for i in range(iterations):
        inputs: Dict[str, Any] = {}
        for arg_name, vtype in spec.inputs.items():
            inputs[arg_name] = _generate_value(rng, vtype)
        try:
            result = impl(**inputs)
            spec.output.validate(result)
            # run registered properties
            all_props_ok = True
            for prop_fn in forge.properties:
                try:
                    prop_ok = prop_fn(result)
                    if not prop_ok:
                        all_props_ok = False
                        break
                except Exception:
                    all_props_ok = False
                    break
            if all_props_ok:
                generative_passed += 1
            else:
                if len(counterexamples) < 5:
                    counterexamples.append(dict(inputs))
        except Exception as exc:
            if len(counterexamples) < 5:
                cx = dict(inputs)
                cx["__exception__"] = f"{type(exc).__name__}: {exc}"
                counterexamples.append(cx)

    # --- Phase 3: Coverage heuristic ----------------------------------
    branches_hit = generative_passed / max(iterations, 1) * 100.0
    coverage_pct = min(100.0, branches_hit + (edge_passed / max(len(edge_cases), 1)) * 20.0)

    duration_ms = (time.perf_counter() - start) * 1000.0

    passed = generative_passed == iterations and edge_passed == len(edge_cases)

    return VerificationResult(
        spec_name=spec_name,
        passed=passed,
        tests_run=iterations,
        tests_passed=generative_passed,
        coverage_pct=coverage_pct,
        counterexamples=counterexamples,
        edge_cases_run=len(edge_cases),
        edge_cases_passed=edge_passed,
        duration_ms=duration_ms,
        messages=messages,
    )
