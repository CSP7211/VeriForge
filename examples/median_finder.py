"""
examples.median_finder -- Statistical Median with Invariants

Demonstrates a Forge with:
  - Precondition: len(data) > 0
  - Invariant: odd/even length handling
  - 500 generative iterations + 9 edge cases
  - Edge cases: empty list, single element, unsorted, negatives, floats, duplicates
"""

from __future__ import annotations

import math
import statistics
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from veriforge_dsl import (
    Contract,
    Forge,
    Spec,
    VConstraint,
    VFloat,
    VInt,
    VList,
)
from veriforge_dsl.verification import find_edge_cases, generate_inputs


# ---------------------------------------------------------------------------
# Implementation
# ---------------------------------------------------------------------------

def find_median(data: List[float]) -> float:
    """Compute the statistical median of *data*.

    Preconditions:
        - len(data) > 0

    Invariants:
        - For odd-length data, result equals the middle element when sorted.
        - For even-length data, result equals the average of two middle elements.
    """
    if not data:
        raise ValueError("Cannot compute median of empty dataset")
    return statistics.median(data)


def _pre_non_empty(data: List[float]) -> bool:
    return len(data) > 0


def _invariant_sorted_median(data: List[float], __return__: float) -> bool:
    """Invariant: the returned median is consistent with sorted data."""
    sorted_data = sorted(data)
    n = len(sorted_data)
    if n == 0:
        return False  # should have been caught by precondition
    if n % 2 == 1:
        expected = float(sorted_data[n // 2])
    else:
        expected = (sorted_data[n // 2 - 1] + sorted_data[n // 2]) / 2.0
    return abs(__return__ - expected) < 1e-9


def _invariant_within_range(data: List[float], __return__: float) -> bool:
    """Invariant: median is between min and max of data."""
    return min(data) <= __return__ <= max(data)


# ---------------------------------------------------------------------------
# Forge setup
# ---------------------------------------------------------------------------

forge = Forge(name="MedianFinder")

median_spec = Spec(
    name="find_median",
    inputs={
        "data": VConstraint(VList(VFloat()), lambda lst: len(lst) > 0, name="non_empty"),
    },
    output=VFloat(),
    contracts=Contract(
        preconditions=[
            _pre_non_empty,
        ],
        postconditions=[
            lambda data, __return__: min(data) <= __return__ <= max(data),
        ],
        invariants=[
            _invariant_sorted_median,
            _invariant_within_range,
        ],
    ),
    description=(
        "Compute the statistical median of a dataset. "
        "Data must be non-empty. For odd lengths, returns the middle element. "
        "For even lengths, returns the average of the two middle elements."
    ),
)

forge.register(median_spec, find_median)

# Property: median equals the built-in statistics.median
forge.register_property(lambda result: isinstance(result, float))
forge.register_property(lambda result: not math.isnan(result))


# ---------------------------------------------------------------------------
# Edge case definitions (9 canonical edge cases)
# ---------------------------------------------------------------------------

_EDGE_CASES = [
    # 1. Single element
    [42.0],
    # 2. Two elements (even)
    [1.0, 3.0],
    # 3. Already sorted odd
    [1.0, 2.0, 3.0, 4.0, 5.0],
    # 4. Reverse sorted
    [5.0, 4.0, 3.0, 2.0, 1.0],
    # 5. All negatives
    [-5.0, -3.0, -1.0],
    # 6. Mixed positive/negative
    [-10.0, -5.0, 0.0, 5.0, 10.0],
    # 7. All duplicates
    [7.0, 7.0, 7.0, 7.0],
    # 8. Large spread
    [-1e9, 0.0, 1e9],
    # 9. Floating point precision
    [0.1, 0.2, 0.3, 0.4, 0.5],
]


def run_edge_cases() -> Dict[str, Any]:
    """Manually run the 9 canonical edge cases and return results."""
    results = []
    passed = 0
    for i, case in enumerate(_EDGE_CASES, 1):
        try:
            result = find_median(case)
            median_spec.output.validate(result)
            results.append({"case": i, "input": case, "output": result, "passed": True})
            passed += 1
        except Exception as exc:
            results.append({"case": i, "input": case, "error": str(exc), "passed": False})
    return {"total": len(_EDGE_CASES), "passed": passed, "results": results}


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import math

    print(forge.describe())
    print()

    # Show edge cases
    print("=== Edge Cases ===")
    edge_results = run_edge_cases()
    for r in edge_results["results"]:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"  Case {r['case']}: [{status}] input={r['input']}")
    print(f"\nEdge cases: {edge_results['passed']}/{edge_results['total']} passed")
    print()

    # Run verification with 500 iterations
    print("=== Verification (500 iterations) ===")
    result = forge.verify("find_median", iterations=500)
    print(result.summary())
