"""
VeriForge DSL -- Formal Specification Language for Python

A domain-specific language for writing formal specifications, contracts,
property-based tests, and natural-language-to-code pipelines.

Usage::

    from veriforge_dsl import Forge, Spec, VInt, VFloat, VStr

    forge = Forge(name="my_module")
    spec = Spec(name="add", inputs={"a": VInt(), "b": VInt()}, output=VInt())
    forge.register(spec, lambda a, b: a + b)
    result = forge.verify("add", iterations=1000)
    print(result.summary())
"""

__version__ = "0.5.0"
__author__ = "VeriForge Contributors"

from .contracts import Contract, Spec, check_invariants, enforce_contracts, enforce_pre, enforce_post, invariant, post, pre
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
from .verification import check_property, find_edge_cases, generate_inputs, run_verification

__all__ = [
    # Version
    "__version__",
    # Types
    "VType",
    "VFloat",
    "VInt",
    "VStr",
    "VBool",
    "VEnum",
    "VOptional",
    "VConstraint",
    "VUnion",
    "VList",
    "VDict",
    # Contracts
    "Contract",
    "Spec",
    "pre",
    "post",
    "invariant",
    "enforce_pre",
    "enforce_post",
    "enforce_contracts",
    "check_invariants",
    # Core
    "Forge",
    "VerificationResult",
    # Verification
    "generate_inputs",
    "check_property",
    "find_edge_cases",
    "run_verification",
]
