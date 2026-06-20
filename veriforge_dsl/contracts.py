"""
veriforge_dsl.contracts -- Contract System

Preconditions, postconditions, and invariants for formal specifications.
Decorators enforce contracts at runtime with detailed error messages.
"""

from __future__ import annotations

import functools
import inspect
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .types import VType


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Contract:
    """A contract bundles preconditions, postconditions, and invariants."""

    preconditions: List[Callable[..., bool]] = field(default_factory=list)
    postconditions: List[Callable[..., bool]] = field(default_factory=list)
    invariants: List[Callable[..., bool]] = field(default_factory=list)

    def add_pre(self, fn: Callable[..., bool]) -> "Contract":
        self.preconditions.append(fn)
        return self

    def add_post(self, fn: Callable[..., bool]) -> "Contract":
        self.postconditions.append(fn)
        return self

    def add_invariant(self, fn: Callable[..., bool]) -> "Contract":
        self.invariants.append(fn)
        return self


@dataclass
class Spec:
    """Formal specification of a function or method."""

    name: str
    inputs: Dict[str, VType]
    output: VType
    contracts: Contract = field(default_factory=Contract)
    description: str = ""

    def signature_str(self) -> str:
        params = ", ".join(f"{k}: {v!r}" for k, v in self.inputs.items())
        return f"{self.name}({params}) -> {self.output!r}"


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _bind_args(func: Callable, args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> inspect.BoundArguments:
    """Bind *args/**kwargs to *func*'s signature."""
    sig = inspect.signature(func)
    return sig.bind(*args, **kwargs)


def _validate_inputs(spec: Spec, bound: inspect.BoundArguments) -> None:
    """Run input types + preconditions against bound arguments."""
    bound.apply_defaults()
    for arg_name, vtype in spec.inputs.items():
        if arg_name in bound.arguments:
            try:
                vtype.validate(bound.arguments[arg_name])
            except (TypeError, ValueError) as exc:
                raise TypeError(f"Input validation failed for '{arg_name}': {exc}") from exc
    # Preconditions
    ctx = dict(bound.arguments)
    for pre in spec.contracts.preconditions:
        try:
            result = pre(**{k: v for k, v in ctx.items() if k in inspect.signature(pre).parameters})
            if result is False:
                raise AssertionError(f"Precondition {pre.__name__} returned False")
        except Exception as exc:
            raise AssertionError(f"Precondition failed: {pre.__name__}: {exc}") from exc


def _validate_output(spec: Spec, bound: inspect.BoundArguments, output: Any) -> None:
    """Run output type + postconditions against *output*."""
    try:
        spec.output.validate(output)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"Output validation failed: {exc}") from exc
    ctx = dict(bound.arguments)
    ctx["__return__"] = output
    for post in spec.contracts.postconditions:
        sig_params = set(inspect.signature(post).parameters)
        kwargs = {k: v for k, v in ctx.items() if k in sig_params}
        if "__return__" in sig_params:
            kwargs["__return__"] = output
        try:
            result = post(**kwargs)
            if result is False:
                raise AssertionError(f"Postcondition {post.__name__} returned False")
        except Exception as exc:
            raise AssertionError(f"Postcondition failed: {post.__name__}: {exc}") from exc


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def enforce_pre(spec: Spec):
    """Decorator that enforces input types + preconditions."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = _bind_args(func, args, kwargs)
            _validate_inputs(spec, bound)
            return func(*args, **kwargs)
        wrapper.__spec__ = spec  # type: ignore[attr-defined]
        return wrapper
    return decorator


def enforce_post(spec: Spec):
    """Decorator that enforces output type + postconditions."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = _bind_args(func, args, kwargs)
            result = func(*args, **kwargs)
            bound.apply_defaults()
            _validate_output(spec, bound, result)
            return result
        wrapper.__spec__ = spec  # type: ignore[attr-defined]
        return wrapper
    return decorator


def enforce_contracts(spec: Spec):
    """Decorator enforcing both pre- and post-conditions (plus output type)."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = _bind_args(func, args, kwargs)
            _validate_inputs(spec, bound)
            result = func(*args, **kwargs)
            bound.apply_defaults()
            _validate_output(spec, bound, result)
            return result
        wrapper.__spec__ = spec  # type: ignore[attr-defined]
        return wrapper
    return decorator


def check_invariants(obj: Any, spec: Spec) -> None:
    """Validate invariants on *obj* using the invariants defined in *spec*."""
    ctx: Dict[str, Any] = {"self": obj}
    for inv in spec.contracts.invariants:
        sig_params = set(inspect.signature(inv).parameters)
        kwargs = {k: v for k, v in ctx.items() if k in sig_params}
        # also inject any accessible attributes
        for attr in dir(obj):
            if not attr.startswith("_") and attr in sig_params:
                kwargs[attr] = getattr(obj, attr)
        try:
            result = inv(**kwargs)
            if result is False:
                raise AssertionError(f"Invariant {inv.__name__} returned False")
        except Exception as exc:
            raise AssertionError(f"Invariant failed: {inv.__name__}: {exc}") from exc


# ---------------------------------------------------------------------------
# Utility helpers for quick contract building
# ---------------------------------------------------------------------------

def pre(predicate: Callable[..., bool]) -> Contract:
    """Shorthand: ``pre(lambda x: x > 0)``."""
    return Contract(preconditions=[predicate])


def post(predicate: Callable[..., bool]) -> Contract:
    """Shorthand: ``post(lambda __return__: __return__ > 0)``."""
    return Contract(postconditions=[predicate])


def invariant(predicate: Callable[..., bool]) -> Contract:
    """Shorthand for invariant contract."""
    return Contract(invariants=[predicate])
