"""
veriforge_dsl.types -- Formal Type System

Provides runtime-validated formal types for the VeriForge DSL.
Each VType subclass implements ``validate(value)`` which either returns
the (possibly coerced) value or raises ``TypeError`` / ``ValueError``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional, Sequence, Union


# ---------------------------------------------------------------------------
# Base type
# ---------------------------------------------------------------------------

@dataclass
class VType:
    """Base class for all VeriForge formal types."""

    def validate(self, value: Any) -> Any:
        """Validate and optionally coerce *value*.  Raise on failure."""
        raise NotImplementedError

    def __repr__(self) -> str:
        return self.__class__.__name__ + "()"


# ---------------------------------------------------------------------------
# Scalar types
# ---------------------------------------------------------------------------

@dataclass
class VFloat(VType):
    """IEEE-754 double-precision floating point."""

    min: Optional[float] = None
    max: Optional[float] = None

    def validate(self, value: Any) -> float:
        if isinstance(value, bool):
            raise TypeError(f"VFloat does not accept bool (got {value!r})")
        if isinstance(value, (int, float)):
            f = float(value)
        else:
            raise TypeError(f"Expected float-compatible, got {type(value).__name__}: {value!r}")
        if self.min is not None and f < self.min:
            raise ValueError(f"VFloat: {f} < min {self.min}")
        if self.max is not None and f > self.max:
            raise ValueError(f"VFloat: {f} > max {self.max}")
        return f

    def __repr__(self) -> str:
        bounds = ""
        if self.min is not None or self.max is not None:
            bounds = f"(min={self.min}, max={self.max})"
        return f"VFloat{bounds}"


@dataclass
class VInt(VType):
    """Arbitrary-precision integer."""

    min: Optional[int] = None
    max: Optional[int] = None

    def validate(self, value: Any) -> int:
        if isinstance(value, bool):
            raise TypeError(f"VInt does not accept bool (got {value!r})")
        if isinstance(value, int):
            i = value
        elif isinstance(value, float) and value == int(value):
            i = int(value)
        else:
            raise TypeError(f"Expected int, got {type(value).__name__}: {value!r}")
        if self.min is not None and i < self.min:
            raise ValueError(f"VInt: {i} < min {self.min}")
        if self.max is not None and i > self.max:
            raise ValueError(f"VInt: {i} > max {self.max}")
        return i

    def __repr__(self) -> str:
        bounds = ""
        if self.min is not None or self.max is not None:
            bounds = f"(min={self.min}, max={self.max})"
        return f"VInt{bounds}"


@dataclass
class VStr(VType):
    """Unicode string with optional length and regex constraints."""

    min_len: Optional[int] = None
    max_len: Optional[int] = None
    regex: Optional[str] = None

    def validate(self, value: Any) -> str:
        if not isinstance(value, str):
            raise TypeError(f"Expected str, got {type(value).__name__}: {value!r}")
        if self.min_len is not None and len(value) < self.min_len:
            raise ValueError(f"VStr: len({value!r}) < min_len {self.min_len}")
        if self.max_len is not None and len(value) > self.max_len:
            raise ValueError(f"VStr: len({value!r}) > max_len {self.max_len}")
        if self.regex is not None:
            import re

            if not re.search(self.regex, value):
                raise ValueError(f"VStr: {value!r} does not match regex {self.regex}")
        return value

    def __repr__(self) -> str:
        parts = []
        if self.min_len is not None:
            parts.append(f"min_len={self.min_len}")
        if self.max_len is not None:
            parts.append(f"max_len={self.max_len}")
        if self.regex is not None:
            parts.append(f"regex={self.regex!r}")
        return f"VStr({', '.join(parts)})" if parts else "VStr()"


@dataclass
class VBool(VType):
    """Boolean type (True / False only)."""

    def validate(self, value: Any) -> bool:
        if not isinstance(value, bool):
            raise TypeError(f"Expected bool, got {type(value).__name__}: {value!r}")
        return value


# ---------------------------------------------------------------------------
# Composite types
# ---------------------------------------------------------------------------

@dataclass
class VEnum(VType):
    """Enumeration of permitted string values."""

    values: List[str] = field(default_factory=list)

    def validate(self, value: Any) -> str:
        if not isinstance(value, str):
            raise TypeError(f"VEnum expects str, got {type(value).__name__}: {value!r}")
        if value not in self.values:
            raise ValueError(f"VEnum: {value!r} not in {self.values}")
        return value

    def __repr__(self) -> str:
        return f"VEnum(values={self.values!r})"


@dataclass
class VOptional(VType):
    """Optional wrapper -- None or inner type."""

    inner: VType

    def validate(self, value: Any) -> Any:
        if value is None:
            return None
        return self.inner.validate(value)

    def __repr__(self) -> str:
        return f"VOptional({self.inner!r})"


@dataclass
class VConstraint(VType):
    """Type decorated with a runtime predicate."""

    inner: VType
    predicate: Callable[[Any], bool]
    name: str = "constraint"

    def validate(self, value: Any) -> Any:
        coerced = self.inner.validate(value)
        if not self.predicate(coerced):
            raise ValueError(
                f"VConstraint({self.name!r}): predicate failed for {coerced!r}"
            )
        return coerced

    def __repr__(self) -> str:
        return f"VConstraint({self.inner!r}, name={self.name!r})"


@dataclass
class VUnion(VType):
    """Disjoint union of types -- tries each in order."""

    types: List[VType] = field(default_factory=list)

    def validate(self, value: Any) -> Any:
        errors: List[str] = []
        for vt in self.types:
            try:
                return vt.validate(value)
            except (TypeError, ValueError) as exc:
                errors.append(str(exc))
        raise TypeError(f"VUnion: no branch matched for {value!r}. Errors: {errors}")

    def __repr__(self) -> str:
        return f"VUnion({self.types!r})"


@dataclass
class VList(VType):
    """Homogeneous list with optional length constraints."""

    element_type: VType
    min_len: Optional[int] = None
    max_len: Optional[int] = None

    def validate(self, value: Any) -> List[Any]:
        if not isinstance(value, (list, tuple)):
            raise TypeError(f"VList expects list/tuple, got {type(value).__name__}: {value!r}")
        if self.min_len is not None and len(value) < self.min_len:
            raise ValueError(f"VList: len({value}) < min_len {self.min_len}")
        if self.max_len is not None and len(value) > self.max_len:
            raise ValueError(f"VList: len({value}) > max_len {self.max_len}")
        return [self.element_type.validate(v) for v in value]

    def __repr__(self) -> str:
        parts = [f"element_type={self.element_type!r}"]
        if self.min_len is not None:
            parts.append(f"min_len={self.min_len}")
        if self.max_len is not None:
            parts.append(f"max_len={self.max_len}")
        return f"VList({', '.join(parts)})"


@dataclass
class VDict(VType):
    """Dictionary with typed keys and values."""

    key_type: VType
    value_type: VType

    def validate(self, value: Any) -> dict:
        if not isinstance(value, dict):
            raise TypeError(f"VDict expects dict, got {type(value).__name__}: {value!r}")
        return {
            self.key_type.validate(k): self.value_type.validate(v)
            for k, v in value.items()
        }

    def __repr__(self) -> str:
        return f"VDict(key_type={self.key_type!r}, value_type={self.value_type!r})"


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

VPositiveInt = lambda: VConstraint(VInt(), lambda x: x > 0, name="positive")
VNonEmptyStr = lambda: VConstraint(VStr(), lambda s: len(s) > 0, name="non_empty")
VProbability = lambda: VConstraint(
    VFloat(min=0.0, max=1.0), lambda p: 0.0 <= p <= 1.0, name="probability"
)
