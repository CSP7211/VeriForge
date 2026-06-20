# VeriForge DSL v0.5.0

**Formal Specification Language for Python**

VeriForge DSL is a domain-specific language for writing formal specifications,
contracts, property-based tests, and natural-language-to-code pipelines in pure
Python. No external dependencies required.

---

## Features

| Feature | Description |
|---------|-------------|
| **Formal Types** | Runtime-validated type system with constraints, unions, optionals, lists |
| **Contracts** | Preconditions, postconditions, and invariants enforced at runtime |
| **Property-Based Testing** | Generative test input generation with configurable iterations |
| **Edge Case Detection** | Automatic boundary value, empty collection, NaN, infinity detection |
| **NL-to-Spec Pipeline** | Translate natural language descriptions into formal specifications |
| **Verification Reports** | Detailed pass/fail, coverage %, counterexample reporting |

---

## Quick Start

```python
from veriforge_dsl import Forge, Spec, VInt, VFloat, VStr

# Create a forge (module container)
forge = Forge(name="math")

# Define a formal spec
spec = Spec(
    name="add",
    inputs={"a": VInt(), "b": VInt()},
    output=VInt(),
)

# Register implementation
forge.register(spec, lambda a, b: a + b)

# Verify with 1000 random inputs
result = forge.verify("add", iterations=1000)
print(result.summary())
```

## Type System

```python
from veriforge_dsl import (
    VInt, VFloat, VStr, VBool, VEnum,
    VOptional, VConstraint, VUnion, VList
)

# Scalar types
VInt().validate(42)          # OK
VFloat().validate(3.14)      # OK
VStr().validate("hello")     # OK
VBool().validate(True)       # OK

# Constrained types
VConstraint(VInt(), lambda x: x > 0).validate(5)   # OK
VConstraint(VInt(), lambda x: x > 0).validate(-1)  # Raises ValueError

# Enums
VEnum(values=["USD", "EUR", "GBP"]).validate("USD")  # OK

# Optionals
VOptional(VInt()).validate(None)   # OK
VOptional(VInt()).validate(42)     # OK

# Unions
VUnion([VInt(), VStr()]).validate(42)      # OK (matches VInt)
VUnion([VInt(), VStr()]).validate("hi")    # OK (matches VStr)

# Lists
VList(VInt()).validate([1, 2, 3])          # OK
VList(VInt()).validate([1, "two"])         # Raises TypeError
```

## Contracts

```python
from veriforge_dsl import Contract, Spec, VInt
from veriforge_dsl.contracts import enforce_contracts

spec = Spec(
    name="divide",
    inputs={"a": VInt(), "b": VInt()},
    output=VInt(),
    contracts=Contract(
        preconditions=[lambda b: b != 0],
        postconditions=[lambda __return__: __return__ >= 0],
    ),
)

@enforce_contracts(spec)
def divide(a: int, b: int) -> int:
    return a // b

divide(10, 2)   # OK
divide(10, 0)   # Raises AssertionError (precondition)
```

## Natural Language to Spec

```python
from veriforge_dsl.agent import SpecAgent

agent = SpecAgent()
spec = agent.translate(
    "function find_median takes data: list of float and returns a float"
)
print(spec.signature_str())
# find_median(data: VList(element_type=VFloat())) -> VFloat()

impl = agent.generate_impl(spec)
print(impl([1.0, 3.0, 5.0]))  # 3.0
```

## CLI

```bash
# Describe a forge
python -m veriforge_dsl describe examples.payment_processor

# Verify a specific spec
python -m veriforge_dsl verify examples.median_finder --iterations 500

# List specs
python -m veriforge_dsl list examples.payment_processor
```

## Examples

### Payment Processor

See `examples/payment_processor.py` -- atomic payments with UUID uniqueness,
currency validation, and 100+ generative test iterations.

### Median Finder

See `examples/median_finder.py` -- statistical median with 500 generative
iterations and 9 canonical edge cases.

## Project Structure

```
veriforge_dsl/
├── veriforge_dsl/          # Core package
│   ├── types.py            # Formal type system
│   ├── contracts.py        # Pre/post/invariant contracts
│   ├── core.py             # Forge, Spec, Module
│   ├── verification.py     # Property-based testing, edge cases
│   ├── agent.py            # NL -> Spec -> Impl -> Verify
│   ├── __init__.py         # Package exports
│   └── __main__.py         # CLI
├── tests/
│   └── test_dsl.py         # 25+ comprehensive tests
├── examples/
│   ├── payment_processor.py
│   └── median_finder.py
├── setup.py
├── pyproject.toml
├── README.md
└── LICENSE
```

## License

MIT License -- see LICENSE file.
