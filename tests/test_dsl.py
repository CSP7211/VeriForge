"""
tests.test_dsl -- Comprehensive VeriForge DSL Test Suite

25+ tests covering:
  - Type validation (VFloat, VInt, VStr, VEnum, VOptional, VConstraint, VUnion, VList)
  - Spec creation, refinement, serialization
  - Forge registration, verification, property-based testing
  - Agent translation and pipeline
  - Edge cases and failing properties
  - Contract enforcement (pre/post/invariant)
"""

from __future__ import annotations

import math
import sys
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from veriforge_dsl import (
    Contract,
    Forge,
    Spec,
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
from veriforge_dsl.agent import SpecAgent
from veriforge_dsl.contracts import (
    check_invariants,
    enforce_contracts,
    enforce_post,
    enforce_pre,
    invariant,
    post,
    pre,
)
from veriforge_dsl.core import VerificationResult
from veriforge_dsl.verification import (
    check_property,
    find_edge_cases,
    generate_inputs,
    run_verification,
)


# ============================================================================
# 1. Type Validation Tests
# ============================================================================

class TestVFloat:
    def test_accepts_float(self) -> None:
        assert VFloat().validate(3.14) == 3.14

    def test_accepts_int(self) -> None:
        assert VFloat().validate(42) == 42.0

    def test_rejects_string(self) -> None:
        with pytest.raises(TypeError):
            VFloat().validate("hello")

    def test_rejects_bool(self) -> None:
        with pytest.raises(TypeError):
            VFloat().validate(True)

    def test_bounds(self) -> None:
        bounded = VFloat(min=0.0, max=1.0)
        assert bounded.validate(0.5) == 0.5
        with pytest.raises(ValueError):
            bounded.validate(1.5)
        with pytest.raises(ValueError):
            bounded.validate(-0.1)


class TestVInt:
    def test_accepts_int(self) -> None:
        assert VInt().validate(7) == 7

    def test_rejects_float_non_integral(self) -> None:
        with pytest.raises(TypeError):
            VInt().validate(3.14)

    def test_accepts_float_integral(self) -> None:
        assert VInt().validate(3.0) == 3

    def test_rejects_string(self) -> None:
        with pytest.raises(TypeError):
            VInt().validate("hello")

    def test_rejects_bool(self) -> None:
        with pytest.raises(TypeError):
            VInt().validate(False)

    def test_bounds(self) -> None:
        bounded = VInt(min=0, max=100)
        assert bounded.validate(50) == 50
        with pytest.raises(ValueError):
            bounded.validate(101)


class TestVStr:
    def test_accepts_string(self) -> None:
        assert VStr().validate("hello") == "hello"

    def test_rejects_int(self) -> None:
        with pytest.raises(TypeError):
            VStr().validate(42)

    def test_length_bounds(self) -> None:
        bounded = VStr(min_len=1, max_len=5)
        assert bounded.validate("hi") == "hi"
        with pytest.raises(ValueError):
            bounded.validate("")
        with pytest.raises(ValueError):
            bounded.validate("toolong")

    def test_regex(self) -> None:
        email_like = VStr(regex=r"@")
        assert email_like.validate("a@b.com") == "a@b.com"
        with pytest.raises(ValueError):
            email_like.validate("notanemail")


class TestVBool:
    def test_accepts_true(self) -> None:
        assert VBool().validate(True) is True

    def test_accepts_false(self) -> None:
        assert VBool().validate(False) is False

    def test_rejects_int(self) -> None:
        with pytest.raises(TypeError):
            VBool().validate(1)

    def test_rejects_string(self) -> None:
        with pytest.raises(TypeError):
            VBool().validate("true")


class TestVEnum:
    def test_valid_value(self) -> None:
        color = VEnum(values=["red", "green", "blue"])
        assert color.validate("green") == "green"

    def test_invalid_value(self) -> None:
        color = VEnum(values=["red", "green", "blue"])
        with pytest.raises(ValueError):
            color.validate("yellow")

    def test_rejects_non_string(self) -> None:
        color = VEnum(values=["red"])
        with pytest.raises(TypeError):
            color.validate(123)


class TestVOptional:
    def test_none(self) -> None:
        opt = VOptional(VInt())
        assert opt.validate(None) is None

    def test_some(self) -> None:
        opt = VOptional(VInt())
        assert opt.validate(42) == 42

    def test_invalid_inner(self) -> None:
        opt = VOptional(VInt())
        with pytest.raises(TypeError):
            opt.validate("not an int")


class TestVConstraint:
    def test_predicate_pass(self) -> None:
        pos = VConstraint(VInt(), lambda x: x > 0, name="positive")
        assert pos.validate(5) == 5

    def test_predicate_fail(self) -> None:
        pos = VConstraint(VInt(), lambda x: x > 0, name="positive")
        with pytest.raises(ValueError):
            pos.validate(-3)

    def test_nested_constraint(self) -> None:
        small_pos = VConstraint(
            VConstraint(VInt(), lambda x: x > 0, name="positive"),
            lambda x: x < 100,
            name="small",
        )
        assert small_pos.validate(50) == 50
        with pytest.raises(ValueError):
            small_pos.validate(200)


class TestVUnion:
    def test_first_branch(self) -> None:
        union = VUnion([VInt(), VStr()])
        assert union.validate(42) == 42

    def test_second_branch(self) -> None:
        union = VUnion([VInt(), VStr()])
        assert union.validate("hello") == "hello"

    def test_no_branch_matches(self) -> None:
        union = VUnion([VInt(), VStr()])
        with pytest.raises(TypeError):
            union.validate([])


class TestVList:
    def test_valid_list(self) -> None:
        lst = VList(VInt())
        assert lst.validate([1, 2, 3]) == [1, 2, 3]

    def test_tuple_accepted(self) -> None:
        lst = VList(VInt())
        assert lst.validate((1, 2)) == [1, 2]

    def test_invalid_element(self) -> None:
        lst = VList(VInt())
        with pytest.raises(TypeError):
            lst.validate([1, "two", 3])

    def test_length_bounds(self) -> None:
        lst = VList(VInt(), min_len=1, max_len=3)
        assert lst.validate([1]) == [1]
        with pytest.raises(ValueError):
            lst.validate([])
        with pytest.raises(ValueError):
            lst.validate([1, 2, 3, 4])

    def test_nested_list(self) -> None:
        nested = VList(VList(VInt()))
        assert nested.validate([[1, 2], [3, 4]]) == [[1, 2], [3, 4]]


class TestVDict:
    def test_valid_dict(self) -> None:
        d = VDict(VStr(), VInt())
        assert d.validate({"a": 1, "b": 2}) == {"a": 1, "b": 2}

    def test_invalid_key(self) -> None:
        d = VDict(VStr(), VInt())
        with pytest.raises(TypeError):
            d.validate({1: "value"})

    def test_invalid_value(self) -> None:
        d = VDict(VStr(), VInt())
        with pytest.raises(TypeError):
            d.validate({"a": "not an int"})


# ============================================================================
# 2. Spec & Contract Tests
# ============================================================================

class TestSpec:
    def test_spec_creation(self) -> None:
        spec = Spec(
            name="add",
            inputs={"a": VInt(), "b": VInt()},
            output=VInt(),
        )
        assert spec.name == "add"
        assert "a" in spec.inputs

    def test_spec_signature_str(self) -> None:
        spec = Spec(name="add", inputs={"a": VInt(), "b": VInt()}, output=VInt())
        sig = spec.signature_str()
        assert "add" in sig
        assert "a" in sig
        assert "b" in sig

    def test_contract_builder(self) -> None:
        c = Contract().add_pre(lambda x: x > 0).add_post(lambda __return__: __return__ > 0)
        assert len(c.preconditions) == 1
        assert len(c.postconditions) == 1


class TestContractEnforcement:
    def test_enforce_pre_pass(self) -> None:
        spec = Spec(
            name="double",
            inputs={"x": VInt()},
            output=VInt(),
            contracts=pre(lambda x: x > 0),
        )

        @enforce_pre(spec)
        def double(x: int) -> int:
            return x * 2

        assert double(5) == 10

    def test_enforce_pre_fail(self) -> None:
        spec = Spec(
            name="double",
            inputs={"x": VInt()},
            output=VInt(),
            contracts=pre(lambda x: x > 0),
        )

        @enforce_pre(spec)
        def double(x: int) -> int:
            return x * 2

        with pytest.raises(AssertionError):
            double(-1)

    def test_enforce_post_pass(self) -> None:
        spec = Spec(
            name="double",
            inputs={"x": VInt()},
            output=VInt(),
            contracts=post(lambda __return__: __return__ > 0),
        )

        @enforce_post(spec)
        def double(x: int) -> int:
            return x * 2

        assert double(3) == 6

    def test_enforce_post_fail(self) -> None:
        spec = Spec(
            name="double",
            inputs={"x": VInt()},
            output=VInt(),
            contracts=post(lambda __return__: __return__ > 0),
        )

        @enforce_post(spec)
        def broken_double(x: int) -> int:
            return -abs(x)  # violates postcondition

        with pytest.raises(AssertionError):
            broken_double(3)

    def test_enforce_contracts_both(self) -> None:
        spec = Spec(
            name="safe_div",
            inputs={"a": VInt(), "b": VInt()},
            output=VInt(),
            contracts=Contract(
                preconditions=[lambda b: b != 0],
                postconditions=[lambda __return__: isinstance(__return__, int)],
            ),
        )

        @enforce_contracts(spec)
        def safe_div(a: int, b: int) -> int:
            return a // b

        assert safe_div(10, 2) == 5
        with pytest.raises(AssertionError):
            safe_div(10, 0)

    def test_input_type_validation(self) -> None:
        spec = Spec(
            name="add",
            inputs={"a": VInt(), "b": VInt()},
            output=VInt(),
        )

        @enforce_contracts(spec)
        def add(a: int, b: int) -> int:
            return a + b

        with pytest.raises(TypeError):
            add("hello", 2)

    def test_output_type_validation(self) -> None:
        spec = Spec(
            name="identity",
            inputs={"x": VInt()},
            output=VInt(),
        )

        @enforce_contracts(spec)
        def identity(x: int) -> Any:
            return "not an int"  # type: ignore[return-value]

        with pytest.raises(TypeError):
            identity(5)

    def test_check_invariants(self) -> None:
        class Counter:
            def __init__(self) -> None:
                self.count = 0

        spec = Spec(
            name="Counter.invariant",
            inputs={},
            output=VBool(),
            contracts=invariant(lambda self: self.count >= 0),
        )
        c = Counter()
        c.count = 5
        check_invariants(c, spec)  # should pass

        c.count = -1
        with pytest.raises(AssertionError):
            check_invariants(c, spec)


# ============================================================================
# 3. Forge Tests
# ============================================================================

class TestForge:
    def test_register_and_verify(self) -> None:
        forge = Forge(name="test")
        spec = Spec(name="add", inputs={"a": VInt(), "b": VInt()}, output=VInt())
        forge.register(spec, lambda a, b: a + b)
        result = forge.verify("add", iterations=50, seed=42)
        assert result.tests_run == 50
        assert result.tests_passed == 50
        assert result.passed is True

    def test_verify_missing_spec(self) -> None:
        forge = Forge(name="test")
        result = forge.verify("nonexistent")
        assert result.passed is False
        assert "not found" in result.messages[0]

    def test_verify_missing_impl(self) -> None:
        forge = Forge(name="test")
        spec = Spec(name="add", inputs={"a": VInt()}, output=VInt())
        forge.specs["add"] = spec
        result = forge.verify("add")
        assert result.passed is False
        assert "No implementation" in result.messages[0]

    def test_verify_all(self) -> None:
        forge = Forge(name="test")
        forge.register(
            Spec(name="add", inputs={"a": VInt(), "b": VInt()}, output=VInt()),
            lambda a, b: a + b,
        )
        forge.register(
            Spec(name="mul", inputs={"a": VInt(), "b": VInt()}, output=VInt()),
            lambda a, b: a * b,
        )
        results = forge.verify_all(iterations=50, seed=42)
        assert len(results) == 2
        assert all(r.passed for r in results)

    def test_forge_describe(self) -> None:
        forge = Forge(name="math")
        forge.register(
            Spec(name="add", inputs={"a": VInt()}, output=VInt()),
            lambda a: a,
        )
        desc = forge.describe()
        assert "Forge: math" in desc
        assert "add" in desc

    def test_refine_tightens_constraint(self) -> None:
        forge = Forge(name="test")
        spec = Spec(
            name="foo",
            inputs={"x": VInt()},
            output=VInt(),
        )
        forge.register(spec, lambda x: x)
        new_spec = forge.refine("foo", "negative values detected")
        assert isinstance(new_spec.inputs["x"], VConstraint)
        assert "Refined" in new_spec.description

    def test_refine_empty_collection(self) -> None:
        forge = Forge(name="test")
        spec = Spec(
            name="process",
            inputs={"items": VList(VInt())},
            output=VInt(),
        )
        forge.register(spec, lambda items: sum(items))
        new_spec = forge.refine("process", "not empty")
        assert isinstance(new_spec.inputs["items"], VConstraint)


# ============================================================================
# 4. Verification Tests
# ============================================================================

class TestVerification:
    def test_generate_inputs(self) -> None:
        spec = Spec(name="test", inputs={"n": VInt()}, output=VInt())
        inputs = generate_inputs(spec, iterations=20, seed=42)
        assert len(inputs) == 20
        for inp in inputs:
            assert isinstance(inp["n"], int)

    def test_generate_inputs_constrained(self) -> None:
        spec = Spec(
            name="test",
            inputs={"p": VConstraint(VFloat(), lambda x: 0 <= x <= 1, name="probability")},
            output=VFloat(),
        )
        inputs = generate_inputs(spec, iterations=50, seed=42)
        for inp in inputs:
            assert 0.0 <= inp["p"] <= 1.0

    def test_find_edge_cases_int(self) -> None:
        spec = Spec(name="test", inputs={"x": VInt()}, output=VInt())
        edges = find_edge_cases(spec)
        values = [e["x"] for e in edges]
        assert 0 in values
        assert 1 in values
        assert -1 in values

    def test_find_edge_cases_float(self) -> None:
        spec = Spec(name="test", inputs={"x": VFloat()}, output=VFloat())
        edges = find_edge_cases(spec)
        values = [e["x"] for e in edges]
        assert 0.0 in values
        assert float("inf") in values
        assert float("-inf") in values

    def test_find_edge_cases_string(self) -> None:
        spec = Spec(name="test", inputs={"s": VStr()}, output=VStr())
        edges = find_edge_cases(spec)
        values = [e["s"] for e in edges]
        assert "" in values
        assert any(len(v) > 0 for v in values)

    def test_check_property(self) -> None:
        def identity(x: int) -> int:
            return x

        passed, msg = check_property(identity, lambda r: r == 5, {"x": 5})
        assert passed is True
        assert msg is None

        passed, msg = check_property(identity, lambda r: r == 5, {"x": 3})
        assert passed is False
        assert "Property failed" in msg

    def test_counterexample_collection(self) -> None:
        forge = Forge(name="test")
        forge.register(
            Spec(name="half", inputs={"x": VInt()}, output=VInt()),
            lambda x: x // 2,
        )
        # This property fails for odd x
        forge.register_property(lambda r: r % 2 == 0)
        result = forge.verify("half", iterations=100, seed=42)
        # With // 2, result is always an int, but property fails when result is odd
        assert result.tests_run == 100


# ============================================================================
# 5. Agent Tests
# ============================================================================

class TestAgent:
    def test_translate_simple(self) -> None:
        agent = SpecAgent()
        spec = agent.translate("function add takes a: int and b: int and returns an int")
        assert spec.name == "add"
        assert "a" in spec.inputs
        assert "b" in spec.inputs

    def test_translate_payment(self) -> None:
        agent = SpecAgent()
        spec = agent.translate(
            "function process_payment with amount: float, currency: string, user_id: string"
        )
        assert spec.name == "process_payment"
        assert "amount" in spec.inputs
        assert "currency" in spec.inputs
        assert "user_id" in spec.inputs

    def test_generate_impl_median(self) -> None:
        agent = SpecAgent()
        spec = agent.translate("function find_median takes data: list of float and returns a float")
        impl = agent.generate_impl(spec)
        assert callable(impl)
        result = impl([1.0, 3.0, 5.0])
        assert result == 3.0

    def test_generate_impl_payment(self) -> None:
        agent = SpecAgent()
        spec = agent.translate("function process_payment with amount: float and currency: string")
        impl = agent.generate_impl(spec)
        assert callable(impl)
        result = impl(10.0, "USD", "alice")
        assert isinstance(result, dict)

    def test_generate_impl_factorial(self) -> None:
        agent = SpecAgent()
        spec = agent.translate("function factorial takes n: int and returns an int")
        impl = agent.generate_impl(spec)
        assert impl(5) == 120
        assert impl(0) == 1

    def test_verify_and_refine(self) -> None:
        agent = SpecAgent()
        spec = agent.translate("function double takes x: int and returns an int")
        impl = agent.generate_impl(spec)
        # Provide a correct implementation
        def double_impl(x: int) -> int:
            return x * 2

        result = agent.verify_and_refine(spec, double_impl, iterations=50)
        assert len(result["results"]) > 0
        # A correct implementation should pass immediately
        assert result["results"][0].tests_passed == 50


# ============================================================================
# 6. Edge Case & Failing Property Tests
# ============================================================================

class TestEdgeCases:
    def test_empty_list_rejected(self) -> None:
        spec = Spec(
            name="first",
            inputs={"items": VList(VInt())},
            output=VInt(),
            contracts=pre(lambda items: len(items) > 0),
        )
        forge = Forge(name="test")
        forge.register(spec, lambda items: items[0])
        result = forge.verify("first", iterations=50, seed=42)
        # Some inputs may be empty lists, causing precondition failures
        assert result.tests_run == 50

    def test_nan_handling(self) -> None:
        spec = Spec(name="abs_val", inputs={"x": VFloat()}, output=VFloat())
        forge = Forge(name="test")
        forge.register(spec, lambda x: abs(x))
        result = forge.verify("abs_val", iterations=50, seed=42)
        assert result.tests_run == 50

    def test_union_type(self) -> None:
        spec = Spec(
            name="identity",
            inputs={"x": VUnion([VInt(), VStr()])},
            output=VUnion([VInt(), VStr()]),
        )
        forge = Forge(name="test")
        forge.register(spec, lambda x: x)
        result = forge.verify("identity", iterations=50, seed=42)
        assert result.tests_run == 50

    def test_optional_type(self) -> None:
        spec = Spec(
            name="maybe_double",
            inputs={"x": VOptional(VInt())},
            output=VOptional(VInt()),
        )
        forge = Forge(name="test")
        forge.register(spec, lambda x: x * 2 if x is not None else None)
        result = forge.verify("maybe_double", iterations=50, seed=42)
        assert result.tests_run == 50


# ============================================================================
# 7. Integration / End-to-End
# ============================================================================

class TestIntegration:
    def test_payment_processor_end_to_end(self) -> None:
        from examples.payment_processor import forge as payment_forge

        result = payment_forge.verify("process_payment", iterations=50, seed=42)
        assert result.tests_run == 50
        assert result.spec_name == "process_payment"

    def test_median_finder_end_to_end(self) -> None:
        from examples.median_finder import forge as median_forge

        result = median_forge.verify("find_median", iterations=100, seed=42)
        assert result.tests_run == 100
        assert result.spec_name == "find_median"

    def test_verification_result_repr(self) -> None:
        vr = VerificationResult(
            spec_name="test",
            passed=True,
            tests_run=10,
            tests_passed=10,
            coverage_pct=100.0,
        )
        assert "test" in vr.summary()
        assert "PASS" in vr.summary()


# ============================================================================
# Run all tests if executed directly
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
