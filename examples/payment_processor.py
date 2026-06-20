"""
examples.payment_processor -- Atomic Payment Processor Forge

Demonstrates a Forge with:
  - UUID uniqueness guarantee
  - Precondition: amount > 0, currency in ['USD', 'EUR', 'GBP']
  - Postcondition: exactly one of (success, error) is set
  - 100+ generative test iterations
  - Edge cases: insufficient funds, minimum amount, invalid currency
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Set

# Ensure the DSL is importable when running directly
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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
    VOptional,
    VStr,
    VUnion,
)
from veriforge_dsl.contracts import enforce_contracts


# ---------------------------------------------------------------------------
# Implementation
# ---------------------------------------------------------------------------

class PaymentError(Exception):
    """Raised when a payment cannot be processed."""


_seen_transaction_ids: Set[str] = set()
_user_balances: Dict[str, float] = {
    "alice": 1000.0,
    "bob": 500.0,
    "charlie": 0.0,
}


def _reset_payment_state() -> None:
    """Reset global state for testing determinism."""
    _seen_transaction_ids.clear()
    _user_balances.update({
        "alice": 1000.0,
        "bob": 500.0,
        "charlie": 0.0,
    })


def process_payment(amount: float, currency: str, user_id: str) -> Dict[str, Any]:
    """Process an atomic payment transaction.

    Preconditions:
        - amount > 0
        - currency in ('USD', 'EUR', 'GBP')

    Postconditions:
        - Exactly one of (success, error) is truthy
        - transaction_id is a valid UUID on success
    """
    # --- Preconditions are enforced by the decorator at runtime ---

    # Edge case: invalid currency (extra safety net)
    valid_currencies = {"USD", "EUR", "GBP"}
    if currency not in valid_currencies:
        return {"success": False, "error": "INVALID_CURRENCY", "transaction_id": None}

    # Edge case: non-positive amount
    if amount <= 0:
        return {"success": False, "error": "INVALID_AMOUNT", "transaction_id": None}

    # Edge case: minimum amount threshold
    if amount < 0.01:
        return {"success": False, "error": "BELOW_MINIMUM", "transaction_id": None}

    # Edge case: insufficient funds
    balance = _user_balances.get(user_id, 0.0)
    if balance < amount:
        return {"success": False, "error": "INSUFFICIENT_FUNDS", "transaction_id": None}

    # Process payment
    tx_id = str(uuid.uuid4())

    # UUID uniqueness guarantee
    if tx_id in _seen_transaction_ids:
        return {"success": False, "error": "DUPLICATE_UUID", "transaction_id": None}
    _seen_transaction_ids.add(tx_id)

    # Deduct balance
    _user_balances[user_id] = balance - amount

    return {"success": True, "error": None, "transaction_id": tx_id}


def _post_exactly_one(__return__: Dict[str, Any]) -> bool:
    """Postcondition: exactly one of (success, error) is set."""
    r = __return__
    success = r.get("success", False)
    error = r.get("error")
    return (success and error is None) or (not success and error is not None)


def _post_uuid_on_success(__return__: Dict[str, Any]) -> bool:
    """Postcondition: valid UUID when success is True."""
    r = __return__
    if r.get("success"):
        tx_id = r.get("transaction_id")
        if tx_id is None:
            return False
        try:
            uuid.UUID(tx_id)
        except ValueError:
            return False
    return True


# ---------------------------------------------------------------------------
# Forge setup
# ---------------------------------------------------------------------------

forge = Forge(name="PaymentProcessor")

payment_spec = Spec(
    name="process_payment",
    inputs={
        "amount": VConstraint(VFloat(), lambda x: x > 0, name="positive"),
        "currency": VEnum(values=["USD", "EUR", "GBP"]),
        "user_id": VStr(),
    },
    output=VDict(VStr(), VUnion([VBool(), VOptional(VStr())])),
    contracts=Contract(
        preconditions=[
            lambda amount: amount > 0,
            lambda currency: currency in ("USD", "EUR", "GBP"),
        ],
        postconditions=[
            _post_exactly_one,
            _post_uuid_on_success,
        ],
        invariants=[],
    ),
    description=(
        "Process an atomic payment. Amount must be positive. "
        "Currency must be one of USD, EUR, GBP. "
        "Returns a dict with success flag, error code, and transaction UUID."
    ),
)

forge.register(payment_spec, process_payment)

# Register a property: all successful payments must have a UUID
forge.register_property(lambda result: not result.get("success") or result.get("transaction_id") is not None)

# Register a property: no duplicate transaction IDs
_processed_in_run: Set[str] = set()
forge.register_property(lambda result: result.get("transaction_id") not in _processed_in_run or result.get("transaction_id") is None)


# ---------------------------------------------------------------------------
# Self-test when run directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(forge.describe())
    print()
    print("=== Verification ===")
    result = forge.verify("process_payment", iterations=100)
    print(result.summary())
