#!/usr/bin/env python3
"""
basic_usage.py — Basic VeriForge verification example.

Usage:
    export VERIFORGE_SECRET="my-secret"
    export VERIFORGE_JWT_SECRET="my-jwt-secret"
    export VERIFORGE_AUDIT_SECRET="my-audit-secret"
    python examples/basic_usage.py
"""

import os
import sys

# Ensure veriforge is importable from the repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from veriforge.engine import VeriForgeEngine
from veriforge.config import SecureConfig


def main() -> int:
    # Initialize configuration (reads env vars)
    config = SecureConfig()
    if errors := config.validate():
        print("Configuration errors:", errors)
        return 1

    # Create engine
    engine = VeriForgeEngine(config=config, timeout_seconds=10)

    # Sample Python code to verify
    source_code = """
def calculate_sum(numbers):
    total = 0
    for n in numbers:
        total += n
    return total

result = calculate_sum([1, 2, 3, 4, 5])
print(result)
"""

    # Run verification
    print("Running VeriForge verification...")
    result = engine.verify_code(source_code, filename="example.py")

    print(f"\nSource: {result.source}")
    print(f"Verified: {result.verified}")
    print(f"Findings: {result.findings}")
    print(f"Execution time: {result.execution_time_ms} ms")
    print(f"HMAC signature: {result.hmac_signature[:16]}...")

    # Verify HMAC signature
    assert result.verify_hmac(config.secret_key), "HMAC verification failed!"
    print("HMAC signature: VALID")

    # Verify code with a security issue
    print("\n--- Testing dangerous code detection ---")
    bad_code = "eval(user_input)"
    bad_result = engine.verify_code(bad_code, filename="bad.py")
    print(f"Bad code verified: {bad_result.verified}")
    print(f"Findings: {bad_result.findings}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
