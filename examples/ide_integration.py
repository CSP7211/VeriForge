#!/usr/bin/env python3
"""
ide_integration.py — IDE path sanitization example.

Demonstrates:
  * Safe path resolution for IDE-opened files
  * Directory traversal blocking
  * Symlink resolution
  * Allow-list enforcement

Usage:
    export VERIFORGE_SECRET="my-secret"
    export VERIFORGE_JWT_SECRET="my-jwt-secret"
    export VERIFORGE_AUDIT_SECRET="my-audit-secret"
    python examples/ide_integration.py
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from veriforge.ide import IDEVerifier, PathSanitizationError


def main() -> int:
    # Create a safe working directory
    with tempfile.TemporaryDirectory() as safe_dir:
        # Create a test file in the safe directory
        test_file = os.path.join(safe_dir, "user_script.py")
        with open(test_file, "w") as f:
            f.write("def hello():\n    print('Hello, world!')\n")

        # Create verifier with allow-list
        verifier = IDEVerifier(allowed_base_dirs=[safe_dir])

        # 1. Safe path verification
        print("=== Safe Path Verification ===")
        try:
            result = verifier.ide_verify(test_file)
            print(f"File: {test_file}")
            print(f"Verified: {result.verified}")
            print(f"Findings: {result.findings}")
        except PathSanitizationError as exc:
            print(f"Blocked: {exc}")

        # 2. Directory traversal attempt (BLOCKED)
        print("\n=== Directory Traversal Blocked ===")
        try:
            verifier.ide_verify(os.path.join(safe_dir, "../../../etc/passwd"))
            print("ERROR: Should have been blocked!")
            return 1
        except PathSanitizationError as exc:
            print(f"Correctly blocked: {exc}")

        # 3. Null byte injection (BLOCKED)
        print("\n=== Null Byte Injection Blocked ===")
        try:
            verifier.ide_verify(test_file + "\x00.py")
            print("ERROR: Should have been blocked!")
            return 1
        except PathSanitizationError as exc:
            print(f"Correctly blocked: {exc}")

        # 4. Unsafe shell characters (BLOCKED)
        print("\n=== Unsafe Characters Blocked ===")
        try:
            verifier.ide_verify(os.path.join(safe_dir, "file; rm -rf /"))
            print("ERROR: Should have been blocked!")
            return 1
        except PathSanitizationError as exc:
            print(f"Correctly blocked: {exc}")

        # 5. Outside allow-list (BLOCKED)
        print("\n=== Outside Allow-List Blocked ===")
        try:
            verifier.ide_verify("/etc/hosts")
            print("ERROR: Should have been blocked!")
            return 1
        except PathSanitizationError as exc:
            print(f"Correctly blocked: {exc}")

        # 6. Quick syntax check
        print("\n=== Quick Syntax Check ===")
        syntax_result = verifier.quick_check(test_file)
        print(f"Path: {syntax_result['path']}")
        print(f"Valid: {syntax_result['valid']}")
        print(f"Errors: {syntax_result['errors']}")

        # 7. is_safe_path check
        print("\n=== Path Safety Checks ===")
        print(f"safe path: {verifier.is_safe_path(test_file)}")
        print(f"traversal: {verifier.is_safe_path('../etc/passwd')}")
        print(f"null byte: {verifier.is_safe_path('file\x00.txt')}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
