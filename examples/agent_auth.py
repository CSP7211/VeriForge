#!/usr/bin/env python3
"""
agent_auth.py — Agent authentication and authorization example.

Demonstrates:
  * Agent registration with JWT token issuance
  * Authenticated code verification
  * RBAC permission enforcement
  * Rate limiting
  * Agent revocation

Usage:
    export VERIFORGE_SECRET="my-secret"
    export VERIFORGE_JWT_SECRET="my-jwt-secret"
    export VERIFORGE_AUDIT_SECRET="my-audit-secret"
    python examples/agent_auth.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from veriforge.agent import AgentVerifier
from veriforge.auth import AuthManager, Role


def main() -> int:
    auth = AuthManager(
        jwt_secret=os.environ.get("VERIFORGE_JWT_SECRET", "demo-jwt-secret"),
        rate_limit_max=100,
        rate_limit_window=60,
    )
    verifier = AgentVerifier(auth=auth)

    # 1. Register an agent with SCANNER role
    print("=== Agent Registration ===")
    agent_token = verifier.register_agent("agent-42", role=Role.SCANNER)
    print(f"Agent registered. Token: {agent_token[:40]}...")

    # 2. Verify code with the agent token
    print("\n=== Authenticated Verification ===")
    source = "x = 1 + 2\n"
    result = verifier.verify(agent_token, source, filename="agent_test.py")
    print(f"Verified: {result.verified}")
    print(f"Findings: {result.findings}")

    # 3. Attempt with VIEWER role (should fail — no scan permission)
    print("\n=== RBAC Enforcement ===")
    viewer_token = verifier.register_agent("viewer-1", role=Role.VIEWER)
    try:
        verifier.verify(viewer_token, "x = 1\n")
        print("ERROR: Should have been rejected!")
        return 1
    except Exception as exc:
        print(f"Correctly denied: {type(exc).__name__}: {exc}")

    # 4. Attempt with invalid token
    print("\n=== Invalid Token Rejection ===")
    try:
        verifier.verify("totally-invalid-token", "x = 1\n")
        print("ERROR: Should have been rejected!")
        return 1
    except Exception as exc:
        print(f"Correctly rejected: {type(exc).__name__}: {exc}")

    # 5. Revoke the agent (admin action)
    print("\n=== Agent Revocation ===")
    admin_token = verifier.register_agent("admin-1", role=Role.ADMIN)
    verifier.revoke_agent(admin_token, "agent-42")
    print("Agent-42 has been revoked.")

    # 6. Show audit log
    print("\n=== Audit Log ===")
    entries = verifier.audit.export_entries()
    for entry in entries:
        print(f"  [{entry['index']}] {entry['action']} by {entry['subject']}: {entry['detail']}")

    chain_valid = verifier.audit.verify_chain()
    print(f"\nAudit chain integrity: {'VALID' if chain_valid else 'INVALID'}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
