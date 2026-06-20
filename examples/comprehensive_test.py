#!/usr/bin/env python3
"""Comprehensive example using all 7 VeriForge products.

This script demonstrates every product in the VeriForge platform
through a single unified client.

Usage:
    export VERIFORGE_API_KEY="your-key"  # optional
    python comprehensive_test.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from veriforge_sdk import VeriForgeClient


def demo_red_scan(client: VeriForgeClient) -> None:
    """1. RED -- Security code scan."""
    print("\n" + "=" * 60)
    print("1. RED -- Security Code Scanner")
    print("=" * 60)

    # Create a temporary file with some suspicious code
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("# Sample file for scanning\n")
        f.write("import os\n")
        f.write("password = 'secret123'\n")
        f.write("result = eval(user_input)\n")
        f.write("data = query.execute(\"SELECT * FROM users WHERE id = \" + user_id)\n")
        temp_path = f.name

    result = client.red.scan(temp_path)

    print(f"  Target:   {result.target}")
    print(f"  Grade:    {result.grade.value}")
    print(f"  Findings: {len(result.findings)}")
    for finding in result.findings:
        print(f"    [{finding.severity.value}] {finding.title}")
    print(f"  Fingerprint: {result.fingerprint}")

    Path(temp_path).unlink(missing_ok=True)


def demo_vericlaw_test(client: VeriForgeClient) -> None:
    """2. VeriClaw -- Automated testing."""
    print("\n" + "=" * 60)
    print("2. VeriClaw -- Test Generation & Execution")
    print("=" * 60)

    result = client.vericlaw.test("./tests", coverage=True)

    print(f"  Test ID:      {result.test_id}")
    print(f"  Total:        {result.total}")
    print(f"  Passed:       {result.passed}")
    print(f"  Failed:       {result.failed}")
    print(f"  Skipped:      {result.skipped}")
    print(f"  Coverage:     {result.coverage_percent:.1f}%")
    print(f"  Success Rate: {result.success_rate:.1%}")
    print(f"  OK:           {result.ok}")


def demo_dsl_verify(client: VeriForgeClient) -> None:
    """3. DSL Verify -- Policy validation."""
    print("\n" + "=" * 60)
    print("3. DSL Verify -- Policy & Config Validation")
    print("=" * 60)

    # Create a temporary config file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("database:\n")
        f.write("  host: localhost\n")
        f.write("  port: 5432\n")
        f.write("  password: 'db_secret_123'\n")  # Intentional issue
        f.write("  url: http://api.example.com\n")  # Intentional issue
        temp_path = f.name

    result = client.dsl.verify(temp_path, rules="security.rules")

    print(f"  Verified:      {result.verified}")
    print(f"  Rules checked: {result.rules_checked}")
    print(f"  Rules passed:  {result.rules_passed}")
    print(f"  Rules failed:  {result.rules_failed}")
    for violation in result.violations:
        print(f"    [VIOLATION] {violation}")

    Path(temp_path).unlink(missing_ok=True)


def demo_mcp_tools(client: VeriForgeClient) -> None:
    """4. MCP Tools -- Sandboxed tool invocation."""
    print("\n" + "=" * 60)
    print("4. MCP Tools -- Sandboxed Tool Invocation")
    print("=" * 60)

    result = client.mcp.call_tool("git.status", {"path": "/repo"})

    print(f"  Tool:      {result.tool_name}")
    print(f"  Exit Code: {result.exit_code}")
    print(f"  Success:   {result.success}")
    print(f"  Duration:  {result.duration_ms:.1f} ms")
    print(f"  Output:    {result.output}")
    if result.stdout:
        print(f"  Stdout:\n{result.stdout}")


def demo_swarm_consensus(client: VeriForgeClient) -> None:
    """5. Swarm -- Distributed consensus."""
    print("\n" + "=" * 60)
    print("5. Swarm -- Distributed Consensus")
    print("=" * 60)

    result = client.swarm.consensus(
        topic="deploy-v2",
        proposal="Approve deployment of v2.0.0",
        quorum=3,
    )

    print(f"  Reached:   {result.reached}")
    print(f"  Outcome:   {result.outcome}")
    print(f"  Quorum:    {result.quorum}")
    print(f"  Votes:     {result.votes}")
    print(f"  Agreement: {result.agreement_ratio:.1%}")
    print(f"  Confidence:{result.confidence.value}")


def demo_core_compliance(client: VeriForgeClient) -> None:
    """6. Core -- Compliance audit."""
    print("\n" + "=" * 60)
    print("6. Core -- Compliance Audit")
    print("=" * 60)

    result = client.core.audit_compliance("SOC2")

    print(f"  Standard: {result.standard}")
    print(f"  Compliant:{result.compliant}")
    print(f"  Score:    {result.score}%")
    for ctrl in result.controls:
        status = "PASS" if ctrl.passed else "FAIL"
        print(f"    [{status}] {ctrl.control_id}: {ctrl.title}")
        if ctrl.evidence:
            print(f"         Evidence: {ctrl.evidence}")
        if not ctrl.passed and ctrl.remediation:
            print(f"         Fix: {ctrl.remediation}")

    # Sign and verify the result
    signed = client.core.sign_result(result)
    print(f"\n  Signed payload:")
    print(f"    Algorithm:  {signed.algorithm}")
    print(f"    Signature:  {signed.signature[:32]}...")
    print(f"    Timestamp:  {signed.timestamp}")

    is_valid = client.core.verify_signature(signed)
    print(f"    Valid:      {is_valid}")


def demo_health(client: VeriForgeClient) -> None:
    """7. Health -- Platform status."""
    print("\n" + "=" * 60)
    print("7. Platform Health Check")
    print("=" * 60)

    health = client.health()

    print(f"  Status:       {health.status}")
    print(f"  Healthy:      {health.healthy}")
    print(f"  Version:      {health.version}")
    print(f"  Uptime:       {health.uptime_seconds:.0f}s")
    for product, status in health.products.items():
        print(f"    {product:12} {status}")


def main() -> int:
    """Run all product demonstrations."""
    print("VeriForge SDK -- Comprehensive Product Demonstration")
    print("Initializing client (local mode if no API key)...")

    client = VeriForgeClient()
    print(f"Client ready: {client}")
    print(f"Products: {', '.join(client.list_products().keys())}")

    demo_red_scan(client)
    demo_vericlaw_test(client)
    demo_dsl_verify(client)
    demo_mcp_tools(client)
    demo_swarm_consensus(client)
    demo_core_compliance(client)
    demo_health(client)

    print("\n" + "=" * 60)
    print("All demonstrations completed successfully!")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
