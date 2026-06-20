#!/usr/bin/env python3
"""Basic RED scan example.

Demonstrates the simplest possible usage of the VeriForge SDK to
scan a codebase for security issues.

Usage:
    export VERIFORGE_API_KEY="your-key"  # optional, falls back to local mode
    python basic_scan.py /path/to/code
"""

from __future__ import annotations

import sys

from veriforge_sdk import VeriForgeClient


def main(target_path: str) -> int:
    """Run a RED scan on *target_path* and print findings."""
    client = VeriForgeClient()
    result = client.red.scan(target_path)

    print(f"=== RED Scan Results ===")
    print(f"Target:   {result.target}")
    print(f"Grade:    {result.grade.value}")
    print(f"Scan ID:  {result.scan_id}")
    print(f"Duration: {result.duration_ms:.1f} ms")
    print(f"Findings: {len(result.findings)}")
    print()

    if not result.findings:
        print("No findings -- great job!")
        return 0

    for finding in result.findings:
        print(f"  [{finding.severity.value.upper():8}] {finding.title}")
        if finding.file_path:
            print(f"           Location: {finding.file_path}:{finding.line_start}")
        if finding.category:
            print(f"           Category: {finding.category}")
        if finding.remediation:
            print(f"           Fix:      {finding.remediation}")
        print()

    # Return non-zero if critical findings exist
    return 1 if result.has_critical else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path-to-code>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
