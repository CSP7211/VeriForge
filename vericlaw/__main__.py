"""vericlaw/__main__.py — CLI entry point for VeriClaw.

Usage::

    python -m vericlaw scan --target myapp.py
    python -m vericlaw red-team --target myapp.py --rounds 5
    python -m vericlaw certify --target myapp.py
    python -m vericlaw gate --target . --policy strict
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .certifier import SecurityCertifier
from .ci import PolicyEngine
from .engine import VeriClawEngine


def _ensure_secrets() -> None:
    """Warn if VERIFORGE_SECRET_KEY is not set."""
    if not os.environ.get("VERIFORGE_SECRET_KEY"):
        print(
            "WARNING: VERIFORGE_SECRET_KEY not set. "
            "Certificates will use a default key.",
            file=sys.stderr,
        )


def cmd_scan(args: argparse.Namespace) -> int:
    """Run a full adversarial scan."""
    _ensure_secrets()
    engine = VeriClawEngine(
        config={"policy_level": args.policy or "standard"}
    )
    target = args.target

    print(f"VeriClaw v{__version__} — Scanning: {target}")
    result = engine.scan(target)

    print(f"\n{'=' * 50}")
    print(f"  Grade: {result.grade}")
    print(f"  Risk Score: {result.risk_score:.1f}/10")
    print(f"  Findings: {len(result.findings)}")
    print(f"  Mutations: {len(result.mutations)}")
    print(f"  Payloads: {len(result.payloads)}")
    print(f"  Proofs: {len(result.proofs)}")
    print(f"{'=' * 50}")

    if result.findings:
        print("\n--- Findings ---")
        for f in sorted(
            result.findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4)
        ):
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(f.severity, "⚪")
            print(f"  {icon} [{f.severity.upper()}] {f.title}")
            print(f"     CWE-{f.cwe_id or 'N/A'} | {f.description[:80]}")

    if args.output:
        output_path = Path(args.output)
        if args.format == "json":
            output_path.write_text(
                json.dumps(
                    {
                        "grade": result.grade,
                        "risk_score": result.risk_score,
                        "findings": [
                            {
                                "id": f.id,
                                "title": f.title,
                                "severity": f.severity,
                                "cwe_id": f.cwe_id,
                                "description": f.description,
                            }
                            for f in result.findings
                        ],
                    },
                    indent=2,
                )
            )
        elif args.format == "html":
            from .report import ReportGenerator
            report = ReportGenerator()
            output_path.write_text(report.generate_html(result))
        elif args.format == "sarif":
            from .report import ReportGenerator
            report = ReportGenerator()
            output_path.write_text(json.dumps(report.generate_sarif(result), indent=2))
        print(f"\nOutput written to: {output_path}")

    return 0 if result.grade in ("A+", "A", "B") else 1


def cmd_red_team(args: argparse.Namespace) -> int:
    """Run an autonomous red team simulation."""
    _ensure_secrets()
    engine = VeriClawEngine()
    target = args.target
    rounds = args.rounds or 5

    print(f"VeriClaw v{__version__} — Red Team: {target} ({rounds} rounds)")
    result = engine.red_team(target, rounds=rounds)

    print(f"\n{'=' * 50}")
    print(f"  Status: {result.rounds} rounds completed")
    print(f"  Findings: {len(result.findings)}")
    print(f"  Success Rate: {result.success_rate:.0%}")
    print(f"{'=' * 50}")

    if result.attack_chain:
        print("\n--- Attack Chain ---")
        for i, step in enumerate(result.attack_chain, 1):
            print(f"  {i}. [{step.get('phase', '?')}] {step.get('finding', 'Unknown')}")
            if step.get("next_steps"):
                print(f"     → Next: {', '.join(step['next_steps'])}")

    return 0


def cmd_certify(args: argparse.Namespace) -> int:
    """Generate a security certificate."""
    _ensure_secrets()
    engine = VeriClawEngine()
    target = args.target

    print(f"VeriClaw v{__version__} — Certifying: {target}")
    cert = engine.certify(target)

    print(f"\n{'=' * 50}")
    print(f"  Certificate for: {cert.target}")
    print(f"  Grade: {cert.grade}")
    print(f"  Risk Score: {cert.risk_score:.1f}/10")
    print(f"  Issued: {cert.timestamp}")
    print(f"  Expires: {cert.expires}")
    print(f"  Signature: {cert.signature[:16]}...")
    print(f"{'=' * 50}")

    certifier = SecurityCertifier()
    verified = certifier.verify(cert)
    print(f"\nSignature verification: {'✅ VALID' if verified else '❌ INVALID'}")

    if args.output:
        from .report import ReportGenerator
        report = ReportGenerator()
        html = report.render_certificate(cert)
        Path(args.output).write_text(html)
        print(f"Certificate HTML written to: {args.output}")

    return 0 if verified else 1


def cmd_gate(args: argparse.Namespace) -> int:
    """CI/CD security gate."""
    _ensure_secrets()
    engine = VeriClawEngine()
    policy = PolicyEngine(level=args.policy or "standard")
    target = args.target

    print(f"VeriClaw v{__version__} — Security Gate ({args.policy or 'standard'})")
    result = engine.scan(target)
    decision = policy.check(result)

    print(f"\n{'=' * 50}")
    print(f"  Decision: {decision.decision.upper()}")
    print(f"  Grade: {result.grade}")
    print(f"  Risk Score: {result.risk_score:.1f}/10")
    print(f"{'=' * 50}")

    if decision.violations:
        print("\n--- Violations ---")
        for v in decision.violations:
            print(f"  ❌ {v}")

    if decision.recommendations:
        print("\n--- Recommendations ---")
        for r in decision.recommendations:
            print(f"  💡 {r}")

    return 0 if decision.passed else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vericlaw",
        description="VeriClaw — Adversarial Security Testing Framework",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    scan_parser = sub.add_parser("scan", help="Run adversarial scan")
    scan_parser.add_argument("--target", required=True, help="File or directory to scan")
    scan_parser.add_argument("--format", choices=["json", "html", "sarif"], default="json")
    scan_parser.add_argument("--output", "-o", help="Output file path")
    scan_parser.add_argument("--policy", choices=["strict", "standard", "permissive"])
    scan_parser.set_defaults(func=cmd_scan)

    # red-team
    rt_parser = sub.add_parser("red-team", help="Run red team simulation")
    rt_parser.add_argument("--target", required=True)
    rt_parser.add_argument("--rounds", type=int, default=5)
    rt_parser.set_defaults(func=cmd_red_team)

    # certify
    cert_parser = sub.add_parser("certify", help="Generate security certificate")
    cert_parser.add_argument("--target", required=True)
    cert_parser.add_argument("--output", "-o", help="Output HTML file")
    cert_parser.set_defaults(func=cmd_certify)

    # gate
    gate_parser = sub.add_parser("gate", help="CI/CD security gate")
    gate_parser.add_argument("--target", required=True)
    gate_parser.add_argument("--policy", choices=["strict", "standard", "permissive"], default="standard")
    gate_parser.set_defaults(func=cmd_gate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
