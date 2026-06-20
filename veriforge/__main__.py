"""
VeriForge CLI entry point.

Usage:
    python -m veriforge verify <file.py>
    python -m veriforge audit-log
    python -m veriforge version
"""

from __future__ import annotations

import argparse
import pathlib
import sys

from veriforge.config import SecureConfig
from veriforge.engine import VeriForgeEngine
from veriforge.semantic import SemanticAnalyzer
from veriforge.compliance import SOC2Auditor, ISO27001Auditor, PCIDSSAuditor
from veriforge.report import ReportGenerator


def _build_engine() -> VeriForgeEngine:
    config = SecureConfig()
    secret = config.secret_key or "dev-secret"
    compliance = [
        SOC2Auditor(),
        ISO27001Auditor(),
        PCIDSSAuditor(),
    ]
    return VeriForgeEngine(
        secret=secret,
        semantic=SemanticAnalyzer(),
        compliance_auditors=compliance,
    )


def _cmd_verify(args: argparse.Namespace) -> int:
    path = pathlib.Path(args.file)
    if not path.is_file():
        print(f"File not found", file=sys.stderr)
        return 1

    engine = _build_engine()
    source = path.read_text(encoding="utf-8")
    result = engine.verify_code(source, filename=str(path))

    report = ReportGenerator.export_result(result)
    print(report)

    return 0 if result.passed else 1


def _cmd_audit_log(_args: argparse.Namespace) -> int:
    print("Audit log viewer — implement as needed")
    return 0


def _cmd_version(_args: argparse.Namespace) -> int:
    from veriforge import __version__

    print(f"VeriForge {__version__}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="veriforge",
        description="VeriForge Hardened Code Verification Platform",
    )
    sub = parser.add_subparsers(dest="command")

    verify_parser = sub.add_parser("verify", help="Verify a Python file")
    verify_parser.add_argument("file", help="Path to the Python file")

    sub.add_parser("audit-log", help="View audit log")
    sub.add_parser("version", help="Show version")

    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0

    commands = {
        "verify": _cmd_verify,
        "audit-log": _cmd_audit_log,
        "version": _cmd_version,
    }
    handler = commands.get(args.command, lambda _: parser.print_help() or 0)
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
