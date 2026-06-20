"""
VeriForge CLI — Command-line interface for the verification engine.

Subcommands:
    scan       Run formal verification on a file or directory
    audit      Query or export the immutable audit log
    dashboard  Start the monitoring dashboard server
"""

import argparse
import sys
import json

from .engine import VeriForgeEngine
from .audit import ImmutableAuditLog
from .config import SecureConfig


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="veriforge",
        description="VeriForge — Hardened Formal Verification Platform",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # ---- scan ----
    scan_cmd = sub.add_parser("scan", help="Verify source files")
    scan_cmd.add_argument("path", help="File or directory to verify")
    scan_cmd.add_argument("--output", "-o", default=None, help="Output JSON file")
    scan_cmd.add_argument("--timeout", type=int, default=30, help="Timeout in seconds")

    # ---- audit ----
    audit_cmd = sub.add_parser("audit", help="Query the audit log")
    audit_cmd.add_argument("--export", default=None, help="Export audit log to file")
    audit_cmd.add_argument("--verify-chain", action="store_true", help="Verify HMAC chain integrity")

    # ---- dashboard ----
    sub.add_parser("dashboard", help="Start monitoring dashboard")

    args = parser.parse_args()

    if args.command == "scan":
        return _cmd_scan(args)
    elif args.command == "audit":
        return _cmd_audit(args)
    elif args.command == "dashboard":
        print("Dashboard server starting on http://127.0.0.1:8080")
        return 0
    else:
        parser.print_help()
        return 1


def _cmd_scan(args: argparse.Namespace) -> int:
    """Execute the scan subcommand."""
    import os

    if not os.path.exists(args.path):
        print(f"Error: path not found: {args.path}", file=sys.stderr)
        return 1

    config = SecureConfig()
    engine = VeriForgeEngine(config=config, timeout_seconds=args.timeout)

    if os.path.isfile(args.path):
        results = [engine.verify_file(args.path)]
    else:
        results = engine.verify_directory(args.path)

    summary = {
        "scanned": len(results),
        "verified": sum(1 for r in results if r.verified),
        "failed": sum(1 for r in results if not r.verified),
        "results": [r.to_dict() for r in results],
    }

    print(json.dumps(summary, indent=2))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"\nReport written to {args.output}")

    return 0 if summary["failed"] == 0 else 1


def _cmd_audit(args: argparse.Namespace) -> int:
    """Execute the audit subcommand."""
    config = SecureConfig()
    audit_log = ImmutableAuditLog(secret=config.audit_secret)

    if args.verify_chain:
        valid = audit_log.verify_chain()
        print(f"Audit chain integrity: {'VALID' if valid else 'INVALID'}")
        return 0 if valid else 1

    entries = audit_log.export_entries()
    print(f"Audit log contains {len(entries)} entries")

    if args.export:
        with open(args.export, "w") as f:
            json.dump(entries, f, indent=2, default=str)
        print(f"Exported to {args.export}")
    else:
        for entry in entries:
            print(json.dumps(entry, indent=2, default=str))

    return 0


if __name__ == "__main__":
    sys.exit(main())
