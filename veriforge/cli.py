import sys
import argparse
import json
from .engine import VeriForgeEngine
from .config import SecureConfig
from .audit import ImmutableAuditLog
from .report import ReportGenerator

def main():
    parser = argparse.ArgumentParser(prog="veriforge", description="VeriForge Red CLI")
    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="Scan a file or directory")
    scan.add_argument("path", help="File or directory to scan")
    scan.add_argument("--output", "-o", help="Output JSON file")
    audit_cmd = sub.add_parser("audit", help="Audit log operations")
    audit_cmd.add_argument("--verify-chain", action="store_true", help="Verify chain integrity")
    audit_cmd.add_argument("--export", help="Export audit log to file")
    args = parser.parse_args()
    if args.command == "scan":
        config = SecureConfig()
        engine = VeriForgeEngine(config)
        with open(args.path, "r") as f:
            code = f.read()
        result = engine.verify_code(code)
        report = ReportGenerator().generate(result)
        out = json.dumps(report, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(out)
        print(out)
    elif args.command == "audit":
        config = SecureConfig()
        audit = ImmutableAuditLog(config)
        if args.verify_chain:
            ok = audit.verify_chain()
            print(f"Chain integrity: {'PASS' if ok else 'FAIL'}")
        if args.export:
            with open(args.export, "w") as f:
                json.dump(audit.export(), f, indent=2)
            print(f"Audit exported to {args.export}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
