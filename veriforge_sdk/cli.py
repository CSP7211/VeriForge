"""Command-line interface (CLI) entry point for the VeriForge SDK.

The CLI exposes several subcommands that interact with the VeriForge platform::

    veriforge-sdk health       Show health status of all products
    veriforge-sdk scan <tgt>   Run a security scan against *target*
    veriforge-sdk products     List available products
    veriforge-sdk version      Show the SDK version

All commands print JSON-formatted output to stdout.
"""

import argparse
import json
import sys
from typing import List, Optional, Sequence

from .client import VeriForgeClient
from .version import __version__


def _build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="veriforge-sdk",
        description="VeriForge SDK — command-line interface for the VeriForge security platform.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s health
  %(prog)s scan https://example.com
  %(prog)s products
  %(prog)s version""",
    )
    parser.add_argument(
        "--api-key",
        dest="api_key",
        default=None,
        help="VeriForge API key (falls back to VERIFORGE_API_KEY env var)",
    )
    parser.add_argument(
        "--base-url",
        dest="base_url",
        default=None,
        help="Override the default VeriForge API base URL",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose (debug) logging",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # health
    health_parser = subparsers.add_parser(
        "health",
        help="Show health status of all products",
        description="Query the health status for every registered product.",
    )
    health_parser.set_defaults(func=_cmd_health)

    # scan
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run a security scan against a target",
        description="Initiate a security scan on the given target.",
    )
    scan_parser.add_argument(
        "target",
        metavar="TARGET",
        help="URL, domain, or IP address to scan",
    )
    scan_parser.add_argument(
        "--product",
        dest="product",
        default=None,
        help="Specific product to use for the scan (default: all enabled products)",
    )
    scan_parser.set_defaults(func=_cmd_scan)

    # products
    products_parser = subparsers.add_parser(
        "products",
        help="List available products",
        description="Retrieve the list of products available to the authenticated account.",
    )
    products_parser.set_defaults(func=_cmd_products)

    # version
    version_parser = subparsers.add_parser(
        "version",
        help="Show the SDK version",
        description="Display the currently installed SDK version.",
    )
    version_parser.set_defaults(func=_cmd_version)

    return parser


def _new_client(args: argparse.Namespace) -> VeriForgeClient:
    """Instantiate a :class:`VeriForgeClient` from parsed CLI arguments."""
    return VeriForgeClient(
        api_key=args.api_key,
        base_url=args.base_url,
    )


def _cmd_health(args: argparse.Namespace) -> int:
    """Handle the ``health`` subcommand."""
    client = _new_client(args)
    result = client.health()
    print(json.dumps(result, indent=2, default=str))
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    """Handle the ``scan`` subcommand."""
    client = _new_client(args)
    result = client.scan(
        target=args.target,
        product=args.product,
    )
    print(json.dumps(result, indent=2, default=str))
    return 0


def _cmd_products(args: argparse.Namespace) -> int:
    """Handle the ``products`` subcommand."""
    client = _new_client(args)
    result = client.products()
    print(json.dumps(result, indent=2, default=str))
    return 0


def _cmd_version(args: argparse.Namespace) -> int:
    """Handle the ``version`` subcommand."""
    print(json.dumps({"version": __version__}, indent=2))
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Main entry point for the CLI.

    Args:
        argv: Command-line arguments.  When *None*, ``sys.argv[1:]`` is used.

    Returns:
        Exit code (``0`` on success, non-zero on error).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        import logging
        from .utils import get_logger

        get_logger("veriforge_sdk", level="debug")
        # Also enable urllib3 / requests debug output
        logging.getLogger("urllib3").setLevel(logging.DEBUG)

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    try:
        return args.func(args)
    except Exception as exc:
        error_payload = {
            "error": type(exc).__name__,
            "message": str(exc),
        }
        print(json.dumps(error_payload, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
