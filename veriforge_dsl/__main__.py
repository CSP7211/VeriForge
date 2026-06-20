"""
VeriForge DSL -- CLI entry point.

Usage::

    python -m veriforge_dsl --help
    python -m veriforge_dsl --describe examples.payment_processor
    python -m veriforge_dsl --verify examples.median_finder --iterations 500
"""

from __future__ import annotations

import argparse
import importlib
import sys


def _load_forge(dotted_path: str):
    """Import a module and return its ``forge`` object."""
    module = importlib.import_module(dotted_path)
    forge = getattr(module, "forge", None)
    if forge is None:
        print(f"ERROR: module '{dotted_path}' has no 'forge' object", file=sys.stderr)
        sys.exit(1)
    return forge


def cmd_describe(args: argparse.Namespace) -> int:
    forge = _load_forge(args.module)
    print(forge.describe())
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    forge = _load_forge(args.module)
    if args.spec:
        result = forge.verify(args.spec, iterations=args.iterations, seed=args.seed)
        print(result.summary())
        return 0 if result.passed else 1
    else:
        all_passed = True
        for result in forge.verify_all(iterations=args.iterations, seed=args.seed):
            print(result.summary())
            print()
            if not result.passed:
                all_passed = False
        return 0 if all_passed else 1


def cmd_list_specs(args: argparse.Namespace) -> int:
    forge = _load_forge(args.module)
    for name in forge.specs:
        print(name)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="veriforge_dsl",
        description="VeriForge DSL -- Formal specification language CLI",
    )
    sub = parser.add_subparsers(dest="command")

    # describe
    p_desc = sub.add_parser("describe", help="Show forge description")
    p_desc.add_argument("module", help="Dotted path to module containing forge")
    p_desc.set_defaults(func=cmd_describe)

    # verify
    p_ver = sub.add_parser("verify", help="Run verification on a forge")
    p_ver.add_argument("module", help="Dotted path to module containing forge")
    p_ver.add_argument("--spec", "-s", default=None, help="Specific spec to verify")
    p_ver.add_argument("--iterations", "-n", type=int, default=100, help="Number of iterations")
    p_ver.add_argument("--seed", type=int, default=None, help="Random seed")
    p_ver.set_defaults(func=cmd_verify)

    # list
    p_list = sub.add_parser("list", help="List specs in a forge")
    p_list.add_argument("module", help="Dotted path to module containing forge")
    p_list.set_defaults(func=cmd_list_specs)

    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
