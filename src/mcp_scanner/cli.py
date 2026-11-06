"""Command-line interface for the scanner foundation."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    """Build the public command-line parser."""
    parser = argparse.ArgumentParser(
        prog="mcp-scanner",
        description="Static scanner for potentially malicious MCP servers.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subcommands = parser.add_subparsers(dest="command")

    scan = subcommands.add_parser(
        "scan", help="scan an inventory (available after the Inventory milestone)"
    )
    scan.add_argument(
        "--input",
        metavar="PATH",
        help="reserved for the Inventory output path",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        parser.error(
            "scan is unavailable: inventory collection has not been implemented yet"
        )

    parser.print_help()
    return 0
