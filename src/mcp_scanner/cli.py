"""Command-line interface for the scanner foundation."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .inventory import InventoryError, collect, write_inventory


def build_parser() -> argparse.ArgumentParser:
    """Build the public command-line parser."""
    parser = argparse.ArgumentParser(
        prog="mcp-scanner",
        description="Static scanner for potentially malicious MCP servers.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subcommands = parser.add_subparses(dest="command")

    scan = subcommands.add_parser(
        "scan", help="scan an inventory (available after the Inventory milestone)"
    )
    scan.add_argument(
        "--input",
        metavar="PATH",
        help="reserved for the Inventory output path",
    )

    inventory = subcommands.add_parser(
        "inventory", help="inventory explicit MCP configuration files"
    )
    inventory.add_argument(
        "--config",
        action="append",
        metavar="PATH",
        type=Path,
        required=True,
        help="MCP JSON configuration file; specify once per file",
    )
    inventory.add_argument(
        "--output",
        metavar="PATH",
        type=Path,
        default=Path("inventory.json"),
        help="output artifact path (default: inventory.json)",
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

    if args.command == "inventory":
        try:
            inventory = collect(args.config)
            write_inventory(inventory, args.output)
        except InventoryError as error:
            parser.error(str(error))
        print(f"Wrote {len(inventory['items'])} inventory item(s) to {args.output}")
        return 0

    parser.print_help()
    return 0
