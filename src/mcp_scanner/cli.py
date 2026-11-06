"""Command-line interface for the scanner foundation."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .semgrep_adapter import scan_code


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

    code = subcommands.add_parser(
        "scan-code", help="scan a local source file or directory with Semgrep"
    )
    code.add_argument("source", type=Path)
    code.add_argument("--rules", type=Path, required=True, help="local YAML ruleset")
    code.add_argument("--server-id", required=True, help="identity of the source MCP server")
    code.add_argument("--semgrep", default="semgrep", help="Semgrep executable name or path")
    code.add_argument("--timeout", type=float, default=60, help="scan timeout in seconds")
    code.add_argument(
        "--windows-temp", type=Path, help="override TMP and TEMP for the Windows child process"
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

    if args.command == "scan-code":
        artifact = scan_code(
            args.source,
            args.rules,
            server_id=args.server_id,
            semgrep=args.semgrep,
            timeout=args.timeout,
            windows_temp=args.windows_temp,
        )
        print(json.dumps(artifact, indent=2))
        return {"complete": 0, "partial": 1, "failed": 2}[artifact["status"]]

    parser.print_help()
    return 0
