"""Command-line interface for mcp-scanner."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .discovery import DiscoveryError, discover, write_discovery
from .inventory import InventoryError, collect, write_inventory
from .models import INPUT_KINDS
from .scanner import DEFAULT_BUDGET_CUTOFF_SECONDS, DEFAULT_HARD_TIMEOUT_SECONDS, run_scan
from .semgrep_adapter import scan_code
from .source_inventory import DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_FILES
from .tui import (
    MAC_SUBTITLE,
    MAC_TAGLINE,
    discover_batch_targets,
    make_stage_progress_callback,
    normalize_user_path,
    render_banner,
    render_batch_list,
    render_batch_summary,
    render_scan_details,
    render_scan_summary,
    run_batch_scan,
    run_interactive_session,
    serialize_batch_report,
)

_SUBCOMMANDS = frozenset({"scan", "inventory", "discover", "scan-code", "snapshot-p", "diff-p-snapshots"})


def build_parser(
    *,
    prog: str = "mcp-scanner",
    default_format: str = "json",
) -> argparse.ArgumentParser:
    """Build the public command-line parser."""
    description = (
        f"MAC ({MAC_TAGLINE}) — {MAC_SUBTITLE}."
        if prog == "mac"
        else "Static scanner for potentially malicious MCP servers."
    )
    parser = argparse.ArgumentParser(
        prog=prog,
        description=description,
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colors in terminal UI output",
    )
    subcommands = parser.add_subparsers(dest="command")

    scan = subcommands.add_parser(
        "scan",
        help="run unified static scan on a snapshot directory or source file (v1.0 JSON report)",
    )
    scan.add_argument(
        "target",
        nargs="?",
        type=Path,
        help="path to local MCP snapshot directory or source file",
    )
    scan.add_argument(
        "--input",
        dest="input_path",
        metavar="PATH",
        type=Path,
        help="alternative flag for the target directory or file path",
    )
    scan.add_argument(
        "--output",
        metavar="PATH",
        type=Path,
        help="write canonical v1.0 JSON report to file",
    )
    scan.add_argument(
        "--format",
        choices=["json", "text"],
        default=default_format,
        help=f"terminal output format (default: {default_format})",
    )
    scan.add_argument(
        "--details",
        action="store_true",
        help="show detailed finding traces and coverage drill-down in text mode",
    )
    scan.add_argument(
        "--batch",
        action="store_true",
        help="scan each child subdirectory as an independent MCP server snapshot",
    )
    scan.add_argument(
        "--single",
        action="store_true",
        help="force scanning target as a single repository without auto-batch detection",
    )
    scan.add_argument(
        "--no-color",
        dest="scan_no_color",
        action="store_true",
        help="disable ANSI colors in terminal UI output",
    )
    p_mode = scan.add_mutually_exclusive_group()
    p_mode.add_argument("--no-p-detector", action="store_true",
                        help="disable P-surface analysis")
    p_mode.add_argument("--strict-p", action="store_true",
                        help="require complete P-surface and relation coverage")
    scan.add_argument("--server-id", help="stable server identifier override")
    scan.add_argument("--source-id", help="upstream source identifier (e.g. github:org/repo)")
    scan.add_argument(
        "--input-kind",
        choices=sorted(INPUT_KINDS),
        help="provenance input kind override",
    )
    scan.add_argument("--revision", help="pinned commit SHA or snapshot revision")
    scan.add_argument("--package-name", help="package name for package_artifact_only inputs")
    scan.add_argument("--package-version", help="package version for package_artifact_only inputs")
    scan.add_argument(
        "--rules",
        action="append",
        type=Path,
        help="local Semgrep YAML rules file (may be repeated; defaults to bundled rules/)",
    )
    scan.add_argument("--semgrep", default="semgrep", help="Semgrep executable name or path")
    scan.add_argument(
        "--windows-temp",
        type=Path,
        help="override TMP and TEMP for the Semgrep child process on Windows",
    )
    scan.add_argument(
        "--no-semgrep",
        action="store_true",
        help="skip Semgrep CE execution (useful for AST-only ablation/testing)",
    )
    scan.add_argument(
        "--no-python-ast",
        action="store_true",
        help="skip Python AST execution (useful for rule-only ablation/testing)",
    )
    scan.add_argument(
        "--osv-db",
        type=Path,
        help="path to pinned offline OSV vulnerability database directory for SCA",
    )
    scan.add_argument(
        "--osv-db-sha256",
        help="expected SHA-256 digest pin for the offline OSV database directory",
    )
    scan.add_argument(
        "--osv-scanner",
        help="optional path to pinned osv-scanner binary (always executed strictly offline)",
    )
    scan.add_argument(
        "--no-sca",
        action="store_true",
        help="disable offline SCA lookup even if MCP_SCANNER_OSV_DB is configured",
    )
    scan.add_argument(
        "--max-files",
        type=int,
        default=DEFAULT_MAX_FILES,
        help=f"maximum source files to inspect (default: {DEFAULT_MAX_FILES})",
    )
    scan.add_argument(
        "--max-file-bytes",
        type=int,
        default=DEFAULT_MAX_FILE_BYTES,
        help=f"maximum size per file in bytes (default: {DEFAULT_MAX_FILE_BYTES})",
    )
    scan.add_argument(
        "--cutoff",
        type=float,
        default=DEFAULT_BUDGET_CUTOFF_SECONDS,
        help=f"analysis cutoff deadline in seconds (default: {DEFAULT_BUDGET_CUTOFF_SECONDS})",
    )
    scan.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_HARD_TIMEOUT_SECONDS,
        help=f"overall hard server timeout cap in seconds (default: {DEFAULT_HARD_TIMEOUT_SECONDS})",
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

    discovery = subcommands.add_parser(
        "discover", help="discover stdio MCP servers from an inventory artifact"
    )
    discovery.add_argument(
        "--input",
        metavar="PATH",
        type=Path,
        required=True,
        help="inventory artifact generated by mcp-scanner inventory",
    )
    discovery.add_argument(
        "--output",
        metavar="PATH",
        type=Path,
        default=Path("discovery.json"),
        help="output artifact path (default: discovery.json)",
    )

    code = subcommands.add_parser(
        "scan-code", help="scan a local source file or directory with Semgrep (v0.1 artifact)"
    )
    code.add_argument("source", type=Path)
    code.add_argument("--rules", type=Path, required=True, help="local YAML ruleset")
    code.add_argument("--server-id", required=True, help="identity of the source MCP server")
    code.add_argument("--semgrep", default="semgrep", help="Semgrep executable name or path")
    code.add_argument("--timeout", type=float, default=60, help="scan timeout in seconds")
    code.add_argument(
        "--windows-temp", type=Path, help="override TMP and TEMP for the Windows child process"
    )
    snapshot = subcommands.add_parser("snapshot-p", help="capture hash-only static P metadata; never start a server")
    snapshot.add_argument("target", type=Path)
    snapshot.add_argument("--server-id", required=True)
    snapshot.add_argument("--protocol-version", required=True)
    snapshot.add_argument("--scope", required=True, help='explicit JSON scope, e.g. {"tenant":"local","transport":"stdio"}')
    snapshot.add_argument("--revision")
    snapshot.add_argument("--approved-by", help="human review attestation; omit until the snapshot has been reviewed")
    snapshot.add_argument("--timeout", type=float, default=60.0)
    snapshot.add_argument("--output", type=Path, required=True)
    diff = subcommands.add_parser("diff-p-snapshots", help="compare reviewed baseline P metadata without replacing it")
    diff.add_argument("baseline", type=Path)
    diff.add_argument("current", type=Path)
    diff.add_argument("--output", type=Path, required=True)
    return parser


def _execute_p_snapshot_command(args, parser):
    from .p_snapshot import capture_p_snapshot, compare_p_snapshots
    try:
        output = args.output.resolve()
        if output.exists():
            raise ValueError("Output already exists; choose a new artifact path.")
        if args.command == "snapshot-p":
            target = args.target.resolve()
            if output == target or target in output.parents:
                raise ValueError("P snapshot output must be outside the source snapshot.")
            result = capture_p_snapshot(
                target, server_id=args.server_id, protocol_version=args.protocol_version,
                scope=json.loads(args.scope), revision=args.revision,
                approved_by=args.approved_by, timeout=args.timeout)
            exit_code = 2 if any(v in {"partial","unmeasured"} for v in result["coverage"].values()) else 0
        else:
            if output in {args.baseline.resolve(),args.current.resolve()}:
                raise ValueError("Diff output cannot overwrite either input.")
            def read(path):
                if path.stat().st_size > 5_000_000:
                    raise ValueError("P snapshot artifact exceeds the 5 MB limit.")
                return json.loads(path.read_text(encoding="utf-8-sig"))
            result = compare_p_snapshots(read(args.baseline),read(args.current))
            exit_code = 2 if result["coverage_status"]=="partial" else 1 if result["review_required"] else 0
        rendered = json.dumps(result,indent=2,ensure_ascii=True)+"\n"
        output.parent.mkdir(parents=True,exist_ok=True)
        with output.open("x",encoding="utf-8") as stream:
            stream.write(rendered)
        print(f"Saved P artifact: {output}")
        return exit_code
    except (ValueError, OSError, RecursionError) as error:
        parser.error(str(error))


def _execute_scan_command(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    *,
    default_target_dot: bool = False,
) -> int:
    raw_target = args.target or args.input_path
    if raw_target is None:
        if default_target_dot:
            resolved_target = Path(".")
        else:
            parser.error("scan requires a target path (positional TARGET or --input PATH)")
    else:
        resolved_target = normalize_user_path(str(raw_target))

    no_color = bool(getattr(args, "no_color", False) or getattr(args, "scan_no_color", False))
    output_format = getattr(args, "format", "json")
    force_batch = bool(getattr(args, "batch", False))
    force_single = bool(getattr(args, "single", False))
    if force_batch and force_single:
        parser.error("--batch and --single cannot be used together")

    # Batch scope is strictly invariant to --format (text vs json):
    # - `mac scan` auto-detects batch collections unless --single is passed.
    # - `mcp-scanner scan` keeps single-snapshot default unless --batch is passed.
    use_batch = force_batch or (default_target_dot and not force_single)
    subtargets, skipped_entries = (
        discover_batch_targets(resolved_target, force_batch=force_batch)
        if use_batch
        else ([], [])
    )
    if subtargets or force_batch:
        if output_format == "text":
            render_banner(no_color=no_color)
        batch_data = run_batch_scan(
            subtargets,
            parent_target=resolved_target,
            no_color=no_color,
            show_progress=(output_format == "text"),
            skipped_entries=skipped_entries,
            source_id=args.source_id,
            input_kind=args.input_kind,
            revision=args.revision,
            package_name=args.package_name,
            package_version=args.package_version,
            rules=args.rules,
            semgrep=args.semgrep,
            windows_temp=args.windows_temp,
            enable_semgrep=not args.no_semgrep,
            enable_python_ast=not args.no_python_ast,
            enable_p_detector=not args.no_p_detector,
            strict_p=args.strict_p,
            enable_sca=not args.no_sca,
            osv_db=args.osv_db,
            osv_db_sha256=args.osv_db_sha256,
            osv_scanner=args.osv_scanner,
            max_file_bytes=args.max_file_bytes,
            max_files=args.max_files,
            budget_cutoff_seconds=args.cutoff,
            hard_timeout_seconds=args.timeout,
        )
        rendered_batch_json = serialize_batch_report(batch_data)
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered_batch_json, encoding="utf-8")
        if output_format == "text":
            render_batch_summary(
                batch_data,
                no_color=no_color,
                show_banner=False,
                saved_path=args.output,
            )
            if getattr(args, "details", False):
                render_batch_list(batch_data, no_color=no_color)
        else:
            if args.output is None:
                print(rendered_batch_json, end="")
        return int(batch_data["exit_code"])

    progress_cb = None
    if output_format == "text":
        render_banner(no_color=no_color)
        progress_cb = make_stage_progress_callback(no_color=no_color)

    report = run_scan(
        resolved_target,
        server_id=args.server_id,
        source_id=args.source_id,
        input_kind=args.input_kind,
        revision=args.revision,
        package_name=args.package_name,
        package_version=args.package_version,
        rules=args.rules,
        semgrep=args.semgrep,
        windows_temp=args.windows_temp,
        enable_semgrep=not args.no_semgrep,
        enable_python_ast=not args.no_python_ast,
        enable_p_detector=not args.no_p_detector,
        strict_p=args.strict_p,
        enable_sca=not args.no_sca,
        osv_db=args.osv_db,
        osv_db_sha256=args.osv_db_sha256,
        osv_scanner=args.osv_scanner,
        max_file_bytes=args.max_file_bytes,
        max_files=args.max_files,
        budget_cutoff_seconds=args.cutoff,
        hard_timeout_seconds=args.timeout,
        on_stage=progress_cb,
    )

    rendered_json = report.to_json()
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered_json, encoding="utf-8")

    if output_format == "text":
        render_scan_summary(
            report,
            no_color=no_color,
            show_banner=False,
            saved_path=args.output,
        )
        if getattr(args, "details", False):
            render_scan_details(report, no_color=no_color)
    else:
        if args.output is None:
            print(rendered_json, end="")

    return int(report.exit_code if report.exit_code is not None else 2)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the mcp-scanner CLI (defaults to JSON output) and return a process exit code."""
    parser = build_parser(prog="mcp-scanner", default_format="json")
    args = parser.parse_args(argv)

    if args.command in {"snapshot-p", "diff-p-snapshots"}:
        return _execute_p_snapshot_command(args, parser)

    if args.command == "scan":
        return _execute_scan_command(args, parser, default_target_dot=False)

    if args.command == "inventory":
        try:
            inventory = collect(args.config)
            write_inventory(inventory, args.output)
        except InventoryError as error:
            parser.error(str(error))
        print(f"Wrote {len(inventory['items'])} inventory item(s) to {args.output}")
        return 0

    if args.command == "discover":
        try:
            artifact = discover(args.input)
            write_discovery(artifact, args.output)
        except DiscoveryError as error:
            parser.error(str(error))
        print(f"Wrote {len(artifact['items'])} discovery item(s) to {args.output}")
        return 0

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


def mac_main(argv: Sequence[str] | None = None) -> int:
    """Run the MAC (Maintain an Auspicious Cloud) terminal CLI/TUI entrypoint."""
    raw_args = list(sys.argv[1:] if argv is None else argv)

    # Shorthand: `mac ./target` -> `mac scan ./target`
    if raw_args and raw_args[0] not in _SUBCOMMANDS and not raw_args[0].startswith("-"):
        raw_args = ["scan", *raw_args]

    parser = build_parser(prog="mac", default_format="text")
    args = parser.parse_args(raw_args)

    if args.command == "scan":
        return _execute_scan_command(args, parser, default_target_dot=True)

    if args.command in {"inventory", "discover", "scan-code", "snapshot-p", "diff-p-snapshots"}:
        return main(raw_args)

    # No subcommand (`mac` or `mac --no-color`): launch interactive menu if running in a terminal
    if sys.stdin is not None and sys.stdin.isatty():
        return run_interactive_session(no_color=bool(args.no_color))

    render_banner(no_color=bool(args.no_color))
    parser.print_help()
    return 0
