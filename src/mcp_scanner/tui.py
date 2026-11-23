"""Terminal UI (TUI) and interactive menu for MAC (Maintain an Auspicious Cloud).

Provides an English terminal interface with a purple MAC banner, step-by-step
stage progress, color-coded summary & detail views, and an interactive menu
while keeping canonical v1.0 ScanReport JSON output intact.
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, TextIO

from . import __version__
from .models import ScanReport, utc_now_iso
from .scanner import run_scan
from .source_inventory import IGNORED_DIRS, _is_link_or_junction

MAC_BANNER_UNICODE = (
    "███╗   ███╗ █████╗  ██████╗\n"
    "████╗ ████║██╔══██╗██╔════╝\n"
    "██╔████╔██║███████║██║     \n"
    "██║╚██╔╝██║██╔══██║██║     \n"
    "██║ ╚═╝ ██║██║  ██║╚██████╗\n"
    "╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝"
)

MAC_BANNER_ASCII = (
    " __  __    _    ____ \n"
    "|  \\/  |  / \\  / ___|\n"
    "| |\\/| | / _ \\| |    \n"
    "| |  | |/ ___ \\ |___ \n"
    "|_|  |_/_/   \\_\\____|"
)

MAC_TAGLINE = "Maintain an Auspicious Cloud"
MAC_SUBTITLE = "MCP Security Scanner"

_STAGE_META: dict[str, tuple[int, str]] = {
    "inventory": (1, "Collecting source inventory"),
    "package_json": (2, "Inspecting package.json manifests"),
    "python_ast": (3, "Running Python AST analysis"),
    "semgrep": (4, "Running Semgrep CE rules (Python + JS/TS)"),
}


def _ensure_utf8_stream(stream: TextIO) -> bool:
    """Attempt UTF-8 output on Windows consoles; return True if Unicode block chars are supported."""
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        MAC_BANNER_UNICODE.encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
                return True
            except Exception:
                return False
        return False


def _make_console(stream: TextIO | None = None, *, no_color: bool = False) -> Any:
    """Create a Rich Console bound to stream if rich is available, else return None."""
    target_stream = stream if stream is not None else sys.stdout
    _ensure_utf8_stream(target_stream)
    disable_color = bool(no_color or os.environ.get("NO_COLOR"))
    try:
        from rich.console import Console

        return Console(
            file=target_stream,
            no_color=disable_color,
            highlight=False,
            soft_wrap=True,
        )
    except ImportError:
        return None


def normalize_user_path(raw: str) -> Path:
    """Strip whitespace and surrounding Windows/shell quotes from a user-supplied path."""
    cleaned = raw.strip()
    while len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {'"', "'"}:
        cleaned = cleaned[1:-1].strip()
    cleaned = cleaned.strip('"').strip("'").strip()
    if not cleaned:
        return Path(".")
    return Path(cleaned).expanduser()


def default_report_filename(target: Path, *, is_batch: bool = False) -> Path:
    """Generate a friendly default JSON report filename from the scan target."""
    try:
        resolved = target.resolve()
        base = resolved.stem if resolved.is_file() else resolved.name
    except OSError:
        base = target.name or "scan"
    safe = "".join(ch if (ch.isalnum() or ch in "-_.") else "_" for ch in base).strip("_.")
    if not safe:
        safe = "scan"
    suffix = "_batch_report.json" if is_batch else "_report.json"
    return Path(f"{safe}{suffix}")


_ROOT_SERVER_MARKERS: frozenset[str] = frozenset(
    {
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "setup.py",
        "setup.cfg",
        "cargo.toml",
        "go.mod",
        "mcp.json",
        "tools.json",
    }
)
_ROOT_CODE_EXTS: frozenset[str] = frozenset(
    {".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
)
_SINGLE_REPO_LAYOUT_DIRS: frozenset[str] = frozenset(
    {
        "src",
        "lib",
        "app",
        "pkg",
        "internal",
        "cmd",
        "bin",
        "include",
        "test",
        "tests",
        "spec",
        "docs",
        "doc",
        "examples",
        "scripts",
        "assets",
        "static",
        "public",
        "config",
        "configs",
        "rules",
        "schemas",
        "types",
        "utils",
        "helpers",
        "core",
        "common",
        "models",
        "services",
        "handlers",
        "tools",
        "resources",
        "prompts",
    }
)


def _is_single_server_dir(directory: Path) -> bool:
    """Return True if directory looks like a single MCP server repository rather than a collection folder."""
    if _is_link_or_junction(directory):
        return False
    try:
        entries = list(directory.iterdir())
    except OSError:
        return False

    has_layout_subdir = False
    for item in entries:
        if _is_link_or_junction(item):
            continue
        name_low = item.name.lower()
        try:
            if item.is_file():
                if name_low in _ROOT_SERVER_MARKERS or item.suffix.lower() in _ROOT_CODE_EXTS:
                    return True
            elif item.is_dir() and name_low in _SINGLE_REPO_LAYOUT_DIRS:
                has_layout_subdir = True
        except OSError:
            continue
    return has_layout_subdir


def _rel_display(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name or str(path)


def _collect_batch_leaves(
    directory: Path,
    *,
    root: Path,
    depth: int,
    max_depth: int = 3,
    skipped_entries: list[dict[str, str]],
) -> list[Path]:
    """Unwrap category/grouping folders up to max_depth without following symlinks or junctions."""
    try:
        entries = sorted(directory.iterdir(), key=lambda p: (p.name.lower(), p.name))
    except OSError as error:
        skipped_entries.append(
            {
                "path": _rel_display(directory, root),
                "reason": f"unreadable_directory:{type(error).__name__}",
            }
        )
        return []

    subdirs: list[Path] = []
    for item in entries:
        if item.name.startswith(".") or item.name in IGNORED_DIRS:
            continue
        if _is_link_or_junction(item):
            skipped_entries.append(
                {
                    "path": _rel_display(item, root),
                    "reason": "symlink_or_junction_not_followed",
                }
            )
            continue
        try:
            if item.is_dir():
                try:
                    has_children = any(item.iterdir())
                except OSError as error:
                    skipped_entries.append(
                        {
                            "path": _rel_display(item, root),
                            "reason": f"unreadable_directory:{type(error).__name__}",
                        }
                    )
                    continue
                if has_children:
                    subdirs.append(item)
        except OSError as error:
            skipped_entries.append(
                {
                    "path": _rel_display(item, root),
                    "reason": f"unreadable_entry:{type(error).__name__}",
                }
            )
            continue

    results: list[Path] = []
    for sub in subdirs:
        if _is_single_server_dir(sub) or depth >= max_depth:
            results.append(sub)
        else:
            nested = _collect_batch_leaves(
                sub,
                root=root,
                depth=depth + 1,
                max_depth=max_depth,
                skipped_entries=skipped_entries,
            )
            results.extend(nested if nested else [sub])
    return results


def discover_batch_targets(
    target: Path, *, force_batch: bool = False
) -> tuple[list[Path], list[dict[str, str]]]:
    """Discover child snapshot directories and record skipped symlink/unreadable entries."""
    skipped_entries: list[dict[str, str]] = []
    if _is_link_or_junction(target):
        return [], [{"path": str(target), "reason": "symlink_or_junction_root_rejected"}]
    try:
        if not target.exists() or not target.is_dir():
            return [], []
    except OSError as error:
        return [], [{"path": str(target), "reason": f"unreadable_root:{type(error).__name__}"}]

    if not force_batch and _is_single_server_dir(target):
        return [], []

    leaves = _collect_batch_leaves(
        target,
        root=target,
        depth=1,
        max_depth=3,
        skipped_entries=skipped_entries,
    )
    if force_batch:
        return leaves, skipped_entries
    if len(leaves) >= 2:
        return leaves, skipped_entries
    return [], skipped_entries


def detect_batch_subtargets(target: Path, *, force_batch: bool = False) -> list[Path]:
    """Return sorted child snapshot directories if target is a multi-sample collection folder."""
    leaves, _skipped = discover_batch_targets(target, force_batch=force_batch)
    return leaves


def run_batch_scan(
    subtargets: Sequence[Path],
    *,
    parent_target: Path,
    scan_fn: Callable[..., ScanReport] = run_scan,
    stream: TextIO | None = None,
    no_color: bool = False,
    show_progress: bool = True,
    skipped_entries: Sequence[dict[str, str]] | None = None,
    **scan_kwargs: Any,
) -> dict[str, Any]:
    """Scan each child directory as an independent MCP server snapshot and aggregate results."""
    out = stream if stream is not None else sys.stdout
    console = _make_console(out, no_color=no_color) if show_progress else None
    total = len(subtargets)
    t0 = time.monotonic()

    reports: list[tuple[str, Path, ScanReport]] = []
    status_counts = {"complete": 0, "partial": 0, "failed": 0, "unsupported": 0}
    policy_counts = {"pass": 0, "fail": 0, "not_evaluated": 0}
    cat_snapshot_hits: dict[str, int] = {}
    cat_finding_counts: dict[str, int] = {}
    skipped_list = list(skipped_entries or [])

    step_interval = 1 if total <= 20 else (10 if total <= 200 else 25)
    for idx, sub in enumerate(subtargets, start=1):
        try:
            sub_label = sub.relative_to(parent_target).as_posix()
        except ValueError:
            sub_label = sub.name
        rep = scan_fn(sub, **scan_kwargs)
        reports.append((sub_label, sub, rep))
        status_counts[rep.scan_status] = status_counts.get(rep.scan_status, 0) + 1
        policy_counts[rep.policy_status] = policy_counts.get(rep.policy_status, 0) + 1

        actionable = [
            f for f in rep.findings if f.kind != "capability_info" and f.severity != "info"
        ]
        seen_cats: set[str] = set()
        for f in actionable:
            cat_finding_counts[f.category] = cat_finding_counts.get(f.category, 0) + 1
            seen_cats.add(f.category)
        for c in seen_cats:
            cat_snapshot_hits[c] = cat_snapshot_hits.get(c, 0) + 1

        if show_progress and (idx == 1 or idx == total or idx % step_interval == 0):
            cats_tag = ",".join(sorted(seen_cats)) if seen_cats else "none"
            verdict = _verdict_label(rep.policy_status)
            if console is not None:
                v_color = (
                    "bold red"
                    if verdict == "ALERT"
                    else ("bold green" if verdict == "CLEAN" else "bold yellow")
                )
                console.print(
                    f"  [bold green]\\[done][/bold green] \\[{idx}/{total}] Scanned [bold]{sub_label}[/bold] "
                    f"[dim]({rep.scan_status} · [/dim][{v_color}]{verdict}[/{v_color}][dim] · {cats_tag})[/dim]"
                )
            else:
                out.write(
                    f"  [done] [{idx}/{total}] Scanned {sub_label} ({rep.scan_status} · {verdict} · {cats_tag})\n"
                )
                out.flush()

    elapsed = time.monotonic() - t0
    overall_exit = 0
    empty_reason: str | None = None
    if total == 0:
        overall_exit = 2
        empty_reason = "all_entries_skipped" if skipped_list else "no_snapshots_found"
    elif (
        skipped_list
        or status_counts.get("failed", 0)
        or status_counts.get("partial", 0)
        or status_counts.get("unsupported", 0)
    ):
        overall_exit = 2
    elif policy_counts.get("fail", 0):
        overall_exit = 1

    result: dict[str, Any] = {
        "contract_version": "1.0",
        "artifact_type": "batch_scan_report",
        "generated_at": utc_now_iso(),
        "scanner_version": __version__,
        "parent_target": str(parent_target),
        "mode": "fast_ast" if not scan_kwargs.get("enable_semgrep", True) else "full_semgrep",
        "total_snapshots": total,
        "elapsed_seconds": round(elapsed, 4),
        "exit_code": overall_exit,
        "status_counts": status_counts,
        "policy_counts": policy_counts,
        "category_snapshot_hits": dict(sorted(cat_snapshot_hits.items())),
        "category_finding_counts": dict(sorted(cat_finding_counts.items())),
        "skipped_entries": skipped_list,
        "reports": reports,
    }
    if empty_reason is not None:
        result["reason"] = empty_reason
    return result


def serialize_batch_report(batch_data: dict[str, Any]) -> str:
    """Serialize batch summary and per-sample digests to canonical JSON."""
    items = []
    for name, sub_path, rep in batch_data["reports"]:
        actionable = [
            f for f in rep.findings if f.kind != "capability_info" and f.severity != "info"
        ]
        items.append(
            {
                "name": name,
                "location": str(sub_path),
                "scan_status": rep.scan_status,
                "policy_status": rep.policy_status,
                "exit_code": rep.exit_code,
                "trust_score": rep.trust_score.displayed_score,
                "score_scope": rep.trust_score.score_scope,
                "actionable_findings": len(actionable),
                "categories": sorted({f.category for f in actionable}),
                "rule_ids": sorted({f.rule_id for f in actionable}),
            }
        )
    payload = {k: v for k, v in batch_data.items() if k != "reports"}
    payload["items"] = items
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def render_batch_summary(
    batch_data: dict[str, Any],
    *,
    stream: TextIO | None = None,
    no_color: bool = False,
    show_banner: bool = True,
    saved_path: Path | None = None,
    show_action_bar: bool = False,
) -> None:
    """Render the English batch scan summary screen."""
    out = stream if stream is not None else sys.stdout
    use_unicode = _ensure_utf8_stream(out)
    rule_line = "─" * 62 if use_unicode else "-" * 62
    console = _make_console(out, no_color=no_color)

    if show_banner:
        render_banner(stream=out, no_color=no_color)
    else:
        if console is not None:
            console.print(f"[dim]{rule_line}[/dim]")
        else:
            out.write(f"{rule_line}\n")

    total = batch_data["total_snapshots"]
    sc = batch_data["status_counts"]
    pc = batch_data["policy_counts"]
    cat_hits = batch_data["category_snapshot_hits"]
    cat_finds = batch_data["category_finding_counts"]
    mode_label = (
        "Fast Batch (Python AST + package.json)"
        if batch_data["mode"] == "fast_ast"
        else "Full Batch (Python AST + package.json + Semgrep CE)"
    )

    if console is not None:
        console.print(f"  [dim]Batch Target[/dim] {batch_data['parent_target']}")
        console.print(f"  [dim]Scan Mode   [/dim] [bold #c084fc]{mode_label}[/bold #c084fc]")
        console.print(
            f"  [dim]Scan Status [/dim] [bold green]{sc.get('complete', 0)} COMPLETE[/bold green] · "
            f"[bold yellow]{sc.get('partial', 0)} PARTIAL[/bold yellow] · "
            f"[bold red]{sc.get('failed', 0)} FAILED[/bold red] [dim](Total: {total})[/dim]"
        )
        unverified_cnt = pc.get("not_evaluated", 0)
        unver_rich = (
            f" · [bold yellow]{unverified_cnt} UNVERIFIED[/bold yellow]"
            if unverified_cnt
            else ""
        )
        console.print(
            f"  [dim]Verdict     [/dim] [bold red]{pc.get('fail', 0)} ALERT[/bold red] · "
            f"[bold green]{pc.get('pass', 0)} CLEAN[/bold green]{unver_rich} · "
            f"[dim]{batch_data['elapsed_seconds']:.2f} s[/dim]"
        )
        console.print(f"[dim]{rule_line}[/dim]")
        console.print("  [bold]Category Breakdown (Alert Snapshots / Total Findings):[/bold]")
        if total == 0:
            reason_label = batch_data.get("reason") or "no_snapshots_found"
            console.print(
                f"    [bold yellow]No scannable snapshots discovered ({reason_label}).[/bold yellow]"
            )
        elif cat_hits:
            for cat, snap_cnt in cat_hits.items():
                f_cnt = cat_finds.get(cat, snap_cnt)
                console.print(
                    f"    • [bold #c084fc]\\[{cat}][/bold #c084fc] : [bold]{snap_cnt}[/bold] / {total} snapshot(s) "
                    f"[dim]({f_cnt} finding(s))[/dim]"
                )
        else:
            console.print("    [bold green]0 actionable findings across all snapshots.[/bold green]")

        # Preview first 10 alert snapshots
        flagged = [
            (name, rep)
            for name, _, rep in batch_data["reports"]
            if rep.policy_status == "fail"
        ]
        if flagged:
            console.print(f"[dim]{rule_line}[/dim]")
            console.print(
                f"  [bold]Alert Snapshots Preview (showing {min(10, len(flagged))} of {len(flagged)}):[/bold]"
            )
            for name, rep in flagged[:10]:
                act = [
                    f for f in rep.findings if f.kind != "capability_info" and f.severity != "info"
                ]
                cats = ",".join(sorted({f.category for f in act}))
                rules = ",".join(sorted({f.rule_id for f in act}))
                score = rep.trust_score.displayed_score
                console.print(
                    f"    [bold red]ALERT[/bold red] [bold]{name:<10}[/bold] · Score {score:>3}/100 · "
                    f"[bold #c084fc]\\[{cats}][/bold #c084fc] [dim]{rules} ({len(act)} finding(s))[/dim]"
                )

        skipped_entries = batch_data.get("skipped_entries") or []
        if skipped_entries:
            console.print(f"[dim]{rule_line}[/dim]")
            console.print(
                f"  [bold yellow]Skipped Discovery Entries ({len(skipped_entries)}):[/bold yellow]"
            )
            for ent in skipped_entries[:5]:
                console.print(f"    • {ent['path']} [dim]({ent['reason']})[/dim]")

        console.print(
            "  [dim]Scope: static M/C/S/exec/supply-chain only (prompt poisoning P & runtime not evaluated).[/dim]"
        )

        if saved_path is not None:
            console.print(f"[dim]{rule_line}[/dim]")
            console.print(f"  [bold #c084fc]Saved Batch JSON report:[/bold #c084fc] {saved_path}")

        if show_action_bar:
            console.print(f"[dim]{rule_line}[/dim]")
            console.print(
                "  [bold #c084fc]\\[I][/bold #c084fc] Inspect Sample   "
                "[bold #c084fc]\\[L][/bold #c084fc] List All   "
                "[bold #c084fc]\\[S][/bold #c084fc] Save Batch JSON   "
                "[bold #c084fc]\\[N][/bold #c084fc] New Scan   "
                "[bold #c084fc]\\[Q][/bold #c084fc] Quit"
            )
    else:
        out.write(f"  Batch Target {batch_data['parent_target']}\n")
        out.write(f"  Scan Mode    {mode_label}\n")
        out.write(
            f"  Scan Status  {sc.get('complete', 0)} COMPLETE · {sc.get('partial', 0)} PARTIAL · {sc.get('failed', 0)} FAILED (Total: {total})\n"
        )
        unverified_cnt = pc.get("not_evaluated", 0)
        unver_plain = f" · {unverified_cnt} UNVERIFIED" if unverified_cnt else ""
        out.write(
            f"  Verdict      {pc.get('fail', 0)} ALERT · {pc.get('pass', 0)} CLEAN{unver_plain} · {batch_data['elapsed_seconds']:.2f} s\n"
        )
        out.write(f"{rule_line}\n  Category Breakdown:\n")
        if total == 0:
            reason_label = batch_data.get("reason") or "no_snapshots_found"
            out.write(f"    No scannable snapshots discovered ({reason_label}).\n")
        elif cat_hits:
            for cat, snap_cnt in cat_hits.items():
                f_cnt = cat_finds.get(cat, snap_cnt)
                out.write(f"    - [{cat}] : {snap_cnt} / {total} snapshot(s) ({f_cnt} finding(s))\n")
        else:
            out.write("    0 actionable findings across all snapshots.\n")
        skipped_entries = batch_data.get("skipped_entries") or []
        if skipped_entries:
            out.write(f"{rule_line}\n  Skipped Discovery Entries ({len(skipped_entries)}):\n")
            for ent in skipped_entries[:5]:
                out.write(f"    - {ent['path']} ({ent['reason']})\n")
        out.write(
            "  Scope: static M/C/S/exec/supply-chain only (prompt poisoning P & runtime not evaluated).\n"
        )
        if saved_path is not None:
            out.write(f"{rule_line}\n  Saved Batch JSON report: {saved_path}\n")
        if show_action_bar:
            out.write(
                f"{rule_line}\n  [I] Inspect Sample   [L] List All   [S] Save Batch JSON   [N] New Scan   [Q] Quit\n"
            )
        out.flush()


def render_batch_list(
    batch_data: dict[str, Any],
    *,
    stream: TextIO | None = None,
    no_color: bool = False,
) -> None:
    """List all snapshots in a batch scan with status, score, and matched categories."""
    out = stream if stream is not None else sys.stdout
    use_unicode = _ensure_utf8_stream(out)
    rule_line = "─" * 62 if use_unicode else "-" * 62
    console = _make_console(out, no_color=no_color)

    if console is not None:
        console.print(f"[dim]{rule_line}[/dim]")
        console.print(f"  [bold #c084fc]All Scanned Snapshots ({batch_data['total_snapshots']}):[/bold #c084fc]")
        for idx, (name, _, rep) in enumerate(batch_data["reports"], start=1):
            act = [
                f for f in rep.findings if f.kind != "capability_info" and f.severity != "info"
            ]
            cats = ",".join(sorted({f.category for f in act})) or "-"
            pol_tag = (
                "[bold red]ALERT[/bold red]"
                if rep.policy_status == "fail"
                else ("[bold green]CLEAN[/bold green]" if rep.policy_status == "pass" else "[bold yellow]UNVER[/bold yellow]")
            )
            score = rep.trust_score.displayed_score
            sc_str = f"{score:>3}/100" if score is not None else "N/A    "
            console.print(
                f"  {idx:>3}. {pol_tag} [bold]{name:<12}[/bold] · {rep.scan_status:<8} · "
                f"Score {sc_str} · Cat: [bold #c084fc]{cats:<6}[/bold #c084fc] [dim]({len(act)} finding(s))[/dim]"
            )
    else:
        out.write(f"{rule_line}\n  All Scanned Snapshots ({batch_data['total_snapshots']}):\n")
        for idx, (name, _, rep) in enumerate(batch_data["reports"], start=1):
            act = [
                f for f in rep.findings if f.kind != "capability_info" and f.severity != "info"
            ]
            cats = ",".join(sorted({f.category for f in act})) or "-"
            verdict = _verdict_label(rep.policy_status)
            score = rep.trust_score.displayed_score
            sc_str = f"{score}/100" if score is not None else "N/A"
            out.write(
                f"  {idx:>3}. {verdict:<10} {name:<12} · {rep.scan_status:<8} · "
                f"Score {sc_str} · Cat: {cats} ({len(act)} finding(s))\n"
            )
        out.flush()


def render_banner(
    *,
    stream: TextIO | None = None,
    no_color: bool = False,
    profile: str = "static-default",
) -> None:
    """Render the purple MAC banner and English subtitle."""
    out = stream if stream is not None else sys.stdout
    use_unicode = _ensure_utf8_stream(out)
    banner_art = MAC_BANNER_UNICODE if use_unicode else MAC_BANNER_ASCII
    rule_line = "─" * 62 if use_unicode else "-" * 62
    console = _make_console(out, no_color=no_color)

    if console is not None:
        console.print(f"[bold #a855f7]{banner_art}[/bold #a855f7]")
        console.print(
            f"[bold #c084fc]{MAC_TAGLINE}[/bold #c084fc]"
            f" [dim]· {MAC_SUBTITLE} v{__version__} \\[{profile}][/dim]"
        )
        console.print(f"[dim]{rule_line}[/dim]")
    else:
        out.write(f"{banner_art}\n")
        out.write(f"{MAC_TAGLINE} · {MAC_SUBTITLE} v{__version__} [{profile}]\n")
        out.write(f"{rule_line}\n")
        out.flush()


def make_stage_progress_callback(
    *,
    stream: TextIO | None = None,
    no_color: bool = False,
) -> Callable[[str, str], None]:
    """Create a step-by-step stage progress printer for run_scan(on_stage=...)."""
    out = stream if stream is not None else sys.stdout
    console = _make_console(out, no_color=no_color)

    def _on_stage(event: str, detail: str) -> None:
        stage_key, _, phase = event.partition(":")
        meta = _STAGE_META.get(stage_key)
        if meta is None:
            return
        idx, label = meta
        if phase == "done":
            if console is not None:
                console.print(
                    f"  [bold green]\\[done][/bold green] \\[{idx}/4] {label} [dim]({detail})[/dim]"
                )
            else:
                out.write(f"  [done] [{idx}/4] {label} ({detail})\n")
                out.flush()

    return _on_stage


def _verdict_label(policy_status: str) -> str:
    """Map machine policy_status to clear human-facing terminal verdict badges."""
    if policy_status == "fail":
        return "ALERT"
    if policy_status == "pass":
        return "CLEAN"
    return "UNVERIFIED"


def _severity_rich_tag(severity: str) -> str:
    sev = severity.lower()
    if sev == "critical":
        return "[bold bright_red]CRITICAL[/bold bright_red]"
    if sev == "high":
        return "[bold red]HIGH[/bold red]"
    if sev == "medium":
        return "[bold yellow]MEDIUM[/bold yellow]"
    if sev == "low":
        return "[bold cyan]LOW[/bold cyan]"
    return "[dim]INFO[/dim]"


def render_scan_summary(
    report: ScanReport,
    *,
    stream: TextIO | None = None,
    no_color: bool = False,
    show_banner: bool = True,
    saved_path: Path | None = None,
    show_action_bar: bool = False,
) -> None:
    """Render the English scan result screen for a canonical v1.0 ScanReport."""
    out = stream if stream is not None else sys.stdout
    use_unicode = _ensure_utf8_stream(out)
    rule_line = "─" * 62 if use_unicode else "-" * 62
    console = _make_console(out, no_color=no_color)

    if show_banner:
        render_banner(stream=out, no_color=no_color, profile=report.scanner.profile)
    else:
        if console is not None:
            console.print(f"[dim]{rule_line}[/dim]")
        else:
            out.write(f"{rule_line}\n")

    prov = report.input_provenance
    meta_tags = ", ".join([*prov.frameworks, *prov.languages])
    target_display = f"{prov.location} ({meta_tags})" if meta_tags else prov.location

    status_upper = report.scan_status.upper()
    verdict_upper = _verdict_label(report.policy_status)
    exit_code = report.exit_code if report.exit_code is not None else 2

    ts = report.trust_score
    if ts.displayed_score is not None:
        score_text = f"{ts.displayed_score}/100 ({ts.score_scope})"
    else:
        score_text = f"N/A ({ts.score_scope})"

    cov = report.coverage
    non_ignored_skips = [s for s in cov.skipped_files if s.reason != "ignored_directory"]
    cov_parts = [f"{cov.files_scanned} / {cov.files_discovered} scanned"]
    if non_ignored_skips:
        cov_parts.append(f"{len(non_ignored_skips)} skipped")
    if cov.read_errors:
        cov_parts.append(f"{len(cov.read_errors)} read error(s)")
    if cov.skipped_budget:
        cov_parts.append(f"{len(cov.skipped_budget)} budget-skipped")
    cov_parts.append(f"{report.telemetry.elapsed_seconds:.2f} s")
    coverage_display = " · ".join(cov_parts)

    actionable = [
        f for f in report.findings if f.kind != "capability_info" and f.severity != "info"
    ]
    info_count = sum(
        1 for f in report.findings if f.kind == "capability_info" or f.severity == "info"
    )
    finding_by_id = {f.finding_id: f for f in report.findings}

    if console is not None:
        status_color = (
            "bold green"
            if report.scan_status == "complete"
            else ("bold yellow" if report.scan_status == "partial" else "bold red")
        )
        policy_color = (
            "bold green"
            if report.policy_status == "pass"
            else ("bold red" if report.policy_status == "fail" else "bold yellow")
        )
        if ts.displayed_score is None:
            score_color = "bold red"
        elif ts.displayed_score >= 80 and report.scan_status == "complete":
            score_color = "bold green"
        elif ts.displayed_score >= 50:
            score_color = "bold yellow"
        else:
            score_color = "bold red"

        console.print(f"  [dim]Target     [/dim] {target_display}")
        console.print(
            f"  [dim]Status     [/dim] [{status_color}]{status_upper}[/{status_color}]"
            f" · Verdict [{policy_color}]{verdict_upper}[/{policy_color}] [dim](exit {exit_code})[/dim]"
        )
        console.print(f"  [dim]Trust Score[/dim] [{score_color}]{score_text}[/{score_color}]")
        console.print(f"  [dim]Coverage   [/dim] {coverage_display}")
        console.print(f"[dim]{rule_line}[/dim]")

        if report.scan_status in {"partial", "failed"}:
            tier = report.review_queue.priority_tier
            console.print(f"  [bold yellow]Coverage / Scan Note[/bold yellow] [dim](Review: {tier})[/dim]")
            console.print(f"  [yellow]{ts.reason}[/yellow]")
            if report.diagnostics:
                for diag in report.diagnostics[:3]:
                    msg = diag.get("message") or diag.get("kind") or "diagnostic"
                    path_str = f" ({diag['path']})" if diag.get("path") else ""
                    console.print(f"  [dim]• {msg}{path_str}[/dim]")
            console.print(f"[dim]{rule_line}[/dim]")

        if report.executive_summary.top_5:
            sev_counts = report.executive_summary.severity_counts
            summary_badges = (
                f"Critical: {sev_counts.get('critical', 0)}, "
                f"High: {sev_counts.get('high', 0)}, "
                f"Medium: {sev_counts.get('medium', 0)}, "
                f"Low: {sev_counts.get('low', 0)}"
            )
            console.print(
                f"  [bold]Top Findings ({len(actionable)} actionable · {summary_badges})[/bold]"
            )
            for idx, item in enumerate(report.executive_summary.top_5, start=1):
                full_f = finding_by_id.get(item.finding_id)
                cat = full_f.category if full_f is not None else "?"
                comp = full_f.component if full_f is not None else ""
                comp_suffix = f" ({comp})" if comp and comp != "unknown" else ""
                console.print(
                    f"  {idx}. {_severity_rich_tag(item.severity)} [bold #c084fc]\\[{cat}][/bold #c084fc] "
                    f"{item.title}"
                )
                console.print(
                    f"     [dim]{item.location}{comp_suffix} · {item.impact_summary}[/dim]"
                )
        else:
            if report.scan_status == "complete":
                extra = f" ({info_count} informational item(s))" if info_count else ""
                console.print(f"  [bold green]No actionable security findings detected{extra}.[/bold green]")
                console.print(
                    "  [dim]Scope: static M/C/S/exec/supply-chain only (prompt poisoning P & runtime not evaluated).[/dim]"
                )
            else:
                console.print(
                    "  [yellow]No actionable findings in inspected files, but scan coverage is incomplete.[/yellow]"
                )

        if saved_path is not None:
            console.print(f"[dim]{rule_line}[/dim]")
            console.print(f"  [bold #c084fc]Saved JSON report:[/bold #c084fc] {saved_path}")

        if show_action_bar:
            console.print(f"[dim]{rule_line}[/dim]")
            console.print(
                "  [bold #c084fc]\\[D][/bold #c084fc] Details   "
                "[bold #c084fc]\\[S][/bold #c084fc] Save JSON   "
                "[bold #c084fc]\\[N][/bold #c084fc] New Scan   "
                "[bold #c084fc]\\[Q][/bold #c084fc] Quit"
            )
    else:
        out.write(f"  Target      {target_display}\n")
        out.write(f"  Status      {status_upper} · Verdict {verdict_upper} (exit {exit_code})\n")
        out.write(f"  Trust Score {score_text}\n")
        out.write(f"  Coverage    {coverage_display}\n")
        out.write(f"{rule_line}\n")
        if report.scan_status in {"partial", "failed"}:
            out.write(f"  Coverage / Scan Note: {ts.reason}\n")
            out.write(f"{rule_line}\n")
        if report.executive_summary.top_5:
            out.write(f"  Top Findings ({len(actionable)} actionable):\n")
            for idx, item in enumerate(report.executive_summary.top_5, start=1):
                full_f = finding_by_id.get(item.finding_id)
                cat = full_f.category if full_f is not None else "?"
                comp = full_f.component if full_f is not None else ""
                comp_suffix = f" ({comp})" if comp and comp != "unknown" else ""
                out.write(
                    f"  {idx}. {item.severity.upper()} [{cat}] {item.title}\n"
                    f"     {item.location}{comp_suffix} · {item.impact_summary}\n"
                )
        else:
            if report.scan_status == "complete":
                out.write("  No actionable security findings detected.\n")
                out.write(
                    "  Scope: static M/C/S/exec/supply-chain only (prompt poisoning P & runtime not evaluated).\n"
                )
            else:
                out.write("  No actionable findings in inspected files, but scan coverage is incomplete.\n")
        if saved_path is not None:
            out.write(f"{rule_line}\n  Saved JSON report: {saved_path}\n")
        if show_action_bar:
            out.write(f"{rule_line}\n  [D] Details   [S] Save JSON   [N] New Scan   [Q] Quit\n")
        out.flush()


def render_scan_details(
    report: ScanReport,
    *,
    stream: TextIO | None = None,
    no_color: bool = False,
) -> None:
    """Render full finding traces, remediation guidance, and coverage boundaries."""
    out = stream if stream is not None else sys.stdout
    use_unicode = _ensure_utf8_stream(out)
    rule_line = "─" * 62 if use_unicode else "-" * 62
    console = _make_console(out, no_color=no_color)

    if console is not None:
        console.print(f"[dim]{rule_line}[/dim]")
        console.print("  [bold #c084fc]Detailed Findings & Coverage Drill-Down[/bold #c084fc]")
        console.print(f"[dim]{rule_line}[/dim]")
        if not report.findings:
            console.print("  [dim]No findings recorded in this report.[/dim]")
        for idx, f in enumerate(report.findings, start=1):
            sources = ", ".join(f.evidence_sources)
            console.print(
                f"  \\[{idx}] {_severity_rich_tag(f.severity)} · [bold]{f.rule_id}[/bold] "
                f"(Cat: [bold #c084fc]{f.category}[/bold #c084fc] · Surface: {f.mcp_surface}) "
                f"[dim]\\[{sources}][/dim]"
            )
            console.print(f"      [dim]Component:[/dim] {f.component}")
            console.print(f"      [dim]Reasoning:[/dim] {f.reasoning}")
            if f.trace:
                console.print("      [dim]Trace:[/dim]")
                for step_idx, step in enumerate(f.trace, start=1):
                    loc = (
                        f"{step.span.path}:{step.span.start_line}"
                        if step.span.start_line
                        else step.span.path
                    )
                    sym = step.symbol or step.role
                    console.print(
                        f"        {step_idx}. [bold #c084fc]{step.role:<9}[/bold #c084fc] · {sym} @ {loc}"
                    )
            if f.redacted_evidence and f.redacted_evidence.snippet:
                console.print(f"      [dim]Evidence :[/dim] {f.redacted_evidence.snippet}")
            console.print(f"      [dim]Fix      :[/dim] {f.remediation}")
            console.print("")

        non_ignored_skips = [
            s for s in report.coverage.skipped_files if s.reason != "ignored_directory"
        ]
        if non_ignored_skips or report.coverage.read_errors or report.coverage.skipped_budget:
            console.print("  [bold yellow]Skipped / Unreadable Entries:[/bold yellow]")
            for s in non_ignored_skips[:15]:
                console.print(f"    • {s.path} [dim]({s.reason})[/dim]")
            for e in report.coverage.read_errors[:15]:
                console.print(f"    • {e.path} [bold red]({e.error_code})[/bold red]")
            for b in report.coverage.skipped_budget[:15]:
                console.print(f"    • {b.path} [dim]({b.reason})[/dim]")
    else:
        out.write(f"{rule_line}\n  Detailed Findings & Coverage Drill-Down\n{rule_line}\n")
        if not report.findings:
            out.write("  No findings recorded in this report.\n")
        for idx, f in enumerate(report.findings, start=1):
            sources = ", ".join(f.evidence_sources)
            out.write(
                f"  [{idx}] {f.severity.upper()} · {f.rule_id} "
                f"(Cat: {f.category} · Surface: {f.mcp_surface}) [{sources}]\n"
            )
            out.write(f"      Component: {f.component}\n")
            out.write(f"      Reasoning: {f.reasoning}\n")
            if f.trace:
                out.write("      Trace:\n")
                for step_idx, step in enumerate(f.trace, start=1):
                    loc = (
                        f"{step.span.path}:{step.span.start_line}"
                        if step.span.start_line
                        else step.span.path
                    )
                    sym = step.symbol or step.role
                    out.write(f"        {step_idx}. {step.role:<9} · {sym} @ {loc}\n")
            if f.redacted_evidence and f.redacted_evidence.snippet:
                out.write(f"      Evidence : {f.redacted_evidence.snippet}\n")
            out.write(f"      Fix      : {f.remediation}\n\n")
        out.flush()


def run_interactive_session(
    *,
    scan_fn: Callable[..., ScanReport] = run_scan,
    input_fn: Callable[[str], str] = input,
    stream: TextIO | None = None,
    no_color: bool = False,
    **scan_kwargs: Any,
) -> int:
    """Launch the interactive MAC terminal menu loop."""
    out = stream if stream is not None else sys.stdout
    console = _make_console(out, no_color=no_color)
    history: list[tuple[str, ScanReport]] = []
    last_exit_code = 0

    def _print(rich_msg: str, plain_msg: str | None = None) -> None:
        if console is not None:
            console.print(rich_msg)
        else:
            out.write((plain_msg if plain_msg is not None else rich_msg) + "\n")
            out.flush()

    while True:
        render_banner(stream=out, no_color=no_color)
        _print("  [bold]Select an action:[/bold]", "  Select an action:")
        _print(
            "    [bold #c084fc]\\[1][/bold #c084fc] Scan current directory [dim](.)[/dim]",
            "    [1] Scan current directory (.)",
        )
        _print(
            "    [bold #c084fc]\\[2][/bold #c084fc] Paste or enter a target path",
            "    [2] Paste or enter a target path",
        )
        _print(
            f"    [bold #c084fc]\\[3][/bold #c084fc] View recent session scans [dim]({len(history)})[/dim]",
            f"    [3] View recent session scans ({len(history)})",
        )
        _print(
            "    [bold #c084fc]\\[Q][/bold #c084fc] Quit",
            "    [Q] Quit",
        )
        _print(
            "  [dim]Tip: Press Enter or 1 for current directory, or paste a path directly.[/dim]",
            "  Tip: Press Enter or 1 for current directory, or paste a path directly.",
        )

        try:
            choice = input_fn("mac > ").strip()
        except (EOFError, KeyboardInterrupt):
            _print("\n  [dim]Exiting MAC.[/dim]", "\n  Exiting MAC.")
            return last_exit_code

        low = choice.lower()
        if low in {"q", "quit", "exit"}:
            return last_exit_code

        if low == "3":
            if not history:
                _print("  [yellow]No scans run in this session yet.[/yellow]", "  No scans run in this session yet.")
            else:
                _print("  [bold #c084fc]Recent Session Scans:[/bold #c084fc]", "  Recent Session Scans:")
                for idx, (loc, rep) in enumerate(history, start=1):
                    sc = rep.trust_score.displayed_score
                    sc_str = f"{sc}/100" if sc is not None else "N/A"
                    verdict = _verdict_label(rep.policy_status)
                    _print(
                        f"    {idx}. {loc} · [bold]{rep.scan_status.upper()}[/bold] · "
                        f"Verdict {verdict} · Score {sc_str}",
                        f"    {idx}. {loc} · {rep.scan_status.upper()} · Verdict {verdict} · Score {sc_str}",
                    )
            continue

        if low in {"", "1"}:
            target_path = Path(".")
        elif low == "2":
            try:
                raw_path = input_fn("Target path [.]: ")
            except (EOFError, KeyboardInterrupt):
                return last_exit_code
            target_path = normalize_user_path(raw_path)
        else:
            # Allow pasting a path directly at the main `mac > ` prompt
            target_path = normalize_user_path(choice)

        subtargets, skipped_entries = discover_batch_targets(target_path)
        if subtargets:
            first_name, last_name = subtargets[0].name, subtargets[-1].name
            _print(
                f"\n  [bold #c084fc]Detected batch collection:[/bold #c084fc] {len(subtargets)} snapshots "
                f"[dim]({first_name} .. {last_name})[/dim]",
                f"\n  Detected batch collection: {len(subtargets)} snapshots ({first_name} .. {last_name})",
            )
            _print(
                "    [bold #c084fc]\\[1][/bold #c084fc] Fast Batch Scan — Python AST + package.json [dim](recommended, ~1-2s)[/dim]",
                "    [1] Fast Batch Scan — Python AST + package.json (recommended, ~1-2s)",
            )
            _print(
                "    [bold #c084fc]\\[2][/bold #c084fc] Full Batch Scan — Python AST + package.json + Semgrep CE",
                "    [2] Full Batch Scan — Python AST + package.json + Semgrep CE",
            )
            _print(
                "    [bold #c084fc]\\[3][/bold #c084fc] Scan as a single combined repository instead",
                "    [3] Scan as a single combined repository instead",
            )
            _print(
                "    [bold #c084fc]\\[B][/bold #c084fc] Back to menu",
                "    [B] Back to menu",
            )
            try:
                b_choice = input_fn("mac batch [1] > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return last_exit_code

            if b_choice in {"b", "back"}:
                continue
            if b_choice in {"q", "quit", "exit"}:
                return last_exit_code
            if b_choice != "3":
                batch_kwargs = dict(scan_kwargs)
                if b_choice in {"", "1"}:
                    batch_kwargs["enable_semgrep"] = False
                elif b_choice == "2":
                    batch_kwargs["enable_semgrep"] = True

                _print(
                    f"\n  [bold #c084fc]Running batch scan on {len(subtargets)} snapshots...[/bold #c084fc]",
                    f"\n  Running batch scan on {len(subtargets)} snapshots...",
                )
                batch_data = run_batch_scan(
                    subtargets,
                    parent_target=target_path,
                    scan_fn=scan_fn,
                    stream=out,
                    no_color=no_color,
                    skipped_entries=skipped_entries,
                    **batch_kwargs,
                )
                last_exit_code = int(batch_data["exit_code"])
                out.write("\n")
                render_batch_summary(
                    batch_data,
                    stream=out,
                    no_color=no_color,
                    show_banner=True,
                    show_action_bar=True,
                )

                by_name = {name.lower(): (name, rep) for name, _, rep in batch_data["reports"]}
                while True:
                    try:
                        b_act = input_fn("mac batch [I/L/S/N/Q] > ").strip()
                    except (EOFError, KeyboardInterrupt):
                        return last_exit_code
                    b_low = b_act.lower()
                    if b_low in {"q", "quit", "exit"}:
                        return last_exit_code
                    if b_low in {"", "n", "new"}:
                        break
                    if b_low in {"l", "list"}:
                        render_batch_list(batch_data, stream=out, no_color=no_color)
                        continue
                    if b_low in {"i", "inspect"}:
                        try:
                            query = input_fn("Sample name or # (e.g. SIM001 or 1): ").strip()
                        except (EOFError, KeyboardInterrupt):
                            return last_exit_code
                        selected: tuple[str, ScanReport] | None = None
                        if query.isdigit():
                            q_idx = int(query)
                            if 1 <= q_idx <= len(batch_data["reports"]):
                                n_sel, _, r_sel = batch_data["reports"][q_idx - 1]
                                selected = (n_sel, r_sel)
                        else:
                            selected = by_name.get(query.lower())
                        if selected is None:
                            _print(
                                f"  [yellow]Sample '{query}' not found in batch.[/yellow]",
                                f"  Sample '{query}' not found in batch.",
                            )
                        else:
                            render_scan_summary(
                                selected[1],
                                stream=out,
                                no_color=no_color,
                                show_banner=False,
                            )
                            render_scan_details(selected[1], stream=out, no_color=no_color)
                        continue
                    if b_low in {"s", "save"}:
                        suggested = default_report_filename(target_path, is_batch=True)
                        try:
                            raw_out = input_fn(f"Save Batch JSON path [{suggested}]: ").strip()
                        except (EOFError, KeyboardInterrupt):
                            return last_exit_code
                        out_path = normalize_user_path(raw_out) if raw_out else suggested
                        try:
                            out_path.parent.mkdir(parents=True, exist_ok=True)
                            out_path.write_text(serialize_batch_report(batch_data), encoding="utf-8")
                            _print(
                                f"  [bold green]Saved Batch JSON report to:[/bold green] {out_path}",
                                f"  Saved Batch JSON report to: {out_path}",
                            )
                        except OSError as error:
                            _print(
                                f"  [bold red]Failed to save Batch JSON report:[/bold red] {error}",
                                f"  Failed to save Batch JSON report: {error}",
                            )
                        continue
                    _print(
                        "  [yellow]Choose \\[I] Inspect Sample, \\[L] List All, \\[S] Save Batch JSON, \\[N] New Scan, or \\[Q] Quit.[/yellow]",
                        "  Choose [I] Inspect Sample, [L] List All, [S] Save Batch JSON, [N] New Scan, or [Q] Quit.",
                    )
                continue

        _print(
            f"\n  [bold #c084fc]Scanning target:[/bold #c084fc] {target_path}",
            f"\n  Scanning target: {target_path}",
        )
        progress_cb = make_stage_progress_callback(stream=out, no_color=no_color)
        report = scan_fn(target_path, on_stage=progress_cb, **scan_kwargs)
        last_exit_code = int(report.exit_code if report.exit_code is not None else 2)
        history.append((str(target_path), report))

        out.write("\n")
        render_scan_summary(
            report,
            stream=out,
            no_color=no_color,
            show_banner=True,
            show_action_bar=True,
        )

        # Post-scan action loop: [D] Details / [S] Save JSON / [N] New Scan / [Q] Quit
        while True:
            try:
                action = input_fn("mac [D/S/N/Q] > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return last_exit_code

            if action in {"q", "quit", "exit"}:
                return last_exit_code
            if action in {"", "n", "new"}:
                break
            if action in {"d", "detail", "details"}:
                render_scan_details(report, stream=out, no_color=no_color)
                continue
            if action in {"s", "save"}:
                suggested = default_report_filename(target_path)
                try:
                    raw_out = input_fn(f"Save JSON path [{suggested}]: ").strip()
                except (EOFError, KeyboardInterrupt):
                    return last_exit_code
                out_path = normalize_user_path(raw_out) if raw_out else suggested
                try:
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    out_path.write_text(report.to_json(), encoding="utf-8")
                    _print(
                        f"  [bold green]Saved JSON report to:[/bold green] {out_path}",
                        f"  Saved JSON report to: {out_path}",
                    )
                except OSError as error:
                    _print(
                        f"  [bold red]Failed to save JSON report:[/bold red] {error}",
                        f"  Failed to save JSON report: {error}",
                    )
                continue
            _print(
                "  [yellow]Choose \\[D] Details, \\[S] Save JSON, \\[N] New Scan, or \\[Q] Quit.[/yellow]",
                "  Choose [D] Details, [S] Save JSON, [N] New Scan, or [Q] Quit.",
            )
