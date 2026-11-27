"""Unified static scan orchestrator for mcp-scanner (v1.0 contract).

Coordinates Tier 1 (resilient source inventory, package.json analysis, 1-pass
Semgrep CE) and Tier 2 (Python AST M/C/S/obfuscation hook) under a monotonic
server deadline (50s analysis cutoff inside a 60s hard cap).
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .models import (
    PROVISIONAL_SCORE_CAP,
    AnalysisBoundary,
    CoverageInfo,
    ExecutiveSummary,
    Finding,
    InputProvenance,
    LlmTriageTelemetry,
    ReviewQueueState,
    ScannerIdentity,
    ScanReport,
    ScanTelemetry,
    SourceSpan,
    TopFindingSummary,
    TraceStep,
    TrustScore,
    compute_exit_code,
    stable_sha256_id,
)
from .p_detector import PDetectionResult, detect_surface_instructions
from .p_surface import extract_python_tool_descriptions
from .p_schema import extract_python_input_schema_descriptions
from .p_resource import extract_python_resource_metadata, extract_python_resource_bodies
from .p_prompt import extract_python_prompt_metadata, extract_python_prompt_messages
from .p_js import extract_js_surfaces
from .p_tool_result import extract_python_tool_results
from .p_relations import analyze_instruction_relations, RELATION_VERSION
from .mcp_config_analyzer import McpConfigAnalysisResult, analyze_mcp_config_files
from .package_json_analyzer import PackageJsonAnalysisResult, analyze_package_json_files
from .sca_adapter import ScaAnalysisResult, analyze_sca_offline
from .semgrep_adapter import (
    SemgrepV1Result,
    discover_default_rule_files,
    scan_inventory_with_semgrep,
)
from .source_inventory import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES,
    SourceInventory,
    collect_source_inventory,
    is_mcp_config_filename,
)

DEFAULT_BUDGET_CUTOFF_SECONDS = 50.0
DEFAULT_HARD_TIMEOUT_SECONDS = 60.0

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

_EVIDENCE_RANK: dict[str, int] = {
    "verified": 3,
    "traced_or_grounded": 2,
    "heuristic_only": 1,
}

_BASE_PENALTY: dict[str, float] = {
    "critical": 85.0,
    "high": 55.0,
    "medium": 25.0,
    "low": 6.0,
    "info": 0.0,
}

_EVIDENCE_MULTIPLIER: dict[str, float] = {
    "verified": 1.0,
    "traced_or_grounded": 0.75,
    "heuristic_only": 0.5,
}

# Explicit rule-ID -> behavior_class mapping allowed for unambiguous Semgrep <-> Python AST fallback merge.
_EXPLICIT_AST_BEHAVIOR_MAP: dict[str, str] = {
    "mcp-py-command-injection": "command_injection",
}

_PROFILE_SOURCE_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
)
_UNCONDITIONALLY_UNCOVERED_SKIP_REASONS: frozenset[str] = frozenset(
    {"symlink_escape", "symlink_not_followed", "special_file"}
)
_PROFILE_UNCOVERED_SKIP_REASONS: frozenset[str] = frozenset(
    {"file_too_large", "minified_file", "binary_file"}
)


def _is_valid_positive_finite(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) > 0.0
    )


def _is_profile_source_path(rel_path: str) -> bool:
    p = Path(rel_path)
    if p.suffix.lower() in _PROFILE_SOURCE_EXTENSIONS:
        return True
    name = p.name.lower()
    if name in {"package.json", "binding.gyp", "pyproject.toml"}:
        return True
    if name.startswith("requirements") and name.endswith(".txt"):
        return True
    if is_mcp_config_filename(name):
        return True
    return False


def _uncovered_skipped_reasons(inventory: SourceInventory) -> list[str]:
    """Identify skipped inventory entries that represent real static coverage gaps."""
    link_counts: dict[str, int] = {}
    profile_counts: dict[str, int] = {}
    for item in inventory.skipped_files:
        if item.reason in _UNCONDITIONALLY_UNCOVERED_SKIP_REASONS:
            link_counts[item.reason] = link_counts.get(item.reason, 0) + 1
        elif item.reason in _PROFILE_UNCOVERED_SKIP_REASONS and _is_profile_source_path(item.path):
            profile_counts[item.reason] = profile_counts.get(item.reason, 0) + 1

    reasons: list[str] = []
    for reason in sorted(link_counts):
        reasons.append(f"{link_counts[reason]} uninspected link/special entry skipped ({reason})")
    for reason in sorted(profile_counts):
        reasons.append(f"{profile_counts[reason]} profile source/config file(s) skipped ({reason})")
    return reasons


def _infer_ast_behavior_class(finding: Finding) -> str | None:
    return _EXPLICIT_AST_BEHAVIOR_MAP.get(finding.rule_id)


def _span_contains(outer: SourceSpan, inner: SourceSpan) -> bool:
    """Return True if outer span covers inner span within the same file."""
    if outer.path != inner.path:
        return False
    if outer.start_line is None or inner.start_line is None:
        return False
    if outer.end_line is not None:
        o_start = (outer.start_line, outer.start_col or 1)
        o_end = (outer.end_line, outer.end_col if outer.end_col is not None else 10**9)
        i_start = (inner.start_line, inner.start_col or 1)
        i_end = (
            inner.end_line if inner.end_line is not None else inner.start_line,
            inner.end_col if inner.end_col is not None else (inner.start_col or 1),
        )
        return o_start <= i_start and i_end <= o_end
    if outer.start_line != inner.start_line:
        return False
    if outer.start_col is not None and inner.start_col is not None:
        return outer.start_col == inner.start_col
    return True


def _merge_two_findings(primary: Finding, secondary: Finding) -> Finding:
    """Merge secondary evidence sources into primary without double-counting."""
    merged_sources = sorted(set(primary.evidence_sources) | set(secondary.evidence_sources))
    primary.evidence_sources = merged_sources
    if primary.declaration_span is None and secondary.declaration_span is not None:
        primary.declaration_span = secondary.declaration_span
    if primary.sink_span is None and secondary.sink_span is not None:
        primary.sink_span = secondary.sink_span
    if primary.redacted_evidence is None and secondary.redacted_evidence is not None:
        primary.redacted_evidence = secondary.redacted_evidence
    return primary


def _prefer_finding(a: Finding, b: Finding) -> tuple[Finding, Finding]:
    """Return (winner, loser) preferring richer component context, severity, and evidence."""
    score_a = (
        1 if a.component != "unknown" else 0,
        _SEVERITY_RANK.get(a.severity, 0),
        _EVIDENCE_RANK.get(a.evidence_strength, 0),
        1 if a.declaration_span is not None else 0,
    )
    score_b = (
        1 if b.component != "unknown" else 0,
        _SEVERITY_RANK.get(b.severity, 0),
        _EVIDENCE_RANK.get(b.evidence_strength, 0),
        1 if b.declaration_span is not None else 0,
    )
    if score_b > score_a:
        return b, a
    return a, b


def _attach_install_script_provenance(
    findings: list[Finding],
    install_script_provenance: dict[str, list[dict[str, Any]]],
) -> None:
    """Attach file-level manifest install provenance to confirmed sink findings safely."""
    if not install_script_provenance:
        return
    for finding in findings:
        if (
            finding.kind == "capability_info"
            or finding.detector == "package_json_analyzer"
            or finding.sink_span is None
        ):
            continue
        prov_entries = install_script_provenance.get(finding.sink_span.path)
        if not prov_entries:
            continue
        if "package_json_analyzer" not in finding.evidence_sources:
            finding.evidence_sources.append("package_json_analyzer")
        existing_symbols = {step.symbol for step in finding.trace}
        prepended: list[TraceStep] = []
        for prov in prov_entries:
            sym = str(prov["symbol"])
            if sym not in existing_symbols:
                prepended.append(
                    TraceStep(
                        role="source",
                        span=prov["span"],
                        symbol=sym,
                        edge_kind="possible",
                        note="Package manifest install hook references this script file (file-level provenance; install-time reachability to this sink is unverified).",
                    )
                )
                existing_symbols.add(sym)
        if prepended:
            finding.trace = prepended + list(finding.trace)


def deduplicate_findings(
    findings: list[Finding],
    *,
    semgrep_behavior_classes: dict[str, str] | None = None,
) -> list[Finding]:
    """Deduplicate findings by (root_cause_group_id, component) with strict unambiguous AST/Semgrep fallback."""
    by_key: dict[tuple[str, str], Finding] = {}
    for item in findings:
        key = (item.root_cause_group_id, item.component)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = item
        else:
            winner, loser = _prefer_finding(existing, item)
            by_key[key] = _merge_two_findings(winner, loser)

    known_by_rcg: dict[str, list[Finding]] = {}
    for item in by_key.values():
        if item.component != "unknown":
            known_by_rcg.setdefault(item.root_cause_group_id, []).append(item)

    deduped: list[Finding] = []
    for item in by_key.values():
        if item.component == "unknown":
            matches = known_by_rcg.get(item.root_cause_group_id, [])
            if len(matches) == 1:
                _merge_two_findings(matches[0], item)
                continue
        deduped.append(item)
    if not semgrep_behavior_classes:
        return sorted(deduped, key=lambda f: f.finding_id)

    ast_findings = [
        f for f in deduped if f.detector.startswith("python_ast") and f.component != "unknown" and f.sink_span is not None
    ]
    final_findings: list[Finding] = []
    for item in deduped:
        if item.detector == "semgrep_ce" and item.component == "unknown" and item.sink_span is not None:
            sg_behavior = semgrep_behavior_classes.get(item.finding_id)
            if sg_behavior == "command_injection":
                candidates = []
                for ast_f in ast_findings:
                    assert ast_f.sink_span is not None
                    if _infer_ast_behavior_class(ast_f) != sg_behavior:
                        continue
                    if not _span_contains(ast_f.sink_span, item.sink_span):
                        continue
                    candidates.append(ast_f)
                # Strict unambiguous rule: merge ONLY when exactly 1 AST candidate matches
                if len(candidates) == 1:
                    _merge_two_findings(candidates[0], item)
                    continue
        final_findings.append(item)

    return sorted(final_findings, key=lambda f: f.finding_id)


def _compute_baseline_trust_score(
    findings: list[Finding],
    *,
    scan_status: str,
    partial_reasons: list[str],
) -> TrustScore:
    """Compute schema-compliant baseline Trust Score (6/25/55/85, max + 0.25 * top-2 indep)."""
    if scan_status in {"failed", "unsupported"}:
        return TrustScore(
            score_scope="unavailable",
            observed_score=None,
            displayed_score=None,
            provisional_cap=None,
            reason=f"Scan status is '{scan_status}'; trust score is unavailable.",
            contributing_finding_ids=[],
        )

    # Deduplicate by root_cause_group_id so one root cause contributes at most once
    best_per_group: dict[str, tuple[float, str]] = {}
    for f in findings:
        if f.kind == "capability_info" or f.severity == "info":
            continue
        base = _BASE_PENALTY.get(f.severity, 0.0)
        mult = _EVIDENCE_MULTIPLIER.get(f.evidence_strength, 0.75)
        eff = base * mult
        if f.evidence_strength == "heuristic_only":
            eff = min(eff, 20.0)
        prev = best_per_group.get(f.root_cause_group_id)
        if prev is None or eff > prev[0]:
            best_per_group[f.root_cause_group_id] = (eff, f.finding_id)

    ranked = sorted(best_per_group.values(), key=lambda x: (-x[0], x[1]))
    if not ranked:
        observed = 100
        contrib_ids: list[str] = []
    else:
        p_max, id_max = ranked[0]
        extra = ranked[1:3]
        total_risk = min(100.0, p_max + 0.25 * sum(p for p, _ in extra))
        observed = max(0, min(100, round(100.0 - total_risk)))
        contrib_ids = [id_max] + [fid for _, fid in extra]

    if scan_status == "partial":
        displayed = min(PROVISIONAL_SCORE_CAP, observed)
        detail = "; ".join(partial_reasons) if partial_reasons else "Partial coverage."
        return TrustScore(
            score_scope="provisional",
            observed_score=observed,
            displayed_score=displayed,
            provisional_cap=PROVISIONAL_SCORE_CAP,
            reason=f"Provisional score capped at {PROVISIONAL_SCORE_CAP}: {detail}",
            contributing_finding_ids=contrib_ids,
        )

    return TrustScore(
        score_scope="complete",
        observed_score=observed,
        displayed_score=observed,
        provisional_cap=None,
        reason=(
            "No risk findings detected across inspected static surfaces."
            if not contrib_ids
            else f"Computed from {len(contrib_ids)} independent finding group(s)."
        ),
        contributing_finding_ids=contrib_ids,
    )


def _build_executive_summary(
    findings: list[Finding],
    *,
    scan_status: str,
    trust_score: TrustScore,
) -> ExecutiveSummary:
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    owasp_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        if f.owasp_mapping.status == "mapped" and f.owasp_mapping.primary_id:
            oid = f.owasp_mapping.primary_id
            owasp_counts[oid] = owasp_counts.get(oid, 0) + 1

    actionable = [f for f in findings if f.kind != "capability_info" and f.severity != "info"]
    ranked = sorted(
        actionable,
        key=lambda f: (
            -_SEVERITY_RANK.get(f.severity, 0),
            -1 if f.kind == "malicious_behavior" else 0,
            -_EVIDENCE_RANK.get(f.evidence_strength, 0),
            f.finding_id,
        ),
    )

    group_components: dict[str, set[str]] = {}
    for f in actionable:
        group_components.setdefault(f.root_cause_group_id, set()).add(f.component)

    top_5: list[TopFindingSummary] = []
    seen_rcgs: set[str] = set()
    for f in ranked:
        if f.root_cause_group_id in seen_rcgs:
            continue
        seen_rcgs.add(f.root_cause_group_id)
        span = f.sink_span or f.declaration_span
        if span is not None:
            loc = f"{span.path}:{span.start_line}" if span.start_line else span.path
        else:
            loc = f.component
        shared_count = len(group_components.get(f.root_cause_group_id, set()))
        impact = (
            f"{f.reasoning} (shared across {shared_count} components)"
            if shared_count > 1
            else f.reasoning
        )
        top_5.append(
            TopFindingSummary(
                finding_id=f.finding_id,
                title=f.title,
                severity=f.severity,
                owasp_id=f.owasp_mapping.primary_id if f.owasp_mapping.status == "mapped" else None,
                impact_summary=impact,
                location=loc,
                remediation=f.remediation,
            )
        )
        if len(top_5) >= 5:
            break

    if scan_status == "failed":
        tldr = "Scan failed before completing static inspection; review diagnostics for root cause."
    elif scan_status == "partial":
        tldr = (
            f"Partial static scan completed with {len(actionable)} actionable finding(s); "
            f"trust score is provisional ({trust_score.displayed_score}/100, observed {trust_score.observed_score}/100)."
        )
    elif actionable:
        tldr = (
            f"Static scan detected {len(actionable)} actionable finding(s) "
            f"(Critical: {sev_counts['critical']}, High: {sev_counts['high']}, Medium: {sev_counts['medium']}); "
            f"Trust Score {trust_score.displayed_score}/100."
        )
    else:
        tldr = (
            f"No actionable security findings detected in inspected static surfaces "
            f"(Trust Score {trust_score.displayed_score}/100; {sev_counts['info']} informational item(s))."
        )

    return ExecutiveSummary(
        tldr=tldr,
        severity_counts=sev_counts,
        owasp_counts=owasp_counts,
        top_5=top_5,
    )


def _build_review_queue(
    findings: list[Finding],
    *,
    scan_status: str,
    partial_reasons: list[str],
) -> ReviewQueueState:
    reasons: list[str] = []
    has_high_or_crit = any(f.severity in {"high", "critical"} for f in findings)
    has_malicious = any(f.kind == "malicious_behavior" for f in findings)

    if has_high_or_crit:
        reasons.append("Contains CRITICAL or HIGH severity findings")
    if has_malicious:
        reasons.append("Contains malicious_behavior findings")

    if has_high_or_crit or has_malicious:
        return ReviewQueueState(
            requires_review=True,
            priority_tier="p0_high_or_malicious",
            reasons=reasons,
            status="pending",
        )

    if scan_status in {"partial", "failed"}:
        return ReviewQueueState(
            requires_review=True,
            priority_tier="p1_partial_coverage",
            reasons=partial_reasons or [f"Incomplete scan status: {scan_status}"],
            status="pending",
        )

    return ReviewQueueState(
        requires_review=False,
        priority_tier="none",
        reasons=[],
        status="not_required",
    )


def _invoke_python_ast(
    inventory: SourceInventory,
    *,
    server_id: str,
    deadline: float,
) -> tuple[dict[str, Any], float]:
    """Call Branch B's analyze_python_snapshot() safely if available."""
    t0 = time.monotonic()
    try:
        from .python_ast import analyze_python_snapshot
    except ImportError:
        return (
            {
                "available": False,
                "status": "skipped" if not inventory.python_files() else "unavailable",
                "discovered_servers": [],
                "findings": [],
                "surfaces": {},
                "analysis_boundaries": [],
                "diagnostics": (
                    [{"kind": "python_ast_unavailable", "message": "python_ast module not yet installed."}]
                    if inventory.python_files()
                    else []
                ),
                "frameworks": [],
            },
            time.monotonic() - t0,
        )

    try:
        res = analyze_python_snapshot(inventory, server_id=server_id, deadline=deadline)
        return (
            {
                "available": True,
                "status": res.status,
                "discovered_servers": list(res.discovered_servers),
                "findings": list(res.findings),
                "surfaces": dict(res.surfaces),
                "analysis_boundaries": list(res.analysis_boundaries),
                "diagnostics": list(res.diagnostics),
                "frameworks": list(res.frameworks),
            },
            time.monotonic() - t0,
        )
    except Exception as error:  # pragma: no cover - defensive isolation
        return (
            {
                "available": True,
                "status": "failed",
                "discovered_servers": [],
                "findings": [],
                "surfaces": {},
                "analysis_boundaries": [],
                "diagnostics": [
                    {
                        "kind": "python_ast_exception",
                        "message": f"{type(error).__name__}: Python AST analysis failed unexpectedly.",
                    }
                ],
                "frameworks": [],
            },
            time.monotonic() - t0,
        )


def run_scan(
    target: Path,
    *,
    server_id: str | None = None,
    source_id: str | None = None,
    input_kind: str | None = None,
    revision: str | None = None,
    package_name: str | None = None,
    package_version: str | None = None,
    rules: Sequence[Path] | None = None,
    semgrep: str = "semgrep",
    windows_temp: Path | None = None,
    enable_semgrep: bool = True,
    enable_python_ast: bool = True,
    enable_p_detector: bool = True,
    strict_p: bool = False,
    enable_sca: bool = True,
    osv_db: Path | None = None,
    osv_db_sha256: str | None = None,
    osv_scanner: str | None = None,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
    budget_cutoff_seconds: float = DEFAULT_BUDGET_CUTOFF_SECONDS,
    hard_timeout_seconds: float = DEFAULT_HARD_TIMEOUT_SECONDS,
    on_stage: Callable[[str, str], None] | None = None,
) -> ScanReport:
    """Execute the end-to-end static scan pipeline and return a canonical v1.0 ScanReport."""
    if strict_p and not enable_p_detector:
        raise ValueError("Strict P coverage requires the P detector")
    profile = "static-p-strict" if strict_p else "static-default"
    scan_start = time.monotonic()
    stage_durations: dict[str, float] = {}
    diagnostics: list[dict[str, Any]] = []

    def _notify(stage: str, detail: str) -> None:
        if on_stage is not None:
            try:
                on_stage(stage, detail)
            except Exception:
                pass

    if not _is_valid_positive_finite(budget_cutoff_seconds) or not _is_valid_positive_finite(hard_timeout_seconds):
        elapsed = time.monotonic() - scan_start
        fallback_server_id = server_id or stable_sha256_id({"target": str(target)})
        err_msg = "budget_cutoff_seconds and hard_timeout_seconds must be finite positive numbers."
        return ScanReport(
            scanner=ScannerIdentity(version=__version__, profile=profile),
            input_provenance=InputProvenance(
                server_id=fallback_server_id,
                source_id=source_id,
                input_kind=input_kind or "local_directory",
                location=str(target),
                revision=revision,
                package_name=package_name,
                package_version=package_version,
                snapshot_sha256=stable_sha256_id({"error": err_msg}),
            ),
            scan_status="failed",
            policy_status="not_evaluated",
            telemetry=ScanTelemetry(
                elapsed_seconds=elapsed,
                stage_durations_seconds={},
                budget_cutoff_seconds=DEFAULT_BUDGET_CUTOFF_SECONDS,
                hard_timeout_seconds=DEFAULT_HARD_TIMEOUT_SECONDS,
            ),
            trust_score=TrustScore(
                score_scope="unavailable",
                reason=f"Invalid scan configuration: {err_msg}",
            ),
            executive_summary=ExecutiveSummary(
                tldr=f"Scan failed: {err_msg}",
            ),
            review_queue=ReviewQueueState(
                requires_review=True,
                priority_tier="p1_partial_coverage",
                reasons=[f"Configuration error: {err_msg}"],
                status="pending",
            ),
            diagnostics=[{"kind": "configuration", "message": err_msg}],
        )

    cutoff_sec = float(budget_cutoff_seconds)
    hard_sec = float(hard_timeout_seconds)
    effective_cutoff = min(cutoff_sec, hard_sec)
    deadline = scan_start + effective_cutoff
    analysis_boundaries: list[AnalysisBoundary] = [
        AnalysisBoundary(
            kind="runtime_only_unobserved",
            location=None,
            detail="Static/snapshot scan only; runtime-only behavior is not executed or observed.",
        )
    ]

    # Stage 1: Resilient source inventory
    _notify("inventory:start", "Collecting source inventory")
    t0 = time.monotonic()
    try:
        inventory = collect_source_inventory(
            target,
            input_kind=input_kind,
            max_file_bytes=max_file_bytes,
            max_files=max_files,
            deadline=deadline,
        )
    except (FileNotFoundError, OSError, ValueError) as error:
        elapsed = time.monotonic() - scan_start
        fallback_server_id = server_id or stable_sha256_id({"target": str(target)})
        return ScanReport(
            scanner=ScannerIdentity(version=__version__, profile=profile),
            input_provenance=InputProvenance(
                server_id=fallback_server_id,
                source_id=source_id,
                input_kind=input_kind or "local_directory",
                location=str(target),
                revision=revision,
                package_name=package_name,
                package_version=package_version,
                snapshot_sha256=stable_sha256_id({"error": str(error)}),
            ),
            scan_status="failed",
            policy_status="not_evaluated",
            telemetry=ScanTelemetry(
                elapsed_seconds=elapsed,
                stage_durations_seconds={"tier1_inventory": elapsed},
                budget_cutoff_seconds=cutoff_sec,
                hard_timeout_seconds=hard_sec,
            ),
            trust_score=TrustScore(
                score_scope="unavailable",
                reason=f"Target could not be inventoried: {error}",
            ),
            executive_summary=ExecutiveSummary(
                tldr=f"Scan failed: {error}",
            ),
            review_queue=ReviewQueueState(
                requires_review=True,
                priority_tier="p1_partial_coverage",
                reasons=[f"Inventory failed: {error}"],
                status="pending",
            ),
            diagnostics=[{"kind": "inventory_error", "message": str(error)}],
        )
    stage_durations["tier1_inventory"] = time.monotonic() - t0
    _notify(
        "inventory:done",
        f"{len(inventory.files)} file(s), {stage_durations['tier1_inventory'] * 1000:.0f}ms",
    )

    resolved_server_id = server_id or stable_sha256_id(
        {"root_name": inventory.root.name, "snapshot_sha256": inventory.snapshot_sha256}
    )

    if inventory.timed_out:
        analysis_boundaries.append(
            AnalysisBoundary(
                kind="budget_exceeded",
                location=None,
                detail="Source inventory reached analysis cutoff deadline.",
            )
        )

    # Stage 2: package.json static analysis (Branch C)
    _notify("package_json:start", "Inspecting package.json manifests")
    t0 = time.monotonic()
    pkg_result: PackageJsonAnalysisResult = analyze_package_json_files(
        inventory, server_id=resolved_server_id, deadline=deadline
    )
    stage_durations["tier1_package_json"] = time.monotonic() - t0
    _notify(
        "package_json:done",
        f"{pkg_result.status}, {stage_durations['tier1_package_json'] * 1000:.0f}ms",
    )
    diagnostics.extend(pkg_result.diagnostics)
    analysis_boundaries.extend(pkg_result.analysis_boundaries)

    # Stage 2b: MCP launcher configuration static analysis
    _notify("mcp_config:start", "Inspecting MCP launcher configurations")
    t0 = time.monotonic()
    mcp_cfg_result: McpConfigAnalysisResult = analyze_mcp_config_files(
        inventory, server_id=resolved_server_id, deadline=deadline
    )
    stage_durations["tier1_mcp_config"] = time.monotonic() - t0
    _notify(
        "mcp_config:done",
        f"{mcp_cfg_result.status}, {stage_durations['tier1_mcp_config'] * 1000:.0f}ms",
    )
    diagnostics.extend(mcp_cfg_result.diagnostics)
    analysis_boundaries.extend(mcp_cfg_result.analysis_boundaries)

    # Stage 3: Python AST engine (Branch B hook)
    _notify("python_ast:start", "Running Python AST analysis")
    if enable_python_ast:
        py_data, py_dur = _invoke_python_ast(
            inventory, server_id=resolved_server_id, deadline=deadline
        )
        stage_durations["tier2_python_ast"] = py_dur
    else:
        py_data = {
            "available": False,
            "status": "skipped",
            "discovered_servers": [],
            "findings": [],
            "surfaces": {},
            "analysis_boundaries": [],
            "diagnostics": [],
            "frameworks": [],
        }
    _notify(
        "python_ast:done",
        f"{len(py_data['findings'])} finding(s), {stage_durations.get('tier2_python_ast', 0.0) * 1000:.0f}ms",
    )
    diagnostics.extend(py_data["diagnostics"])
    analysis_boundaries.extend(py_data["analysis_boundaries"])

    # Analyze supported English Python metadata through shared P rules.
    t0 = time.monotonic()
    p_result = PDetectionResult()
    p_texts = []
    relation_status = "skipped"
    p_static_surfaces = {"tool_description", "input_schema_description",
                         "resource_metadata", "prompt_metadata"}
    p_static_incomplete = False
    p_tool_result_incomplete = False
    p_surfaces = {
        "tool_description": "skipped",
        "input_schema_description": "skipped",
        "resource_metadata": "skipped",
        "resource_body": "skipped",
        "prompt_metadata": "skipped",
        "prompt_message": "skipped",
        "tool_result": "skipped",
    }
    if enable_p_detector and inventory.python_files():
        if not enable_python_ast or py_data["status"] in {"failed", "unavailable"}:
            p_result.status = "partial"
            p_result.diagnostics.append({
                "code": "P_DISCOVERY_UNAVAILABLE",
                "message": "Python discovery is required for P metadata analysis.",
            })
            p_surfaces = {key: "partial" for key in p_surfaces}
        else:
            extractors = (
                ("tool_description", extract_python_tool_descriptions),
                ("input_schema_description", extract_python_input_schema_descriptions),
                ("resource_metadata", extract_python_resource_metadata),
                ("resource_body", extract_python_resource_bodies),
                ("prompt_metadata", extract_python_prompt_metadata),
                ("prompt_message", extract_python_prompt_messages),
                ("tool_result", extract_python_tool_results),
            )
            for surface, extract in extractors:
                try:
                    extracted = extract(inventory, py_data["discovered_servers"], deadline=deadline)
                    p_texts.extend(extracted.texts)
                    detected = detect_surface_instructions(extracted.texts, deadline=deadline)
                    p_result.findings.extend(detected.findings)
                    p_result.diagnostics.extend(extracted.diagnostics)
                    p_result.diagnostics.extend(detected.diagnostics)
                    if "partial" in {extracted.status, detected.status, py_data["status"]}:
                        p_result.status = "partial"
                        p_surfaces[surface] = "partial"
                    else:
                        p_surfaces[surface] = "scanned" if extracted.texts else "none_found"
                except Exception as error:
                    p_result.status = "partial"
                    p_surfaces[surface] = "failed"
                    p_result.diagnostics.append({
                        "code": "P_ANALYSIS_ERROR", "surface": surface,
                        "message": f"{type(error).__name__}: P metadata analysis failed.",
                    })
        p_static_incomplete = any(
            p_surfaces[surface] in {"partial", "failed"} for surface in p_static_surfaces
        )
        p_tool_result_incomplete = p_surfaces["tool_result"] == "partial"
    elif enable_p_detector:
        p_surfaces = {key: "unmeasured" for key in p_surfaces}
    if enable_p_detector and inventory.js_ts_files():
        try:
            js_result = extract_js_surfaces(inventory, server_id=resolved_server_id, deadline=deadline)
            p_texts.extend(js_result.texts)
            detected = detect_surface_instructions(js_result.texts, deadline=deadline)
            p_result.findings.extend(detected.findings)
            p_result.diagnostics.extend(js_result.diagnostics)
            js_parser_unavailable = any(
                diagnostic.get("code") == "P_JS_PARSER_UNAVAILABLE"
                for diagnostic in js_result.diagnostics
            )
            if js_parser_unavailable:
                analysis_boundaries.append(AnalysisBoundary(
                    kind="external_lib", location=None,
                    detail="JS/TS P surfaces could not be measured because the optional parser is unavailable.",
                ))
            p_static_incomplete |= any(
                js_result.surfaces[surface] == "partial" for surface in p_static_surfaces
            )
            p_tool_result_incomplete |= js_result.surfaces["tool_result"] == "partial"
            p_result.diagnostics.extend(detected.diagnostics)
            if "partial" in {js_result.status, detected.status}:
                p_result.status = "partial"
            for surface, js_state in js_result.surfaces.items():
                previous = p_surfaces[surface]
                if "partial" in {previous, js_state} or previous == "failed":
                    p_surfaces[surface] = "partial"
                elif js_parser_unavailable and previous in {"scanned", "none_found"}:
                    p_surfaces[surface] = "partial"
                elif "scanned" in {previous, js_state}:
                    p_surfaces[surface] = "scanned"
                elif "none_found" in {previous, js_state}:
                    p_surfaces[surface] = "none_found"
                else:
                    p_surfaces[surface] = js_state
        except Exception as error:
            p_result.status = "partial"
            p_surfaces = {
                key: "partial" if state in {"scanned", "none_found", "partial"} else "failed"
                for key, state in p_surfaces.items()
            }
            p_result.diagnostics.append({"code": "P_JS_ANALYSIS_ERROR",
                "message": f"{type(error).__name__}: JS/TS P extraction failed."})
    # Offline composition consumes only approved text and existing core facts.
    # This is a separate bounded analysis scope; it never executes target code.
    if enable_p_detector:
        try:
            relations = analyze_instruction_relations(inventory, py_data["discovered_servers"],
                p_texts, [*py_data["findings"], *p_result.findings], deadline=deadline)
            relation_status = relations.status
            if p_result.status == "partial":
                relation_status = "partial"
            if inventory.js_ts_files():
                relation_status = "partial"
                relations.diagnostics.append({"code": "P_RELATION_JS_UNSUPPORTED",
                    "scope": "Python handler consequence specialization only"})
                analysis_boundaries.append(AnalysisBoundary(
                    kind="runtime_only_unobserved", location=None,
                    detail="P invocation and handler consequence analysis does not cover JS/TS.",
                ))
            if any(component.get("proved_no_instruction_fields")
                   for diagnostic in p_result.diagnostics
                   if diagnostic.get("code") == "P_OUTPUT_COVERAGE_SUMMARY"
                   for component in diagnostic.get("components", [])):
                relation_status = "partial"
                relations.diagnostics.append({"code": "P_RELATION_TOKEN_SCOPE",
                    "scope": "Existing token certificates cover regex rules only, not relation analysis."})
            by_id = {finding.finding_id: finding for finding in p_result.findings}
            by_id.update({finding.finding_id: finding for finding in relations.findings})
            p_result.findings = list(by_id.values())
            p_result.diagnostics.extend(relations.diagnostics)
            if relation_status != "complete":
                p_result.status = "partial"
        except Exception as error:
            relation_status = "failed"
            p_result.status = "partial"
            p_result.diagnostics.append({"code": "P_RELATION_ANALYSIS_ERROR",
                "message": f"{type(error).__name__}: Offline relation analysis failed."})
    diagnostics.extend(p_result.diagnostics)
    p_codes = {d.get("code", "") for d in p_result.diagnostics}
    p_budget_exceeded = any(code.endswith(("_BUDGET", "_DEADLINE")) for code in p_codes)
    p_analysis_error = bool(p_codes & {
        "P_ANALYSIS_ERROR", "P_JS_ANALYSIS_ERROR", "P_RELATION_ANALYSIS_ERROR",
        "P_DISCOVERY_UNAVAILABLE", "P_JS_PARSE_ERROR", "P_JS_SOURCE_UNAVAILABLE",
        "P_SOURCE_PARSE_ERROR", "P_SOURCE_UNAVAILABLE",
        "P_RESOURCE_PARSE_ERROR", "P_RESOURCE_SOURCE_UNAVAILABLE",
        "P_PROMPT_PARSE_ERROR", "P_PROMPT_SOURCE_UNAVAILABLE", "P_OUTPUT_FILE_UNAVAILABLE",
    })
    if p_budget_exceeded:
        analysis_boundaries.append(AnalysisBoundary(
            kind="budget_exceeded", location=None,
            detail="P analysis reached its time or complexity budget.",
        ))
    if p_tool_result_incomplete:
        analysis_boundaries.append(AnalysisBoundary(
            kind="runtime_only_unobserved", location=None,
            detail="Static P analysis did not establish all possible tool results. See P surface diagnostics.",
        ))
    stage_durations["tier2_p_descriptions"] = time.monotonic() - t0

    # Stage 4: 1-pass Semgrep CE over inventory-approved code files (Branch A + C)
    _notify("semgrep:start", "Running Semgrep CE rules (Python + JS/TS)")
    t0 = time.monotonic()
    if enable_semgrep and inventory.code_files():
        rule_files = list(rules) if rules is not None else discover_default_rule_files()
        sg_result = scan_inventory_with_semgrep(
            inventory,
            rule_files,
            server_id=resolved_server_id,
            semgrep=semgrep,
            deadline=deadline,
            windows_temp=windows_temp,
        )
    else:
        sg_result = SemgrepV1Result(status="skipped")
    stage_durations["tier1_semgrep"] = time.monotonic() - t0
    _notify(
        "semgrep:done",
        f"{sg_result.status}, {stage_durations['tier1_semgrep']:.2f}s",
    )
    diagnostics.extend(sg_result.diagnostics)
    analysis_boundaries.extend(sg_result.analysis_boundaries)

    # Stage 4b: Offline SCA over approved lockfiles/manifests (K3.2 — strictly offline)
    t0 = time.monotonic()
    sca_result: ScaAnalysisResult = analyze_sca_offline(
        inventory,
        server_id=resolved_server_id,
        osv_db=osv_db,
        osv_db_sha256=osv_db_sha256,
        osv_scanner=osv_scanner,
        enabled=enable_sca,
        deadline=deadline,
    )
    stage_durations["tier1_sca"] = time.monotonic() - t0
    diagnostics.extend(sca_result.diagnostics)
    analysis_boundaries.extend(sca_result.analysis_boundaries)

    # Stage 5: Deduplicate & assemble canonical ScanReport
    t0 = time.monotonic()
    raw_findings: list[Finding] = []
    raw_findings.extend(pkg_result.findings)
    raw_findings.extend(mcp_cfg_result.findings)
    raw_findings.extend(sca_result.findings)
    raw_findings.extend(py_data["findings"])
    raw_findings.extend(sg_result.findings)
    raw_findings.extend(p_result.findings)
    findings = deduplicate_findings(
        raw_findings, semgrep_behavior_classes=sg_result.behavior_classes
    )

    # Attach file-level install-time hook/binding.gyp provenance to findings confirmed by AST/Semgrep detectors
    _attach_install_script_provenance(findings, pkg_result.install_script_provenance)

    partial_reasons: list[str] = []
    if p_budget_exceeded:
        partial_reasons.append("P analysis reached its time or complexity budget")
    if p_analysis_error or p_static_incomplete:
        partial_reasons.append("P analysis failed or could not cover static metadata")
    if strict_p and p_result.status == "partial":
        partial_reasons.append("Strict P coverage is incomplete")
    if inventory.read_errors:
        partial_reasons.append(f"{len(inventory.read_errors)} file(s) unreadable (IO/AV error)")
    if inventory.skipped_budget:
        partial_reasons.append(f"{len(inventory.skipped_budget)} file(s) skipped due to budget/deadline")
    if inventory.timed_out:
        partial_reasons.append("Inventory timed out at cutoff deadline")

    uncovered_skipped = _uncovered_skipped_reasons(inventory)
    partial_reasons.extend(uncovered_skipped)

    if pkg_result.status == "partial":
        if any(b.kind == "budget_exceeded" for b in pkg_result.analysis_boundaries):
            partial_reasons.append("package.json analysis reached cutoff deadline")
        if any(d.get("kind") == "package_json_parse_error" for d in pkg_result.diagnostics):
            partial_reasons.append("Malformed package.json encountered")
        uninspected_hooks = sum(
            1 for d in pkg_result.diagnostics if d.get("kind") == "lifecycle_script_uninspected"
        )
        if uninspected_hooks:
            partial_reasons.append(
                f"{uninspected_hooks} npm install lifecycle script target(s) could not be inspected"
            )
        uninspected_gyp = sum(
            1 for d in pkg_result.diagnostics if d.get("kind") == "binding_gyp_script_uninspected"
        )
        if uninspected_gyp:
            partial_reasons.append(
                f"{uninspected_gyp} binding.gyp install-time command target(s) could not be inspected"
            )

    if mcp_cfg_result.status == "partial":
        if any(b.kind == "budget_exceeded" for b in mcp_cfg_result.analysis_boundaries):
            partial_reasons.append("MCP configuration analysis reached cutoff deadline")
        if any(d.get("kind") == "mcp_config_parse_error" for d in mcp_cfg_result.diagnostics):
            partial_reasons.append("Malformed MCP configuration JSON encountered")
        if any(d.get("kind") == "mcp_config_invalid_structure" for d in mcp_cfg_result.diagnostics):
            partial_reasons.append("Unsupported or invalid MCP configuration structure encountered")

    py_files = inventory.python_files()
    py_has_dynamic_dispatch = any(
        b.kind == "dynamic_dispatch" for b in py_data["analysis_boundaries"]
    )
    py_has_unsupported_stmt = any(
        d.get("code") == "UNSUPPORTED_PYTHON_STATEMENT" for d in py_data["diagnostics"]
    )
    if py_files:
        if not enable_python_ast:
            partial_reasons.append("Python source files not analyzed (Python AST disabled)")
        else:
            if py_data["status"] in {"partial", "failed", "unavailable"}:
                partial_reasons.append(f"Python AST engine status: {py_data['status']}")
            if py_has_dynamic_dispatch:
                dd_reason = "Python AST encountered unresolved dynamic dispatch affecting coverage"
                if dd_reason not in partial_reasons:
                    partial_reasons.append(dd_reason)
            if py_has_unsupported_stmt:
                stmt_reason = "Python AST encountered unsupported statement syntax"
                if stmt_reason not in partial_reasons:
                    partial_reasons.append(stmt_reason)

    if sca_result.engine_mode != "disabled" and sca_result.status in {"partial", "failed"}:
        partial_reasons.append(f"Offline SCA coverage incomplete ({sca_result.status})")

    js_ts_files = inventory.js_ts_files()
    js_ts_surface_status: str | None = None
    if js_ts_files:
        js_ts_langs = {r.language for r in js_ts_files}
        sg_scanned_set = set(sg_result.scanned_files)
        if not enable_semgrep:
            js_ts_surface_status = "skipped"
            partial_reasons.append("JS/TS source files not analyzed (Semgrep CE disabled)")
        elif sg_result.status == "failed":
            js_ts_surface_status = "failed"
            partial_reasons.append("JS/TS Semgrep CE analysis failed")
        elif not js_ts_langs.issubset(sg_result.rule_languages):
            missing_langs = sorted(js_ts_langs - sg_result.rule_languages)
            js_ts_surface_status = "unmeasured_no_rules"
            partial_reasons.append(
                f"No active Semgrep rules loaded for language(s): {', '.join(missing_langs)}"
            )
        elif sg_result.status in {"partial", "skipped"}:
            js_ts_surface_status = sg_result.status
            partial_reasons.append(f"JS/TS Semgrep CE coverage incomplete ({sg_result.status})")
        elif any(r.rel_path not in sg_scanned_set for r in js_ts_files):
            js_ts_surface_status = "partial"
            partial_reasons.append("Some JS/TS source files were not scanned by Semgrep CE")
        else:
            js_ts_surface_status = "scanned"

    if enable_semgrep and inventory.code_files() and sg_result.status in {"partial", "failed"}:
        sg_reason = f"Semgrep CE status: {sg_result.status}"
        if sg_reason not in partial_reasons:
            partial_reasons.append(sg_reason)

    if not inventory.files and inventory.read_errors:
        scan_status = "failed"
    elif not inventory.files:
        scan_status = "partial"
        partial_reasons.append("No readable source files scanned")
    elif partial_reasons:
        scan_status = "partial"
    else:
        scan_status = "complete"

    has_actionable = any(
        f.kind != "capability_info" and f.severity in {"critical", "high", "medium"}
        for f in findings
    )
    if scan_status == "failed":
        policy_status = "not_evaluated"
    elif has_actionable:
        policy_status = "fail"
    else:
        policy_status = "pass" if scan_status == "complete" else "not_evaluated"

    trust_score = _compute_baseline_trust_score(
        findings, scan_status=scan_status, partial_reasons=partial_reasons
    )
    executive_summary = _build_executive_summary(
        findings, scan_status=scan_status, trust_score=trust_score
    )
    review_queue = _build_review_queue(
        findings, scan_status=scan_status, partial_reasons=partial_reasons
    )

    has_config_files = bool(
        inventory.package_json_files() or inventory.binding_gyp_files() or inventory.mcp_config_files()
    )
    config_partial = pkg_result.status == "partial" or mcp_cfg_result.status == "partial"
    surfaces: dict[str, str] = {
        "bootstrap": "scanned" if (inventory.files and scan_status == "complete") else "partial",
        "config": (
            ("partial" if config_partial else "scanned")
            if has_config_files
            else "none_found"
        ),
    }
    surfaces.update(py_data["surfaces"])
    surfaces.update({f"p_{key}": value for key, value in p_surfaces.items()})
    if py_files and enable_python_ast and (py_has_dynamic_dispatch or py_has_unsupported_stmt):
        for key in ("tools", "resources", "prompts", "bootstrap"):
            if key in surfaces and surfaces[key] == "scanned":
                surfaces[key] = "partial"
    if py_files and not enable_python_ast:
        surfaces["python_code"] = "skipped"
    if js_ts_surface_status is not None:
        surfaces["js_ts_code"] = js_ts_surface_status

    merged_skipped = list(inventory.skipped_files) + list(sg_result.skipped_files)
    coverage = CoverageInfo(
        files_discovered=inventory.files_discovered,
        files_scanned=len(inventory.files),
        scanned_files=[r.rel_path for r in inventory.files],
        skipped_files=merged_skipped,
        read_errors=list(inventory.read_errors),
        skipped_budget=list(inventory.skipped_budget),
        surfaces=surfaces,
        sca_status=sca_result.status,
        analysis_boundaries=analysis_boundaries,
    )

    frameworks = sorted(set(pkg_result.frameworks) | set(py_data["frameworks"]))
    inv_status = (
        "partial"
        if (inventory.read_errors or inventory.timed_out or inventory.skipped_budget or uncovered_skipped)
        else "complete"
    )
    py_engine_status = (
        "partial"
        if (py_data["status"] == "complete" and (py_has_dynamic_dispatch or py_has_unsupported_stmt))
        else py_data["status"]
    )
    engines: list[dict[str, Any]] = [
        {"name": "source_inventory", "version": __version__, "status": inv_status},
        {"name": "package_json_analyzer", "version": __version__, "status": pkg_result.status},
        {"name": "mcp_config_analyzer", "version": __version__, "status": mcp_cfg_result.status},
        {
            "name": "sca_osv",
            "version": __version__,
            "mode": sca_result.engine_mode,
            "db_sha256": sca_result.db_sha256,
            "db_snapshot_id": sca_result.db_snapshot_id,
            "status": "skipped" if sca_result.status == "unmeasured" else sca_result.status,
        },
        {"name": "python_ast", "version": __version__, "status": py_engine_status},
        {"name": "p_offline_relations", "version": RELATION_VERSION,
         "status": relation_status, "language": "en", "mode": "offline",
         "scope": "bounded-invocation-grammar-python-specialized-consequences"},
        *[
            {"name": f"p_{surface}", "version": "0.1",
             "status": {"scanned": "complete", "none_found": "complete",
                        "unmeasured": "skipped"}.get(status, status),
             "language": "en", "scope": f"{'python-js-ts' if inventory.js_ts_files() else 'python'}-{surface}-heuristics"}
            for surface, status in p_surfaces.items()
        ],
        {
            "name": "semgrep",
            "edition": "OSS",
            "version": sg_result.engine_version,
            "exit_code": sg_result.exit_code,
            "status": sg_result.status,
        },
    ]

    stage_durations["tier4_report"] = time.monotonic() - t0
    elapsed_total = time.monotonic() - scan_start
    timed_out_any = inventory.timed_out or any(
        b.kind == "budget_exceeded" for b in analysis_boundaries
    )

    return ScanReport(
        scanner=ScannerIdentity(
            name="mcp-scanner",
            version=__version__,
            profile=profile,
            ruleset_sha256=sg_result.ruleset_sha256,
            engines=engines,
        ),
        input_provenance=InputProvenance(
            server_id=resolved_server_id,
            source_id=source_id,
            input_kind=inventory.input_kind,
            location=str(inventory.root),
            revision=revision,
            package_name=package_name,
            package_version=package_version,
            snapshot_sha256=inventory.snapshot_sha256,
            languages=inventory.languages,
            frameworks=frameworks,
        ),
        scan_status=scan_status,
        policy_status=policy_status,
        exit_code=compute_exit_code(scan_status, policy_status),
        coverage=coverage,
        telemetry=ScanTelemetry(
            elapsed_seconds=elapsed_total,
            stage_durations_seconds=stage_durations,
            budget_cutoff_seconds=cutoff_sec,
            hard_timeout_seconds=hard_sec,
            timed_out=timed_out_any,
            llm_triage=LlmTriageTelemetry(enabled=False, status="disabled"),
        ),
        discovered_servers=py_data["discovered_servers"],
        trust_score=trust_score,
        executive_summary=executive_summary,
        findings=findings,
        review_queue=review_queue,
        diagnostics=diagnostics,
    )
