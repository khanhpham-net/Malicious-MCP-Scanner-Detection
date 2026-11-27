"""Static analyzer for MCP launcher configuration files (mcp.json / claude_desktop_config.json).

Inspects declared server ``command`` and ``args`` statically using bounded shell/process
semantics without executing anything and without leaking raw command arguments into reports.
"""

from __future__ import annotations

import json
import posixpath
import re
import time
from dataclasses import dataclass, field
from typing import Any

from .models import (
    AnalysisBoundary,
    Finding,
    OwaspMapping,
    RedactedEvidence,
    SourceSpan,
    TraceStep,
    make_finding_id,
    make_root_cause_group_id,
)
from .package_json_analyzer import _SUSPICIOUS_SCRIPT_RULES
from .python_ast.process_effects import SENSITIVE_TRANSFER, fixed_process_effect
from .source_inventory import SourceFileRecord, SourceInventory

_SHELL_RUNNERS: frozenset[str] = frozenset(
    {"bash", "sh", "zsh", "dash", "ksh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
)
_INLINE_INTERPRETERS: frozenset[str] = frozenset({"node", "nodejs", "python", "python3", "bun", "deno"})
_INLINE_FLAGS: frozenset[str] = frozenset(
    {"-c", "-lc", "/c", "-e", "--eval", "-enc", "-encodedcommand", "-command"}
)
_SHORT_SHELL_C_FLAG_RE = re.compile(r"-[eiluxc]+")


@dataclass
class McpConfigAnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    analysis_boundaries: list[AnalysisBoundary] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    status: str = "complete"


def _find_entry_line(raw_text: str, section_key: str, entry_key: str) -> int | None:
    """Locate 1-based line number of entry_key within section_key when present."""
    sec_re = re.compile(rf'"{re.escape(section_key)}"\s*:')
    key_re = re.compile(rf'"{re.escape(entry_key)}"\s*:')
    lines = raw_text.splitlines()
    in_section = False
    for idx, line in enumerate(lines, start=1):
        if not in_section:
            if sec_re.search(line):
                in_section = True
                if key_re.search(line.split(":", 1)[1]):
                    return idx
        elif key_re.search(line):
            return idx
    for idx, line in enumerate(lines, start=1):
        if key_re.search(line):
            return idx
    return 1 if lines else None


def _has_inline_execution_flag(prog: str, str_args: list[str]) -> bool:
    for tok in str_args:
        low = tok.lower()
        if low in _INLINE_FLAGS:
            return True
        if prog in _SHELL_RUNNERS and _SHORT_SHELL_C_FLAG_RE.fullmatch(low) and "c" in low:
            return True
    return False


def _classify_launcher_argv(command: str, str_args: list[str]) -> tuple[
    str, str, str, str, str, str, list[str], OwaspMapping
] | None:
    """Classify a launcher argv without executing it; returns metadata tuple or None."""
    argv = [command, *str_args]
    effect = fixed_process_effect(None, argv, shell=False)
    if effect == SENSITIVE_TRANSFER:
        return (
            "mcp-config-launcher-sensitive-transfer",
            "S",
            "critical",
            "malicious_behavior",
            "MCP launcher configuration transmits sensitive data over network",
            effect,
            ["CWE-200"],
            OwaspMapping(
                status="mapped",
                primary_id="MCP01:2025",
                primary_name="Token Mismanagement and Secret Exposure",
                predicate_rationale="MCP server launcher command pipes environment or credential data to a network client.",
            ),
        )
    if effect is not None:
        return (
            "mcp-config-launcher-risky-command",
            "C",
            "critical",
            "malicious_behavior",
            "MCP launcher configuration executes a high-risk shell command",
            effect,
            ["CWE-78"],
            OwaspMapping(
                status="mapped",
                primary_id="MCP05:2025",
                primary_name="Command Injection & Execution",
                predicate_rationale="MCP server launcher command invokes a high-risk shell or destructive operation.",
            ),
        )

    prog = posixpath.basename(command.replace("\\", "/")).lower()
    if (prog in _SHELL_RUNNERS or prog in _INLINE_INTERPRETERS) and _has_inline_execution_flag(prog, str_args):
        cmd_str = " ".join(argv)
        for rule_id, severity, kind, _title, pat, safe_label, _rationale, _remed in _SUSPICIOUS_SCRIPT_RULES:
            if pat.search(cmd_str):
                if rule_id == "mcp-pkg-lifecycle-env-exfil":
                    return (
                        "mcp-config-launcher-sensitive-transfer",
                        "S",
                        "critical",
                        "malicious_behavior",
                        "MCP launcher configuration transmits sensitive data over network",
                        safe_label,
                        ["CWE-200"],
                        OwaspMapping(
                            status="mapped",
                            primary_id="MCP01:2025",
                            primary_name="Token Mismanagement and Secret Exposure",
                            predicate_rationale="MCP server launcher command combines network utilities with environment or credential sources.",
                        ),
                    )
                return (
                    "mcp-config-launcher-risky-command",
                    "C",
                    severity,
                    kind,
                    "MCP launcher configuration executes a high-risk shell command",
                    safe_label,
                    ["CWE-78"],
                    OwaspMapping(
                        status="mapped",
                        primary_id="MCP05:2025",
                        primary_name="Command Injection & Execution",
                        predicate_rationale="MCP server launcher command matched a suspicious shell or inline execution pattern.",
                    ),
                )
    return None


def _analyze_single_mcp_config(
    record: SourceFileRecord,
    *,
    server_id: str,
) -> tuple[list[Finding], list[dict[str, Any]]]:
    findings: list[Finding] = []
    diagnostics: list[dict[str, Any]] = []

    if record.text is None:
        return findings, diagnostics

    try:
        payload = json.loads(record.text)
    except (json.JSONDecodeError, ValueError, RecursionError) as error:
        diagnostics.append(
            {
                "kind": "mcp_config_parse_error",
                "path": record.rel_path,
                "line": getattr(error, "lineno", None),
                "message": f"Malformed or unsupported JSON in {record.rel_path} ({type(error).__name__}).",
            }
        )
        return findings, diagnostics

    if not isinstance(payload, dict):
        diagnostics.append(
            {
                "kind": "mcp_config_invalid_structure",
                "path": record.rel_path,
                "reason": "top_level_not_object",
                "message": f"Top-level JSON in {record.rel_path} must be an object.",
            }
        )
        return findings, diagnostics

    present_sections = [k for k in ("mcpServers", "servers") if k in payload]
    if not present_sections:
        if posixpath.basename(record.rel_path).lower() != "claude_desktop_config.json":
            diagnostics.append(
                {
                    "kind": "mcp_config_invalid_structure",
                    "path": record.rel_path,
                    "reason": "missing_servers_object",
                    "message": f"MCP configuration {record.rel_path} has no 'mcpServers' or 'servers' object.",
                }
            )
        return findings, diagnostics

    for top_key in present_sections:
        section = payload[top_key]
        if not isinstance(section, dict):
            diagnostics.append(
                {
                    "kind": "mcp_config_invalid_structure",
                    "path": record.rel_path,
                    "section": top_key,
                    "reason": "servers_section_not_object",
                    "message": f"Field '{top_key}' in {record.rel_path} must be an object.",
                }
            )
            continue
        for entry_name in sorted(section.keys()):
            cfg = section[entry_name]
            if not isinstance(entry_name, str) or not entry_name.strip() or not isinstance(cfg, dict):
                diagnostics.append(
                    {
                        "kind": "mcp_config_invalid_structure",
                        "path": record.rel_path,
                        "section": top_key,
                        "reason": "server_entry_not_object",
                        "message": f"Server entry under '{top_key}' in {record.rel_path} must be an object.",
                    }
                )
                continue
            if "command" in cfg:
                command = cfg["command"]
                if not isinstance(command, str) or not command.strip():
                    diagnostics.append(
                        {
                            "kind": "mcp_config_invalid_structure",
                            "path": record.rel_path,
                            "section": top_key,
                            "reason": "invalid_command_field",
                            "message": f"Server entry under '{top_key}' in {record.rel_path} has a missing or non-string 'command'.",
                        }
                    )
                    continue
                raw_args = cfg.get("args")
                if (
                    "args" in cfg
                    and raw_args is not None
                    and (not isinstance(raw_args, list) or any(not isinstance(a, str) for a in raw_args))
                ):
                    diagnostics.append(
                        {
                            "kind": "mcp_config_invalid_structure",
                            "path": record.rel_path,
                            "section": top_key,
                            "reason": "invalid_args_field",
                            "message": f"Server entry under '{top_key}' in {record.rel_path} has non-string-array 'args'.",
                        }
                    )
                    continue
                str_args = list(raw_args) if isinstance(raw_args, list) else []
            else:
                url_val = cfg.get("url") if "url" in cfg else cfg.get("serverUrl")
                valid_remote = (
                    ("url" in cfg or "serverUrl" in cfg)
                    and isinstance(url_val, str)
                    and bool(url_val.strip())
                    and "args" not in cfg
                )
                if not valid_remote:
                    diagnostics.append(
                        {
                            "kind": "mcp_config_invalid_structure",
                            "path": record.rel_path,
                            "section": top_key,
                            "reason": "missing_command_or_url",
                            "message": f"Server entry under '{top_key}' in {record.rel_path} lacks a valid 'command' or 'url' transport definition.",
                        }
                    )
                continue

            classified = _classify_launcher_argv(command, str_args)
            if classified is None:
                continue

            rule_id, category, severity, kind, title, safe_label, cwes, owasp = classified
            line_no = _find_entry_line(record.text, top_key, entry_name)
            escaped_entry = entry_name.replace("~", "~0").replace("/", "~1")
            json_pointer = f"/{top_key}/{escaped_entry}"
            span = SourceSpan(
                path=record.rel_path,
                start_line=line_no,
                end_line=line_no,
                json_pointer=json_pointer,
            )
            component = f"config:{entry_name}"
            finding_id = make_finding_id(server_id, rule_id, span)
            rcg_id = make_root_cause_group_id(server_id, component, rule_id, span)
            loc_suffix = f":{line_no}" if line_no is not None else ""
            safe_snippet = (
                f"{record.rel_path}{loc_suffix} ({json_pointer}): "
                f"launcher command matched {rule_id} [{safe_label}]"
            )
            remediation = (
                "Remove credential transmission from MCP launcher configuration and rotate exposed secrets."
                if category == "S"
                else "Replace shell wrapper commands in MCP launcher configuration with direct, audited server executables."
            )
            findings.append(
                Finding(
                    finding_id=finding_id,
                    root_cause_group_id=rcg_id,
                    server_id=server_id,
                    component=component,
                    rule_id=rule_id,
                    rule_version="0.5",
                    detector="mcp_config_analyzer",
                    kind=kind,
                    category=category,
                    severity=severity,
                    evidence_strength="verified",
                    confidence=0.95 if severity == "critical" else 0.85,
                    mcp_surface="A3",
                    title=f"{title} ({entry_name})",
                    reasoning=f"MCP launcher entry '{entry_name}' in {record.rel_path}: {safe_label}.",
                    remediation=remediation,
                    owasp_mapping=owasp,
                    cwe_ids=cwes,
                    sink_span=span,
                    trace=[
                        TraceStep(
                            role="sink",
                            span=span,
                            symbol=f"{record.rel_path}#{top_key}.{entry_name}",
                            edge_kind="definite",
                        )
                    ],
                    redacted_evidence=RedactedEvidence(snippet=safe_snippet, secrets_redacted=True),
                    limitations=[
                        "Static inspection only; MCP launcher command was never executed and raw arguments are omitted to avoid leaking secrets.",
                    ],
                    evidence_sources=["mcp_config_analyzer"],
                    review_status="pending" if severity in {"high", "critical"} or kind == "malicious_behavior" else "not_required",
                )
            )

    return findings, diagnostics


def analyze_mcp_config_files(
    inventory: SourceInventory,
    *,
    server_id: str,
    deadline: float | None = None,
) -> McpConfigAnalysisResult:
    """Inspect all MCP launcher configuration JSON manifests in a SourceInventory."""
    cfg_files = inventory.mcp_config_files()
    if not cfg_files:
        return McpConfigAnalysisResult(status="skipped")

    all_findings: list[Finding] = []
    all_diagnostics: list[dict[str, Any]] = []
    all_boundaries: list[AnalysisBoundary] = []
    timed_out = False

    for record in cfg_files:
        if deadline is not None and time.monotonic() >= deadline:
            timed_out = True
            all_boundaries.append(
                AnalysisBoundary(
                    kind="budget_exceeded",
                    location=record.rel_path,
                    detail="Deadline reached before analyzing remaining MCP config files.",
                )
            )
            break
        f_list, diags = _analyze_single_mcp_config(record, server_id=server_id)
        all_findings.extend(f_list)
        all_diagnostics.extend(diags)

    status = "partial" if (all_diagnostics or timed_out) else "complete"
    return McpConfigAnalysisResult(
        findings=all_findings,
        analysis_boundaries=all_boundaries,
        diagnostics=all_diagnostics,
        status=status,
    )
