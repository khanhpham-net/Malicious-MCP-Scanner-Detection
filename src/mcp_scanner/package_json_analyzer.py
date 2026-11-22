"""Static analyzer for package.json manifests in MCP server snapshots.

Detects MCP JS/TS frameworks and suspicious npm lifecycle scripts
(preinstall/install/postinstall/prepare/prepublish) without ever executing
npm or any target code, and without leaking raw script literals into reports.
"""

from __future__ import annotations

import json
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
from .source_inventory import SourceFileRecord, SourceInventory

LIFECYCLE_HOOKS: frozenset[str] = frozenset(
    {
        "preinstall",
        "install",
        "postinstall",
        "prepare",
        "prepublish",
        "prepublishOnly",
        "prepack",
        "postpack",
    }
)

MCP_JS_PACKAGES: dict[str, str] = {
    "@modelcontextprotocol/sdk": "mcp-ts-sdk",
    "fastmcp": "fastmcp-js",
    "mcp-framework": "mcp-framework",
    "@modelcontextprotocol/server-everything": "mcp-ts-sdk",
}

# (rule_id, severity, kind, title, pattern, safe_indicator_label, rationale, remediation)
_SUSPICIOUS_SCRIPT_RULES: tuple[tuple[str, str, str, str, re.Pattern[str], str, str, str], ...] = (
    (
        "mcp-pkg-lifecycle-download-exec",
        "critical",
        "malicious_behavior",
        "Suspicious npm lifecycle script downloads and executes remote payload",
        re.compile(
            r"(?i)(?:\b(?:curl|wget|fetch|iwr|invoke-webrequest)\b[^|&;\n]*(?:\|\s*(?:ba|z|da|k|a)?sh\b|\|\s*(?:pwsh|powershell|node|python3?)\b|&&\s*(?:chmod\s+\+x|\./|sh\b|bash\b|node\b|python3?\b)))"
        ),
        "remote download piped/chained to shell or interpreter",
        "Package lifecycle hook downloads remote content and pipes or chains it directly into a shell or interpreter during install.",
        "Remove remote fetch-and-execute commands from npm lifecycle scripts and pin verified build artifacts instead.",
    ),
    (
        "mcp-pkg-lifecycle-reverse-shell",
        "critical",
        "malicious_behavior",
        "Suspicious npm lifecycle script contains reverse-shell or interactive network shell pattern",
        re.compile(
            r"(?i)(?:/dev/tcp/|/dev/udp/|\bnc(?:at)?\b[^\n]*(?:-e\b|-c\b)|\bbash\s+-i\b|\bmkfifo\b[^\n]*\bnc\b)"
        ),
        "reverse-shell network primitive",
        "Package lifecycle hook invokes a reverse-shell network primitive during installation.",
        "Remove the malicious lifecycle hook immediately and audit the package provenance.",
    ),
    (
        "mcp-pkg-lifecycle-obfuscated-exec",
        "high",
        "malicious_behavior",
        "Suspicious npm lifecycle script decodes obfuscated payload into execution",
        re.compile(
            r"(?i)(?:"
            r"\bbase64\s+(?:-d|--decode)\b[^\n]*(?:\|\s*(?:ba|z)?sh\b|\|\s*node\b|\|\s*python3?\b|\beval\b)"
            r"|\bpowershell(?:\.exe)?\b[^\n]*(?:-e(?:nc(?:odedcommand)?)?\b)"
            r"|\b(?:eval|Function|execSync|exec|spawnSync|spawn|runInNewContext|runInThisContext)\b[^\n]*\b(?:Buffer\.from\s*\([^)]*['\"](?:base64|hex)['\"]\s*\)|atob\s*\()"
            r"|\b(?:Buffer\.from\s*\([^)]*['\"](?:base64|hex)['\"]\s*\)|atob\s*\()[^\n]*(?:\b(?:eval|Function|execSync|exec|spawnSync|spawn|runInNewContext|runInThisContext)\b|\|\s*(?:ba|z)?sh\b|\|\s*node\b)"
            r")"
        ),
        "encoded payload decoded into execution sink",
        "Package lifecycle hook decodes an encoded payload into a shell or interpreter execution sink during install.",
        "Replace obfuscated install-time execution with transparent, auditable build scripts.",
    ),
    (
        "mcp-pkg-lifecycle-env-exfil",
        "critical",
        "malicious_behavior",
        "Suspicious npm lifecycle script transmits environment or credential files over network",
        re.compile(
            r"(?i)\b(?:curl|wget|nc)\b[^\n]*(?:\benv\b|\bprintenv\b|process\.env|\$\{?[A-Z_]*(?:TOKEN|KEY|SECRET|PASS|AWS|NPM)[A-Z_]*\}?|~/\.ssh|~/\.aws|\.npmrc|\.env\b)"
        ),
        "network utility paired with environment/credential source",
        "Package lifecycle hook combines network transmission tools with environment variables or credential paths.",
        "Remove outbound secret/environment transmission from package install scripts and rotate any exposed credentials.",
    ),
    (
        "mcp-pkg-lifecycle-inline-dynamic-exec",
        "high",
        "vulnerability",
        "Suspicious npm lifecycle script runs inline interpreter accessing network, env, or child_process",
        re.compile(
            r"(?i)\b(?:node\s+(?:-e|--eval)\b|python3?\s+-c\b)[^\n]*(?:https?://|child_process|execSync|spawnSync|process\.env|os\.environ|\beval\s*\(|\bexec\s*\(|urllib|requests\.|fetch\s*\()"
        ),
        "inline interpreter with network/env/process execution primitive",
        "Package lifecycle hook runs inline code referencing network, process execution, or environment variables.",
        "Eliminate inline network/shell evaluation from lifecycle hooks and inspect the script payload.",
    ),
)


@dataclass
class PackageJsonAnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    analysis_boundaries: list[AnalysisBoundary] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    status: str = "complete"


def _find_script_line(raw_text: str, script_name: str) -> int | None:
    pattern = re.compile(rf'"{re.escape(script_name)}"\s*:')
    for idx, line in enumerate(raw_text.splitlines(), start=1):
        if pattern.search(line):
            return idx
    return None


def _analyze_single_package_json(
    record: SourceFileRecord,
    *,
    server_id: str,
) -> tuple[list[Finding], set[str], list[dict[str, Any]]]:
    findings: list[Finding] = []
    frameworks: set[str] = set()
    diagnostics: list[dict[str, Any]] = []

    if record.text is None:
        return findings, frameworks, diagnostics

    try:
        payload = json.loads(record.text)
    except (json.JSONDecodeError, ValueError, RecursionError) as error:
        diagnostics.append(
            {
                "kind": "package_json_parse_error",
                "path": record.rel_path,
                "line": getattr(error, "lineno", None),
                "message": f"Malformed or unsupported JSON in {record.rel_path} ({type(error).__name__}).",
            }
        )
        return findings, frameworks, diagnostics

    if not isinstance(payload, dict):
        diagnostics.append(
            {
                "kind": "package_json_parse_error",
                "path": record.rel_path,
                "message": f"Top-level JSON in {record.rel_path} is not an object.",
            }
        )
        return findings, frameworks, diagnostics

    # Detect JS/TS MCP frameworks from declared dependencies
    for dep_section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = payload.get(dep_section)
        if isinstance(deps, dict):
            for pkg_name, fw_label in MCP_JS_PACKAGES.items():
                if pkg_name in deps:
                    frameworks.add(fw_label)

    scripts = payload.get("scripts")
    if not isinstance(scripts, dict):
        return findings, frameworks, diagnostics

    for hook_name in sorted(scripts.keys()):
        if hook_name not in LIFECYCLE_HOOKS:
            continue
        cmd = scripts[hook_name]
        if not isinstance(cmd, str) or not cmd.strip():
            continue

        line_no = _find_script_line(record.text, hook_name)
        span = SourceSpan(
            path=record.rel_path,
            start_line=line_no,
            end_line=line_no,
            json_pointer=f"/scripts/{hook_name}",
        )

        matched_rule = None
        for rule in _SUSPICIOUS_SCRIPT_RULES:
            if rule[4].search(cmd):
                matched_rule = rule
                break

        if matched_rule is None:
            continue

        rule_id, severity, kind, title, _pat, safe_indicator, rationale, remediation = matched_rule
        finding_id = make_finding_id(server_id, rule_id, span)
        rcg_id = make_root_cause_group_id(
            server_id=server_id,
            component="bootstrap",
            root_behavior=f"npm_lifecycle_{hook_name}",
            primary_span=span,
        )
        # Emit structural safe evidence only — never copy raw script literals into JSON reports.
        loc_suffix = f":{line_no}" if line_no is not None else ""
        safe_snippet = (
            f"{record.rel_path}{loc_suffix} (/scripts/{hook_name}): "
            f"matched {rule_id} [{safe_indicator}]"
        )
        findings.append(
            Finding(
                finding_id=finding_id,
                root_cause_group_id=rcg_id,
                server_id=server_id,
                component="bootstrap",
                rule_id=rule_id,
                rule_version="0.5",
                detector="package_json_analyzer",
                kind=kind,
                category="supply_chain",
                severity=severity,
                evidence_strength="verified",
                confidence=0.92 if severity == "critical" else 0.85,
                mcp_surface="A3",
                title=f"{title} ({hook_name})",
                reasoning=f"Lifecycle script '{hook_name}' in {record.rel_path}: {rationale}",
                remediation=remediation,
                owasp_mapping=OwaspMapping(
                    status="mapped",
                    primary_id="MCP04:2025",
                    primary_name="Software Supply Chain Attacks and Dependency Tampering",
                    llm_top10_ids=("LLM03:2025",),
                    predicate_rationale=f"Suspicious npm install/build lifecycle hook '{hook_name}' detected in package.json.",
                ),
                cwe_ids=["CWE-506"],
                sink_span=span,
                trace=[
                    TraceStep(
                        role="sink",
                        span=span,
                        symbol=f"package.json#scripts.{hook_name}",
                        edge_kind="definite",
                    )
                ],
                redacted_evidence=RedactedEvidence(snippet=safe_snippet, secrets_redacted=True),
                limitations=[
                    "Static inspection only; lifecycle script was never executed and raw command arguments are omitted to avoid leaking secrets.",
                ],
                evidence_sources=["package_json_analyzer"],
                review_status="pending" if severity in {"high", "critical"} else "not_required",
            )
        )

    return findings, frameworks, diagnostics


def analyze_package_json_files(
    inventory: SourceInventory,
    *,
    server_id: str,
    deadline: float | None = None,
) -> PackageJsonAnalysisResult:
    """Inspect all package.json files present in a SourceInventory."""
    pkg_files = inventory.package_json_files()
    if not pkg_files:
        return PackageJsonAnalysisResult(status="skipped")

    all_findings: list[Finding] = []
    all_frameworks: set[str] = set()
    all_diagnostics: list[dict[str, Any]] = []
    all_boundaries: list[AnalysisBoundary] = []
    timed_out = False

    for record in pkg_files:
        if deadline is not None and time.monotonic() >= deadline:
            timed_out = True
            all_boundaries.append(
                AnalysisBoundary(
                    kind="budget_exceeded",
                    location=record.rel_path,
                    detail="Deadline reached before analyzing remaining package.json files.",
                )
            )
            break
        f_list, fws, diags = _analyze_single_package_json(record, server_id=server_id)
        all_findings.extend(f_list)
        all_frameworks.update(fws)
        all_diagnostics.extend(diags)

    status = "partial" if (all_diagnostics or timed_out) else "complete"
    return PackageJsonAnalysisResult(
        findings=all_findings,
        frameworks=sorted(all_frameworks),
        analysis_boundaries=all_boundaries,
        diagnostics=all_diagnostics,
        status=status,
    )
