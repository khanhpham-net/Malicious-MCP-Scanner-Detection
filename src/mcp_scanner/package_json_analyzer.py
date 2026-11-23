"""Static analyzer for package.json manifests in MCP server snapshots.

Detects MCP JS/TS frameworks and suspicious npm lifecycle scripts
(preinstall/install/postinstall/prepare/prepublish) without ever executing
npm or any target code, and without leaking raw script literals into reports.
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
            r"(?i)\b(?:node\s+(?:-e|--eval)\b|python3?\s+-c\b)[^\n]*(?:child_process|execSync|spawnSync|process\.env|os\.environ|\beval\s*\(|\bexec\s*\(|urllib|requests\.|fetch\s*\(|https?\.(?:request|get)\b|axios\b|net\.connect\b|socket\.)"
        ),
        "inline interpreter with network/env/process execution primitive",
        "Package lifecycle hook runs inline code referencing network, process execution, or environment variables.",
        "Eliminate inline network/shell evaluation from lifecycle hooks and inspect the script payload.",
    ),
)

_INSTALL_LIFECYCLE_HOOKS: frozenset[str] = frozenset({"preinstall", "install", "postinstall"})
_LOCAL_INTERPRETERS: frozenset[str] = frozenset(
    {"node", "nodejs", "python", "python3", "sh", "bash", "pwsh", "powershell", "powershell.exe"}
)
_INLINE_CODE_FLAGS: frozenset[str] = frozenset(
    {"-e", "--eval", "-p", "--print", "-c", "-m", "-enc", "-encodedcommand"}
)
_CMD_SPLIT_RE = re.compile(r"(?:&&|\|\||[;|\n])")
_TOKEN_RE = re.compile(r"""'([^']*)'|"([^"]*)"|(\S+)""")
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_SUPPORTED_SCRIPT_LANGUAGES: frozenset[str] = frozenset({"javascript", "typescript", "python"})


def _extract_local_script_targets(cmd: str) -> list[str]:
    """Extract local script paths invoked by install-time interpreters without executing cmd."""
    targets: list[str] = []
    for segment in _CMD_SPLIT_RE.split(cmd):
        tokens = [
            next(g for g in match.groups() if g is not None)
            for match in _TOKEN_RE.finditer(segment)
        ]
        idx = 0
        while idx < len(tokens) and _ENV_ASSIGN_RE.match(tokens[idx]):
            idx += 1
        if idx >= len(tokens):
            continue
        prog = posixpath.basename(tokens[idx].replace("\\", "/")).lower()
        if prog not in _LOCAL_INTERPRETERS:
            continue
        args = tokens[idx + 1 :]
        if any(tok.lower() in _INLINE_CODE_FLAGS for tok in args):
            continue
        arg_idx = 0
        while arg_idx < len(args):
            tok = args[arg_idx]
            low = tok.lower()
            if low in {"-f", "-file", "--file"} and arg_idx + 1 < len(args):
                cand = args[arg_idx + 1]
                if cand and not cand.startswith(("http://", "https://", "-")):
                    targets.append(cand)
                break
            if tok.startswith("-"):
                arg_idx += 1
                continue
            if not tok.startswith(("http://", "https://")):
                targets.append(tok)
            break
    return targets


def _resolve_script_rel_path(pkg_rel_path: str, raw_target: str) -> tuple[str | None, str | None]:
    """Resolve a script path relative to package.json inside the snapshot root."""
    cleaned = raw_target.strip().replace("\\", "/")
    if not cleaned or cleaned.startswith("/") or re.match(r"^[A-Za-z]:", cleaned):
        return None, "absolute_path_outside_snapshot"
    pkg_dir = posixpath.dirname(pkg_rel_path)
    joined = posixpath.normpath(posixpath.join(pkg_dir, cleaned) if pkg_dir else cleaned)
    if joined == ".." or joined.startswith("../") or joined == ".":
        return None, "path_escape_outside_snapshot"
    return joined, None


@dataclass
class PackageJsonAnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    analysis_boundaries: list[AnalysisBoundary] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    install_script_provenance: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
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
    files_by_rel: dict[str, SourceFileRecord],
    skipped_by_rel: dict[str, str],
    errors_by_rel: dict[str, str],
) -> tuple[list[Finding], set[str], list[dict[str, Any]], list[AnalysisBoundary], dict[str, list[dict[str, Any]]]]:
    findings: list[Finding] = []
    frameworks: set[str] = set()
    diagnostics: list[dict[str, Any]] = []
    boundaries: list[AnalysisBoundary] = []
    provenance: dict[str, list[dict[str, Any]]] = {}

    if record.text is None:
        return findings, frameworks, diagnostics, boundaries, provenance

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
        return findings, frameworks, diagnostics, boundaries, provenance

    if not isinstance(payload, dict):
        diagnostics.append(
            {
                "kind": "package_json_parse_error",
                "path": record.rel_path,
                "message": f"Top-level JSON in {record.rel_path} is not an object.",
            }
        )
        return findings, frameworks, diagnostics, boundaries, provenance

    # Detect JS/TS MCP frameworks from declared dependencies
    for dep_section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = payload.get(dep_section)
        if isinstance(deps, dict):
            for pkg_name, fw_label in MCP_JS_PACKAGES.items():
                if pkg_name in deps:
                    frameworks.add(fw_label)

    scripts = payload.get("scripts")
    if not isinstance(scripts, dict):
        return findings, frameworks, diagnostics, boundaries, provenance

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

        if matched_rule is not None:
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
            continue

        # For install-time hooks running local scripts (e.g. `node setup.js`), resolve and inspect the target file.
        if hook_name not in _INSTALL_LIFECYCLE_HOOKS:
            continue
        for raw_target in _extract_local_script_targets(cmd):
            resolved_rel, path_err = _resolve_script_rel_path(record.rel_path, raw_target)
            if path_err is not None or resolved_rel is None:
                diagnostics.append(
                    {
                        "kind": "lifecycle_script_uninspected",
                        "path": record.rel_path,
                        "hook": hook_name,
                        "reason": path_err or "unresolved_path",
                        "message": f"Install lifecycle hook '{hook_name}' references an unresolvable script path ({path_err}).",
                    }
                )
                boundaries.append(
                    AnalysisBoundary(
                        kind="external_lib",
                        location=record.rel_path,
                        detail=f"Install lifecycle hook '{hook_name}' references script outside snapshot root ({path_err}).",
                    )
                )
                continue

            # Resolve exact path or Node extensionless fallback (.js / .cjs / .mjs)
            candidates = [resolved_rel]
            if "." not in posixpath.basename(resolved_rel):
                candidates.extend([f"{resolved_rel}.js", f"{resolved_rel}.cjs", f"{resolved_rel}.mjs"])

            target_rec: SourceFileRecord | None = None
            matched_rel = resolved_rel
            for cand in candidates:
                if cand in files_by_rel:
                    target_rec = files_by_rel[cand]
                    matched_rel = cand
                    break

            if target_rec is not None and target_rec.text is not None:
                if target_rec.language in _SUPPORTED_SCRIPT_LANGUAGES:
                    # Keep hook->script as artifact provenance only; downstream AST/Semgrep
                    # sink/taint detectors confirm any actual vulnerability or malicious behavior.
                    provenance.setdefault(matched_rel, []).append(
                        {
                            "manifest": record.rel_path,
                            "hook": hook_name,
                            "symbol": f"package.json#scripts.{hook_name}",
                            "span": span,
                        }
                    )
                else:
                    diagnostics.append(
                        {
                            "kind": "lifecycle_script_uninspected",
                            "path": record.rel_path,
                            "hook": hook_name,
                            "target": matched_rel,
                            "reason": f"unsupported_script_language:{target_rec.language}",
                            "message": f"Install lifecycle hook '{hook_name}' invokes '{matched_rel}' (unsupported static script language: {target_rec.language}).",
                        }
                    )
                    boundaries.append(
                        AnalysisBoundary(
                            kind="external_lib",
                            location=record.rel_path,
                            detail=f"Install lifecycle hook '{hook_name}' invokes '{matched_rel}' ({target_rec.language}); no static AST/taint analyzer for this language.",
                        )
                    )
            else:
                # Target script is missing, quarantined, or skipped -> coverage gap (partial), NOT an ungrounded ALERT
                uninspected_reason = "missing_in_snapshot"
                for cand in candidates:
                    if cand in errors_by_rel:
                        uninspected_reason = errors_by_rel[cand]
                        matched_rel = cand
                        break
                    if cand in skipped_by_rel:
                        uninspected_reason = skipped_by_rel[cand]
                        matched_rel = cand
                        break
                diagnostics.append(
                    {
                        "kind": "lifecycle_script_uninspected",
                        "path": record.rel_path,
                        "hook": hook_name,
                        "target": matched_rel,
                        "reason": uninspected_reason,
                        "message": f"Install lifecycle hook '{hook_name}' invokes '{matched_rel}' which could not be inspected ({uninspected_reason}).",
                    }
                )
                boundaries.append(
                    AnalysisBoundary(
                        kind="external_lib",
                        location=record.rel_path,
                        detail=f"Install lifecycle hook '{hook_name}' references '{matched_rel}' ({uninspected_reason}); install-time payload unobserved.",
                    )
                )

    return findings, frameworks, diagnostics, boundaries, provenance


def _extract_gyp_command_expansions(raw_text: str) -> list[tuple[int, str]]:
    """Extract balanced `<!(...)` and `<!@(...)` command expansions with 1-based line numbers."""
    results: list[tuple[int, str]] = []
    idx = 0
    length = len(raw_text)
    while idx < length:
        start = raw_text.find("<!", idx)
        if start == -1:
            break
        pos = start + 2
        if pos < length and raw_text[pos] == "@":
            pos += 1
        if pos >= length or raw_text[pos] != "(":
            idx = start + 2
            continue
        depth = 1
        cursor = pos + 1
        limit = min(length, cursor + 1024)
        while cursor < limit and depth > 0:
            ch = raw_text[cursor]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch in ("\r", "\n"):
                break
            cursor += 1
        if depth == 0:
            cmd = raw_text[pos + 1 : cursor - 1].strip()
            if cmd:
                line_no = raw_text.count("\n", 0, start) + 1
                results.append((line_no, cmd))
            idx = cursor
        else:
            idx = pos + 1
    return results


def _analyze_single_binding_gyp(
    record: SourceFileRecord,
    *,
    server_id: str,
    files_by_rel: dict[str, SourceFileRecord],
    skipped_by_rel: dict[str, str],
    errors_by_rel: dict[str, str],
) -> tuple[list[Finding], list[dict[str, Any]], list[AnalysisBoundary], dict[str, list[dict[str, Any]]]]:
    """Inspect binding.gyp install-time `<!(...)` command expansions safely without execution."""
    findings: list[Finding] = []
    diagnostics: list[dict[str, Any]] = []
    boundaries: list[AnalysisBoundary] = []
    provenance: dict[str, list[dict[str, Any]]] = {}

    if record.text is None:
        return findings, diagnostics, boundaries, provenance

    for line_no, cmd in _extract_gyp_command_expansions(record.text):
        span = SourceSpan(path=record.rel_path, start_line=line_no, end_line=line_no)
        matched_rule = None
        for rule in _SUSPICIOUS_SCRIPT_RULES:
            if rule[4].search(cmd):
                matched_rule = rule
                break

        if matched_rule is not None:
            rule_id, severity, kind, title, _pat, safe_indicator, rationale, remediation = matched_rule
            finding_id = make_finding_id(server_id, rule_id, span)
            rcg_id = make_root_cause_group_id(
                server_id=server_id,
                component="bootstrap",
                root_behavior="binding_gyp_command_expansion",
                primary_span=span,
            )
            safe_snippet = (
                f"{record.rel_path}:{line_no} (binding.gyp command expansion): "
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
                    title=f"{title} (binding.gyp)",
                    reasoning=f"Install-time node-gyp command expansion in {record.rel_path}:{line_no}: {rationale}",
                    remediation=remediation,
                    owasp_mapping=OwaspMapping(
                        status="mapped",
                        primary_id="MCP04:2025",
                        primary_name="Software Supply Chain Attacks and Dependency Tampering",
                        llm_top10_ids=("LLM03:2025",),
                        predicate_rationale=f"Suspicious install-time command expansion detected in {record.rel_path}.",
                    ),
                    cwe_ids=["CWE-506"],
                    sink_span=span,
                    trace=[
                        TraceStep(
                            role="sink",
                            span=span,
                            symbol="binding.gyp#command_expansion",
                            edge_kind="definite",
                        )
                    ],
                    redacted_evidence=RedactedEvidence(snippet=safe_snippet, secrets_redacted=True),
                    limitations=[
                        "Static inspection only; node-gyp command expansion was never executed and raw command literals are omitted.",
                    ],
                    evidence_sources=["package_json_analyzer"],
                    review_status="pending" if severity in {"high", "critical"} else "not_required",
                )
            )
            continue

        for raw_target in _extract_local_script_targets(cmd):
            resolved_rel, path_err = _resolve_script_rel_path(record.rel_path, raw_target)
            if path_err is not None or resolved_rel is None:
                diagnostics.append(
                    {
                        "kind": "binding_gyp_script_uninspected",
                        "path": record.rel_path,
                        "line": line_no,
                        "reason": path_err or "unresolved_path",
                        "message": f"binding.gyp command expansion references an unresolvable script path ({path_err}).",
                    }
                )
                boundaries.append(
                    AnalysisBoundary(
                        kind="external_lib",
                        location=record.rel_path,
                        detail=f"binding.gyp command expansion references script outside snapshot root ({path_err}).",
                    )
                )
                continue

            candidates = [resolved_rel]
            if "." not in posixpath.basename(resolved_rel):
                candidates.extend([f"{resolved_rel}.js", f"{resolved_rel}.cjs", f"{resolved_rel}.mjs"])

            target_rec: SourceFileRecord | None = None
            matched_rel = resolved_rel
            for cand in candidates:
                if cand in files_by_rel:
                    target_rec = files_by_rel[cand]
                    matched_rel = cand
                    break

            if target_rec is not None and target_rec.text is not None:
                if target_rec.language in _SUPPORTED_SCRIPT_LANGUAGES:
                    provenance.setdefault(matched_rel, []).append(
                        {
                            "manifest": record.rel_path,
                            "hook": "binding.gyp",
                            "symbol": "binding.gyp#command_expansion",
                            "span": span,
                        }
                    )
                else:
                    diagnostics.append(
                        {
                            "kind": "binding_gyp_script_uninspected",
                            "path": record.rel_path,
                            "line": line_no,
                            "target": matched_rel,
                            "reason": f"unsupported_script_language:{target_rec.language}",
                            "message": f"binding.gyp command expansion invokes '{matched_rel}' (unsupported static script language: {target_rec.language}).",
                        }
                    )
                    boundaries.append(
                        AnalysisBoundary(
                            kind="external_lib",
                            location=record.rel_path,
                            detail=f"binding.gyp command expansion invokes '{matched_rel}' ({target_rec.language}); no static AST/taint analyzer for this language.",
                        )
                    )
            else:
                uninspected_reason = "missing_in_snapshot"
                for cand in candidates:
                    if cand in errors_by_rel:
                        uninspected_reason = errors_by_rel[cand]
                        matched_rel = cand
                        break
                    if cand in skipped_by_rel:
                        uninspected_reason = skipped_by_rel[cand]
                        matched_rel = cand
                        break
                diagnostics.append(
                    {
                        "kind": "binding_gyp_script_uninspected",
                        "path": record.rel_path,
                        "line": line_no,
                        "target": matched_rel,
                        "reason": uninspected_reason,
                        "message": f"binding.gyp command expansion invokes '{matched_rel}' which could not be inspected ({uninspected_reason}).",
                    }
                )
                boundaries.append(
                    AnalysisBoundary(
                        kind="external_lib",
                        location=record.rel_path,
                        detail=f"binding.gyp command expansion references '{matched_rel}' ({uninspected_reason}); install-time payload unobserved.",
                    )
                )

    return findings, diagnostics, boundaries, provenance


def analyze_package_json_files(
    inventory: SourceInventory,
    *,
    server_id: str,
    deadline: float | None = None,
) -> PackageJsonAnalysisResult:
    """Inspect all package.json and binding.gyp manifests present in a SourceInventory."""
    pkg_files = inventory.package_json_files()
    gyp_files = inventory.binding_gyp_files()
    if not pkg_files and not gyp_files:
        return PackageJsonAnalysisResult(status="skipped")

    files_by_rel = inventory.by_rel_path()
    skipped_by_rel = {s.path: s.reason for s in inventory.skipped_files}
    skipped_by_rel.update({s.path: s.reason for s in inventory.skipped_budget})
    errors_by_rel = {e.path: e.error_code for e in inventory.read_errors}

    all_findings: list[Finding] = []
    all_frameworks: set[str] = set()
    all_diagnostics: list[dict[str, Any]] = []
    all_boundaries: list[AnalysisBoundary] = []
    all_provenance: dict[str, list[dict[str, Any]]] = {}
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
        f_list, fws, diags, bounds, prov = _analyze_single_package_json(
            record,
            server_id=server_id,
            files_by_rel=files_by_rel,
            skipped_by_rel=skipped_by_rel,
            errors_by_rel=errors_by_rel,
        )
        all_findings.extend(f_list)
        all_frameworks.update(fws)
        all_diagnostics.extend(diags)
        all_boundaries.extend(bounds)
        for target_rel, entries in prov.items():
            all_provenance.setdefault(target_rel, []).extend(entries)

    if not timed_out:
        for record in gyp_files:
            if deadline is not None and time.monotonic() >= deadline:
                timed_out = True
                all_boundaries.append(
                    AnalysisBoundary(
                        kind="budget_exceeded",
                        location=record.rel_path,
                        detail="Deadline reached before analyzing remaining binding.gyp files.",
                    )
                )
                break
            f_list, diags, bounds, prov = _analyze_single_binding_gyp(
                record,
                server_id=server_id,
                files_by_rel=files_by_rel,
                skipped_by_rel=skipped_by_rel,
                errors_by_rel=errors_by_rel,
            )
            all_findings.extend(f_list)
            all_diagnostics.extend(diags)
            all_boundaries.extend(bounds)
            for target_rel, entries in prov.items():
                all_provenance.setdefault(target_rel, []).extend(entries)

    status = "partial" if (all_diagnostics or timed_out) else "complete"
    return PackageJsonAnalysisResult(
        findings=all_findings,
        frameworks=sorted(all_frameworks),
        analysis_boundaries=all_boundaries,
        diagnostics=all_diagnostics,
        install_script_provenance=all_provenance,
        status=status,
    )
