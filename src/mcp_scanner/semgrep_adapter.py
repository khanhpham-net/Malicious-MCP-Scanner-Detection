"""Run Semgrep CE against local source and produce a v0.1 finding artifact."""

from __future__ import annotations

import hashlib
import importlib.resources
import json
import math
import os
import re
import shutil
import subprocess
import time
from collections.abc import Sequence
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory, TemporaryFile
from typing import Any

from . import __version__
from .models import (
    AnalysisBoundary,
    Finding,
    OwaspMapping,
    RedactedEvidence,
    SkippedFile,
    SourceSpan,
    TraceStep,
    make_finding_id,
    make_root_cause_group_id,
    stable_sha256_id,
)
from .source_inventory import SourceInventory

SEVERITIES = {
    "INFO": "info",
    "LOW": "low",
    "WARNING": "medium",
    "MEDIUM": "medium",
    "ERROR": "high",
    "HIGH": "high",
    "CRITICAL": "critical",
}


def _identifier(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=True).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _relative_path(value: str, root: Path) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("Expected a non-empty file path.")
    return (root / value).resolve().relative_to(root).as_posix()


def _position(value: dict[str, int]) -> dict[str, int]:
    line, column = value["line"], value["col"]
    if type(line) is not int or type(column) is not int or min(line, column) < 1:
        raise ValueError("Expected a one-based source position.")
    return {"line": line, "column": column}


def _normalize_report(
    raw: dict[str, Any], root: Path, server_id: str, returncode: int
) -> dict[str, Any]:
    paths = raw["paths"]
    scanned = sorted({_relative_path(path, root) for path in paths["scanned"]})
    skipped = [
        {"path": _relative_path(item["path"], root), "reason": item.get("reason")}
        for item in (paths.get("skipped") or [])
    ]
    diagnostics = [
        {
            "kind": "semgrep_error",
            "type": error["type"],
            "code": error.get("code"),
            "level": error.get("level"),
        }
        for error in raw["errors"]
    ]
    skipped_rules = raw.get("skipped_rules") or []
    if skipped_rules:
        diagnostics.append({"kind": "skipped_rules", "count": len(skipped_rules)})

    findings: dict[str, dict[str, Any]] = {}
    evidence: dict[str, dict[str, Any]] = {}
    for match in raw["results"]:
        rule_id = match["check_id"]
        details = match["extra"]
        location = {
            "path": _relative_path(match["path"], root),
            "start": _position(match["start"]),
            "end": _position(match["end"]),
        }
        finding_id = _identifier([server_id, rule_id, location])
        evidence_id = _identifier([server_id, location])
        findings[finding_id] = {
            "finding_id": finding_id,
            "server_id": server_id,
            "rule_id": rule_id,
            "severity": SEVERITIES[details["severity"]],
            "title": details["message"],
            "evidence_ids": [evidence_id],
        }
        evidence[evidence_id] = {"evidence_id": evidence_id, **location}

    if returncode and not diagnostics:
        diagnostics.append({"kind": "semgrep_exit", "code": returncode})
        status = "failed"
    elif (returncode or diagnostics) and not scanned:
        status = "failed"
    elif returncode or diagnostics or skipped:
        status = "partial"
    else:
        status = "complete"
    if not scanned:
        diagnostics.append({"kind": "no_scanned_files"})
        if status == "complete":
            status = "partial"

    return {
        "status": status,
        "items": list(findings.values()),
        "evidence": list(evidence.values()),
        "coverage": {"scanned": scanned, "skipped": skipped},
        "diagnostics": diagnostics,
    }


def scan_code(
    source: Path,
    rules: Path,
    *,
    server_id: str,
    semgrep: str = "semgrep",
    timeout: float = 60,
    windows_temp: Path | None = None,
) -> dict[str, Any]:
    """Scan a file or directory using a trusted local YAML ruleset."""
    artifact: dict[str, Any] = {
        "contract_version": "0.1",
        "artifact_type": "finding",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": {"name": "mcp-scanner.semgrep", "version": __version__},
        "status": "failed",
        "engine": {"name": "semgrep", "edition": "OSS", "version": None, "exit_code": None},
        "ruleset_sha256": None,
        "items": [],
        "evidence": [],
        "coverage": {"scanned": [], "skipped": []},
        "diagnostics": [],
    }

    try:
        if not server_id.strip():
            raise ValueError("server_id must be non-empty.")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite, positive number of seconds.")
        source, rules = source.resolve(), rules.resolve()
        if not (source.is_file() or source.is_dir()):
            raise ValueError(f"Source file or directory does not exist: {source}")
        if rules.suffix.lower() not in {".yml", ".yaml"} or not rules.is_file():
            raise ValueError(f"Expected a local .yml or .yaml rules file: {rules}")
        artifact["source"]["location"] = str(source)
        artifact["ruleset_sha256"] = hashlib.sha256(rules.read_bytes()).hexdigest()
        executable = shutil.which(semgrep)
        if executable is None or (os.name == "nt" and Path(executable).suffix.lower() != ".exe"):
            raise ValueError(f"Semgrep executable not found: {semgrep}")
        executable_path = Path(executable).resolve()
        if Path(semgrep).name == semgrep and executable_path.parent == Path.cwd().resolve():
            raise ValueError("Pass an explicit --semgrep path for an executable in the working directory.")
        executable = str(executable_path)
        env = {**os.environ, "PYTHONUTF8": "1"}
        if windows_temp is not None and os.name == "nt":
            windows_temp = windows_temp.resolve()
            windows_temp.mkdir(parents=True, exist_ok=True)
            # The Windows OCaml runtime binds a socket in the process temp directory.
            env.update(TMP=str(windows_temp), TEMP=str(windows_temp))
    except (OSError, ValueError, RuntimeError) as error:
        artifact["diagnostics"] = [{"kind": "configuration", "message": str(error)}]
        return artifact

    root = source.parent if source.is_file() else source
    target = source.name if source.is_file() else "."
    command = [
        executable, "scan", "--json", "--strict", "--verbose", "--oss-only",
        "--metrics=off", "--disable-version-check", "--no-rewrite-rule-ids",
        "--no-git-ignore", "--no-autofix", "--config", str(rules), "--", target,
    ]
    socket_error = False
    try:
        # File output lets the timeout return without waiting on pipes held by engine children.
        with TemporaryFile() as output, TemporaryFile() as errors:
            process = subprocess.run(
                command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                stdout=output, stderr=errors, timeout=timeout, check=False,
            )
            artifact["engine"]["exit_code"] = process.returncode
            output.seek(0)
            errors.seek(0)
            if process.returncode:
                socket_error = b"Invalid argument socketpair" in errors.read()
            raw = json.load(output)
        artifact["engine"]["version"] = raw["version"]
        artifact.update(_normalize_report(raw, root, server_id, process.returncode))
    except subprocess.TimeoutExpired:
        artifact["diagnostics"] = [{"kind": "timeout", "seconds": timeout}]
    except OSError as error:
        artifact["diagnostics"] = [{"kind": "launch_error", "message": str(error)}]
    except (KeyError, ValueError, TypeError, AttributeError, RuntimeError):
        artifact["diagnostics"] = [{
            "kind": "invalid_semgrep_output",
            "message": "Semgrep did not return a supported JSON report.",
        }]
    if socket_error:
        artifact["diagnostics"].append({
            "kind": "windows_socketpair",
            "message": "Use windows_temp to select a compatible local temp directory.",
        })
    return artifact


_DEFAULT_RULE_DEFAULTS: dict[str, dict[str, Any]] = {
    "mcp-shell-input": {
        "category": "C",
        "kind": "vulnerability",
        "mcp_surface": "A5",
        "behavior_class": "command_injection",
        "cwe": ["CWE-78"],
        "remediation": "Use a fixed executable with separately validated argv arguments instead of shell execution.",
    },
    "mcp-path-traversal-read": {
        "category": "other",
        "kind": "vulnerability",
        "mcp_surface": "A5",
        "behavior_class": "path_traversal_read",
        "cwe": ["CWE-22"],
        "remediation": "Resolve candidate paths and enforce Path.resolve().is_relative_to(ROOT) on a dominating control-flow branch before opening.",
    },
}

_FLASK_IMPORT_RE = re.compile(r"(?m)^\s*(?:from\s+flask\b|import\s+flask\b)")
_FASTMCP_IMPORT_RE = re.compile(r"(?m)^\s*(?:from\s+(?:mcp\.server\.fastmcp|fastmcp)\b|import\s+fastmcp\b)")
_RULE_LANG_LINE_RE = re.compile(r"(?i)\b(python|javascript|typescript|js|ts)\b")


@dataclass
class SemgrepV1Result:
    findings: list[Finding] = field(default_factory=list)
    behavior_classes: dict[str, str] = field(default_factory=dict)  # finding_id -> explicit behavior_class
    scanned_files: list[str] = field(default_factory=list)
    skipped_files: list[SkippedFile] = field(default_factory=list)
    rule_languages: set[str] = field(default_factory=set)
    analysis_boundaries: list[AnalysisBoundary] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    engine_version: str | None = None
    ruleset_sha256: str | None = None
    exit_code: int | None = None
    status: str = "skipped"  # "complete" | "partial" | "failed" | "skipped"


def discover_default_rule_files() -> list[Path]:
    """Return bundled local YAML rule files from installed package data or repo checkout."""
    candidates: list[Path] = []

    # 1. Bundled package directory inside wheel/site-packages install (mcp_scanner/rules/)
    pkg_rules = Path(__file__).resolve().parent / "rules"
    if pkg_rules.is_dir():
        candidates.append(pkg_rules)

    # 2. importlib.resources lookup (handles editable package-dir and installed distributions)
    try:
        res = importlib.resources.files("mcp_scanner.rules")
        res_path = Path(str(res))
        if res_path.is_dir() and res_path not in candidates:
            candidates.append(res_path)
    except (ImportError, ModuleNotFoundError, TypeError, OSError):
        pass

    # 3. Checkout fallback (repo_root/rules/) when running directly from src/ without install
    repo_rules = Path(__file__).resolve().parents[2] / "rules"
    if repo_rules.is_dir() and repo_rules not in candidates:
        candidates.append(repo_rules)

    for rule_dir in candidates:
        found = sorted(
            p.resolve()
            for p in rule_dir.iterdir()
            if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}
        )
        if found:
            return found
    return []


def _combined_ruleset_sha256(rule_files: Sequence[Path]) -> str:
    entries = sorted(
        (p.name, hashlib.sha256(p.read_bytes()).hexdigest())
        for p in rule_files
    )
    return stable_sha256_id(entries)


def _detect_rule_languages(rule_files: Sequence[Path]) -> set[str]:
    """Inspect declared languages in loaded YAML rule files."""
    langs: set[str] = set()
    for rf in rule_files:
        try:
            text = rf.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        in_lang_block = False
        for raw_line in text.splitlines():
            stripped = raw_line.strip()
            if stripped.startswith("languages:"):
                in_lang_block = True
                for m in _RULE_LANG_LINE_RE.findall(stripped):
                    tok = m.lower()
                    langs.add({"js": "javascript", "ts": "typescript"}.get(tok, tok))
                if "[" in stripped and "]" in stripped:
                    in_lang_block = False
            elif in_lang_block:
                if stripped.startswith("-"):
                    for m in _RULE_LANG_LINE_RE.findall(stripped):
                        tok = m.lower()
                        langs.add({"js": "javascript", "ts": "typescript"}.get(tok, tok))
                elif stripped and not stripped.startswith("#"):
                    in_lang_block = False
    return langs


def _is_false_flask_finding_on_fastmcp(rule_id: str, file_text: str | None) -> bool:
    """Suppress Flask-specific alerts (e.g. mcp-flask-no-ssl) when file actually uses FastMCP without Flask."""
    if "flask" not in rule_id.lower() or not file_text:
        return False
    has_flask = bool(_FLASK_IMPORT_RE.search(file_text))
    has_fastmcp = bool(_FASTMCP_IMPORT_RE.search(file_text))
    return has_fastmcp and not has_flask


def _structural_safe_evidence(rule_id: str, behavior_class: str, span: SourceSpan) -> RedactedEvidence:
    """Build literal-free structural evidence so arbitrary secrets cannot leak into JSON reports."""
    pos = (
        f"{span.start_line}:{span.start_col}-{span.end_line}:{span.end_col}"
        if span.start_line is not None and span.start_col is not None
        else str(span.start_line or "")
    )
    loc = f"{span.path}:{pos}" if pos else span.path
    return RedactedEvidence(
        snippet=f"{loc} matched {rule_id} ({behavior_class})",
        secrets_redacted=True,
    )


def _resolve_semgrep_executable(semgrep: str) -> str:
    executable = shutil.which(semgrep)
    if executable is None or (os.name == "nt" and Path(executable).suffix.lower() != ".exe"):
        raise ValueError(f"Semgrep executable not found: {semgrep}")
    executable_path = Path(executable).resolve()
    if Path(semgrep).name == semgrep and executable_path.parent == Path.cwd().resolve():
        raise ValueError("Pass an explicit --semgrep path for an executable in the working directory.")
    return str(executable_path)


def _is_same_or_child(candidate: Path, root: Path) -> bool:
    try:
        candidate.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def _prepare_windows_socket_temp(
    windows_temp: Path | None,
    inventory_root: Path,
    stack: ExitStack,
) -> Path | None:
    """Return a directory for TMP/TEMP on Windows, completely separate from the source staging tree."""
    if os.name != "nt":
        return None
    if windows_temp is not None:
        wt = windows_temp.resolve()
        wt.mkdir(parents=True, exist_ok=True)
        return wt
    env_wt = os.environ.get("MCP_SCANNER_WINDOWS_TEMP")
    if env_wt:
        wt = Path(env_wt).resolve()
        wt.mkdir(parents=True, exist_ok=True)
        return wt
    default_tmp = os.environ.get("TEMP") or os.environ.get("TMP") or ""
    if default_tmp and " " not in default_tmp:
        return None
    cwd_path = Path.cwd().resolve()
    if (
        " " not in str(cwd_path)
        and len(str(cwd_path)) <= 65
        and not _is_same_or_child(cwd_path, inventory_root)
    ):
        try:
            sock_dir = stack.enter_context(TemporaryDirectory(prefix="sg_", dir=str(cwd_path)))
            return Path(sock_dir).resolve()
        except OSError:
            pass
    return None


def scan_inventory_with_semgrep(
    inventory: SourceInventory,
    rules: Sequence[Path],
    *,
    server_id: str,
    semgrep: str = "semgrep",
    deadline: float | None = None,
    windows_temp: Path | None = None,
) -> SemgrepV1Result:
    """Run a single-pass Semgrep CE invocation over a private staging copy of inventory-approved files."""
    code_records = inventory.code_files()
    if not code_records:
        return SemgrepV1Result(status="skipped")

    resolved_rules = [Path(r).resolve() for r in rules]
    for rf in resolved_rules:
        if rf.suffix.lower() not in {".yml", ".yaml"} or not rf.is_file():
            return SemgrepV1Result(
                status="failed",
                diagnostics=[{"kind": "configuration", "message": f"Invalid Semgrep rules file: {rf}"}],
            )
    if not resolved_rules:
        return SemgrepV1Result(status="skipped")

    ruleset_sha = _combined_ruleset_sha256(resolved_rules)
    rule_languages = _detect_rule_languages(resolved_rules)

    try:
        executable = _resolve_semgrep_executable(semgrep)
    except ValueError as error:
        return SemgrepV1Result(
            status="failed",
            ruleset_sha256=ruleset_sha,
            rule_languages=rule_languages,
            diagnostics=[{"kind": "configuration", "message": str(error)}],
        )

    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0.25:
            return SemgrepV1Result(
                status="partial",
                ruleset_sha256=ruleset_sha,
                rule_languages=rule_languages,
                analysis_boundaries=[
                    AnalysisBoundary(
                        kind="budget_exceeded",
                        location=None,
                        detail="Insufficient remaining server deadline before running Semgrep CE.",
                    )
                ],
            )
        run_timeout = remaining
    else:
        run_timeout = 50.0

    by_path = inventory.by_rel_path()

    env = {**os.environ, "PYTHONUTF8": "1"}
    findings_by_id: dict[str, Finding] = {}
    behavior_classes: dict[str, str] = {}
    scanned_set: set[str] = set()
    skipped_list: list[SkippedFile] = []
    diagnostics: list[dict[str, Any]] = []
    boundaries: list[AnalysisBoundary] = []
    engine_version: str | None = None
    last_exit_code: int | None = None
    had_failure = False
    had_partial = False

    # Materialize ONLY inventory-approved files into a private OS-temp staging tree (strictly
    # decoupled from windows_temp / .venv so Semgrep's built-in ignore rules never exclude targets).
    with ExitStack() as stack:
        try:
            work_dir = stack.enter_context(TemporaryDirectory(prefix="mcpsg_stage_"))
        except OSError as error:
            return SemgrepV1Result(
                status="failed",
                ruleset_sha256=ruleset_sha,
                rule_languages=rule_languages,
                diagnostics=[{"kind": "staging_error", "message": f"Cannot create staging directory: {error}"}],
            )

        staging_root = (Path(work_dir).resolve() / "src")
        staging_root.mkdir(parents=True, exist_ok=True)
        # Override Semgrep's built-in default ignore list (e.g., tests/, fixtures/) inside staging
        # because SourceInventory already enforced all ignore/size/minify/symlink policies.
        (staging_root / ".semgrepignore").write_text(
            "# Inventory-approved snapshot staging root\n", encoding="utf-8"
        )

        sock_temp = _prepare_windows_socket_temp(windows_temp, inventory.root, stack)
        if sock_temp is not None:
            env.update(TMP=str(sock_temp), TEMP=str(sock_temp))

        staged_count = 0
        for record in code_records:
            if deadline is not None and time.monotonic() >= deadline:
                boundaries.append(
                    AnalysisBoundary(
                        kind="budget_exceeded",
                        location=record.rel_path,
                        detail="Deadline reached while staging inventory files for Semgrep CE.",
                    )
                )
                had_partial = True
                break
            if record.text is None:
                had_partial = True
                continue
            dest = (staging_root / record.rel_path).resolve()
            try:
                dest.relative_to(staging_root)
            except ValueError:
                skipped_list.append(SkippedFile(path=record.rel_path, reason="staging_path_rejected"))
                had_partial = True
                continue
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(record.text, encoding="utf-8")
                staged_count += 1
            except OSError as error:
                diagnostics.append(
                    {
                        "kind": "staging_write_error",
                        "path": record.rel_path,
                        "message": f"{type(error).__name__}: failed to stage file.",
                    }
                )
                had_partial = True

        if staged_count == 0:
            return SemgrepV1Result(
                status="partial" if had_partial else "skipped",
                ruleset_sha256=ruleset_sha,
                rule_languages=rule_languages,
                skipped_files=skipped_list,
                analysis_boundaries=boundaries,
                diagnostics=diagnostics,
            )

        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0.25:
                boundaries.append(
                    AnalysisBoundary(
                        kind="budget_exceeded",
                        location=None,
                        detail="Deadline reached before launching Semgrep CE subprocess.",
                    )
                )
                return SemgrepV1Result(
                    status="partial",
                    ruleset_sha256=ruleset_sha,
                    rule_languages=rule_languages,
                    skipped_files=skipped_list,
                    analysis_boundaries=boundaries,
                    diagnostics=diagnostics,
                )
            run_timeout = remaining

        command = [
            executable,
            "scan",
            "--json",
            "--strict",
            "--verbose",
            "--oss-only",
            "--metrics=off",
            "--disable-version-check",
            "--no-rewrite-rule-ids",
            "--no-git-ignore",
            "--no-autofix",
        ]
        for rf in resolved_rules:
            command.extend(["--config", str(rf)])
        command.extend(["--", "."])

        raw: dict[str, Any] | None = None
        stderr_bytes = b""
        try:
            with TemporaryFile() as output, TemporaryFile() as errors:
                process = subprocess.run(
                    command,
                    cwd=staging_root,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=errors,
                    timeout=run_timeout,
                    check=False,
                )
                last_exit_code = process.returncode
                output.seek(0)
                errors.seek(0)
                stderr_bytes = errors.read() if process.returncode else b""
                raw = json.load(output)
        except subprocess.TimeoutExpired:
            diagnostics.append({"kind": "semgrep_timeout", "seconds": round(run_timeout, 2)})
            boundaries.append(
                AnalysisBoundary(
                    kind="budget_exceeded",
                    location=None,
                    detail=f"Semgrep CE exceeded remaining budget ({round(run_timeout, 2)}s).",
                )
            )
            had_partial = True
        except OSError as error:
            diagnostics.append({"kind": "semgrep_launch_error", "message": str(error)})
            had_failure = True
        except (KeyError, ValueError, TypeError):
            diag: dict[str, Any] = {
                "kind": "invalid_semgrep_output",
                "message": "Semgrep did not return a supported JSON report.",
            }
            if b"Invalid argument socketpair" in stderr_bytes:
                diag["hint"] = "Pass --windows-temp pointing to a short ASCII directory without spaces."
            diagnostics.append(diag)
            had_failure = True

        if raw is not None:
            engine_version = raw.get("version") or engine_version
            paths_obj = raw.get("paths") or {}
            for p in paths_obj.get("scanned") or []:
                try:
                    rel = _relative_path(p, staging_root)
                    if rel in by_path:
                        scanned_set.add(rel)
                except ValueError:
                    pass
            for item in paths_obj.get("skipped") or []:
                try:
                    rel = _relative_path(item["path"], staging_root)
                except (KeyError, ValueError):
                    continue
                skipped_list.append(SkippedFile(path=rel, reason=str(item.get("reason") or "semgrep_skipped")))
                had_partial = True

            for err in raw.get("errors") or []:
                diagnostics.append(
                    {
                        "kind": "semgrep_error",
                        "type": err.get("type"),
                        "code": err.get("code"),
                        "level": err.get("level"),
                    }
                )
                had_partial = True

            if last_exit_code and not raw.get("errors"):
                diagnostics.append({"kind": "semgrep_exit", "code": last_exit_code})
                had_failure = True

            for match in raw.get("results") or []:
                rule_id = match["check_id"]
                details = match["extra"]
                try:
                    rel_path = _relative_path(match["path"], staging_root)
                except ValueError:
                    continue
                record = by_path.get(rel_path)
                file_text = record.text if record is not None else None

                # Framework-aware guard: suppress Flask-specific alerts on FastMCP files
                if _is_false_flask_finding_on_fastmcp(rule_id, file_text):
                    continue

                start_pos = _position(match["start"])
                end_pos = _position(match["end"])
                sink_span = SourceSpan(
                    path=rel_path,
                    start_line=start_pos["line"],
                    start_col=start_pos["column"],
                    end_line=end_pos["line"],
                    end_col=end_pos["column"],
                )

                meta = details.get("metadata") or {}
                defaults = _DEFAULT_RULE_DEFAULTS.get(rule_id, {})
                category = str(meta.get("category") or defaults.get("category") or "other")
                kind = str(meta.get("kind") or defaults.get("kind") or "vulnerability")
                mcp_surface = str(meta.get("mcp_surface") or defaults.get("mcp_surface") or "A5")
                behavior_class = str(meta.get("behavior_class") or defaults.get("behavior_class") or rule_id)
                raw_cwe = meta.get("cwe") if meta.get("cwe") is not None else defaults.get("cwe", [])
                cwe_ids = [raw_cwe] if isinstance(raw_cwe, str) else [str(c) for c in raw_cwe]

                severity = SEVERITIES.get(str(details.get("severity", "WARNING")).upper(), "medium")
                evidence_strength = "traced_or_grounded" if kind != "capability_info" else "verified"
                finding_id = make_finding_id(server_id, rule_id, sink_span)
                rcg_id = make_root_cause_group_id(
                    server_id=server_id,
                    component="unknown",
                    root_behavior=behavior_class,
                    primary_span=sink_span,
                )
                safe_ev = _structural_safe_evidence(rule_id, behavior_class, sink_span)
                remediation = str(
                    defaults.get("remediation")
                    or "Review the matched sink, restrict untrusted inputs, and verify alignment with declared MCP server functionality."
                )

                owasp = (
                    OwaspMapping(
                        status="not_applicable",
                        predicate_rationale="Informational capability matched by Semgrep rule.",
                    )
                    if kind == "capability_info"
                    else OwaspMapping(
                        status="pending_review",
                        predicate_rationale=f"Matched Semgrep rule '{rule_id}' ({behavior_class}); awaiting OWASP predicate enrichment.",
                    )
                )

                findings_by_id[finding_id] = Finding(
                    finding_id=finding_id,
                    root_cause_group_id=rcg_id,
                    server_id=server_id,
                    component="unknown",
                    rule_id=rule_id,
                    rule_version="0.5",
                    detector="semgrep_ce",
                    kind=kind,
                    category=category,
                    severity=severity,
                    evidence_strength=evidence_strength,
                    confidence=0.85 if severity in {"high", "critical"} else 0.75,
                    mcp_surface=mcp_surface,
                    title=str(details.get("message") or rule_id),
                    reasoning=f"Semgrep CE rule '{rule_id}' matched pattern/taint flow in {rel_path}:{sink_span.start_line}.",
                    remediation=remediation,
                    owasp_mapping=owasp,
                    cwe_ids=cwe_ids,
                    sink_span=sink_span,
                    trace=[
                        TraceStep(
                            role="sink",
                            span=sink_span,
                            symbol=rule_id,
                            edge_kind="definite",
                        )
                    ],
                    redacted_evidence=safe_ev,
                    limitations=[
                        "Semgrep CE operates intra-procedurally within a single file; cross-file flows require AST/summary correlation."
                    ],
                    evidence_sources=["semgrep_ce"],
                    review_status=(
                        "pending"
                        if severity in {"high", "critical"} or kind == "malicious_behavior"
                        else "not_required"
                    ),
                )
                behavior_classes[finding_id] = behavior_class

    if had_failure and not scanned_set:
        status = "failed"
    elif had_failure or had_partial or not scanned_set:
        status = "partial"
    else:
        status = "complete"

    return SemgrepV1Result(
        findings=sorted(findings_by_id.values(), key=lambda f: f.finding_id),
        behavior_classes=behavior_classes,
        scanned_files=sorted(scanned_set),
        skipped_files=skipped_list,
        rule_languages=rule_languages,
        analysis_boundaries=boundaries,
        diagnostics=diagnostics,
        engine_version=engine_version,
        ruleset_sha256=ruleset_sha,
        exit_code=last_exit_code,
        status=status,
    )
