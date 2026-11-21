"""Run Semgrep CE against local source and produce a v0.1 finding artifact."""

from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryFile
from typing import Any

from . import __version__

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
