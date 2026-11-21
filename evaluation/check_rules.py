"""Compare B0 and the two code mechanisms on the same labeled local corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from mcp_scanner.semgrep_adapter import scan_code

REPO = Path(__file__).resolve().parents[1]
BASELINE = REPO / "tests/fixtures/mcp-shell-input.yaml"
RULESET = REPO / "rules/mcp-code.yaml"
CORPUS = {
    "development": REPO / "tests/fixtures/mcp-code.py",
    "reserved": REPO / "evaluation/reserved/mcp-code.py",
    "boundaries": REPO / "evaluation/boundaries/mcp-code.py",
}
RULES = ("mcp-shell-input", "mcp-path-traversal-read")
ANNOTATION = re.compile(r"\s*# (ruleid|ok|boundary): ([\w-]+)\s*")
LEGACY_FILES = (
    "file_manager_malicious_mcp/File_manager_MCP.py",
    "SQL_malicous_MCP/sql_context_mcp.py",
    "todo_malicous_MCP/todoMCP.py",
    "SQL_malicous_MCP/stager.py",
    "todo_malicous_MCP/stager.py",
)

Location = tuple[str, int, str]


def labels(root: Path) -> dict[str, set[Location]]:
    expected: dict[str, set[Location]] = {"ruleid": set(), "ok": set(), "boundary": set()}
    for path in root.glob("*/*.py"):
        for line, text in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            marker = ANNOTATION.fullmatch(text)
            if marker:
                kind, rule_id = marker.groups()
                expected[kind].add((path.relative_to(root).as_posix(), line + 1, rule_id))
    return expected


def locations(report: dict) -> set[Location]:
    evidence = {item["evidence_id"]: item for item in report["evidence"]}
    return {
        (evidence[ref]["path"], evidence[ref]["start"]["line"], item["rule_id"])
        for item in report["items"]
        for ref in item["evidence_ids"]
    }


def score(matches: set[Location], expected: dict[str, set[Location]], split: str, rule: str) -> dict:
    def select(entries: set[Location]) -> set[Location]:
        return {item for item in entries if item[0].split("/")[0] == split and item[2] == rule}

    hits = select(matches)
    positive = select(expected["ruleid"])
    negative = select(expected["ok"])
    false_positives = hits - positive
    false_negatives = positive - hits
    return {
        "tp": len(hits & positive),
        "tn": len(negative - hits),
        "fp": len(false_positives),
        "fn": len(false_negatives),
        "false_positives": sorted(false_positives),
        "false_negatives": sorted(false_negatives),
    }


def isolated_scan(root: Path, executable: str, windows_temp: Path | None, excluded: str) -> set[Location]:
    env = {**os.environ, "PYTHONUTF8": "1"}
    if os.name == "nt" and windows_temp is not None:
        env.update(TMP=str(windows_temp), TEMP=str(windows_temp))
    result = subprocess.run(
        [
            executable, "scan", "--json", "--strict", "--verbose", "--oss-only",
            "--metrics=off", "--disable-version-check", "--no-rewrite-rule-ids",
            "--no-git-ignore", "--no-autofix", "--config", str(RULESET),
            "--exclude-rule", excluded, "--", ".",
        ],
        cwd=root, env=env, stdin=subprocess.DEVNULL, capture_output=True,
        encoding="utf-8", timeout=60, check=True,
    )
    raw = json.loads(result.stdout)
    if raw["errors"] or raw.get("skipped_rules") or raw["paths"].get("skipped"):
        raise RuntimeError(f"Isolated scan excluding {excluded} did not complete.")
    scanned = {(root / path).relative_to(root).as_posix() for path in raw["paths"]["scanned"]}
    if scanned != {p.relative_to(root).as_posix() for p in root.glob("*/*.py")}:
        raise RuntimeError(f"Isolated scan excluding {excluded} did not cover the corpus.")
    return {
        ((root / match["path"]).relative_to(root).as_posix(), match["start"]["line"], match["check_id"])
        for match in raw["results"]
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", required=True, type=Path)
    parser.add_argument("--windows-temp", type=Path)
    parser.add_argument("--legacy-root", type=Path, help="optional checkout of the previous sample repository")
    args = parser.parse_args()
    executable = str(args.semgrep.resolve(strict=True))
    windows_temp = args.windows_temp.resolve() if args.windows_temp else None
    options = {"semgrep": executable, "windows_temp": windows_temp}

    with TemporaryDirectory(prefix="mcp-rule-evaluation-") as directory:
        root = Path(directory)
        for split, fixture in CORPUS.items():
            target = root / split / fixture.name
            target.parent.mkdir()
            shutil.copyfile(fixture, target)
        expected = labels(root)
        expected_files = {p.relative_to(root).as_posix() for p in root.glob("*/*.py")}
        report = {}
        expanded_matches: set[Location] = set()
        for name, ruleset in (("baseline", BASELINE), ("expanded", RULESET)):
            artifact = scan_code(root, ruleset, server_id="lab:code-evaluation", **options)
            if artifact["status"] != "complete" or set(artifact["coverage"]["scanned"]) != expected_files:
                raise RuntimeError(f"{name} scan did not cover the corpus: {artifact['diagnostics']}")
            matches = locations(artifact)
            if name == "expanded":
                expanded_matches = matches
            report[name] = {
                "engine": artifact["engine"],
                "ruleset_sha256": artifact["ruleset_sha256"],
                "scanned": artifact["coverage"]["scanned"],
                "scores": {
                    split: {rule: score(matches, expected, split, rule) for rule in RULES}
                    for split in ("development", "reserved")
                },
                "boundary_findings": sorted(
                    item for item in matches if item[0].startswith("boundaries/")
                ),
            }
        isolation = {}
        for rule, excluded in (RULES, RULES[::-1]):
            separate = isolated_scan(root, executable, windows_temp, excluded)
            isolation[rule] = separate == {item for item in expanded_matches if item[2] == rule}
        report["isolated_matches_combined"] = isolation
        report["boundary_cases"] = sorted(expected["boundary"])
        report["fixture_sha256"] = {
            split: hashlib.sha256(path.read_bytes()).hexdigest() for split, path in CORPUS.items()
        }

    legacy_incomplete = False
    if args.legacy_root:
        legacy_root = args.legacy_root.resolve(strict=True)
        report["legacy_coverage_audit"] = []
        for filename in LEGACY_FILES:
            source = (legacy_root / filename).resolve(strict=True)
            if not source.is_relative_to(legacy_root) or source.suffix != ".py":
                raise ValueError(f"Expected a Python source under the legacy root: {filename}")
            artifact = scan_code(source, RULESET, server_id=f"legacy:{filename}", **options)
            if artifact["status"] != "complete" or artifact["coverage"]["scanned"] != [source.name]:
                legacy_incomplete = True
            report["legacy_coverage_audit"].append({
                "path": filename,
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "status": artifact["status"],
                "scanned": artifact["coverage"]["scanned"],
                "findings": sorted(locations(artifact)),
                "diagnostics": artifact["diagnostics"],
            })

    print(json.dumps(report, indent=2))
    regressions = any(
        metrics["fp"] or metrics["fn"]
        for split in report["expanded"]["scores"].values()
        for metrics in split.values()
    )
    return int(regressions or not all(isolation.values()) or legacy_incomplete)


if __name__ == "__main__":
    raise SystemExit(main())
