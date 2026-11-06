from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mcp_scanner.semgrep_adapter import scan_code

FIXTURES = Path(__file__).resolve().parent / "fixtures"
RULES = FIXTURES / "mcp-shell-input.yaml"
SOURCE = FIXTURES / "mcp-shell-input.py"
SEMGREP = os.environ.get("MCP_SCANNER_TEST_SEMGREP")
WINDOWS_TEMP = os.environ.get("MCP_SCANNER_TEST_WINDOWS_TEMP")


class AdapterFailureTests(unittest.TestCase):
    def test_timeout_is_reported_as_failed(self) -> None:
        with (
            patch("mcp_scanner.semgrep_adapter.shutil.which", return_value=sys.executable),
            patch(
                "mcp_scanner.semgrep_adapter.subprocess.run",
                side_effect=subprocess.TimeoutExpired("semgrep", 0.1),
            ),
        ):
            result = scan_code(SOURCE, RULES, server_id="lab:test", timeout=0.1)

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["items"], [])
        self.assertEqual(result["diagnostics"], [{"kind": "timeout", "seconds": 0.1}])


@unittest.skipUnless(SEMGREP, "set MCP_SCANNER_TEST_SEMGREP to test the real engine")
class RealSemgrepTests(unittest.TestCase):
    def scan(self, source: Path, rules: Path = RULES) -> dict:
        return scan_code(
            source,
            rules,
            server_id="lab:test",
            semgrep=SEMGREP,
            windows_temp=Path(WINDOWS_TEMP) if WINDOWS_TEMP else None,
        )

    def test_cli_emits_two_distinct_findings_with_evidence(self) -> None:
        command = [
            sys.executable, "-m", "mcp_scanner", "scan-code", str(SOURCE),
            "--rules", str(RULES), "--semgrep", SEMGREP, "--server-id", "lab:test",
        ]
        if WINDOWS_TEMP:
            command.extend(["--windows-temp", WINDOWS_TEMP])
        process = subprocess.run(command, capture_output=True, text=True, timeout=75)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result["contract_version"], "0.1")
        self.assertEqual(result["artifact_type"], "finding")
        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(result["items"]), 2)
        self.assertEqual(len({item["finding_id"] for item in result["items"]}), 2)
        self.assertEqual({item["server_id"] for item in result["items"]}, {"lab:test"})
        self.assertEqual({item["rule_id"] for item in result["items"]}, {"mcp-shell-input"})
        self.assertEqual({item["severity"] for item in result["items"]}, {"medium"})
        evidence = {item["evidence_id"]: item for item in result["evidence"]}
        locations = [
            (evidence[ref]["path"], evidence[ref]["start"]["line"])
            for item in result["items"]
            for ref in item["evidence_ids"]
        ]
        self.assertCountEqual(locations, [(SOURCE.name, 13), (SOURCE.name, 20)])

    def test_reported_skip_preserves_available_findings(self) -> None:
        with TemporaryDirectory(prefix="semgrep adapter ") as temp:
            root = Path(temp)
            (root / SOURCE.name).write_bytes(SOURCE.read_bytes())
            (root / "large.py").write_bytes(b"# large fixture\n" * 70_000)
            result = self.scan(root)

        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(result["items"]), 2)
        self.assertEqual(result["coverage"]["scanned"], [SOURCE.name])
        self.assertIn("large.py", {item["path"] for item in result["coverage"]["skipped"]})

    def test_zero_findings_with_and_without_coverage(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            valid = root / "safe.py"
            valid.write_text("print('safe')\n", encoding="utf-8")
            unscanned = root / "notes.txt"
            unscanned.write_text("notes\n", encoding="utf-8")
            clean = self.scan(valid)
            empty = self.scan(unscanned)

        self.assertEqual(clean["status"], "complete")
        self.assertEqual(clean["items"], [])
        self.assertEqual(clean["coverage"]["scanned"], [valid.name])
        self.assertEqual(empty["status"], "partial")
        self.assertEqual(empty["coverage"]["scanned"], [])
        self.assertIn({"kind": "no_scanned_files"}, empty["diagnostics"])

    def test_invalid_yaml_is_a_scan_failure(self) -> None:
        with TemporaryDirectory() as temp:
            broken = Path(temp) / "broken.yaml"
            broken.write_text("rules: [\n", encoding="utf-8")
            result = self.scan(SOURCE, broken)

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["items"], [])
        self.assertNotEqual(result["engine"]["exit_code"], 0)
        self.assertIn("semgrep_error", {item["kind"] for item in result["diagnostics"]})
