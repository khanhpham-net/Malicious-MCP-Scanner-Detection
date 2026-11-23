from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mcp_scanner.semgrep_adapter import scan_code, scan_inventory_with_semgrep
from mcp_scanner.source_inventory import collect_source_inventory

FIXTURES = Path(__file__).resolve().parent / "fixtures"
RULES = FIXTURES / "mcp-shell-input.yaml"
SOURCE = FIXTURES / "mcp-shell-input.py"
EXPANDED_RULES = FIXTURES.parents[1] / "rules/mcp-code.yaml"
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

    def test_expanded_rules_keep_original_finding_ids_and_ranges(self) -> None:
        baseline = self.scan(SOURCE)
        expanded = self.scan(SOURCE, EXPANDED_RULES)

        self.assertEqual(baseline["status"], "complete")
        self.assertEqual(expanded["status"], "complete")
        self.assertEqual(len(baseline["items"]), 2)
        self.assertCountEqual(
            [item["finding_id"] for item in expanded["items"]],
            [item["finding_id"] for item in baseline["items"]],
        )
        self.assertCountEqual(expanded["evidence"], baseline["evidence"])

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

    def test_mcp_shell_input_sanitizers_respect_context_and_reject_unsafe_cases(self) -> None:
        cases = {
            "guarded_ternary_ok.py": (
                "import subprocess\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('t')\n"
                "@mcp.tool()\ndef inspect(record: str):\n"
                "    safe_ref = str(record) if str(record).replace('-', '').isalnum() else 'DEFAULT'\n"
                "    subprocess.run('echo ' + safe_ref, shell=True)\n",
                0,
            ),
            "guarded_branch_ok.py": (
                "import subprocess\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('t')\n"
                "@mcp.tool()\ndef inspect(record: str):\n"
                "    if not record.isalnum():\n"
                "        return 'bad'\n"
                "    subprocess.run('echo ' + record, shell=True)\n",
                0,
            ),
            "guarded_shlex_ok.py": (
                "import shlex, subprocess\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('t')\n"
                "@mcp.tool()\ndef inspect(record: str):\n"
                "    subprocess.run('echo ' + shlex.quote(record), shell=True)\n",
                0,
            ),
            "unsafe_executable_pos.py": (
                "import subprocess\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('t')\n"
                "@mcp.tool()\ndef inspect(record: str):\n"
                "    safe_ref = str(record) if str(record).replace('-', '').isalnum() else 'DEFAULT'\n"
                "    subprocess.run(safe_ref, shell=True)\n",
                1,
            ),
            "unsafe_wrong_var.py": (
                "import subprocess\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('t')\n"
                "@mcp.tool()\ndef inspect(record: str, other: str):\n"
                "    safe_ref = str(other) if str(other).isalnum() else 'DEFAULT'\n"
                "    subprocess.run('echo ' + record, shell=True)\n",
                1,
            ),
            "unsafe_assert_not_guard.py": (
                "import subprocess\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('t')\n"
                "@mcp.tool()\ndef inspect(record: str):\n"
                "    assert record.isalnum()\n"
                "    subprocess.run('echo ' + record, shell=True)\n",
                1,
            ),
            "unsafe_rstrip.py": (
                "import subprocess\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('t')\n"
                "@mcp.tool()\ndef inspect(command: str):\n"
                "    subprocess.run(command.rstrip('\\n'), shell=True)\n",
                1,
            ),
            "unsafe_replace_metachar.py": (
                "import subprocess\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('t')\n"
                "@mcp.tool()\ndef inspect(record: str):\n"
                "    safe_ref = str(record) if str(record).replace(';', '').isalnum() else 'DEFAULT'\n"
                "    subprocess.run('echo ' + safe_ref, shell=True)\n",
                1,
            ),
            "unsafe_prefix_quote.py": (
                "import subprocess\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('t')\n"
                "@mcp.tool()\ndef inspect(record: str):\n"
                "    safe_ref = str(record) if record.isalnum() else 'DEFAULT'\n"
                "    subprocess.run(\"sh -c '\" + safe_ref, shell=True)\n",
                1,
            ),
            "unsafe_mismatch_ternary.py": (
                "import subprocess\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('t')\n"
                "@mcp.tool()\ndef inspect(record: str, other: str):\n"
                "    safe_ref = str(record) if str(other).isalnum() else 'DEFAULT'\n"
                "    subprocess.run('echo ' + safe_ref, shell=True)\n",
                1,
            ),
            "unsafe_reassigned_ternary.py": (
                "import subprocess\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('t')\n"
                "@mcp.tool()\ndef inspect(record: str, other: str):\n"
                "    safe_ref = str(record) if str(record).replace('-', '').isalnum() else 'DEFAULT'\n"
                "    safe_ref = other\n"
                "    subprocess.run('echo ' + safe_ref, shell=True)\n",
                1,
            ),
            "unsafe_reassigned_augassign.py": (
                "import subprocess\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('t')\n"
                "@mcp.tool()\ndef inspect(record: str, other: str):\n"
                "    safe_ref = str(record) if str(record).isalnum() else 'DEFAULT'\n"
                "    safe_ref += other\n"
                "    subprocess.run('echo ' + safe_ref, shell=True)\n",
                1,
            ),
            "unsafe_reassigned_branch.py": (
                "import subprocess\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('t')\n"
                "@mcp.tool()\ndef inspect(record: str, other: str):\n"
                "    if not record.isalnum():\n"
                "        return 'bad'\n"
                "    record = other\n"
                "    subprocess.run('echo ' + record, shell=True)\n",
                1,
            ),
            "guarded_reassigned_before_guard_ok.py": (
                "import subprocess\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('t')\n"
                "@mcp.tool()\ndef inspect(record: str):\n"
                "    safe_ref = 'init'\n"
                "    safe_ref = str(record) if str(record).replace('-', '').isalnum() else 'DEFAULT'\n"
                "    subprocess.run('echo ' + safe_ref, shell=True)\n",
                0,
            ),
        }
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, (code, _) in cases.items():
                (root / name).write_text(code, encoding="utf-8")
            res = self.scan(root, EXPANDED_RULES)
        self.assertEqual(res["status"], "complete", res)
        evidence_by_id = {ev["evidence_id"]: ev for ev in res["evidence"]}
        counts: dict[str, int] = {}
        for item in res["items"]:
            for eid in item["evidence_ids"]:
                path = evidence_by_id[eid]["path"]
                counts[path] = counts.get(path, 0) + 1
        for name, (_, expected_count) in cases.items():
            self.assertEqual(
                counts.get(name, 0),
                expected_count,
                f"Case {name} expected {expected_count} finding(s), got {counts.get(name, 0)} (all={counts})",
            )

    def test_crlf_inventory_staging_preserves_exact_bytes_for_multiline_sanitizers(self) -> None:
        c_guarded_crlf = (
            "from mcp.server.fastmcp import FastMCP\r\n"
            "import subprocess\r\n"
            "mcp = FastMCP('audit')\r\n"
            "@mcp.tool()\r\n"
            "def inspect(record: str):\r\n"
            "    safe_ref = str(record) if str(record).replace('-', '').isalnum() else 'DEFAULT'\r\n"
            "    subprocess.run('echo ' + safe_ref, shell=True)\r\n"
        ).encode("utf-8")
        c_rstrip_crlf = (
            "from mcp.server.fastmcp import FastMCP\r\n"
            "import subprocess\r\n"
            "mcp = FastMCP('audit')\r\n"
            "@mcp.tool()\r\n"
            "def inspect(command: str):\r\n"
            "    subprocess.run(command.rstrip('\\n'), shell=True)\r\n"
        ).encode("utf-8")
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "guarded.py").write_bytes(c_guarded_crlf)
            (root / "rstrip.py").write_bytes(c_rstrip_crlf)
            inv = collect_source_inventory(root)
            res = scan_inventory_with_semgrep(
                inv,
                rules=[EXPANDED_RULES],
                server_id="lab:crlf",
                semgrep=SEMGREP,
                windows_temp=Path(WINDOWS_TEMP) if WINDOWS_TEMP else None,
            )
        self.assertEqual(res.status, "complete", res)
        paths = [f.sink_span.path for f in res.findings if f.sink_span is not None]
        self.assertEqual(paths, ["rstrip.py"])
