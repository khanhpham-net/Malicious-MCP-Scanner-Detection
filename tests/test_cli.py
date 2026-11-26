from __future__ import annotations

import json
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mcp_scanner import __version__
from mcp_scanner.cli import mac_main, main
from mcp_scanner.tui import (
    detect_batch_subtargets,
    discover_batch_targets,
    normalize_user_path,
    run_batch_scan,
    run_interactive_session,
)


class CliTests(unittest.TestCase):
    def test_version_flag(self) -> None:
        output = StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as result:
            main(["--version"])
        self.assertEqual(result.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), __version__)

    def test_no_command_shows_help(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main([]), 0)
        self.assertIn("Static scanner", output.getvalue())

    def test_scan_without_target_returns_usage_error(self) -> None:
        errors = StringIO()
        with redirect_stderr(errors), self.assertRaises(SystemExit) as result:
            main(["scan"])
        self.assertEqual(result.exception.code, 2)
        self.assertIn("requires a target path", errors.getvalue())

    def test_scan_writes_v10_report_to_output_file(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "package.json").write_text('{"name": "demo"}\n', encoding="utf-8")
            out_file = Path(tmp) / "report.json"

            code = main(["scan", str(root), "--no-semgrep", "--no-python-ast", "--output", str(out_file)])
            self.assertEqual(code, 0)
            data = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(data["contract_version"], "1.0")
            self.assertEqual(data["artifact_type"], "scan_report")
            self.assertEqual(data["scan_status"], "complete")

    def test_runtime_p_limit_is_partial_only_with_strict_p(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "server.py").write_text(
                "import subprocess\n"
                "from mcp.server.fastmcp import FastMCP\n"
                "mcp = FastMCP('demo')\n"
                "@mcp.tool()\n"
                "def status() -> str:\n"
                "    subprocess.run(['echo', 'ok'], check=False)\n"
                "    return 'ok'\n", encoding="utf-8",
            )
            out_file = Path(tmp) / "report.json"
            args = ["scan", str(root), "--no-semgrep", "--no-sca", "--output", str(out_file)]
            for flags, profile, status, exit_code in (
                ([], "static-default", "complete", 0),
                (["--strict-p"], "static-p-strict", "partial", 2),
            ):
                with self.subTest(profile=profile):
                    self.assertEqual(main([*args, *flags]), exit_code)
                    report = json.loads(out_file.read_text(encoding="utf-8"))
                    self.assertEqual(report["scanner"]["profile"], profile)
                    self.assertEqual(report["scan_status"], status)
                    self.assertEqual(report["coverage"]["surfaces"]["p_tool_result"], "partial")
                    self.assertIn("P_OUTPUT_UNSUPPORTED_CALL", {d.get("code") for d in report["diagnostics"]})

    def test_module_entry_point_shows_version(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "mcp_scanner", "--version"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), __version__)

    def test_mac_scan_renders_english_text_summary_and_optional_json_output(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "demo_repo"
            root.mkdir()
            (root / "package.json").write_text('{"name": "demo"}\n', encoding="utf-8")
            out_file = Path(tmp) / "saved.json"

            buf = StringIO()
            with redirect_stdout(buf):
                code = mac_main(
                    [
                        "scan",
                        str(root),
                        "--no-semgrep",
                        "--no-python-ast",
                        "--no-color",
                        "--output",
                        str(out_file),
                    ]
                )
            text_out = buf.getvalue()
            self.assertEqual(code, 0)
            self.assertIn("Maintain an Auspicious Cloud", text_out)
            self.assertIn("MCP Security Scanner", text_out)
            self.assertIn("[1/4] Collecting source inventory", text_out)
            self.assertIn("Trust Score", text_out)
            self.assertIn("100/100 (complete)", text_out)
            self.assertIn("No actionable security findings detected", text_out)
            self.assertIn("Saved JSON report:", text_out)

            saved = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(saved["contract_version"], "1.0")
            self.assertEqual(saved["scan_status"], "complete")

    def test_mac_scan_format_json_emits_pure_json_and_shorthand_path_works(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "package.json").write_text('{"name": "demo"}\n', encoding="utf-8")

            buf = StringIO()
            with redirect_stdout(buf):
                code = mac_main([str(root), "--format", "json", "--no-semgrep", "--no-python-ast"])
            self.assertEqual(code, 0)
            parsed = json.loads(buf.getvalue())
            self.assertEqual(parsed["contract_version"], "1.0")
            self.assertEqual(parsed["scan_status"], "complete")

    def test_mac_interactive_session_details_save_history_and_quoted_paths(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "sim_sample"
            root.mkdir()
            (root / "server.py").write_text(
                "\n".join(
                    [
                        "from pathlib import Path",
                        "from mcp.server.fastmcp import FastMCP",
                        "from mcp.types import ToolAnnotations",
                        'mcp = FastMCP("demo")',
                        "@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))",
                        "def read_only_tool():",
                        '    Path("state.txt").write_text("mutated")',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            save_file = Path(tmp) / "custom_report.json"

            # Verify quoted Windows path normalization
            quoted = f'  "{root}"  '
            self.assertEqual(normalize_user_path(quoted), root)

            # Interactive flow:
            # 1) choose [2] paste quoted path
            # 2) press [d] for Details
            # 3) press [s] to Save JSON to custom_report.json
            # 4) press [n] for New Scan
            # 5) choose [3] to view recent session history
            # 6) choose [q] to quit
            inputs = iter(["2", quoted, "d", "s", str(save_file), "n", "3", "q"])
            out_buf = StringIO()
            rc = run_interactive_session(
                input_fn=lambda _prompt: next(inputs),
                stream=out_buf,
                no_color=True,
                enable_semgrep=False,
                enable_python_ast=True,
            )

            rendered = out_buf.getvalue()
            self.assertEqual(rc, 1)
            self.assertIn("Maintain an Auspicious Cloud", rendered)
            self.assertIn("Select an action:", rendered)
            self.assertIn("Detailed Findings & Coverage Drill-Down", rendered)
            self.assertIn("mcp-py-contract-mutation", rendered)
            self.assertIn("Trace:", rendered)
            self.assertIn("Saved JSON report to:", rendered)
            self.assertIn("Recent Session Scans:", rendered)
            self.assertTrue(save_file.is_file())
            saved_data = json.loads(save_file.read_text(encoding="utf-8"))
            self.assertEqual(saved_data["policy_status"], "fail")
            self.assertEqual(saved_data["scan_status"], "complete")
            self.assertEqual(saved_data["coverage"]["surfaces"]["p_tool_result"], "partial")

    def test_mac_batch_mode_detects_collection_and_inspects_samples(self) -> None:
        with TemporaryDirectory() as tmp:
            collection = Path(tmp) / "samples"
            s1 = collection / "SIM_A"
            s2 = collection / "SIM_B"
            s1.mkdir(parents=True)
            s2.mkdir(parents=True)
            (s1 / "server.py").write_text(
                "\n".join(
                    [
                        "from pathlib import Path",
                        "from mcp.server.fastmcp import FastMCP",
                        "from mcp.types import ToolAnnotations",
                        'mcp = FastMCP("a")',
                        "@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))",
                        "def tool_a():",
                        '    Path("f.txt").write_text("x")',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (s2 / "package.json").write_text('{"name": "clean-b"}\n', encoding="utf-8")
            batch_out = Path(tmp) / "batch.json"

            # 1) Direct CLI `mac scan <collection>` auto-detects batch mode
            cli_buf = StringIO()
            with redirect_stdout(cli_buf):
                rc = mac_main(
                    [
                        "scan",
                        str(collection),
                        "--no-semgrep",
                        "--no-color",
                        "--output",
                        str(batch_out),
                    ]
                )
            cli_text = cli_buf.getvalue()
            self.assertEqual(rc, 1)
            self.assertIn("Batch Target", cli_text)
            self.assertIn("1 ALERT · 1 CLEAN", cli_text)
            batch_json = json.loads(batch_out.read_text(encoding="utf-8"))
            self.assertEqual(batch_json["artifact_type"], "batch_scan_report")
            self.assertEqual(batch_json["total_snapshots"], 2)
            self.assertEqual(batch_json["status_counts"]["partial"], 0)
            self.assertEqual(batch_json["status_counts"]["complete"], 2)

            # 2) Interactive menu: paste collection path -> [1] Fast Batch -> [i] SIM_A -> [l] List All -> [q] Quit
            inputs = iter([str(collection), "1", "i", "SIM_A", "l", "q"])
            tui_buf = StringIO()
            rc_tui = run_interactive_session(
                input_fn=lambda _p: next(inputs),
                stream=tui_buf,
                no_color=True,
                enable_semgrep=False,
            )
            tui_text = tui_buf.getvalue()
            self.assertEqual(rc_tui, 1)
            self.assertIn("Detected batch collection: 2 snapshots", tui_text)
            self.assertIn("Detailed Findings & Coverage Drill-Down", tui_text)
            self.assertIn("All Scanned Snapshots (2):", tui_text)

            # 3) Single repo with src/ + tests/ layout (no root .py) MUST NOT be mistaken for a batch
            single_repo = Path(tmp) / "single_src_layout"
            (single_repo / "src").mkdir(parents=True)
            (single_repo / "tests").mkdir(parents=True)
            (single_repo / "README.md").write_text("# Single repo\n", encoding="utf-8")
            (single_repo / "src" / "server.py").write_text("x = 1\n", encoding="utf-8")
            (single_repo / "tests" / "test_s.py").write_text("y = 2\n", encoding="utf-8")
            self.assertEqual(detect_batch_subtargets(single_repo), [])

            # 4) Nested category collection with arbitrary folder names unwraps to leaf server repos
            nested = Path(tmp) / "arbitrary_corpus"
            r1 = nested / "group_alpha" / "my_custom_server"
            r2 = nested / "group_beta" / "another_project"
            r1.mkdir(parents=True)
            r2.mkdir(parents=True)
            (r1 / "main.py").write_text("a = 1\n", encoding="utf-8")
            (r2 / "package.json").write_text("{}\n", encoding="utf-8")
            leaves = detect_batch_subtargets(nested)
            self.assertEqual([p.name for p in leaves], ["my_custom_server", "another_project"])

    def test_batch_json_stdout_format_invariance_and_symlink_policy(self) -> None:
        with TemporaryDirectory() as tmp:
            collection = Path(tmp) / "corpus"
            a = collection / "srv_a"
            b = collection / "srv_b"
            link_dir = collection / "srv_link"
            a.mkdir(parents=True)
            b.mkdir(parents=True)
            link_dir.mkdir(parents=True)
            (a / "package.json").write_text('{"name": "a"}\n', encoding="utf-8")
            (b / "package.json").write_text('{"name": "b"}\n', encoding="utf-8")
            (link_dir / "package.json").write_text('{"name": "l"}\n', encoding="utf-8")

            # 1. `mac scan <corpus> --format json` MUST emit pure parseable JSON and keep same batch scope as text
            buf_mac_json = StringIO()
            with redirect_stdout(buf_mac_json):
                rc_mac = mac_main(["scan", str(collection), "--format", "json", "--no-semgrep", "--no-python-ast"])
            self.assertEqual(rc_mac, 0)
            parsed_mac = json.loads(buf_mac_json.getvalue())
            self.assertEqual(parsed_mac["artifact_type"], "batch_scan_report")
            self.assertEqual(parsed_mac["total_snapshots"], 3)

            # 2. `mac scan <corpus> --single --format json` forces single combined ScanReport
            buf_single = StringIO()
            with redirect_stdout(buf_single):
                rc_single = mac_main(["scan", str(collection), "--single", "--format", "json", "--no-semgrep", "--no-python-ast"])
            self.assertEqual(rc_single, 0)
            parsed_single = json.loads(buf_single.getvalue())
            self.assertEqual(parsed_single["artifact_type"], "scan_report")

            # 3. `mcp-scanner scan <corpus>` preserves legacy single-snapshot default; `--batch` emits pure JSON batch
            buf_legacy = StringIO()
            with redirect_stdout(buf_legacy):
                main(["scan", str(collection), "--no-semgrep", "--no-python-ast"])
            self.assertEqual(json.loads(buf_legacy.getvalue())["artifact_type"], "scan_report")

            buf_legacy_batch = StringIO()
            with redirect_stdout(buf_legacy_batch):
                main(["scan", str(collection), "--batch", "--no-semgrep", "--no-python-ast"])
            self.assertEqual(json.loads(buf_legacy_batch.getvalue())["artifact_type"], "batch_scan_report")

            # 4. Symlink/junction policy in batch discovery: never follow linked subdirs or linked root
            with patch(
                "mcp_scanner.tui._is_link_or_junction",
                side_effect=lambda p: p.name == "srv_link",
            ):
                leaves, skipped = discover_batch_targets(collection)
            self.assertEqual([p.name for p in leaves], ["srv_a", "srv_b"])
            self.assertEqual(len(skipped), 1)
            self.assertEqual(skipped[0]["reason"], "symlink_or_junction_not_followed")
            batch_res = run_batch_scan(
                leaves,
                parent_target=collection,
                show_progress=False,
                skipped_entries=skipped,
                enable_semgrep=False,
                enable_python_ast=False,
            )
            self.assertEqual(batch_res["exit_code"], 2)
            self.assertEqual(len(batch_res["skipped_entries"]), 1)

            with patch("mcp_scanner.tui._is_link_or_junction", return_value=True):
                root_leaves, root_skipped = discover_batch_targets(collection)
            self.assertEqual(root_leaves, [])
            self.assertEqual(root_skipped[0]["reason"], "symlink_or_junction_root_rejected")

    def test_explicit_batch_with_no_snapshots_returns_batch_exit_2_without_single_fallback(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("# Empty parent directory\n", encoding="utf-8")

            mac_out = StringIO()
            with redirect_stdout(mac_out):
                rc_mac = mac_main(["scan", str(root), "--batch", "--format", "json", "--no-semgrep"])
            self.assertEqual(rc_mac, 2)
            payload_mac = json.loads(mac_out.getvalue())
            self.assertEqual(payload_mac["artifact_type"], "batch_scan_report")
            self.assertEqual(payload_mac["total_snapshots"], 0)
            self.assertEqual(payload_mac["reason"], "no_snapshots_found")
            self.assertEqual(payload_mac["items"], [])

            legacy_out = StringIO()
            with redirect_stdout(legacy_out):
                rc_legacy = main(["scan", str(root), "--batch", "--no-semgrep"])
            self.assertEqual(rc_legacy, 2)
            payload_legacy = json.loads(legacy_out.getvalue())
            self.assertEqual(payload_legacy["artifact_type"], "batch_scan_report")
            self.assertEqual(payload_legacy["total_snapshots"], 0)
            self.assertEqual(payload_legacy["reason"], "no_snapshots_found")
