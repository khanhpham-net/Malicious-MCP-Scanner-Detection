from __future__ import annotations

import json
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from mcp_scanner import __version__
from mcp_scanner.cli import main


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

    def test_module_entry_point_shows_version(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "mcp_scanner", "--version"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), __version__)
