from __future__ import annotations

import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

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


    def test_scan_is_deliberately_unavailable(self) -> None:
        errors = StringIO()
        with redirect_stderr(errors), self.assertRaises(SystemExit) as result:
            main(["scan"])
        self.assertEqual(result.exception.code, 2)
        self.assertIn("inventory collection has not been implemented", errors.getvalue())


    def test_module_entry_point_shows_version(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "mcp_scanner", "--version"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), __version__)
