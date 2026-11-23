from __future__ import annotations

import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mcp_scanner.source_inventory import collect_source_inventory


class SourceInventoryTests(unittest.TestCase):
    def test_ignores_noisy_dirs_binaries_oversized_and_minified(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text("print('ok')\n", encoding="utf-8")
            (root / "index.ts").write_text("export const x = 1;\n", encoding="utf-8")
            (root / "package.json").write_text('{"name": "demo"}\n', encoding="utf-8")

            # Ignored directories
            nm = root / "node_modules" / "pkg"
            nm.mkdir(parents=True)
            (nm / "evil.js").write_text("eval(x);\n", encoding="utf-8")
            git_dir = root / ".git"
            git_dir.mkdir()
            (git_dir / "config").write_text("[core]\n", encoding="utf-8")

            # Binary file (by extension and by NUL byte)
            (root / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")
            (root / "raw.dat").write_bytes(b"hello\x00world")

            # Oversized file
            (root / "huge.py").write_bytes(b"# a\n" * 600)

            # Minified JS (>1000 chars on 1 line, avg_line_len > 300, under max_file_bytes)
            (root / "bundle.js").write_text("var a=1;" * 200, encoding="utf-8")

            inv = collect_source_inventory(root, max_file_bytes=2048)

        scanned_paths = [f.rel_path for f in inv.files]
        self.assertEqual(scanned_paths, ["index.ts", "package.json", "server.py"])
        self.assertEqual(inv.languages, ["python", "typescript"])

        reasons = {(s.path, s.reason) for s in inv.skipped_files}
        self.assertIn(("node_modules", "ignored_directory"), reasons)
        self.assertIn((".git", "ignored_directory"), reasons)
        self.assertIn(("logo.png", "binary_file"), reasons)
        self.assertIn(("raw.dat", "binary_file"), reasons)
        self.assertIn(("huge.py", "file_too_large"), reasons)
        self.assertIn(("bundle.js", "minified_file"), reasons)
        self.assertEqual(inv.read_errors, [])
        self.assertEqual(inv.skipped_budget, [])

    def test_survives_permission_and_av_quarantine_errors(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            ok_file = root / "server.py"
            locked_file = root / "quarantined.py"
            bad_utf8 = root / "latin1.py"
            ok_file.write_text("print('safe')\n", encoding="utf-8")
            locked_file.write_text("print('locked')\n", encoding="utf-8")
            bad_utf8.write_bytes(b"\xff\xfe\xfa\xfb")

            orig_read_bytes = Path.read_bytes

            def fake_read_bytes(self_path: Path) -> bytes:
                if self_path.name == "quarantined.py":
                    err = PermissionError(13, "Operation did not complete successfully because the file contains a virus")
                    err.winerror = 225  # type: ignore[attr-defined]
                    raise err
                return orig_read_bytes(self_path)

            with patch.object(Path, "read_bytes", fake_read_bytes):
                inv = collect_source_inventory(root)

        self.assertEqual([f.rel_path for f in inv.files], ["server.py"])
        err_map = {e.path: e.error_code for e in inv.read_errors}
        self.assertEqual(err_map["quarantined.py"], "EACCES_OR_AV_QUARANTINE")
        self.assertEqual(err_map["latin1.py"], "UNICODE_DECODE_ERROR")

    def test_blocks_symlink_escape(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text("x = 1\n", encoding="utf-8")
            (root / "escape.py").write_text("y = 2\n", encoding="utf-8")

            def fake_is_link(p: Path) -> bool:
                return p.name == "escape.py"

            def fake_inside(p: Path, r: Path) -> bool:
                return p.name != "escape.py"

            with (
                patch("mcp_scanner.source_inventory._is_link_or_junction", side_effect=fake_is_link),
                patch("mcp_scanner.source_inventory._is_inside_root", side_effect=fake_inside),
            ):
                inv = collect_source_inventory(root)

        self.assertEqual([f.rel_path for f in inv.files], ["server.py"])
        self.assertIn(("escape.py", "symlink_escape"), {(s.path, s.reason) for s in inv.skipped_files})

    def test_max_files_budget_prioritizes_entrypoints_and_records_overflow(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text("print('main')\n", encoding="utf-8")
            (root / "package.json").write_text("{}\n", encoding="utf-8")
            (root / "z_notes.txt").write_text("notes\n", encoding="utf-8")
            sub = root / "deep" / "sub"
            sub.mkdir(parents=True)
            (sub / "extra.py").write_text("x = 1\n", encoding="utf-8")

            inv = collect_source_inventory(root, max_files=2)

        self.assertEqual(len(inv.files), 2)
        self.assertEqual(sorted(f.rel_path for f in inv.files), ["package.json", "server.py"])
        overflow = {s.path: s.reason for s in inv.skipped_budget}
        self.assertEqual(overflow["deep/sub/extra.py"], "max_files_budget_exceeded")
        self.assertEqual(overflow["z_notes.txt"], "max_files_budget_exceeded")

    def test_deadline_exceeded_marks_timed_out(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text("x = 1\n", encoding="utf-8")
            inv = collect_source_inventory(root, deadline=time.monotonic() - 1.0)

        self.assertTrue(inv.timed_out)
        self.assertEqual(inv.files, [])

    def test_snapshot_sha256_is_deterministic(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_text("a = 1\n", encoding="utf-8")
            (root / "b.py").write_text("b = 2\n", encoding="utf-8")
            inv1 = collect_source_inventory(root)
            inv2 = collect_source_inventory(root)

        self.assertEqual(inv1.snapshot_sha256, inv2.snapshot_sha256)
        self.assertTrue(inv1.snapshot_sha256.startswith("sha256:"))

    def test_rejects_symlink_or_junction_root_target_before_resolve(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "linked_root"
            root.mkdir()
            (root / "server.py").write_text("x = 1\n", encoding="utf-8")

            with patch("mcp_scanner.source_inventory._is_link_or_junction", return_value=True):
                with self.assertRaises(ValueError) as ctx:
                    collect_source_inventory(root)

        self.assertIn("symlink or junction", str(ctx.exception))

    def test_deadline_checked_during_directory_entry_walk(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for idx in range(12):
                (root / f"mod_{idx:02d}.py").write_text(f"v = {idx}\n", encoding="utf-8")

            ticks = iter([100.0, 100.1, 100.2, 105.0, 105.1, 105.2, 105.3])

            def fake_monotonic() -> float:
                return next(ticks, 200.0)

            with patch("mcp_scanner.source_inventory.time.monotonic", side_effect=fake_monotonic):
                inv = collect_source_inventory(root, deadline=101.0)

        self.assertTrue(inv.timed_out)
        self.assertLess(inv.files_discovered, 12)

    def test_dist_included_only_for_published_npm_package_without_src(self) -> None:
        # 1. Published npm package: package.json points to ./dist/index.js and no src/ directory exists
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"name": "published-mcp", "bin": {"cli": "./dist/index.js"}}\n',
                encoding="utf-8",
            )
            (root / "dist").mkdir()
            (root / "dist" / "index.js").write_text("console.log('ok');\n", encoding="utf-8")
            inv_npm = collect_source_inventory(root)

        self.assertIn("dist/index.js", [f.rel_path for f in inv_npm.files])

        # 2. Repo with src/ AND dist/ where package.json explicitly declares main=./dist/index.js:
        #    BOTH src/index.ts and the declared runtime entrypoint dist/index.js must be covered
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"name": "source-and-dist-mcp", "main": "./dist/index.js"}\n',
                encoding="utf-8",
            )
            (root / "src").mkdir()
            (root / "src" / "index.ts").write_text("export const ok = 1;\n", encoding="utf-8")
            (root / "dist").mkdir()
            (root / "dist" / "index.js").write_text("exports.ok = 1;\n", encoding="utf-8")
            inv_both = collect_source_inventory(root)

        self.assertIn("src/index.ts", [f.rel_path for f in inv_both.files])
        self.assertIn("dist/index.js", [f.rel_path for f in inv_both.files])

        # 3. Source TS repo with src/ AND unreferenced dist/ (package.json points to src/): dist stays ignored
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"name": "source-only-mcp", "main": "./src/index.ts"}\n',
                encoding="utf-8",
            )
            (root / "src").mkdir()
            (root / "src" / "index.ts").write_text("export const ok = 1;\n", encoding="utf-8")
            (root / "dist").mkdir()
            (root / "dist" / "stale.js").write_text("exports.ok = 1;\n", encoding="utf-8")
            inv_src = collect_source_inventory(root)

        self.assertIn("src/index.ts", [f.rel_path for f in inv_src.files])
        self.assertNotIn("dist/stale.js", [f.rel_path for f in inv_src.files])
        self.assertIn(("dist", "ignored_directory"), {(s.path, s.reason) for s in inv_src.skipped_files})

        # 4. Python repo without package.json: build/ stays ignored_directory
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text("x = 1\n", encoding="utf-8")
            (root / "build").mkdir()
            (root / "build" / "gen.py").write_text("y = 2\n", encoding="utf-8")
            inv_py = collect_source_inventory(root)

        self.assertEqual([f.rel_path for f in inv_py.files], ["server.py"])
        self.assertIn(("build", "ignored_directory"), {(s.path, s.reason) for s in inv_py.skipped_files})
