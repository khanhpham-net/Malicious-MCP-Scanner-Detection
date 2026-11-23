from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from mcp_scanner.cli import main
from mcp_scanner.sca_adapter import analyze_sca_offline
from mcp_scanner.scanner import run_scan
from mcp_scanner.source_inventory import collect_source_inventory
from tests.test_models_and_schema import SCHEMA_PATH, _validate_against_schema


def _write_pinned_osv_db(db_dir: Path, advisories: list[dict], *, write_manifest: bool = True) -> str:
    db_dir.mkdir(parents=True, exist_ok=True)
    adv_file = db_dir / "advisories.json"
    raw = json.dumps({"advisories": advisories}, indent=2).encode("utf-8")
    adv_file.write_bytes(raw)
    hasher = hashlib.sha256()
    hasher.update(b"advisories.json\x00")
    hasher.update(hashlib.sha256(raw).digest())
    hasher.update(b"\n")
    digest = hasher.hexdigest()
    if write_manifest:
        (db_dir / "manifest.json").write_text(
            json.dumps({"snapshot_id": "osv-offline-test-2026-11", "sha256": digest}, indent=2),
            encoding="utf-8",
        )
    return digest


SAMPLE_ADVISORIES = [
    {
        "id": "GHSA-test-npm-0001",
        "aliases": ["CVE-2026-10001"],
        "summary": "Prototype pollution in demo-lib",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "demo-lib"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.5"}],
                    }
                ],
            }
        ],
    },
    {
        "id": "GHSA-test-pypi-0002",
        "aliases": ["CVE-2026-20002"],
        "summary": "Request smuggling in demo-http",
        "database_specific": {"severity": "CRITICAL"},
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "Demo_HTTP"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.1.0"}],
                    }
                ],
            }
        ],
    },
    {
        "id": "GHSA-test-git-0003",
        "aliases": [],
        "summary": "Advisory with unsupported GIT commit range",
        "database_specific": {"severity": "MEDIUM"},
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "git-range-pkg"},
                "ranges": [
                    {
                        "type": "GIT",
                        "events": [{"introduced": "abc1234"}, {"fixed": "def5678"}],
                    }
                ],
            }
        ],
    },
]


class OfflineScaAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_unconfigured_sca_reports_unmeasured_without_breaking_static_complete(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("demo-http>=1.0\n", encoding="utf-8")
            (root / "server.py").write_text("x = 1\n", encoding="utf-8")
            report = run_scan(root, enable_semgrep=False, enable_python_ast=True)

        self.assertEqual(report.coverage.sca_status, "unmeasured")
        self.assertEqual(report.scan_status, "complete")
        self.assertEqual(report.exit_code, 0)
        _validate_against_schema(report.to_dict(), self.schema, self.schema)

    def test_npm_lockfile_resolves_manifest_range_and_detects_or_clears_semver_cve(self) -> None:
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            db_dir = base / "osv_db"
            digest = _write_pinned_osv_db(db_dir, SAMPLE_ADVISORIES)

            # 1. Vulnerable lockfile version (1.2.3 < 1.2.5) while package.json has range ^1.2.0
            vuln_repo = base / "vuln_npm"
            vuln_repo.mkdir()
            (vuln_repo / "package.json").write_text(
                json.dumps({"name": "mcp-vuln", "dependencies": {"demo-lib": "^1.2.0"}}),
                encoding="utf-8",
            )
            (vuln_repo / "package-lock.json").write_text(
                json.dumps(
                    {
                        "name": "mcp-vuln",
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"name": "mcp-vuln"},
                            "node_modules/demo-lib": {"version": "1.2.3"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            rep_vuln = run_scan(
                vuln_repo,
                enable_semgrep=False,
                enable_python_ast=False,
                osv_db=db_dir,
                osv_db_sha256=digest,
            )
            self.assertEqual(rep_vuln.coverage.sca_status, "complete")
            self.assertEqual(rep_vuln.scan_status, "complete")
            self.assertEqual(rep_vuln.policy_status, "fail")
            self.assertEqual(rep_vuln.exit_code, 1)
            self.assertEqual(len(rep_vuln.findings), 1)
            self.assertEqual(rep_vuln.findings[0].kind, "dependency_advisory")
            self.assertEqual(rep_vuln.findings[0].category, "supply_chain")
            self.assertIn("GHSA-test-npm-0001", rep_vuln.findings[0].title)
            _validate_against_schema(rep_vuln.to_dict(), self.schema, self.schema)

            # 2. Fixed lockfile version (1.2.5) resolving package.json ^1.2.0 -> complete, 0 findings
            fixed_repo = base / "fixed_npm"
            fixed_repo.mkdir()
            (fixed_repo / "package.json").write_text(
                json.dumps({"name": "mcp-fixed", "dependencies": {"demo-lib": "^1.2.0"}}),
                encoding="utf-8",
            )
            (fixed_repo / "package-lock.json").write_text(
                json.dumps(
                    {
                        "name": "mcp-fixed",
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"name": "mcp-fixed"},
                            "node_modules/demo-lib": {"version": "1.2.5"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            rep_fixed = run_scan(
                fixed_repo,
                enable_semgrep=False,
                enable_python_ast=False,
                osv_db=db_dir,
                osv_db_sha256=digest,
            )
            self.assertEqual(rep_fixed.coverage.sca_status, "complete")
            self.assertEqual(rep_fixed.scan_status, "complete")
            self.assertEqual(rep_fixed.policy_status, "pass")
            self.assertEqual(rep_fixed.exit_code, 0)
            self.assertEqual(rep_fixed.findings, [])

    def test_unpinned_manifest_without_lockfile_returns_partial_for_both_sca_and_scan(self) -> None:
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            db_dir = base / "osv_db"
            _write_pinned_osv_db(db_dir, SAMPLE_ADVISORIES)

            repo = base / "unpinned"
            repo.mkdir()
            (repo / "package.json").write_text(
                json.dumps({"name": "no-lock", "dependencies": {"demo-lib": "^1.2.0"}}),
                encoding="utf-8",
            )
            rep = run_scan(repo, enable_semgrep=False, enable_python_ast=False, osv_db=db_dir)

        self.assertEqual(rep.coverage.sca_status, "partial")
        self.assertEqual(rep.scan_status, "partial")
        self.assertEqual(rep.policy_status, "not_evaluated")
        self.assertEqual(rep.exit_code, 2)
        self.assertLessEqual(rep.trust_score.displayed_score, 60)
        self.assertTrue(any(d.get("kind") == "sca_unresolved_dependencies" for d in rep.diagnostics))
        _validate_against_schema(rep.to_dict(), self.schema, self.schema)

    def test_pypi_pep440_matching_uv_lock_resolution_and_unsupported_git_range(self) -> None:
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            db_dir = base / "osv_db"
            _write_pinned_osv_db(db_dir, SAMPLE_ADVISORIES)

            # 1. PEP 440 prerelease 2.1.0rc1 < 2.1.0 in requirements.txt -> affected (CRITICAL)
            req_repo = base / "req_vuln"
            req_repo.mkdir()
            (req_repo / "requirements.txt").write_text("demo-http==2.1.0rc1\n", encoding="utf-8")
            rep_req = run_scan(req_repo, enable_semgrep=False, enable_python_ast=False, osv_db=db_dir)
            self.assertEqual(rep_req.coverage.sca_status, "complete")
            self.assertEqual(rep_req.exit_code, 1)
            self.assertEqual(len(rep_req.findings), 1)
            self.assertEqual(rep_req.findings[0].severity, "critical")

            # 2. pyproject.toml range resolved by sibling uv.lock -> complete, 0 findings
            uv_repo = base / "uv_resolved"
            uv_repo.mkdir()
            (uv_repo / "pyproject.toml").write_text(
                '[project]\nname = "demo"\ndependencies = ["demo-http>=2.0"]\n',
                encoding="utf-8",
            )
            (uv_repo / "uv.lock").write_text(
                'version = 1\n[[package]]\nname = "demo-http"\nversion = "2.1.0"\n',
                encoding="utf-8",
            )
            rep_uv = run_scan(uv_repo, enable_semgrep=False, enable_python_ast=False, osv_db=db_dir)
            self.assertEqual(rep_uv.coverage.sca_status, "complete")
            self.assertEqual(rep_uv.scan_status, "complete")
            self.assertEqual(rep_uv.exit_code, 0)
            self.assertEqual(rep_uv.findings, [])

            # 3. Unsupported GIT range in OSV advisory -> partial (never silent 0 CVE)
            git_repo = base / "git_range"
            git_repo.mkdir()
            (git_repo / "requirements.txt").write_text("git-range-pkg==1.0.0\n", encoding="utf-8")
            rep_git = run_scan(git_repo, enable_semgrep=False, enable_python_ast=False, osv_db=db_dir)
            self.assertEqual(rep_git.coverage.sca_status, "partial")
            self.assertEqual(rep_git.scan_status, "partial")
            self.assertEqual(rep_git.exit_code, 2)
            self.assertTrue(
                any(d.get("kind") == "sca_unsupported_version_range" for d in rep_git.diagnostics)
            )

    def test_tampered_osv_db_hash_pin_fails_sca_and_marks_scan_partial(self) -> None:
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            db_dir = base / "osv_db"
            _write_pinned_osv_db(db_dir, SAMPLE_ADVISORIES)
            # Tamper with advisories.json after manifest.json was written
            (db_dir / "advisories.json").write_text('{"advisories": []}\n', encoding="utf-8")

            repo = base / "repo"
            repo.mkdir()
            (repo / "requirements.txt").write_text("demo-http==2.1.0\n", encoding="utf-8")
            rep = run_scan(repo, enable_semgrep=False, enable_python_ast=False, osv_db=db_dir)

        self.assertEqual(rep.coverage.sca_status, "failed")
        self.assertEqual(rep.scan_status, "partial")
        self.assertEqual(rep.exit_code, 2)
        self.assertTrue(any(d.get("kind") == "osv_db_hash_mismatch" for d in rep.diagnostics))

    def test_osv_scanner_binary_checks_offline_help_flags_strictly(self) -> None:
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            db_dir = base / "osv_db"
            db_dir.mkdir()
            fake_bin = base / "fake-osv-scanner"
            fake_bin.write_text("stub", encoding="utf-8")
            repo = base / "repo"
            repo.mkdir()
            (repo / "requirements.txt").write_text("demo-http==1.0.0\n", encoding="utf-8")
            inv = collect_source_inventory(repo)

            # 1. Binary --help does NOT support --offline / --all-packages -> refuse to run (failed)
            bad_help = subprocess.CompletedProcess(["fake"], 0, stdout="Usage: scan\n", stderr="")
            with patch("mcp_scanner.sca_adapter.subprocess.run", return_value=bad_help) as mocked:
                res_bad = analyze_sca_offline(
                    inv, server_id="srv:1", osv_db=db_dir, osv_scanner=str(fake_bin)
                )
            self.assertEqual(mocked.call_count, 2)  # tried `scan source --help` then `scan --help`
            self.assertEqual(res_bad.status, "failed")
            self.assertEqual(res_bad.diagnostics[0]["kind"], "osv_scanner_offline_flags_unsupported")

            # 2. Binary `scan source --help` supports v2 offline + all-packages -> executes offline via env var
            good_help = subprocess.CompletedProcess(
                ["fake"],
                0,
                stdout="--offline --offline-vulnerabilities --all-packages\n",
                stderr="",
            )
            scan_json = json.dumps(
                {
                    "results": [
                        {
                            "source": {"path": "requirements.txt", "type": "lockfile"},
                            "packages": [
                                {
                                    "package": {"ecosystem": "PyPI", "name": "demo-http", "version": "1.0.0"},
                                    "vulnerabilities": [SAMPLE_ADVISORIES[1]],
                                }
                            ],
                        }
                    ]
                }
            )
            good_scan = subprocess.CompletedProcess(["fake"], 1, stdout=scan_json, stderr="")
            with patch("mcp_scanner.sca_adapter.subprocess.run", side_effect=[good_help, good_scan]) as mocked2:
                res_ok = analyze_sca_offline(
                    inv, server_id="srv:2", osv_db=db_dir, osv_scanner=str(fake_bin)
                )
            self.assertEqual(res_ok.status, "complete")
            self.assertEqual(len(res_ok.findings), 1)
            invoked_cmd = mocked2.call_args_list[1].args[0]
            invoked_env = mocked2.call_args_list[1].kwargs["env"]
            self.assertEqual(invoked_cmd[1:3], ["scan", "source"])
            self.assertIn("--offline", invoked_cmd)
            self.assertIn("--offline-vulnerabilities", invoked_cmd)
            self.assertIn("--all-packages", invoked_cmd)
            self.assertEqual(invoked_env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"], str(db_dir.resolve()))

    def test_osv_scanner_binary_rejects_false_complete_and_accepts_clean_all_packages(self) -> None:
        good_help = subprocess.CompletedProcess(
            ["fake"],
            0,
            stdout="--offline --offline-vulnerabilities --all-packages\n",
            stderr="",
        )
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            db_dir = base / "osv_db"
            db_dir.mkdir()
            fake_bin = base / "fake-osv-scanner"
            fake_bin.write_text("stub", encoding="utf-8")
            repo = base / "repo"
            repo.mkdir()
            (repo / "requirements.txt").write_text("demo-http==2.0.0\n", encoding="utf-8")

            # Case 1: exit 128 empty stdout despite pinned dep -> partial (never complete)
            with patch(
                "mcp_scanner.sca_adapter.subprocess.run",
                side_effect=[good_help, subprocess.CompletedProcess(["fake"], 128, stdout="", stderr="")],
            ):
                rep_128 = run_scan(
                    repo, enable_semgrep=False, enable_python_ast=False, osv_db=db_dir, osv_scanner=str(fake_bin)
                )
            self.assertEqual(rep_128.coverage.sca_status, "partial")
            self.assertEqual(rep_128.scan_status, "partial")
            self.assertEqual(rep_128.exit_code, 2)
            self.assertTrue(any(d.get("kind") == "osv_scanner_no_packages_detected" for d in rep_128.diagnostics))

            # Case 2: exit 1 empty stdout -> failed
            with patch(
                "mcp_scanner.sca_adapter.subprocess.run",
                side_effect=[good_help, subprocess.CompletedProcess(["fake"], 1, stdout="", stderr="")],
            ):
                rep_e1 = run_scan(
                    repo, enable_semgrep=False, enable_python_ast=False, osv_db=db_dir, osv_scanner=str(fake_bin)
                )
            self.assertEqual(rep_e1.coverage.sca_status, "failed")
            self.assertEqual(rep_e1.scan_status, "partial")
            self.assertEqual(rep_e1.exit_code, 2)
            self.assertTrue(any(d.get("kind") == "osv_scanner_empty_output" for d in rep_e1.diagnostics))

            # Case 3: exit 0 JSON null -> failed
            with patch(
                "mcp_scanner.sca_adapter.subprocess.run",
                side_effect=[good_help, subprocess.CompletedProcess(["fake"], 0, stdout="null\n", stderr="")],
            ):
                rep_null = run_scan(
                    repo, enable_semgrep=False, enable_python_ast=False, osv_db=db_dir, osv_scanner=str(fake_bin)
                )
            self.assertEqual(rep_null.coverage.sca_status, "failed")
            self.assertEqual(rep_null.scan_status, "partial")
            self.assertEqual(rep_null.exit_code, 2)
            self.assertTrue(any(d.get("kind") == "osv_scanner_invalid_output_shape" for d in rep_null.diagnostics))

            # Case 4: exit 0 {"results": []} when pinned dep exists -> partial (never complete)
            with patch(
                "mcp_scanner.sca_adapter.subprocess.run",
                side_effect=[good_help, subprocess.CompletedProcess(["fake"], 0, stdout='{"results": []}\n', stderr="")],
            ):
                rep_empty_res = run_scan(
                    repo, enable_semgrep=False, enable_python_ast=False, osv_db=db_dir, osv_scanner=str(fake_bin)
                )
            self.assertEqual(rep_empty_res.coverage.sca_status, "partial")
            self.assertEqual(rep_empty_res.scan_status, "partial")
            self.assertEqual(rep_empty_res.exit_code, 2)
            self.assertTrue(any(d.get("kind") == "osv_scanner_incomplete_package_coverage" for d in rep_empty_res.diagnostics))

            # Case 5: exit 1 with valid JSON but 0 vulnerabilities -> failed (exit mismatch)
            clean_json = json.dumps(
                {
                    "results": [
                        {
                            "source": {"path": "requirements.txt", "type": "lockfile"},
                            "packages": [
                                {"package": {"ecosystem": "PyPI", "name": "demo-http", "version": "2.0.0"}}
                            ],
                        }
                    ]
                }
            )
            with patch(
                "mcp_scanner.sca_adapter.subprocess.run",
                side_effect=[good_help, subprocess.CompletedProcess(["fake"], 1, stdout=clean_json, stderr="")],
            ):
                rep_mismatch = run_scan(
                    repo, enable_semgrep=False, enable_python_ast=False, osv_db=db_dir, osv_scanner=str(fake_bin)
                )
            self.assertEqual(rep_mismatch.coverage.sca_status, "failed")
            self.assertEqual(rep_mismatch.exit_code, 2)
            self.assertTrue(any(d.get("kind") == "osv_scanner_exit_mismatch" for d in rep_mismatch.diagnostics))

            # Case 6: valid clean all-packages result (exit 0 + expected package observed, 0 vulns) -> genuine complete
            with patch(
                "mcp_scanner.sca_adapter.subprocess.run",
                side_effect=[good_help, subprocess.CompletedProcess(["fake"], 0, stdout=clean_json, stderr="")],
            ):
                rep_clean = run_scan(
                    repo, enable_semgrep=False, enable_python_ast=False, osv_db=db_dir, osv_scanner=str(fake_bin)
                )
            self.assertEqual(rep_clean.coverage.sca_status, "complete")
            self.assertEqual(rep_clean.scan_status, "complete")
            self.assertEqual(rep_clean.policy_status, "pass")
            self.assertEqual(rep_clean.exit_code, 0)
            self.assertEqual(rep_clean.findings, [])
            self.assertEqual(rep_clean.diagnostics, [])
            _validate_against_schema(rep_clean.to_dict(), self.schema, self.schema)

            # Case 7: exact pinned package.json without lockfile in binary mode -> partial (not silently skipped)
            pkg_only = base / "pkg_only"
            pkg_only.mkdir()
            (pkg_only / "package.json").write_text(
                json.dumps({"name": "pin-no-lock", "dependencies": {"demo-lib": "1.2.3"}}),
                encoding="utf-8",
            )
            rep_pkg_only = run_scan(
                pkg_only, enable_semgrep=False, enable_python_ast=False, osv_db=db_dir, osv_scanner=str(fake_bin)
            )
            self.assertEqual(rep_pkg_only.coverage.sca_status, "partial")
            self.assertEqual(rep_pkg_only.scan_status, "partial")
            self.assertEqual(rep_pkg_only.exit_code, 2)
            self.assertTrue(any(d.get("kind") == "osv_scanner_incomplete_package_coverage" for d in rep_pkg_only.diagnostics))

    def test_toml_parser_unavailable_falls_back_gracefully_for_python_310(self) -> None:
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            db_dir = base / "osv_db"
            _write_pinned_osv_db(db_dir, SAMPLE_ADVISORIES)
            repo = base / "repo"
            repo.mkdir()
            (repo / "server.py").write_text("x = 1\n", encoding="utf-8")
            (repo / "uv.lock").write_text('version = 1\n[[package]]\nname = "demo-http"\nversion = "2.1.0"\n', encoding="utf-8")

            with patch("mcp_scanner.sca_adapter.tomllib", None):
                rep_static = run_scan(repo, enable_semgrep=False, enable_python_ast=True)
                self.assertEqual(rep_static.scan_status, "complete")
                self.assertEqual(rep_static.coverage.sca_status, "unmeasured")
                self.assertEqual(rep_static.exit_code, 0)

                rep_sca = run_scan(repo, enable_semgrep=False, enable_python_ast=False, osv_db=db_dir)
                self.assertEqual(rep_sca.coverage.sca_status, "partial")
                self.assertEqual(rep_sca.scan_status, "partial")
                self.assertEqual(rep_sca.exit_code, 2)
                self.assertTrue(any(d.get("kind") == "sca_toml_parser_unavailable" for d in rep_sca.diagnostics))

    def test_cli_scan_supports_osv_db_and_no_sca_flags(self) -> None:
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            db_dir = base / "osv_db"
            digest = _write_pinned_osv_db(db_dir, SAMPLE_ADVISORIES)
            repo = base / "repo"
            repo.mkdir()
            (repo / "requirements.txt").write_text("demo-http==1.5.0\n", encoding="utf-8")
            out_json = base / "report.json"

            rc = main(
                [
                    "scan",
                    str(repo),
                    "--no-semgrep",
                    "--no-python-ast",
                    "--osv-db",
                    str(db_dir),
                    "--osv-db-sha256",
                    digest,
                    "--output",
                    str(out_json),
                ]
            )
            self.assertEqual(rc, 1)
            loaded = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(loaded["coverage"]["sca_status"], "complete")
            self.assertEqual(loaded["findings"][0]["kind"], "dependency_advisory")
            _validate_against_schema(loaded, self.schema, self.schema)

    def test_unordered_multi_interval_osv_events_sort_strictly_before_matching(self) -> None:
        unordered_adv = [
            {
                "id": "GHSA-test-unordered-0004",
                "aliases": [],
                "summary": "Multi-interval advisory with out-of-order events",
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "multi-pkg"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "1.2.0"},
                                    {"fixed": "2.1.0"},
                                    {"introduced": "2.0.0"},
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            db_dir = base / "osv_db"
            _write_pinned_osv_db(db_dir, unordered_adv)

            # 2.2.0 is >= fixed 2.1.0 -> NOT affected
            safe_repo = base / "safe"
            safe_repo.mkdir()
            (safe_repo / "package.json").write_text('{"name":"s","dependencies":{"multi-pkg":"2.2.0"}}', encoding="utf-8")
            rep_safe = run_scan(safe_repo, enable_semgrep=False, enable_python_ast=False, osv_db=db_dir)
            self.assertEqual(rep_safe.coverage.sca_status, "complete")
            self.assertEqual(rep_safe.findings, [])

            # 2.0.5 is in [2.0.0, 2.1.0) -> affected
            vuln_repo = base / "vuln"
            vuln_repo.mkdir()
            (vuln_repo / "package.json").write_text('{"name":"v","dependencies":{"multi-pkg":"2.0.5"}}', encoding="utf-8")
            rep_vuln = run_scan(vuln_repo, enable_semgrep=False, enable_python_ast=False, osv_db=db_dir)
            self.assertEqual(rep_vuln.coverage.sca_status, "complete")
            self.assertEqual(len(rep_vuln.findings), 1)
            self.assertIn("GHSA-test-unordered-0004", rep_vuln.findings[0].title)
