from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any

from mcp_scanner.models import (
    CONTRACT_VERSION,
    Finding,
    OwaspMapping,
    RedactedEvidence,
    ScanReport,
    SourceSpan,
    TrustScore,
    compute_exit_code,
    findings_from_v01_semgrep_artifact,
    make_finding_id,
    redact_secrets,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "docs" / "schema-v1.0.json"
EXAMPLES_DIR = REPO_ROOT / "examples" / "schema-v1.0"


def _resolve_ref(schema: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    if "$ref" not in schema:
        return schema
    ref = schema["$ref"]
    assert ref.startswith("#/"), f"Unsupported $ref: {ref}"
    node: Any = root
    for part in ref[2:].split("/"):
        node = node[part]
    return node


def _validate_against_schema(instance: Any, schema: dict[str, Any], root: dict[str, Any], path: str = "$") -> None:
    """Minimal Draft 2020-12 structural validator using stdlib only."""
    schema = _resolve_ref(schema, root)

    if "oneOf" in schema:
        matches = 0
        errors: list[str] = []
        for sub in schema["oneOf"]:
            try:
                _validate_against_schema(instance, sub, root, path)
                matches += 1
            except AssertionError as exc:
                errors.append(str(exc))
        assert matches == 1, f"{path}: expected exactly 1 oneOf match, got {matches}: {errors}"
        return

    if "const" in schema:
        assert instance == schema["const"], f"{path}: expected const {schema['const']!r}, got {instance!r}"

    if "enum" in schema:
        assert instance in schema["enum"], f"{path}: {instance!r} not in enum {schema['enum']}"

    expected_type = schema.get("type")
    if expected_type is not None:
        allowed_types = expected_type if isinstance(expected_type, list) else [expected_type]
        type_ok = False
        for t in allowed_types:
            if t == "null" and instance is None:
                type_ok = True
            elif t == "boolean" and type(instance) is bool:
                type_ok = True
            elif t == "integer" and type(instance) is int:
                type_ok = True
            elif t == "number" and type(instance) in (int, float):
                type_ok = True
            elif t == "string" and isinstance(instance, str):
                type_ok = True
            elif t == "array" and isinstance(instance, list):
                type_ok = True
            elif t == "object" and isinstance(instance, dict):
                type_ok = True
        assert type_ok, f"{path}: expected type {allowed_types}, got {type(instance).__name__} ({instance!r})"

    if isinstance(instance, str) and "minLength" in schema:
        assert len(instance) >= schema["minLength"], f"{path}: string shorter than minLength"

    if type(instance) in (int, float):
        if "minimum" in schema:
            assert instance >= schema["minimum"], f"{path}: {instance} < minimum {schema['minimum']}"
        if "exclusiveMinimum" in schema:
            assert instance > schema["exclusiveMinimum"], f"{path}: {instance} <= exclusiveMinimum"
        if "maximum" in schema:
            assert instance <= schema["maximum"], f"{path}: {instance} > maximum {schema['maximum']}"

    if isinstance(instance, list):
        if "minItems" in schema:
            assert len(instance) >= schema["minItems"], f"{path}: len < minItems"
        if "maxItems" in schema:
            assert len(instance) <= schema["maxItems"], f"{path}: len > maxItems"
        if "items" in schema:
            for idx, item in enumerate(instance):
                _validate_against_schema(item, schema["items"], root, f"{path}[{idx}]")

    if isinstance(instance, dict):
        for req in schema.get("required", []):
            assert req in instance, f"{path}: missing required key {req!r}"
        props = schema.get("properties", {})
        add_props = schema.get("additionalProperties")
        for key, val in instance.items():
            if key in props:
                _validate_against_schema(val, props[key], root, f"{path}.{key}")
            elif isinstance(add_props, dict):
                _validate_against_schema(val, add_props, root, f"{path}.{key}")


class ModelsAndSchemaTests(unittest.TestCase):
    def test_schema_file_is_valid_json(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["contract_version"]["const"], CONTRACT_VERSION)

    def test_exit_code_precedence(self) -> None:
        self.assertEqual(compute_exit_code("complete", "pass"), 0)
        self.assertEqual(compute_exit_code("complete", "not_evaluated"), 0)
        self.assertEqual(compute_exit_code("complete", "fail"), 1)
        # Scan failures / partial coverage MUST override pass/clean
        self.assertEqual(compute_exit_code("partial", "pass"), 2)
        self.assertEqual(compute_exit_code("partial", "fail"), 2)
        self.assertEqual(compute_exit_code("failed", "not_evaluated"), 2)
        self.assertEqual(compute_exit_code("unsupported", "pass"), 2)

    def test_secret_redaction(self) -> None:
        raw = (
            'headers = {"Authorization": "Bearer ghp_1234567890abcdefghijklmnop"}\n'
            'api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"\n'
            'aws = "AKIAIOSFODNN7EXAMPLE"\n'
        )
        cleaned, changed = redact_secrets(raw)
        self.assertTrue(changed)
        self.assertNotIn("ghp_1234567890abcdefghijklmnop", cleaned)
        self.assertNotIn("sk-proj-abcdefghijklmnopqrstuvwxyz123456", cleaned)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", cleaned)

        safe_text = 'result = subprocess.run(["git", "status"], capture_output=True)'
        cleaned_safe, changed_safe = redact_secrets(safe_text)
        self.assertFalse(changed_safe)
        self.assertEqual(cleaned_safe, safe_text)

    def test_provisional_trust_score_cap_enforced(self) -> None:
        with self.assertRaises(ValueError):
            TrustScore(
                score_scope="provisional",
                observed_score=100,
                displayed_score=80,
                provisional_cap=60,
            )
        with self.assertRaises(ValueError):
            TrustScore(score_scope="unavailable", observed_score=None, displayed_score=0)

    def test_all_three_sample_reports_conform_to_schema_and_roundtrip(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        expected_samples = {
            "sample_malicious.json": ("complete", "fail", 1, "complete", 0, True),
            "sample_clean.json": ("complete", "pass", 0, "complete", 100, False),
            "sample_partial.json": ("partial", "not_evaluated", 2, "provisional", 60, True),
        }
        for filename, (scan_st, pol_st, exit_c, score_scope, disp_score, needs_rev) in expected_samples.items():
            path = EXAMPLES_DIR / filename
            self.assertTrue(path.is_file(), f"Missing sample file {path}")
            raw_dict = json.loads(path.read_text(encoding="utf-8"))

            # 1. Validate against JSON Schema v1.0
            _validate_against_schema(raw_dict, schema, schema)

            # 2. Round-trip through ScanReport dataclass
            report = ScanReport.from_dict(raw_dict)
            self.assertEqual(report.to_dict(), raw_dict)

            # 3. Verify core invariants & coverage consistency
            self.assertEqual(report.scan_status, scan_st)
            self.assertEqual(report.policy_status, pol_st)
            self.assertEqual(report.exit_code, exit_c)
            self.assertEqual(report.trust_score.score_scope, score_scope)
            self.assertEqual(report.trust_score.displayed_score, disp_score)
            self.assertEqual(report.review_queue.requires_review, needs_rev)
            self.assertEqual(report.coverage.files_scanned, len(report.coverage.scanned_files))
            self.assertGreaterEqual(report.coverage.files_discovered, report.coverage.files_scanned)

            # 4. Ensure no unredacted secret token leaked into sample evidence
            serialized = json.dumps(raw_dict)
            self.assertNotIn("ghp_1234567890", serialized)

    def test_v01_semgrep_bridge(self) -> None:
        v01 = {
            "contract_version": "0.1",
            "artifact_type": "finding",
            "status": "complete",
            "items": [
                {
                    "finding_id": "sha256:abc",
                    "server_id": "srv:1",
                    "rule_id": "mcp-shell-input",
                    "severity": "medium",
                    "title": "MCP tool input reaches a shell command.",
                    "evidence_ids": ["sha256:ev1"],
                }
            ],
            "evidence": [
                {
                    "evidence_id": "sha256:ev1",
                    "path": "server.py",
                    "start": {"line": 13, "column": 5},
                    "end": {"line": 13, "column": 42},
                }
            ],
            "coverage": {"scanned": ["server.py"], "skipped": []},
            "diagnostics": [],
        }
        findings, scanned, skipped, diags = findings_from_v01_semgrep_artifact(v01)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "C")
        self.assertEqual(findings[0].cwe_ids, ["CWE-78"])
        self.assertEqual(findings[0].sink_span, SourceSpan("server.py", 13, 5, 13, 42))
        self.assertEqual(scanned, ["server.py"])
        self.assertEqual(skipped, [])
        self.assertEqual(diags, [])

    def test_deterministic_finding_id(self) -> None:
        span = SourceSpan("server.py", 10, 1, 12, 20)
        id1 = make_finding_id("srv:1", "rule-a", span)
        id2 = make_finding_id("srv:1", "rule-a", span)
        self.assertEqual(id1, id2)
        self.assertTrue(id1.startswith("sha256:"))

    def test_redacted_evidence_from_raw(self) -> None:
        ev = RedactedEvidence.from_raw('token = "ghp_1234567890abcdefghijklmnop"')
        self.assertTrue(ev.secrets_redacted)
        self.assertNotIn("ghp_1234567890", ev.snippet)

    def test_owasp_mapping_requires_primary_when_mapped(self) -> None:
        with self.assertRaises(ValueError):
            OwaspMapping(status="mapped", primary_id=None)
