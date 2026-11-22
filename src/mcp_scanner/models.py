"""Canonical v1.0 data models and serialization for mcp-scanner.

Pure standard-library dataclasses defining the shared contract between:
- Core static engines & Semgrep adapter (Khanh)
- Collector & benchmark runner (Duy)
- 5-surface P detector, OWASP/Trust Score, reporting & review queue (Van)
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

CONTRACT_VERSION = "1.0"
ARTIFACT_TYPE_SCAN_REPORT = "scan_report"
DEFAULT_OWASP_PROFILE = "OWASP-MCP-Top-10-2025-beta"
DEFAULT_TRUST_POLICY_VERSION = "trust-policy-v1.0"
PROVISIONAL_SCORE_CAP = 60

SCAN_STATUSES = frozenset({"complete", "partial", "failed", "unsupported"})
POLICY_STATUSES = frozenset({"pass", "fail", "not_evaluated"})
INPUT_KINDS = frozenset(
    {
        "git_repo_snapshot",
        "package_artifact_only",
        "metadata_snapshot_only",
        "local_directory",
        "config_file",
    }
)
SCA_STATUSES = frozenset({"complete", "partial", "unmeasured", "unsupported", "failed"})
SCORE_SCOPES = frozenset({"complete", "provisional", "unavailable"})
FINDING_KINDS = frozenset(
    {
        "malicious_behavior",
        "vulnerability",
        "semantic_indicator",
        "capability_info",
        "dependency_advisory",
        "config_risk",
    }
)
FINDING_CATEGORIES = frozenset(
    {
        "M",
        "C",
        "S",
        "P",
        "dynamic_code_execution",
        "supply_chain",
        "config_auth",
        "other",
    }
)
SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
EVIDENCE_STRENGTHS = frozenset({"verified", "traced_or_grounded", "heuristic_only"})
MCP_SURFACES = frozenset(
    {"A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10", "A11", "A12", "unknown"}
)
OWASP_MAPPING_STATUSES = frozenset({"mapped", "pending_review", "not_applicable"})
TRACE_ROLES = frozenset({"source", "call", "transform", "guard", "sink", "artifact"})
EDGE_KINDS = frozenset({"definite", "possible"})
REVIEW_STATUSES = frozenset(
    {
        "not_required",
        "pending",
        "in_review_r1",
        "in_review_r2",
        "confirmed_threat",
        "benign_fp",
        "inconclusive",
    }
)
REVIEW_PRIORITY_TIERS = frozenset(
    {"p0_high_or_malicious", "p1_partial_coverage", "p2_score_ranked", "none"}
)
ANALYSIS_BOUNDARY_KINDS = frozenset(
    {
        "dynamic_dispatch",
        "external_lib",
        "budget_exceeded",
        "runtime_only_unobserved",
        "unobserved_lfs_or_submodule",
    }
)

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Private key blocks
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        "***REDACTED_PRIVATE_KEY***",
    ),
    # Well-known token prefixes (GitHub, OpenAI/Anthropic, AWS, Slack, Google)
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"), "***REDACTED_TOKEN***"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "***REDACTED_TOKEN***"),
    (re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b"), "***REDACTED_API_KEY***"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "***REDACTED_AWS_KEY***"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "***REDACTED_TOKEN***"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "***REDACTED_API_KEY***"),
    # Authorization headers (Bearer / Basic / Token)
    (
        re.compile(r"(?i)(Authorization\s*[:=]\s*['\"]?(?:Bearer|Basic|Token)\s+)([A-Za-z0-9._~+/=-]{8,})"),
        r"\1***REDACTED***",
    ),
    # Generic key/secret/password/token literal assignments in code or config
    (
        re.compile(
            r"""(?i)((?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret|private[_-]?key)\s*[:=]\s*['"])([^'"{}\s]{6,})(['"])"""
        ),
        r"\1***REDACTED***\3",
    ),
)


def utc_now_iso() -> str:
    """Return an RFC 3339 UTC timestamp ending in 'Z'."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def stable_sha256_id(payload: object, *, prefix: str = "sha256:") -> str:
    """Create a deterministic SHA-256 identifier from canonical JSON."""
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=True).encode("ascii")
    return f"{prefix}{hashlib.sha256(encoded).hexdigest()}"


def redact_secrets(text: str) -> tuple[str, bool]:
    """Redact likely credential literals from evidence snippets before storage/export."""
    if not text:
        return text, False
    redacted = text
    changed = False
    for pattern, replacement in _SECRET_PATTERNS:
        updated, count = pattern.subn(replacement, redacted)
        if count:
            redacted = updated
            changed = True
    return redacted, changed


def compute_exit_code(scan_status: str, policy_status: str) -> int:
    """Compute CI exit code with strict precedence: scan_fail(2) > policy_fail(1) > clean(0)."""
    if scan_status not in SCAN_STATUSES:
        raise ValueError(f"Unsupported scan_status: {scan_status!r}")
    if policy_status not in POLICY_STATUSES:
        raise ValueError(f"Unsupported policy_status: {policy_status!r}")
    if scan_status in {"failed", "partial", "unsupported"}:
        return 2
    if policy_status == "fail":
        return 1
    return 0


def _validate_choice(name: str, value: str, allowed: frozenset[str]) -> None:
    if value not in allowed:
        raise ValueError(f"Invalid {name}={value!r}; expected one of {sorted(allowed)}")


@dataclass(frozen=True)
class SourceSpan:
    """File/line span or JSON pointer locating a declaration, sink, or artifact."""

    path: str
    start_line: int | None = None
    start_col: int | None = None
    end_line: int | None = None
    end_col: int | None = None
    json_pointer: str | None = None

    def __post_init__(self) -> None:
        if not self.path or not isinstance(self.path, str):
            raise ValueError("SourceSpan.path must be a non-empty string")
        for label, val in (
            ("start_line", self.start_line),
            ("start_col", self.start_col),
            ("end_line", self.end_line),
            ("end_col", self.end_col),
        ):
            if val is not None and (type(val) is not int or val < 1):
                raise ValueError(f"SourceSpan.{label} must be a positive integer or None")

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"path": self.path}
        if self.start_line is not None:
            data["start_line"] = self.start_line
        if self.start_col is not None:
            data["start_col"] = self.start_col
        if self.end_line is not None:
            data["end_line"] = self.end_line
        if self.end_col is not None:
            data["end_col"] = self.end_col
        if self.json_pointer is not None:
            data["json_pointer"] = self.json_pointer
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SourceSpan:
        return cls(
            path=data["path"],
            start_line=data.get("start_line"),
            start_col=data.get("start_col"),
            end_line=data.get("end_line"),
            end_col=data.get("end_col"),
            json_pointer=data.get("json_pointer"),
        )


@dataclass(frozen=True)
class TraceStep:
    """Single step along a call-graph or data-flow evidence chain."""

    role: str
    span: SourceSpan
    symbol: str | None = None
    edge_kind: str = "definite"
    note: str | None = None

    def __post_init__(self) -> None:
        _validate_choice("TraceStep.role", self.role, TRACE_ROLES)
        _validate_choice("TraceStep.edge_kind", self.edge_kind, EDGE_KINDS)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "role": self.role,
            "span": self.span.to_dict(),
            "edge_kind": self.edge_kind,
        }
        if self.symbol is not None:
            data["symbol"] = self.symbol
        if self.note is not None:
            data["note"] = self.note
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TraceStep:
        return cls(
            role=data["role"],
            span=SourceSpan.from_dict(data["span"]),
            symbol=data.get("symbol"),
            edge_kind=data.get("edge_kind", "definite"),
            note=data.get("note"),
        )


@dataclass(frozen=True)
class RedactedEvidence:
    """Code or metadata snippet with credentials redacted."""

    snippet: str
    secrets_redacted: bool = False

    @classmethod
    def from_raw(cls, raw_snippet: str) -> RedactedEvidence:
        cleaned, changed = redact_secrets(raw_snippet)
        return cls(snippet=cleaned, secrets_redacted=changed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "snippet": self.snippet,
            "secrets_redacted": self.secrets_redacted,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RedactedEvidence:
        return cls(
            snippet=data["snippet"],
            secrets_redacted=bool(data.get("secrets_redacted", False)),
        )


@dataclass(frozen=True)
class OwaspMapping:
    """Predicate-grounded OWASP MCP Top 10:2025 & LLM Top 10:2025 mapping."""

    status: str = "pending_review"
    primary_id: str | None = None
    primary_name: str | None = None
    profile_version: str = DEFAULT_OWASP_PROFILE
    secondary_ids: tuple[str, ...] = ()
    llm_top10_ids: tuple[str, ...] = ()
    predicate_rationale: str = ""

    def __post_init__(self) -> None:
        _validate_choice("OwaspMapping.status", self.status, OWASP_MAPPING_STATUSES)
        if self.status == "mapped" and not self.primary_id:
            raise ValueError("OwaspMapping.primary_id is required when status='mapped'")

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "primary_id": self.primary_id,
            "primary_name": self.primary_name,
            "profile_version": self.profile_version,
            "secondary_ids": list(self.secondary_ids),
            "llm_top10_ids": list(self.llm_top10_ids),
            "predicate_rationale": self.predicate_rationale,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OwaspMapping:
        return cls(
            status=data.get("status", "pending_review"),
            primary_id=data.get("primary_id"),
            primary_name=data.get("primary_name"),
            profile_version=data.get("profile_version", DEFAULT_OWASP_PROFILE),
            secondary_ids=tuple(data.get("secondary_ids", ())),
            llm_top10_ids=tuple(data.get("llm_top10_ids", ())),
            predicate_rationale=data.get("predicate_rationale", ""),
        )


def make_finding_id(
    server_id: str,
    rule_id: str,
    sink_span: SourceSpan | None,
    declaration_span: SourceSpan | None = None,
) -> str:
    """Create a deterministic finding ID stable across reruns."""
    return stable_sha256_id(
        {
            "server_id": server_id,
            "rule_id": rule_id,
            "sink": sink_span.to_dict() if sink_span else None,
            "declaration": declaration_span.to_dict() if declaration_span else None,
        }
    )


def make_root_cause_group_id(
    server_id: str,
    component: str,
    root_behavior: str,
    primary_span: SourceSpan | None,
) -> str:
    """Create a deterministic root-cause key for single-trace deduplication."""
    return stable_sha256_id(
        {
            "server_id": server_id,
            "component": component,
            "root_behavior": root_behavior,
            "primary": primary_span.to_dict() if primary_span else None,
        },
        prefix="rcg:",
    )


@dataclass
class Finding:
    """Canonical security finding emitted by any scanner tier/detector."""

    finding_id: str
    root_cause_group_id: str
    server_id: str
    component: str
    rule_id: str
    rule_version: str
    detector: str
    kind: str
    category: str
    severity: str
    evidence_strength: str
    confidence: float
    mcp_surface: str
    title: str
    reasoning: str
    remediation: str
    owasp_mapping: OwaspMapping = field(default_factory=OwaspMapping)
    cwe_ids: list[str] = field(default_factory=list)
    declaration_span: SourceSpan | None = None
    sink_span: SourceSpan | None = None
    trace: list[TraceStep] = field(default_factory=list)
    redacted_evidence: RedactedEvidence | None = None
    limitations: list[str] = field(default_factory=list)
    evidence_sources: list[str] = field(default_factory=list)
    review_status: str = "not_required"

    def __post_init__(self) -> None:
        _validate_choice("Finding.kind", self.kind, FINDING_KINDS)
        _validate_choice("Finding.category", self.category, FINDING_CATEGORIES)
        _validate_choice("Finding.severity", self.severity, SEVERITIES)
        _validate_choice("Finding.evidence_strength", self.evidence_strength, EVIDENCE_STRENGTHS)
        _validate_choice("Finding.mcp_surface", self.mcp_surface, MCP_SURFACES)
        _validate_choice("Finding.review_status", self.review_status, REVIEW_STATUSES)
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Finding.confidence must be in [0.0, 1.0], got {self.confidence}")
        if not self.evidence_sources:
            self.evidence_sources = [self.detector]

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "root_cause_group_id": self.root_cause_group_id,
            "server_id": self.server_id,
            "component": self.component,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "detector": self.detector,
            "kind": self.kind,
            "category": self.category,
            "severity": self.severity,
            "evidence_strength": self.evidence_strength,
            "confidence": round(float(self.confidence), 4),
            "mcp_surface": self.mcp_surface,
            "owasp_mapping": self.owasp_mapping.to_dict(),
            "cwe_ids": list(self.cwe_ids),
            "title": self.title,
            "declaration_span": self.declaration_span.to_dict() if self.declaration_span else None,
            "sink_span": self.sink_span.to_dict() if self.sink_span else None,
            "trace": [step.to_dict() for step in self.trace],
            "redacted_evidence": self.redacted_evidence.to_dict() if self.redacted_evidence else None,
            "reasoning": self.reasoning,
            "remediation": self.remediation,
            "limitations": list(self.limitations),
            "evidence_sources": sorted(set(self.evidence_sources)),
            "review_status": self.review_status,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            finding_id=data["finding_id"],
            root_cause_group_id=data["root_cause_group_id"],
            server_id=data["server_id"],
            component=data["component"],
            rule_id=data["rule_id"],
            rule_version=data["rule_version"],
            detector=data["detector"],
            kind=data["kind"],
            category=data["category"],
            severity=data["severity"],
            evidence_strength=data["evidence_strength"],
            confidence=float(data["confidence"]),
            mcp_surface=data["mcp_surface"],
            title=data["title"],
            reasoning=data["reasoning"],
            remediation=data["remediation"],
            owasp_mapping=OwaspMapping.from_dict(data["owasp_mapping"]),
            cwe_ids=list(data.get("cwe_ids", [])),
            declaration_span=(
                SourceSpan.from_dict(data["declaration_span"])
                if data.get("declaration_span")
                else None
            ),
            sink_span=(
                SourceSpan.from_dict(data["sink_span"]) if data.get("sink_span") else None
            ),
            trace=[TraceStep.from_dict(item) for item in data.get("trace", [])],
            redacted_evidence=(
                RedactedEvidence.from_dict(data["redacted_evidence"])
                if data.get("redacted_evidence")
                else None
            ),
            limitations=list(data.get("limitations", [])),
            evidence_sources=list(data.get("evidence_sources", [])),
            review_status=data.get("review_status", "not_required"),
        )


@dataclass(frozen=True)
class SkippedFile:
    path: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "reason": self.reason}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SkippedFile:
        return cls(path=data["path"], reason=data["reason"])


@dataclass(frozen=True)
class ReadErrorRecord:
    path: str
    error_code: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "error_code": self.error_code,
            "message": self.message,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReadErrorRecord:
        return cls(
            path=data["path"],
            error_code=data["error_code"],
            message=data["message"],
        )


@dataclass(frozen=True)
class AnalysisBoundary:
    kind: str
    location: str | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        _validate_choice("AnalysisBoundary.kind", self.kind, ANALYSIS_BOUNDARY_KINDS)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "location": self.location, "detail": self.detail}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnalysisBoundary:
        return cls(
            kind=data["kind"],
            location=data.get("location"),
            detail=data.get("detail", ""),
        )


@dataclass
class CoverageInfo:
    """Explicit file, surface, SCA, and analysis-boundary coverage telemetry."""

    files_discovered: int = 0
    files_scanned: int = 0
    scanned_files: list[str] = field(default_factory=list)
    skipped_files: list[SkippedFile] = field(default_factory=list)
    read_errors: list[ReadErrorRecord] = field(default_factory=list)
    skipped_budget: list[SkippedFile] = field(default_factory=list)
    surfaces: dict[str, str] = field(default_factory=dict)
    sca_status: str = "unmeasured"
    analysis_boundaries: list[AnalysisBoundary] = field(default_factory=list)

    def __post_init__(self) -> None:
        _validate_choice("CoverageInfo.sca_status", self.sca_status, SCA_STATUSES)

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_discovered": self.files_discovered,
            "files_scanned": self.files_scanned,
            "scanned_files": sorted(self.scanned_files),
            "skipped_files": [item.to_dict() for item in self.skipped_files],
            "read_errors": [item.to_dict() for item in self.read_errors],
            "skipped_budget": [item.to_dict() for item in self.skipped_budget],
            "surfaces": dict(sorted(self.surfaces.items())),
            "sca_status": self.sca_status,
            "analysis_boundaries": [item.to_dict() for item in self.analysis_boundaries],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CoverageInfo:
        return cls(
            files_discovered=int(data.get("files_discovered", 0)),
            files_scanned=int(data.get("files_scanned", 0)),
            scanned_files=list(data.get("scanned_files", [])),
            skipped_files=[SkippedFile.from_dict(x) for x in data.get("skipped_files", [])],
            read_errors=[ReadErrorRecord.from_dict(x) for x in data.get("read_errors", [])],
            skipped_budget=[SkippedFile.from_dict(x) for x in data.get("skipped_budget", [])],
            surfaces=dict(data.get("surfaces", {})),
            sca_status=data.get("sca_status", "unmeasured"),
            analysis_boundaries=[
                AnalysisBoundary.from_dict(x) for x in data.get("analysis_boundaries", [])
            ],
        )


@dataclass
class LlmTriageTelemetry:
    enabled: bool = False
    status: str = "disabled"
    model_id: str | None = None
    prompt_hash: str | None = None
    tokens_used: int = 0
    estimated_cost_usd: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "status": self.status,
            "model_id": self.model_id,
            "prompt_hash": self.prompt_hash,
            "tokens_used": self.tokens_used,
            "estimated_cost_usd": round(float(self.estimated_cost_usd), 6),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LlmTriageTelemetry:
        return cls(
            enabled=bool(data.get("enabled", False)),
            status=data.get("status", "disabled"),
            model_id=data.get("model_id"),
            prompt_hash=data.get("prompt_hash"),
            tokens_used=int(data.get("tokens_used", 0)),
            estimated_cost_usd=float(data.get("estimated_cost_usd", 0.0)),
        )


@dataclass
class ScanTelemetry:
    elapsed_seconds: float = 0.0
    stage_durations_seconds: dict[str, float] = field(default_factory=dict)
    budget_cutoff_seconds: float = 50.0
    hard_timeout_seconds: float = 60.0
    timed_out: bool = False
    llm_triage: LlmTriageTelemetry = field(default_factory=LlmTriageTelemetry)

    def to_dict(self) -> dict[str, Any]:
        return {
            "elapsed_seconds": round(float(self.elapsed_seconds), 4),
            "stage_durations_seconds": {
                k: round(float(v), 4) for k, v in sorted(self.stage_durations_seconds.items())
            },
            "budget_cutoff_seconds": float(self.budget_cutoff_seconds),
            "hard_timeout_seconds": float(self.hard_timeout_seconds),
            "timed_out": self.timed_out,
            "llm_triage": self.llm_triage.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanTelemetry:
        return cls(
            elapsed_seconds=float(data.get("elapsed_seconds", 0.0)),
            stage_durations_seconds={
                k: float(v) for k, v in data.get("stage_durations_seconds", {}).items()
            },
            budget_cutoff_seconds=float(data.get("budget_cutoff_seconds", 50.0)),
            hard_timeout_seconds=float(data.get("hard_timeout_seconds", 60.0)),
            timed_out=bool(data.get("timed_out", False)),
            llm_triage=LlmTriageTelemetry.from_dict(data.get("llm_triage", {})),
        )


@dataclass
class TrustScore:
    """Evidence-driven 0-100 review-priority score (decoupled from binary verdict)."""

    score_scope: str = "unavailable"
    observed_score: int | None = None
    displayed_score: int | None = None
    provisional_cap: int | None = None
    policy_version: str = DEFAULT_TRUST_POLICY_VERSION
    reason: str = ""
    contributing_finding_ids: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        _validate_choice("TrustScore.score_scope", self.score_scope, SCORE_SCOPES)
        for label, score in (
            ("observed_score", self.observed_score),
            ("displayed_score", self.displayed_score),
        ):
            if score is not None and not (0 <= score <= 100):
                raise ValueError(f"TrustScore.{label} must be in [0, 100], got {score}")
        if self.score_scope == "provisional":
            cap = self.provisional_cap if self.provisional_cap is not None else PROVISIONAL_SCORE_CAP
            if self.displayed_score is not None and self.displayed_score > cap:
                raise ValueError(
                    f"Provisional displayed_score ({self.displayed_score}) cannot exceed cap ({cap})"
                )
        if self.score_scope == "unavailable" and self.displayed_score is not None:
            raise ValueError("Unavailable TrustScore must have displayed_score=None")

    def to_dict(self) -> dict[str, Any]:
        return {
            "score_scope": self.score_scope,
            "observed_score": self.observed_score,
            "displayed_score": self.displayed_score,
            "provisional_cap": self.provisional_cap,
            "policy_version": self.policy_version,
            "reason": self.reason,
            "contributing_finding_ids": list(self.contributing_finding_ids),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrustScore:
        return cls(
            score_scope=data.get("score_scope", "unavailable"),
            observed_score=data.get("observed_score"),
            displayed_score=data.get("displayed_score"),
            provisional_cap=data.get("provisional_cap"),
            policy_version=data.get("policy_version", DEFAULT_TRUST_POLICY_VERSION),
            reason=data.get("reason", ""),
            contributing_finding_ids=list(data.get("contributing_finding_ids", [])),
        )


@dataclass(frozen=True)
class TopFindingSummary:
    """Single item in the Executive Summary TL;DR Top 5."""

    finding_id: str
    title: str
    severity: str
    owasp_id: str | None
    impact_summary: str
    location: str
    remediation: str

    def __post_init__(self) -> None:
        _validate_choice("TopFindingSummary.severity", self.severity, SEVERITIES)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "owasp_id": self.owasp_id,
            "impact_summary": self.impact_summary,
            "location": self.location,
            "remediation": self.remediation,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TopFindingSummary:
        return cls(
            finding_id=data["finding_id"],
            title=data["title"],
            severity=data["severity"],
            owasp_id=data.get("owasp_id"),
            impact_summary=data["impact_summary"],
            location=data["location"],
            remediation=data["remediation"],
        )


@dataclass
class ExecutiveSummary:
    """Executive TL;DR highlighting up to 5 most critical distinct findings."""

    tldr: str = ""
    severity_counts: dict[str, int] = field(
        default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    )
    owasp_counts: dict[str, int] = field(default_factory=dict)
    top_5: list[TopFindingSummary] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.top_5) > 5:
            raise ValueError("ExecutiveSummary.top_5 cannot contain more than 5 items")

    def to_dict(self) -> dict[str, Any]:
        return {
            "tldr": self.tldr,
            "severity_counts": {
                sev: int(self.severity_counts.get(sev, 0))
                for sev in ("critical", "high", "medium", "low", "info")
            },
            "owasp_counts": dict(sorted(self.owasp_counts.items())),
            "top_5": [item.to_dict() for item in self.top_5],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecutiveSummary:
        return cls(
            tldr=data.get("tldr", ""),
            severity_counts=dict(data.get("severity_counts", {})),
            owasp_counts=dict(data.get("owasp_counts", {})),
            top_5=[TopFindingSummary.from_dict(x) for x in data.get("top_5", [])],
        )


@dataclass
class ReviewQueueState:
    """Routing metadata for Phase 5 two-reviewer manual adjudication."""

    requires_review: bool = False
    priority_tier: str = "none"
    reasons: list[str] = field(default_factory=list)
    status: str = "not_required"

    def __post_init__(self) -> None:
        _validate_choice("ReviewQueueState.priority_tier", self.priority_tier, REVIEW_PRIORITY_TIERS)
        _validate_choice("ReviewQueueState.status", self.status, REVIEW_STATUSES)

    def to_dict(self) -> dict[str, Any]:
        return {
            "requires_review": self.requires_review,
            "priority_tier": self.priority_tier,
            "reasons": list(self.reasons),
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReviewQueueState:
        return cls(
            requires_review=bool(data.get("requires_review", False)),
            priority_tier=data.get("priority_tier", "none"),
            reasons=list(data.get("reasons", [])),
            status=data.get("status", "not_required"),
        )


@dataclass
class InputProvenance:
    """Immutable provenance metadata for the scanned target."""

    server_id: str
    input_kind: str
    location: str
    snapshot_sha256: str
    source_id: str | None = None
    revision: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        _validate_choice("InputProvenance.input_kind", self.input_kind, INPUT_KINDS)

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "source_id": self.source_id,
            "input_kind": self.input_kind,
            "location": self.location,
            "revision": self.revision,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "snapshot_sha256": self.snapshot_sha256,
            "languages": sorted(set(self.languages)),
            "frameworks": sorted(set(self.frameworks)),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InputProvenance:
        return cls(
            server_id=data["server_id"],
            input_kind=data["input_kind"],
            location=data["location"],
            snapshot_sha256=data["snapshot_sha256"],
            source_id=data.get("source_id"),
            revision=data.get("revision"),
            package_name=data.get("package_name"),
            package_version=data.get("package_version"),
            languages=list(data.get("languages", [])),
            frameworks=list(data.get("frameworks", [])),
        )


@dataclass
class ScannerIdentity:
    """Version & configuration fingerprint for reproducibility."""

    name: str = "mcp-scanner"
    version: str = "0.5.0-dev"
    profile: str = "static-default"
    ruleset_sha256: str | None = None
    policy_version: str = DEFAULT_TRUST_POLICY_VERSION
    owasp_profile: str = DEFAULT_OWASP_PROFILE
    engines: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "profile": self.profile,
            "ruleset_sha256": self.ruleset_sha256,
            "policy_version": self.policy_version,
            "owasp_profile": self.owasp_profile,
            "engines": list(self.engines),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScannerIdentity:
        return cls(
            name=data.get("name", "mcp-scanner"),
            version=data.get("version", "0.5.0-dev"),
            profile=data.get("profile", "static-default"),
            ruleset_sha256=data.get("ruleset_sha256"),
            policy_version=data.get("policy_version", DEFAULT_TRUST_POLICY_VERSION),
            owasp_profile=data.get("owasp_profile", DEFAULT_OWASP_PROFILE),
            engines=list(data.get("engines", [])),
        )


@dataclass
class ScanReport:
    """Top-level canonical v1.0 scan report envelope."""

    input_provenance: InputProvenance
    scan_status: str
    policy_status: str
    scanner: ScannerIdentity = field(default_factory=ScannerIdentity)
    generated_at: str = field(default_factory=utc_now_iso)
    contract_version: str = CONTRACT_VERSION
    artifact_type: str = ARTIFACT_TYPE_SCAN_REPORT
    coverage: CoverageInfo = field(default_factory=CoverageInfo)
    telemetry: ScanTelemetry = field(default_factory=ScanTelemetry)
    discovered_servers: list[dict[str, Any]] = field(default_factory=list)
    trust_score: TrustScore = field(default_factory=TrustScore)
    executive_summary: ExecutiveSummary = field(default_factory=ExecutiveSummary)
    findings: list[Finding] = field(default_factory=list)
    review_queue: ReviewQueueState = field(default_factory=ReviewQueueState)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    exit_code: int | None = None

    def __post_init__(self) -> None:
        _validate_choice("ScanReport.scan_status", self.scan_status, SCAN_STATUSES)
        _validate_choice("ScanReport.policy_status", self.policy_status, POLICY_STATUSES)
        expected_exit = compute_exit_code(self.scan_status, self.policy_status)
        if self.exit_code is None:
            self.exit_code = expected_exit
        elif self.exit_code != expected_exit:
            raise ValueError(
                f"Inconsistent exit_code={self.exit_code} for "
                f"scan_status={self.scan_status!r}, policy_status={self.policy_status!r} "
                f"(expected {expected_exit})"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "artifact_type": self.artifact_type,
            "generated_at": self.generated_at,
            "scanner": self.scanner.to_dict(),
            "input_provenance": self.input_provenance.to_dict(),
            "scan_status": self.scan_status,
            "policy_status": self.policy_status,
            "exit_code": self.exit_code,
            "coverage": self.coverage.to_dict(),
            "telemetry": self.telemetry.to_dict(),
            "discovered_servers": list(self.discovered_servers),
            "trust_score": self.trust_score.to_dict(),
            "executive_summary": self.executive_summary.to_dict(),
            "findings": [item.to_dict() for item in self.findings],
            "review_queue": self.review_queue.to_dict(),
            "diagnostics": list(self.diagnostics),
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False) + "\n"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanReport:
        return cls(
            contract_version=data["contract_version"],
            artifact_type=data["artifact_type"],
            generated_at=data["generated_at"],
            scanner=ScannerIdentity.from_dict(data["scanner"]),
            input_provenance=InputProvenance.from_dict(data["input_provenance"]),
            scan_status=data["scan_status"],
            policy_status=data["policy_status"],
            exit_code=data.get("exit_code"),
            coverage=CoverageInfo.from_dict(data.get("coverage", {})),
            telemetry=ScanTelemetry.from_dict(data.get("telemetry", {})),
            discovered_servers=list(data.get("discovered_servers", [])),
            trust_score=TrustScore.from_dict(data.get("trust_score", {})),
            executive_summary=ExecutiveSummary.from_dict(data.get("executive_summary", {})),
            findings=[Finding.from_dict(item) for item in data.get("findings", [])],
            review_queue=ReviewQueueState.from_dict(data.get("review_queue", {})),
            diagnostics=list(data.get("diagnostics", [])),
        )


def findings_from_v01_semgrep_artifact(
    artifact: dict[str, Any],
    *,
    rule_category_map: dict[str, str] | None = None,
    rule_cwe_map: dict[str, list[str]] | None = None,
) -> tuple[list[Finding], list[str], list[SkippedFile], list[dict[str, Any]]]:
    """Convert a v0.1 semgrep_adapter finding artifact into canonical v1.0 Findings.

    Preserves backward compatibility with existing semgrep_adapter.scan_code() outputs.
    """
    if artifact.get("contract_version") != "0.1" or artifact.get("artifact_type") != "finding":
        raise ValueError("Expected a v0.1 finding artifact from semgrep_adapter")

    category_map = rule_category_map or {
        "mcp-shell-input": "C",
        "mcp-path-traversal-read": "other",
    }
    cwe_map = rule_cwe_map or {
        "mcp-shell-input": ["CWE-78"],
        "mcp-path-traversal-read": ["CWE-22"],
    }

    evidence_by_id = {ev["evidence_id"]: ev for ev in artifact.get("evidence", [])}
    findings: list[Finding] = []
    for item in artifact.get("items", []):
        rule_id = item["rule_id"]
        server_id = item["server_id"]
        ev_refs = item.get("evidence_ids") or []
        ev = evidence_by_id.get(ev_refs[0]) if ev_refs else None
        sink_span = (
            SourceSpan(
                path=ev["path"],
                start_line=ev["start"]["line"],
                start_col=ev["start"]["column"],
                end_line=ev["end"]["line"],
                end_col=ev["end"]["column"],
            )
            if ev is not None
            else None
        )
        category = category_map.get(rule_id, "other")
        cwe_ids = list(cwe_map.get(rule_id, []))
        rcg_id = make_root_cause_group_id(
            server_id=server_id,
            component="unknown",
            root_behavior=rule_id,
            primary_span=sink_span,
        )
        findings.append(
            Finding(
                finding_id=item["finding_id"],
                root_cause_group_id=rcg_id,
                server_id=server_id,
                component="unknown",
                rule_id=rule_id,
                rule_version="0.1",
                detector="semgrep_ce",
                kind="vulnerability",
                category=category,
                severity=item["severity"],
                evidence_strength="traced_or_grounded",
                confidence=0.85,
                mcp_surface="A5",
                title=item["title"],
                reasoning="Matched static Semgrep CE taint/pattern rule in local source.",
                remediation="Validate untrusted tool arguments and replace unsafe sinks with constrained APIs.",
                owasp_mapping=OwaspMapping(
                    status="pending_review",
                    predicate_rationale="Raw v0.1 Semgrep finding awaiting OWASP predicate enrichment.",
                ),
                cwe_ids=cwe_ids,
                sink_span=sink_span,
                trace=(
                    [TraceStep(role="sink", span=sink_span, symbol=rule_id)]
                    if sink_span
                    else []
                ),
                evidence_sources=["semgrep_ce"],
                review_status="pending" if item["severity"] in {"high", "critical"} else "not_required",
            )
        )

    cov = artifact.get("coverage") or {}
    scanned = list(cov.get("scanned") or [])
    skipped = [
        SkippedFile(path=s["path"], reason=s.get("reason") or "semgrep_skipped")
        for s in (cov.get("skipped") or [])
    ]
    diagnostics = list(artifact.get("diagnostics") or [])
    return findings, scanned, skipped, diagnostics
