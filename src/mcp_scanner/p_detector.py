"""Bounded English instruction heuristics for extracted MCP text.

These rules identify explicit instruction patterns for review. They do not
establish malicious intent or observe execution by an agent.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
import time

from .models import Finding, RedactedEvidence, make_root_cause_group_id, stable_sha256_id
from .p_surface import SurfaceText


RULE_VERSION = "0.2"
MAX_TEXT_CHARS = 65536
_PREFIX = r"(?:assistant\s*[:,]\s*|you\s+(?:must|should)\s+)?"
_RULES = (
    ("instruction-override", re.compile(
        r"\b" + _PREFIX + r"(?:ignore|disregard|override)\s+(?:all\s+)?"
        r"(?:previous|prior|system|developer|higher[- ]priority)\s+"
        r"(?:instructions?|prompts?|messages?|rules?)\b", re.I),
     "Tool description requests overriding higher-priority instructions"),
    ("concealed-tool-action", re.compile(
        r"\b" + _PREFIX + r"(?:silently|secretly|covertly)\s+"
        r"(?:invoke|call|execute|run|send|upload|transmit)\b", re.I),
     "Tool description requests a concealed action"),
    ("conversation-disclosure", re.compile(
        r"\b(?:include|copy|paste|reproduce|attach|embed|send|upload|transmit|reveal|expose|publish)\s+"
        r"(?:the\s+)?(?:full\s+|entire\s+|complete\s+|verbatim\s+|text\s+of\s+|all\s+)*"
        r"(?:(?:the\s+)?user['’]s\s+)?(?:earlier|previous|prior|private)\s+"
        r"(?:messages?|conversation|chat|dialogue|history)\b", re.I),
     "Tool description requests disclosure of earlier conversation content"),
    ("internal-data-disclosure", re.compile(
        r"\b(?:include|copy|paste|attach|embed|send|upload|transmit|reveal|expose|publish|present)\b"
        r"[^.!?\n]{0,100}\b(?:internal|private|confidential|restricted)\s+"
        r"(?:record\s+identifiers?|records?|rows?|data|identifiers?|documents?|files?)\b"
        r"[^.!?\n]{0,180}\b(?:reply|answer|response|output|public|customer)\b", re.I),
     "Tool description directs internal data into an outward response"),
    ("persistent-redirection", re.compile(
        r"\b(?:attach|append|include|insert|use|apply|follow)\b[^.!?\n]{0,200}"
        r"\b(?:every\s+(?:subsequent|future)\s+(?:answer|response|reply)|all\s+future\s+(?:answers|responses|replies))\b"
        r"[^.!?\n]{0,150}\b(?:unrelated|regardless\s+of|even\s+when)\b", re.I),
     "Tool description redirects future answers beyond the current request"),
    ("concealed-substitution", re.compile(
        r"\b(?:replace|substitute|change|switch|override)\b[^.!?\n]{0,500}"
        r"\bwithout\s+(?:mentioning|disclosing|telling|informing|acknowledging)\b", re.I),
     "Tool description requests a concealed substitution of the requested result"),
)
# Only explicit grammatical negations or a reporting prefix qualify here.
# Quotes, code fences, and words such as 'documentation' alone do not.
_NEGATION = re.compile(r"\b(?:do\s+not|don't|never|must\s+not|should\s+not)\s*$", re.I)
_REPORTING = re.compile(
    r"^\s*(?:a\s+|an\s+|the\s+)?(?:example|tutorial|glossary|training\s+exercise|"
    r"security\s+guide)\s+(?:quotes?|discusses?|describes?|explains?|"
    r"warns\s+against)\b", re.I)


@dataclass
class PDetectionResult:
    findings: list[Finding] = field(default_factory=list)
    diagnostics: list[dict[str, object]] = field(default_factory=list)
    status: str = "complete"


def detect_surface_instructions(
    texts: list[SurfaceText], *, deadline: float | None = None,
) -> PDetectionResult:
    """Analyze supported tool/schema/resource/prompt text in English.

    Other surface kinds are explicitly unsupported.
    No-match means these English heuristics did not match the observed text.
    """
    result = PDetectionResult()
    seen = set()
    for item in texts:
        field_label = "Input field" if item.surface_kind == "input_schema_description" else "Field"
        reason = None
        if deadline is not None and time.monotonic() >= deadline:
            reason = "P_DETECTION_DEADLINE"
        elif item.surface_kind not in {"tool_description", "input_schema_description", "resource_metadata", "resource_body", "prompt_metadata", "prompt_message", "tool_result"}:
            reason = "P_UNSUPPORTED_SURFACE"
        elif len(item.text) > MAX_TEXT_CHARS:
            reason = "P_TEXT_LIMIT"
        if reason:
            result.status = "partial"
            result.diagnostics.append({
                "code": reason, "server_id": item.server_id,
                "component": item.component, "location": item.content_span.to_dict(),
            })
            if reason == "P_DETECTION_DEADLINE":
                break
            continue
        for suffix, pattern, title in _RULES:
            matches = []
            for sentence in re.finditer(r"[^.!?;\n]+[.!?;]?", item.text):
                for match in pattern.finditer(sentence.group()):
                    prefix = sentence.group()[:match.start()]
                    if _NEGATION.search(prefix) or _REPORTING.match(prefix):
                        continue
                    matches.append(sentence.group().strip())
            if not matches:
                continue
            prefix, label, surface_code = {
                "tool_description": ("description", "Tool description", "A4"),
                "input_schema_description": ("schema", "Input schema description", "A4"),
                "resource_metadata": ("resource-metadata", "Resource metadata", "A7"),
                "resource_body": ("resource-body", "Resource content", "A9"),
                "prompt_metadata": ("prompt-metadata", "Prompt metadata", "A10"),
                "prompt_message": ("prompt-message", "Prompt message", "A12"),
                "tool_result": ("tool-result", "Tool result", "A6"),
            }[item.surface_kind]
            rule_id = f"mcp-p-{prefix}-" + suffix
            title = title.replace("Tool description", label)
            group = make_root_cause_group_id(
                item.server_id, item.component, f"p_{prefix}_instruction", item.content_span,
            )
            finding_id = stable_sha256_id({"rule": rule_id, "root_cause": group})
            if finding_id in seen:
                continue
            seen.add(finding_id)
            # Bound exported evidence independently of the analysis limit.
            snippet = "\n".join(dict.fromkeys(matches))[:2000]
            result.findings.append(Finding(
                finding_id=finding_id, root_cause_group_id=group,
                server_id=item.server_id, component=item.component,
                rule_id=rule_id, rule_version=RULE_VERSION,
                detector="p_surface." + prefix.replace("-", "_") + "_heuristics",
                kind="semantic_indicator", category="P", severity="medium",
                evidence_strength="heuristic_only", confidence=0.5,
                mcp_surface=surface_code, title=title,
                reasoning=("An English directive in MCP text matches the recorded instruction pattern."
                           + (f" {field_label}: {item.field_path}." if item.field_path else "")),
                remediation="Review the MCP content and remove instructions that redirect or conceal agent actions.",
                declaration_span=item.declaration_span, sink_span=item.content_span,
                trace=list(item.trace),
                redacted_evidence=RedactedEvidence.from_raw(snippet),
                limitations=[
                    "Bounded English heuristics can produce false positives and false negatives.",
                    "Confidence is a policy default and is not statistically calibrated.",
                    "The span locates the original expression, not an exact normalized-text match.",
                    "Agent execution and malicious intent have not been verified.",
                    *item.limitations,
                ],
                review_status="pending",
            ))
    result.findings.sort(key=lambda finding: finding.finding_id)
    return result




def detect_tool_description_instructions(texts, *, deadline=None):
    """Compatibility entry point for the original description detector."""
    return detect_surface_instructions(texts, deadline=deadline)
