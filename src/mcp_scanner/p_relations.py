"""Offline evidence composition for explicitly named MCP invocation directives.

This is a bounded grammar plus static code evidence, not a natural-language
intent model. An LLM-mediated edge is always possible, never observed execution.
"""
from __future__ import annotations

from dataclasses import replace
import ast
import hashlib
import time

from .models import Finding, RedactedEvidence, TraceStep, make_root_cause_group_id, stable_sha256_id, redact_secrets
from .p_behavior import summarize_handlers, specialize_handler
from .p_detector import PDetectionResult
from .p_directives import DirectiveBudgetExceeded, extract_directives

RELATION_VERSION = "0.1"
MAX_RELATIONS = 128
# These rules carry concrete sensitive-data transfer or fixed harmful-action
# evidence. A generic input-to-shell or network capability is deliberately not
# sufficient. No external-content return is classified as injection by itself.
_CONSEQUENCES = frozenset({
    "mcp-py-sensitive-network-flow", "mcp-py-shell-sensitive-transfer",
    "mcp-py-risky-fixed-execution", "mcp-py-resource-destruction",
})
_SURFACES = {"tool_description": "A4", "input_schema_description": "A4",
             "tool_result": "A6", "resource_metadata": "A7", "resource_body": "A9",
             "prompt_metadata": "A10", "prompt_message": "A12"}


def _redacted(value):
    if isinstance(value, str):
        return redact_secrets(value)[0]
    if isinstance(value, dict):
        return {_redacted(key): _redacted(member) for key, member in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redacted(member) for member in value]
    return value


def _site(span):
    return None if span is None else (span.path, span.start_line, span.start_col)


def _resource_names(inventory, summary):
    """Only literal published URIs, read from approved inventory text."""
    span = summary.declaration_span
    record = inventory.by_rel_path().get(span.path)
    if record is None or record.text is None:
        return set()
    try:
        tree = ast.parse(record.text.removeprefix("\ufeff"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and node.lineno == span.start_line
                    and node.col_offset + 1 == span.start_col):
                value = next((kw.value for kw in node.keywords if kw.arg == "uri"),
                             node.args[0] if node.args else None)
                return {value.value} if isinstance(value, ast.Constant) and isinstance(value.value, str) else set()
    except (SyntaxError, ValueError, RecursionError):
        pass
    return set()


def analyze_instruction_relations(inventory, discovered_servers, texts, findings, *, deadline=None):
    """Compose invocation facts with specialized, sink-grounded code evidence.

    Returned replacements retain existing P finding IDs so a second detector
    does not double-charge the same text. Diagnostics never expose raw literals.
    Empty findings are not a general benignness or prompt-injection proof.
    """
    result = PDetectionResult()
    output_flows = {}
    for item in texts:
        if item.surface_kind not in {"tool_result", "resource_body", "prompt_message"}:
            continue
        key = item.server_id, item.component
        flow = output_flows.setdefault(key, {"code": "P_RETURN_FLOW_SUMMARY",
            "server_id": item.server_id, "component": item.component,
            "scope": "statically extracted text to MCP-visible output; not an injection verdict",
            "paths": []})
        if len(flow["paths"]) >= 64:
            # Bound exported telemetry only. Every text is still inspected by
            # the directive pass below; this is not an analysis coverage gap.
            flow["export_truncated"] = True
            flow["omitted_path_count"] = flow.get("omitted_path_count", 0) + 1
            continue
        flow["paths"].append({"field_path": item.field_path,
            "content_sha256": hashlib.sha256(item.text.encode()).hexdigest(),
            "content_span": item.content_span.to_dict(),
            "trace": [step.to_dict() for step in item.trace],
            "limitations": list(item.limitations)})
    result.diagnostics.extend(output_flows.values())
    candidates = []
    try:
        for item in texts:
            if deadline is not None and time.monotonic() >= deadline:
                raise DirectiveBudgetExceeded("deadline")
            for directive in extract_directives(item.text, deadline=deadline):
                candidates.append((item, directive))
                if len(candidates) > MAX_RELATIONS:
                    raise DirectiveBudgetExceeded("relation limit")
    except DirectiveBudgetExceeded:
        result.status = "partial"
        result.diagnostics.append({"code": "P_RELATION_BUDGET", "scope": "offline-instruction-relations"})
        result.diagnostics = _redacted(result.diagnostics)
        return result
    # Summaries are available for audit even when no grammar-supported directive
    # occurs. They report observed static findings, not 'safe' handler labels.
    behavior = summarize_handlers(inventory, discovered_servers, findings, deadline=deadline)
    result.diagnostics.extend(behavior.diagnostics)
    for summary in behavior.summaries:
        result.diagnostics.append({"code": "P_HANDLER_BEHAVIOR_SUMMARY", **summary.to_dict()})
    if behavior.status != "complete":
        result.status = "partial"
    by_name = {}
    for summary in behavior.summaries:
        kind, _, name = summary.component.partition(":")
        keys = {name} if kind == "tool" else _resource_names(inventory, summary) if kind == "resource" else set()
        action = "call_tool" if kind == "tool" else "read_resource"
        for name in keys:
            by_name.setdefault((summary.server_id, action, name), []).append(summary)
    existing = {f.finding_id: f for f in findings if f.category == "P"}
    grouped = {}
    cache = {}
    for item, directive in candidates:
        if not directive.arguments_complete:
            result.status = "partial"
            result.diagnostics.append({"code": "P_RELATION_ARGUMENTS_UNRESOLVED",
                "server_id": item.server_id, "component": item.component,
                "location": item.content_span.to_dict()})
            continue
        key = (item.server_id, directive.action, directive.target)
        matches = by_name.get(key, [])
        if len(matches) != 1:
            result.status = "partial"
            result.diagnostics.append({"code": "P_RELATION_TARGET_UNRESOLVED",
                "server_id": item.server_id, "component": item.component,
                "location": item.content_span.to_dict(), "candidate_count": len(matches)})
            continue
        summary, = matches
        if summary.component == item.component:
            # A tool's own usage documentation is not evidence of cross-tool
            # redirection. Self-directed chains need a separate reviewed model.
            result.status = "partial"
            result.diagnostics.append({"code": "P_RELATION_SELF_UNSUPPORTED",
                "server_id": item.server_id, "component": item.component,
                "location": item.content_span.to_dict()})
            continue
        cache_key = stable_sha256_id({"server": summary.server_id,
            "declaration": summary.declaration_span.to_dict(), "args": directive.arguments})
        if cache_key not in cache:
            cache[cache_key] = specialize_handler(inventory, summary, directive.arguments, deadline=deadline)
        specialized = cache[cache_key]
        if specialized.status != "complete":
            result.status = "partial"
            result.diagnostics.append({"code": "P_RELATION_SPECIALIZATION_PARTIAL",
                "server_id": item.server_id, "component": item.component,
                "location": item.content_span.to_dict(),
                "target_declaration": summary.declaration_span.to_dict()})
            continue
        consequences = [f for f in specialized.findings if f.rule_id in _CONSEQUENCES
                        and f.sink_span is not None and f.component == summary.component]
        for consequence in consequences:
            # A sink on a still-possible code branch is not a literal-activated
            # path. Unknown branch tracing is independently guarded by the
            # specialization implementation.
            if any(step.edge_kind == "possible" for step in consequence.trace):
                result.status = "partial"
                result.diagnostics.append({"code": "P_RELATION_CONSEQUENCE_UNRESOLVED",
                    "server_id": item.server_id, "component": item.component,
                    "location": item.content_span.to_dict()})
                continue
            group_key = item.server_id, item.component, _site(item.content_span)
            entry = grouped.setdefault(group_key, [item, [], []])
            entry[1].append(directive.evidence)
            entry[2].append((summary, consequence))
    for item, evidence, links in grouped.values():
        prior = next((f for f in existing.values() if f.server_id == item.server_id
                      and f.component == item.component and _site(f.sink_span) == _site(item.content_span)), None)
        trace = list(item.trace)
        trace.append(TraceStep("source", item.content_span, symbol="explicit MCP invocation directive"))
        for summary, consequence in links:
            trace.append(TraceStep("call", summary.declaration_span, symbol=summary.component,
                edge_kind="possible", note="Directive requests this invocation; agent compliance is unobserved."))
            trace.extend(replace(step, edge_kind="possible") for step in consequence.trace)
        trace = [s for i,s in enumerate(trace) if s not in trace[:i]]
        limitations = ["English invocation grammar and Python handler specialization are bounded.",
            "Agent compliance is unobserved; the cross-component edge is possible.",
            "Sensitive transfer or fixed harmful-action evidence does not establish author intent.",
            "No-match does not establish benignness or absence of prompt injection.", *item.limitations]
        text_evidence = RedactedEvidence.from_raw("\n".join(dict.fromkeys(evidence))[:2000])
        if prior is not None:
            result.findings.append(replace(prior, trace=prior.trace + [s for s in trace if s not in prior.trace],
                reasoning=prior.reasoning + " Offline specialization also links an explicit invocation directive to a sensitive action in another component.",
                evidence_sources=list(dict.fromkeys([*prior.evidence_sources, "p_offline_relations"])),
                limitations=list(dict.fromkeys([*prior.limitations, *limitations]))))
        else:
            root = make_root_cause_group_id(item.server_id, item.component, "p_offline_instruction", item.content_span)
            result.findings.append(Finding(
                finding_id=stable_sha256_id({"rule": "mcp-p-offline-instruction-chain", "root": root}),
                root_cause_group_id=root, server_id=item.server_id, component=item.component,
                rule_id="mcp-p-offline-instruction-chain", rule_version=RELATION_VERSION,
                detector="p_offline_relations", kind="semantic_indicator", category="P",
                severity="medium", evidence_strength="traced_or_grounded", confidence=0.5,
                mcp_surface=_SURFACES[item.surface_kind], title="MCP directive links to a sensitive action in another component",
                reasoning="An explicit invocation directive is linked to a Python handler whose specialized static path contains sensitive transfer or a fixed harmful action. Agent execution is not established.",
                remediation="Review the instruction and the linked handler together; require explicit authorization for sensitive actions.",
                declaration_span=item.declaration_span, sink_span=item.content_span, trace=trace,
                redacted_evidence=text_evidence, limitations=limitations, review_status="pending"))
    result.findings.sort(key=lambda f: f.finding_id)
    result.diagnostics = _redacted(result.diagnostics)
    return result
