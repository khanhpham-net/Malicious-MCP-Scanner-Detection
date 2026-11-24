"""Passive, hash-only P metadata snapshots and review-gated comparison.

This module never starts servers, updates an approved baseline, or confirms
malicious intent. A diff describes observed static metadata changes only.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re
import time

from .p_detector import detect_surface_instructions
from .p_js import SURFACES, extract_js_surfaces
from .p_prompt import extract_python_prompt_metadata, extract_python_prompt_messages
from .p_resource import extract_python_resource_metadata, extract_python_resource_bodies
from .p_schema import extract_python_input_schema_descriptions
from .p_surface import extract_python_tool_descriptions
from .p_tool_result import extract_python_tool_results
from .python_ast import analyze_python_snapshot
from .source_inventory import collect_source_inventory

FORMAT = "p-static-snapshot/1"


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(raw).hexdigest()


def analyzer_digest():
    root = Path(__file__).parent
    files = sorted(root.glob("p_*.py")) + sorted((root/"python_ast").glob("*.py"))
    files += [root/"source_inventory.py"]
    return digest({p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in files})


def validate_snapshot(snapshot):
    if not isinstance(snapshot, dict) or snapshot.get("format") != FORMAT:
        raise ValueError("Unsupported P snapshot format.")
    for key in ("server_id", "protocol_version"):
        if not isinstance(snapshot.get(key), str) or not snapshot[key].strip():
            raise ValueError(f"Snapshot requires a non-empty {key}.")
    scope = snapshot.get("scope")
    if not isinstance(scope, dict) or not scope or not all(
            isinstance(k,str) and k and isinstance(v,str) and v for k,v in scope.items()):
        raise ValueError("Snapshot scope must be a non-empty string-to-string object.")
    revision = snapshot.get("revision")
    if revision is not None and (not isinstance(revision,str) or not revision.strip()):
        raise ValueError("Revision must be non-empty or null.")
    for key in ("snapshot_sha256", "analyzer_sha256"):
        if not isinstance(snapshot.get(key),str) or not re.fullmatch("(?:sha256:)?[0-9a-f]{64}",snapshot[key]):
            raise ValueError(f"Invalid {key}.")
    fields = snapshot.get("fields")
    if not isinstance(fields,list):
        raise ValueError("Snapshot fields must be an array.")
    seen = set()
    for entry in fields:
        if not isinstance(entry,dict):
            raise ValueError("Invalid P snapshot field.")
        key = field_key(entry)
        if not all(isinstance(v,str) and v for v in key):
            raise ValueError("P snapshot field identity must contain non-empty strings.")
        if key in seen or entry.get("surface") not in SURFACES:
            raise ValueError("Duplicate or unsupported P snapshot field.")
        seen.add(key)
        hashes = entry.get("content_sha256")
        rules = entry.get("rule_ids")
        if (not isinstance(hashes,list) or not hashes or
                any(not isinstance(h,str) or not re.fullmatch("[0-9a-f]{64}",h) for h in hashes) or
                not isinstance(rules,list) or any(not isinstance(r,str) for r in rules)):
            raise ValueError("Invalid field hashes or rule IDs.")
    if snapshot.get("metadata_sha256") != digest(sorted(fields,key=field_key)):
        raise ValueError("P metadata digest mismatch.")
    coverage = snapshot.get("coverage")
    allowed = {"scanned","none_found","partial","unmeasured"}
    if not isinstance(coverage,dict) or set(coverage)!=set(SURFACES) or any(v not in allowed for v in coverage.values()):
        raise ValueError("Invalid P snapshot coverage.")
    review = snapshot.get("review")
    if not isinstance(review,dict) or review.get("status") not in {"pending","approved"}:
        raise ValueError("Invalid snapshot review state.")
    if review["status"]=="approved" and not (
            isinstance(review.get("reviewer"),str) and review["reviewer"].strip()):
        raise ValueError("An approved baseline requires a reviewer identity.")


def field_key(entry):
    return tuple(entry.get(k) for k in ("instance_id","surface","component","field_path"))


def capture_p_snapshot(target, *, server_id, protocol_version, scope, revision=None,
                       approved_by=None, timeout=60.0):
    if not isinstance(timeout,(int,float)) or not math.isfinite(timeout) or timeout<=0:
        raise ValueError("Snapshot timeout must be positive and finite.")
    if approved_by is not None and (not isinstance(approved_by,str) or not approved_by.strip()):
        raise ValueError("Reviewer identity must be non-empty.")
    deadline = time.monotonic()+timeout
    inventory = collect_source_inventory(Path(target),deadline=deadline)
    coverage = {s:"none_found" for s in SURFACES}
    texts = []
    if inventory.python_files():
        discovery = analyze_python_snapshot(inventory,server_id=server_id,deadline=deadline)
        extractors = (
            ("tool_description",extract_python_tool_descriptions),
            ("input_schema_description",extract_python_input_schema_descriptions),
            ("resource_metadata",extract_python_resource_metadata),
            ("resource_body",extract_python_resource_bodies),
            ("prompt_metadata",extract_python_prompt_metadata),
            ("prompt_message",extract_python_prompt_messages),
            ("tool_result",extract_python_tool_results),
        )
        for surface,extract in extractors:
            result = extract(inventory,discovery.discovered_servers,deadline=deadline)
            texts.extend(result.texts)
            coverage[surface] = "partial" if result.status!="complete" or discovery.status!="complete" else (
                "scanned" if result.texts else "none_found")
    if inventory.js_ts_files():
        result = extract_js_surfaces(inventory,server_id=server_id,deadline=deadline)
        texts.extend(result.texts)
        for surface,state in result.surfaces.items():
            if state in {"partial","unmeasured"} or coverage[surface]=="partial":
                coverage[surface]=state if coverage[surface]!="partial" else "partial"
            elif state=="scanned":
                coverage[surface]="scanned"
    if (inventory.read_errors or inventory.skipped_files or inventory.skipped_budget or
            inventory.timed_out or not inventory.code_files()):
        coverage = {s:"partial" for s in SURFACES}
    grouped = {}
    for item in texts:
        key = (item.server_id,item.surface_kind,item.component,item.field_path or "<text>")
        entry = grouped.setdefault(key,{"instance_id":key[0],"surface":key[1],"component":key[2],
                                       "field_path":key[3],"content_sha256":set(),"rule_ids":set()})
        entry["content_sha256"].add(hashlib.sha256(item.text.encode("utf-8")).hexdigest())
        detection = detect_surface_instructions([item],deadline=deadline)
        entry["rule_ids"].update(f.rule_id for f in detection.findings)
        if detection.status!="complete":
            coverage[item.surface_kind]="partial"
    fields = []
    for entry in grouped.values():
        fields.append({k:sorted(v) if isinstance(v,set) else v for k,v in entry.items()})
    fields.sort(key=field_key)
    snapshot = {
        "format":FORMAT,"server_id":server_id,"protocol_version":protocol_version,
        "scope":scope,"revision":revision,"snapshot_sha256":inventory.snapshot_sha256,
        "analyzer_sha256":analyzer_digest(),"metadata_sha256":digest(fields),
        "coverage":coverage,"fields":fields,
        "review":{"status":"approved" if approved_by is not None else "pending","reviewer":approved_by},
        "limitations":[
            "Hash-only static profile; no raw metadata or secret text is exported.",
            "Dynamic content and unsupported code remain unobserved.",
            "Approval is a local human attestation, not a cryptographic signature.",
        ],
    }
    validate_snapshot(snapshot)
    return snapshot


def compare_p_snapshots(baseline, current):
    validate_snapshot(baseline)
    validate_snapshot(current)
    if baseline["review"]["status"]!="approved":
        raise ValueError("The baseline must be approved by a human reviewer.")
    for key in ("server_id","protocol_version","scope","analyzer_sha256"):
        if baseline[key]!=current[key]:
            raise ValueError(f"P snapshots are not comparable: {key} differs.")
    before = {field_key(v):v for v in baseline["fields"]}
    after = {field_key(v):v for v in current["fields"]}
    changes = []
    for key in sorted(before.keys()|after.keys()):
        old,new = before.get(key),after.get(key)
        if old==new:
            continue
        change = "added" if old is None else "removed" if new is None else "modified"
        rules_before = set(old["rule_ids"]) if old else set()
        rules_after = set(new["rule_ids"]) if new else set()
        changes.append({
            "change":change,"identity":dict(zip(
                ("instance_id","surface","component","field_path"),key)),
            "before_sha256":old["content_sha256"] if old else [],
            "after_sha256":new["content_sha256"] if new else [],
            "new_instruction_rule_ids":sorted(rules_after-rules_before),
        })
    same_revision = baseline["revision"] is not None and baseline["revision"]==current["revision"]
    source_changed = baseline["snapshot_sha256"]!=current["snapshot_sha256"]
    coverage_gaps = any(s in {"partial","unmeasured"} for doc in (baseline,current) for s in doc["coverage"].values())
    classification = (
        "same_revision_drift" if same_revision and (source_changed or changes) else
        "version_update" if baseline["revision"]!=current["revision"] else
        "content_change_revision_unknown" if source_changed or changes else "unchanged_observed_metadata")
    return {
        "format":"p-static-diff/1","server_id":baseline["server_id"],
        "classification":classification,"source_changed":source_changed,
        "coverage_status":"partial" if coverage_gaps else "complete",
        "review_required":bool(changes or source_changed or coverage_gaps),
        "confirmed_threat":False,"baseline_updated":False,"changes":changes,
        "limitations":[
            "Changes are review signals; they do not establish rug pull or malicious intent.",
            "Unchanged hashes cover observed static fields only, not runtime equivalence.",
            "Same-revision comparison requires both captures to record a revision.",
        ],
    }
