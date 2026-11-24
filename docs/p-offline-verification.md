# Offline P relation verification — 2026-11-24

The added analyzer is enabled by the existing `scan` command and disabled by
`--no-p-detector`. No LLM, API key, model download, target module import, or MCP
server execution is used.

## Final validation

- Full suite: **1104 passed, 16 skipped** (117 additional passing tests compared
  with the previous 987-pass suite).
- Explicit invocation parser: 64 cases.
- Handler summaries/specialization: 19 cases.
- Separately authored relation acceptance suite: 34 cases across all five
  conceptual source surfaces, including E3 helpers and negative controls.
- Replayed the same 260 development inputs against the previous final baseline.
- P fixture-label table remains TP 25, FN 0, FP 0, TN 160.
- Overall status remains 14 complete and 246 partial.
- No input hash mismatches, no non-P finding identity changes, and no P analyzer
  exceptions. Source fingerprint remained unchanged during the final replay.

The development corpus did not gain additional P detections from this feature.
The new relation capability is demonstrated by the added acceptance cases;
these tests do not establish accuracy on an independent held-out corpus.

## Correctness checks

The suite rejects a relation when a literal selects the benign branch, a guard
rejects the call, the transfer contains only public data, or the target merely
offers an unconstrained shell capability. It also rejects spurious paths from
invalid helper argument binding, dynamic execution, unmodeled Field validation,
assert/raise/try/with control flow, unknown environment gates, and effectful
match subjects.

Existing regex findings at the same source are enriched rather than counted
again. Public summary/trace serialization is checked for secret redaction.
Validated-token certificates retain their original regex-only scope. The
relation engine cannot use those certificates to claim new coverage.

Output trace telemetry exports at most 64 paths per component, with explicit
`export_truncated` and `omitted_path_count`. This export limit does not skip
directive analysis of subsequent fragments or lower actual coverage.

## Reproduction

From the repository, with its existing environment:

```powershell
.\.venv\Scripts\python.exe -B -m pytest -p no:cacheprovider
```

The new focused tests are `test_p_directives.py`, `test_p_behavior.py`, and
`test_p_relations_acceptance.py`.

The development replay uses `scripts/p_development_audit.py` with the baseline:

`D:/Capstone/Malicious-MCP-Scanner/p-five-surface-final-20261124-183309/results.jsonl`

Dataset root: `D:/Capstone/mcp-scanner-ieu/dataset`. Semgrep and SCA are disabled
in this replay to match that baseline. Results are not an official benchmark
with all scanner engines or a new admission/review of dataset snapshots.

## Remaining boundaries

See [scope and research inputs](p-offline-relations.md). This feature is a
bounded, entirely offline evidence composer; it does not perform general
natural-language intent classification or prove that an agent obeys a payload.
Python specialization, scalar arguments and explicit English invocations are
the supported profile. Existing 246 partial reports remain unresolved.
