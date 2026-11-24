# Five-surface P verification — 2026-11-24

P detection now covers all 25 P-family fixtures on the owner-approved English
input revision. The entire scanner is **not** declared complete: 246 of the 260
reports still have coverage gaps. These two facts are deliberately reported
separately.

## Same-input development results

The new English baseline was recorded before this iteration's algorithm changes.
Translation alone still produced 20/25 P detections. The comparison below uses
identical English sample hashes.

| Measure | English baseline | Current |
| --- | ---: | ---: |
| Total samples | 260 | 260 |
| Overall complete | 12 | 14 |
| Overall partial | 248 | 246 |
| P01 tool descriptions flagged | 4/5 | 5/5 |
| P02 resource bodies flagged | 4/5 | 5/5 |
| P03 tool results flagged | 4/5 | 5/5 |
| P04 input-schema descriptions flagged | 4/5 | 5/5 |
| P05 prompt messages flagged | 4/5 | 5/5 |
| BEN flagged by P | 0/160 | 0/160 |

The observed fixture-label table is TP 25, FN 0, FP 0, TN 160. This is a
development signal, not a paper-grade result or proof of real-world intent.
Seventy-five non-P SIM fixtures are excluded from that P table. Partial samples
remain in the denominator. Five translated snapshots require renewed
snapshot-bound review; old reviewed records were not rebound automatically.

P03 tool-result coverage remains partial in four of its five samples even
though the injected payload is detected. Other returned runtime fields remain
unobserved. This iteration does not reclassify those reports to complete.

## Verified functionality

- Five behavior groups cross all five surfaces in the Python acceptance matrix,
  using E1/E3 layouts, direct and opaque-effect paths, and quoted training controls.
- The same five-by-five matrix runs for JS and TS in the declared SDK profile.
- Tests cover helper errors/catch/finally, defaults and factories, aliased
  registration-time metadata, pure loop fixed points, mutation uncertainty,
  sort order/defaults, typography and version-bound token constraints.
- Full suite: **987 passed, 16 skipped**.
- Exported acceptance/proof subset: **429 passed**, with machine-readable JUnit.
- Exact same input hashes in the current replay and English baseline.
- No change to non-P finding IDs and no P_ANALYSIS_ERROR/P_JS_ANALYSIS_ERROR.
- Source/dependency fingerprint remained stable during the replay.
- The replay used AST + P; Semgrep and OSV were disabled.
- No corpus MCP servers or workers were started. JS/TS target modules were not
  imported/executed. Results were derived from static inventory text.

## Reproduction artifacts

Current:
D:/Capstone/Malicious-MCP-Scanner/p-five-surface-final-20261124-183309/

- results.jsonl: 260 full reports
- audit-summary.json: fixture counts, invariance and remaining gap families
- source-state.json: exact scanner source/dependency fingerprint
- acceptance-matrix.xml / verification.json: acceptance gates
- p-family-evidence.json: per-P-sample rule IDs and honest surface/report status
- remaining-gaps.json: 246 samples still needing coverage work
- scanner-changes.zip: working source/test/docs changes against recorded Git base

Same-English-input baseline:
D:/Capstone/Malicious-MCP-Scanner/p-english-input-baseline-20261124-173607/results.jsonl

Translation backup and audit:
D:/Capstone/Malicious-MCP-Scanner/p-five-surface-20261124-173218/

The translation audit normalized translated Python constants back to their
original values and verified the AST was unchanged. Corpus static audit:
100 samples, 265 Python files, zero issues, zero executed samples.
Original runtime evidence remains historical, not a new runtime verification.

## Remaining work and acceptance

This iteration closes the five-surface detection gate on these development
fixtures; it does not close the global scanner completion gate.

The replay still records unmodeled calls/effects, loops over mutable runtime
records, raw runtime text, JSON/worker/HTTP boundaries, some bindings and dynamic
access. Several gap counts increase when more possible tail paths are inspected
or when earlier optimistic assumptions are removed. They must not be hidden.

Further analysis must close each gap by a model/proof or leave it explicit.
Do not promote partial to complete simply because a known P payload was found.
Similarly, do not discard that finding just because another field is partial.

Independent held-out inputs are not available yet. The handoff protocol for Duy
is in [the development guide](p-detector-development.md). Freeze a reviewed
commit and modes before independent evaluation. No commit/push or automated
review approval was performed in this iteration.
