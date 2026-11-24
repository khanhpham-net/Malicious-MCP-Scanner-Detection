# P refinement verification — 2026-11-24

> Historical iteration. See [current five-surface verification](p-five-surface-verification.md) for the subsequent English-input revision and latest code.

This is a development result on the existing synthetic corpora. It is not a
blind evaluation or a claim of complete P detection.

## Observed results

| Measure | Before | After |
| --- | ---: | ---: |
| Samples | 260 | 260 |
| Overall complete | 6 | 12 |
| Overall partial | 254 | 248 |
| Python AST complete | 260 | 260 |
| Tool-result components complete | 224 | 231 |
| Tool-result components partial | 349 | 342 |
| Samples with unsupported-call gaps | 225 | 167 |
| Samples with unsupported-body gaps | 87 | 64 |
| Samples with helper-raise boundaries | 23 | 21 |
| Samples with unresolved-value gaps | 34 | 16 |
| Samples with loop-boundary gaps | 100 | 100 |
| Samples with runtime-parameter gaps | 88 | 89 |
| Samples with path-limit gaps | 0 | 1 |
| SIM P-family samples flagged | 20/25 | 20/25 |
| BEN samples flagged by P | 0/160 | 0/160 |

Gap counts overlap. Deeper traversal can reveal new runtime values or budget
boundaries, so not every diagnostic count decreases.

The observed fixture-label confusion table is TP 20, FN 5, FP 0, TN 160,
with 75 non-P SIM cases excluded. It is provisional because many reports are
partial and the synthetic labels are mechanism expectations, not independently
proven real-world malicious intent. Detection on this development set did not
improve; extraction coverage did.

The five retained misses are SIM078, SIM082, SIM086, SIM095 and SIM099. Direct
extractor inspection observed their Vietnamese directive payloads on the five
respective surfaces. They remain reported misses under the agreed English-only
rule scope. SIM095 now has complete bounded extraction but no English P match:
complete coverage is not a guarantee of correct classification.

## Verified invariants

- Identical baseline sample identities and inventory snapshot hashes.
- No change to non-P finding IDs; no P analysis exception diagnostic.
- Source/dependency fingerprint unchanged during the final replay.
- No dataset files were changed and no MCP server/worker was executed.
- Semgrep and SCA were disabled for this development replay.
- Full regression suite: 558 passed, 16 skipped.
- Scanner environment: pip check reported no broken requirements.
- JS/TS profile was exercised by 38 regression cases, not an independent corpus.
- Snapshot/diff gates were exercised by 21 regression cases.

## Reproduction artifacts

Final full reports and provenance:
D:/Capstone/Malicious-MCP-Scanner/p-audit-release-20261124-171940/

- results.jsonl
- source-state.json
- audit-summary.json
- helper-exception-audit.json
- miss-review.json
- changed-files.zip (working changes only; apply to the recorded Git base)

Baseline:
D:/Capstone/Malicious-MCP-Scanner/SIM100-BEN160-20261123-221105/results.jsonl

See [development and handoff](p-detector-development.md) for the exact audit
command, supported profile and passive snapshot workflow.

## Pending acceptance

The dataset owner has not supplied permitted held-out inputs. A handoff protocol
is prepared for Duy; no blind labels were accessed. Freeze a reviewed commit
before independent evaluation. Remaining runtime/effect/loop boundaries stay
partial and are visible in the reports; this iteration does not close every gap.

The implementation and tests are saved in the scanner checkout, without commit
or push. Snapshot comparison never approves or replaces a real baseline
automatically, and never confirms malicious intent.
