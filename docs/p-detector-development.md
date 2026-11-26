# P detector development and handoff

Status: 2026-11-24. This describes a bounded development implementation, not a
claim that arbitrary MCP servers or all prompt injection are fully covered.

The additional [offline relation analysis](p-offline-relations.md) composes
explicit English invocation facts with registered Python handler evidence and
literal-call specialization. It runs locally with no LLM or model weights.
It is separately scoped from the seven regex rules and does not clear their
unresolved runtime-output boundaries.

## Implemented and verified

The latest iteration is recorded in [five-surface verification](p-five-surface-verification.md).
The earlier refinement report is historical and predates the five translated probes.

- Explicit successful/raised helper outcomes, caller catch/finally handling and
  builtin exception-message extraction. Unmodeled error objects remain gaps.
- Conservative continuation after opaque effects: later possible return text is
  inspected, changed globals/aliases stay uncertain, and snapshot reads after
  possible mutation cannot use stale contents as complete evidence.
- An inductive fixed point for restricted pure scalar for-loops. Mutable loop
  effects and failed joins retain boundaries. A single iteration never proves
  the loop complete.
- Declaration-time description constants/import aliases, guarded against later
  rebinding and opaque imported initializers.
- Prompt returns now use the same bounded helper/control-flow engine as
  tool/resource results, including standard MCP message wrappers.
- Pure Field metadata, known defaults, safe factory provenance, homogeneous and
  heterogeneous sequence domains, sort key/reverse and min/max-default behavior.
- Narrow standalone ASCII-token proofs for validated tool inputs. These prove
  absence of the current reviewed multiword regex patterns only, not benign
  intent. The certificate is bound to both the rule patterns and normalizer;
  callbacks, unanchored/Unicode/wildcard patterns and whitespace-introducing
  transformations do not inherit the proof. Defaults are checked separately.
- English P rule 0.3 adds session-context disclosure and bounded typography/
  whitespace normalization; reporting prefixes cannot hide a later active
  directive just by mentioning a tutorial.
- Optional JS/TS AST metadata, hash-only passive snapshots and the replay runner
  remain integrated.

Coverage does not establish benignness. Runtime text, external worker/API output,
unsupported serializers or mutable effects can remain partial. Current data and
default handling are informed by the [Pydantic Field documentation](https://pydantic.dev/docs/validation/latest/concepts/fields/);
target models/validators are not executed by the scanner.

## Five surfaces and JS/TS profile

The five conceptual surfaces are tool descriptions, tool results, resources,
input-schema descriptions, and MCP prompts. Resource and prompt metadata/body
are recorded separately, giving seven P coverage keys.

Python extraction remains bounded to approved inventory text. Defaults include
32 paths/alternatives, 64 finite loop items and helper depth 12.

Install the optional JS parser extra in the scanner environment:

~~~powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev,js]"
~~~

The pinned JS parser extra requires Python 3.11 or later; core-only scanning
retains the project's Python 3.10 minimum.

Pinned parsers: tree-sitter 0.27.0, tree-sitter-javascript 0.25.0 and
tree-sitter-typescript 0.23.2. JS/TS extraction reads direct top-level ESM
McpServer registrations from these declared import profiles:

- @modelcontextprotocol/sdk/server/mcp.js
- @modelcontextprotocol/server

Supported metadata includes literal descriptions, const string values, Zod
.describe() annotations from zod / zod/v4, and inline literal callback returns.
Both registerTool/registerResource/registerPrompt and the supported SDK v1
variadic registration shapes are recognized. The scanner does not install or
execute the target SDK, and does not attest the installed SDK version.

CommonJS, computed registration, dynamic schema builders, callback control flow
and cross-file JS helpers retain boundaries. Type-only imports are not runtime
constructor evidence. Callback parameters mask global constants. Missing
parsers explicitly produce unmeasured P surfaces and partial analysis; no
regex fallback claims complete coverage.

JS/TS was verified with the new regression fixtures, not a real independent
JS/TS corpus. Semgrep JS/TS code coverage is a separate engine.

Implementation references:
[Tree-sitter Python](https://github.com/tree-sitter/py-tree-sitter) and the
[official SDK registration migration reference](https://github.com/modelcontextprotocol/typescript-sdk/blob/main/skills/mcp-typescript-sdk-upgrade-to-v2/references/server-registration.md).

## Reproduce the development audit

Use the existing full-report JSONL as a baseline. The runner scans sample
directories as independent snapshots, including their first-party files; it
never starts an MCP server or worker. It reads manifest labels only for this
development corpus. Output must be a new directory outside the dataset.

~~~powershell
$runDir = Join-Path "D:\Capstone\Malicious-MCP-Scanner" ("p-audit-" + (Get-Date -Format "yyyyMMdd-HHmmss"))

.\.venv\Scripts\python.exe -B scripts/p_development_audit.py `
  --baseline "D:\Capstone\Malicious-MCP-Scanner\p-english-input-baseline-20261124-173607\results.jsonl" `
  --dataset-root "D:\Capstone\mcp-scanner-ieu\dataset" `
  --output-dir $runDir
~~~

Outputs: results.jsonl (full reports), source-state.json, audit-summary.json.
The command uses Python AST + P, with Semgrep and SCA disabled to match this
baseline. Source or input drift and changes to non-P finding IDs are audit
failures. A valid audit exit 0 does not mean every sample has complete coverage.

The P confusion table uses only SIM P-family mechanism fixtures and BEN
author labels. Other SIM families are not P negatives. Partial cases remain
in the denominator and the table is provisional, not a benign verdict for
unflagged partial reports or a paper-grade benchmark. The English-only scope
does not silently remove non-English misses from the table.

## Hash-only passive snapshot comparison

These commands compare the static fields that were observed. They do not
connect to MCP endpoints, detect time-dependent behavior by execution, or
establish rug pull, shadowing, malicious intent or confirmed threat.

~~~powershell
.\.venv\Scripts\python.exe -m mcp_scanner snapshot-p "D:\path\to\snapshot" `
  --server-id "example-server" `
  --protocol-version "YOUR_ACTUAL_PROTOCOL_VERSION" `
  --scope '{"tenant":"local","transport":"stdio"}' `
  --revision "YOUR_ACTUAL_REVISION" `
  --output "D:\reports\p-current.json"

.\.venv\Scripts\python.exe -m mcp_scanner diff-p-snapshots `
  "D:\reports\p-approved-baseline.json" "D:\reports\p-current.json" `
  --output "D:\reports\p-diff.json"
~~~

Capture output is pending review by default. After a person reviews the
source/evidence and verifies its snapshot digest, --approved-by REVIEWER on
a new capture records their local attestation. The option does not perform
review. Verify the new capture has the reviewed source digest before using
it as a baseline. No real baseline was approved automatically in this work.

Artifacts contain per-field hashes and instruction rule IDs, not raw metadata
or secrets. They still require local access controls. Approval is not a
cryptographic signature.

Comparison requires the same server ID, protocol version, explicit tenant/scope,
and analyzer fingerprint. It distinguishes same-revision drift, a version
update and change without a known revision. The approved baseline is never
updated by diff. Outputs cannot overwrite existing artifacts or the inputs;
capture output must be outside the source snapshot.

A coverage gap remains visible in the diff. Unchanged observed metadata never
proves runtime equivalence. No fixed revision in both captures means the
comparison cannot claim same-revision drift. Analyzer upgrades require
re-extraction and human review under the same analyzer before comparison.

Snapshot command exit codes are local artifact-workflow codes:
capture 0 = observed profile complete, 2 = incomplete/error;
diff 0 = no review trigger, 1 = review needed with complete observed profile,
2 = incomplete/error. A diff exit 1 is not the scan command's policy verdict.

## Handoff to Duy: independent evaluation is pending

The owner confirmed no permitted held-out inputs are available yet. Do not
open hidden labels, tune from blind-set feedback or claim the following work
has already been performed.

1. Freeze a scanner commit and dependency versions after review; record the
   commit, source fingerprint, modes, budgets, host and exact command.
2. Duy runs the held-out snapshots with concealed labels. Start with English
   Python plus independent JS/TS fixtures covering the declared profile.
   Expand beyond it as a separately reported challenge set.
3. Keep one snapshot directory per scan and save full reports, stderr, process
   exit code, duration and snapshot hashes. Do not execute target servers.
4. Run the same inputs/conditions for baselines. Specify Semgrep and offline
   OSV configuration explicitly; keep AST+P ablation separate from full mode.
5. Report P by surface, E1/E3, language, family, runtime/static source and
   coverage. Distinguish extraction misses from rule misses, duplicates and
   tool failures. Lock the treatment of partial reports before opening labels;
   do not silently drop difficult inputs or call them benign.
6. Freeze outputs before Duy scores labels. Report uncertainty and review
   synthetic mechanism expectations separately from independently supported
   real-world malicious intent. Only then decide which fixes require a new,
   untouched held-out set.

Unit/regression fixtures exercise implementation branches. They are not a
substitute for independent or realistic benchmark samples.


## Five translated development probes

At the owner's request, SIM078/SIM082/SIM086/SIM095/SIM099 were translated from
Vietnamese to English without changing business logic. Matching code/views,
tools metadata, scenarios, generator text and hashes were synchronized.
Historical runtime evidence and review identities were not rewritten as if
they had been rerun or approved.

A baseline was captured after translation and before the algorithm changes.
It still detected only 20/25 P fixtures; the new generic English rule and flow
changes were then evaluated against these identical English inputs.
The corpus's strict snapshot-bound admission now marks the five translated
snapshots pending renewed review; do not use --auto-admit to bypass that gate.

## Structured/API checkpoint — 2026-11-25

The P output interpreter now preserves heterogeneous tuple positions, typed
mapping shapes and weak updates through aliases and helper branches. Pure API
summaries check supported argument variants and retain errors or uncertainty.
These are language/API models; no corpus identifier, business field or label is
used to select detector behavior.

Supported Pydantic v2 constructors are checked against reviewed numeric, length
and bounded ASCII pattern constraints. Immutable local/imported annotation
aliases are resolved without target imports. Pattern proof uses a bounded
non-backtracking model of a concatenation grammar, not arbitrary target regex
execution. Unsupported pattern dialects, validators, constructor aliases and
ambiguous union coercions retain partial coverage.

Validated tool input length bounds may prove a compatible constructor accepts
an argument. They never make unknown text safe for P. Stripping drops the
original lower length bound; Unicode case conversion and replacement drop
length certificates. Reflected runtime text is still unobserved. Defaults are
not falsely treated as having passed validation.

Implementation semantics were checked against the documented contracts:
[standard types](https://pydantic.dev/docs/validation/2.12/api/pydantic/standard_library_types/)
and [unions](https://pydantic.dev/docs/validation/latest/concepts/unions/).
Tests interpret source fixtures only; they do not import or run target models.
This does not claim complete Pydantic runtime emulation or held-out accuracy.

The unfinished collection-loop widening draft is excluded from this checkpoint.
Its three acceptance cases remain explicitly skipped until that separate step
has been independently verified. The source and dataset snapshots used for
regression are hashed; the seven earlier coverage regressions are restored
without changing dataset code, labels or coverage-status policy.
