# Malicious MCP Scanner Detection

Static-analysis tooling for identifying potentially malicious Model Context
Protocol (MCP) server configurations and packages.

## Development status

The project contains the scanner foundation, the proposed v0.1 interchange
contract, and a Semgrep adapter for local source files or directories.
The [code rules](rules/mcp-code.yaml) cover selected Python MCP shell commands
and reads using paths built beneath a configured directory.

## Quick start

```bash
python -m pip install -e '.[dev]'
mcp-scanner --help
```

Inventory an explicit MCP configuration file:

```bash
mcp-scanner inventory --config /path/to/mcp.json --output inventory.json
```

The command reads the JSON structure needed to identify MCP configurations and
omits environment-variable values from its output.

Discover static `stdio` server definitions from the inventory:

```bash
mcp-scanner discover --input inventory.json --output discovery.json
```

Discovery reads the listed configuration files. The unified `mcp-scanner scan`
command runs the v1.0 analysis pipeline described below.

## Scan local source with Semgrep

The adapter was verified with Semgrep CE 1.183.0. Install Semgrep separately or
pass the existing executable with `--semgrep PATH`. From the installed
checkout, run the included rule and fixture:

```powershell
mcp-scanner scan-code tests/fixtures/mcp-shell-input.py --rules tests/fixtures/mcp-shell-input.yaml --server-id lab:semgrep
```

To try both mechanisms and reproduce the comparison with this baseline, see
[code-rule scope and evaluation](docs/code-rule-evaluation.md).

If the native Windows engine reports `Invalid argument socketpair`, pass
`--windows-temp PATH` with a compatible local directory. The adapter assigns
`TMP` and `TEMP` to that directory for the child process. The directory is
created if needed. Use a trusted local YAML rules file.

The command writes a v0.1 finding artifact to stdout. Each finding preserves
the caller-supplied `server_id` and references a source range in `evidence`.
Paths in evidence and coverage are relative to the source directory (or the
parent of a single source file). The artifact includes engine version, ruleset
SHA-256, coverage reported by Semgrep, and diagnostics. Semgrep's `WARNING`
maps to `medium` and `ERROR` to `high`.

| Status | Exit code | Meaning |
| --- | ---: | --- |
| `complete` | 0 | Semgrep reported coverage without errors or skipped targets, with or without findings. |
| `partial` | 1 | Reported skips or errors limited coverage, or Semgrep reported no scanned files. |
| `failed` | 2 | An input, timeout, or engine error prevented a usable scan. |

Coverage follows the engine report. Semgrep may recover from some syntax
errors without reporting them. The adapter includes untracked files and
retains Semgrep's other targeting filters.

To enable the real-engine tests, set `MCP_SCANNER_TEST_SEMGREP` to the
executable path and, if needed, `MCP_SCANNER_TEST_WINDOWS_TEMP` to the
compatible temp directory before running `python -m unittest discover -s tests`.


## Unified scan and Python P detector

The current checkout provides the v1.0 unified scan pipeline. For a local
sample, including Python AST and P analysis without Semgrep:

~~~powershell
.\.venv\Scripts\python.exe -m mcp_scanner scan "D:\path\to\sample" --server-id example --no-semgrep --output ".\results\example.json"
~~~

P examines tool descriptions, parameter schema descriptions, resource
metadata/content, prompt metadata/messages, and tool results. English rules
cover explicit instruction overrides, concealed actions, requests to disclose
earlier conversation or internal records, redirection of unrelated future
answers, and concealed substitutions. Findings are heuristic review signals;
their confidence is not statistically calibrated.

The tool/resource return extractor follows bounded first-party functions and
simple instance methods across inventory-approved Python files. Supported
expressions include finite collections/comprehensions, common numeric and string
operations, simple data-only Pydantic models, literal input alternatives, and
read-only JSON/text access through the approved UTF-8 inventory. It follows
if/else paths, bounded for/while loops, break/continue, container updates and
supported async calls. Calls stop at recursion/depth 12; exploration is bounded
to 32 alternatives/paths, 64 loop items, and the shared complexity/deadline budget.

P distinguishes modeled numeric/Boolean results from unobserved text. This uses
the declared, validated FastMCP input contract. Custom validators/serializers,
shadowed framework modules, unknown external calls and other unsupported behavior
retain gaps. Return annotations alone never establish that an output is numeric.
File presence/type checks are grounded only in the immutable approved snapshot;
runtime replacement or modification of those files is not observed.

An unresolved condition is not automatically a coverage gap if all feasible
return branches can be inspected. Their text is marked as statically possible.
Unsupported branches, unbounded effects, runtime-dependent text, external
worker/API output, and exceeded budgets keep coverage partial. A P finding can
coexist with scan_status=partial and exit_code=2.

P_OUTPUT_COVERAGE_SUMMARY diagnostics provide per-component status, observed text
field paths, proven non-text fields, and unresolved field locations/reasons.
A single unresolved component still makes the aggregate surface partial; the
component summaries show which other tools were fully inspected.

Schema extraction follows supported import re-exports, reads explicit model
descriptions, and reports custom model-schema hooks/configuration as unmeasured.
Non-English detection and JS/TS P extraction remain unmeasured. Text spans locate
original expressions/artifacts, not exact normalized character offsets.
The English instruction rules are review heuristics with uncalibrated confidence;
complete coverage within this bounded profile is not a benign verdict.

Regression checks are in tests/test_p_coverage.py and tests/test_p_output_flow.py,
alongside the other tests/test_p_*.py extraction and integration checks.
