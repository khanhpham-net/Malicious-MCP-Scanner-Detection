# MAC (`mcp-scanner`) Developer & Operations Handoff

## Integrated v1.0 Pipeline

`mcp-scanner` (CLI alias `mac` for interactive TUI and batch workflows) performs purely offline static analysis without importing target modules, starting servers, or installing target dependencies:

- **Unified CLI & TUI (`scan`, `mac`):** Single-snapshot and `--batch` repository scanning with bounded file count, file size, and monotonic cutoff/timeout budgets (`--cutoff`, `--timeout`), skipping symlinks/junctions and capturing IO/AV read errors cleanly in `coverage.read_errors`.
- **Python AST Engine (`M`, `C`, `S`, `dynamic_code_execution`):** Discovers MCP tools, resources, prompts, and annotations; traces cross-file calls, bounded fixed-point recursive summaries, worker scripts, and obfuscated/decoded dynamic execution sinks while marking `dynamic_dispatch`, `external_lib`, and `budget_exceeded` boundaries honestly.
- **1-Pass Semgrep CE Engine (Python & JS/TS):** Stages inventory-approved files once into Semgrep OSS (`rules/mcp-code.yaml`, `rules/mcp-js-ts.yaml`) with framework guards and CRLF-preserving byte staging.
- **Package Manifests & Optional Offline SCA:** Inspects `package.json` lifecycle scripts and `binding.gyp` targets; optionally checks pinned dependencies (`package-lock.json`, `npm-shrinkwrap.json`, `requirements*.txt`, `poetry.lock`, `uv.lock`) strictly offline against local OSV JSON advisories or `osv-scanner` (`--osv-db`, `--osv-db-sha256`, `--osv-scanner`).
- **5-Surface P Detector & Passive Snapshot Diff:** Analyzes English MCP text across 7 surface keys (`p_tool_description`, `p_input_schema_description`, `p_resource_metadata`, `p_resource_body`, `p_prompt_metadata`, `p_prompt_message`, `p_tool_result`) plus `p_offline_relations`, with mutually exclusive profile controls (`static-default` by default, `--strict-p` for `static-p-strict`, or `--no-p-detector` for ablations). Hash-only passive comparisons are supported via `snapshot-p` and `diff-p-snapshots`.

## Frozen v1.0 Contract

- **Schema & Models:** [schema-v1.0.json](schema-v1.0.json) and `src/mcp_scanner/models.py` (`contract_version = "1.0"`, `policy_version = "trust-policy-v1.0"`, `owasp_profile = "OWASP-MCP-Top-10-2025-beta"`). See [data-contract-v1.0.md](data-contract-v1.0.md) for producer/consumer ownership.
- **Exit Code Precedence (`2 > 1 > 0`):**
  - `2`: `scan_status` is `partial`, `failed`, or `unsupported` (takes precedence even when findings fail policy).
  - `1`: `scan_status == "complete"` and `policy_status == "fail"`.
  - `0`: `scan_status == "complete"` and `policy_status` is `pass` or `not_evaluated`.

## Clean Install & Verification

```sh
# Core scanner & dev test dependencies (Python >= 3.10)
python -m pip install .
python -m pip install -e ".[dev]"

# Optional JS/TS P-surface tree-sitter parser extra (Python >= 3.11)
python -m pip install ".[js]"

# Full test suite (set MCP_SCANNER_TEST_SEMGREP to include real Semgrep CE tests)
python -m pytest
```

On Windows, if Semgrep CE hits `socketpair` errors in default temp paths, pass `--windows-temp PATH` (short local ASCII path without spaces) or set `MCP_SCANNER_TEST_WINDOWS_TEMP` during test runs.

## Legacy v0.1 Compatibility

The legacy `v0.1` subcommands (`inventory`, `discover`, and `scan-code`) remain intact and preserve their original schemas and exit-code behavior. See [data-contract-v0.1.md](data-contract-v0.1.md) and [code-rule-evaluation.md](code-rule-evaluation.md).
