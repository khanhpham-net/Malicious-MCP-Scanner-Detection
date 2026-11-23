# MAC — Maintain an Auspicious Cloud

MAC is a static security scanner for local Model Context Protocol (MCP) server
snapshots. It accepts a source file, a repository directory, or a collection of
snapshots. It analyzes approved source and dependency files without starting
the server, installing target dependencies, or running target scripts.

## Quick start

Use Python 3.10 or later. Install MAC from this checkout:

```sh
python -m pip install .
```

Install Semgrep CE separately for full scans. MAC was verified with Semgrep CE
1.183.0. Put `semgrep` on PATH or pass `--semgrep PATH`. Install
`rich` for the purple banner and styled terminal output:

```sh
python -m pip install rich
mac
```

Running `mac` in a terminal opens the English interactive menu. It shows scan
progress and findings, supports fast and full batch scans, and lets you export
JSON when needed. For direct use:

```sh
mac scan ./snapshot --details
mac scan ./snapshot --no-semgrep
mac scan ./collection --batch --details
mac scan ./collection --single
```

`mac ./snapshot` is shorthand for `mac scan ./snapshot`. `mac scan` defaults to
the current directory if no target is supplied. It detects batch collections
automatically. `--single` scans the target as one snapshot. `mcp-scanner scan`
requires a target and defaults to a single snapshot unless you pass `--batch`.
Use `--no-color` for plain terminal output.

## What MAC checks

- **Source inventory** enforces file-size, file-count, and time budgets, skips
  symlinks and junctions, and records unreadable files and coverage limits.
- **Python AST analysis** discovers MCP tools, resources, and prompts. It
  follows first-party calls and bounded recursive summaries to report
  unexpected mutation, command execution, sensitive-data flow, and dynamic
  code execution or obfuscation. It can trace subprocess effects into local
  Python workers. Unresolved first-party dispatch can make the scan partial.
- **Semgrep CE** applies bundled [Python](rules/mcp-code.yaml) and
  [JavaScript/TypeScript](rules/mcp-js-ts.yaml) rules in one pass over staged
  source. Fast mode (`--no-semgrep`) keeps the Python AST and manifest checks.
- **Package manifests** are checked for risky npm lifecycle scripts and
  related execution paths. Optional offline software composition analysis
  (SCA) checks pinned dependencies against a local advisory snapshot.

Coverage is static. Runtime tool metadata changes, remote content, and behavior
outside the inspected code require separate evaluation. A coverage gap can
produce a `partial` report even when MAC has actionable findings.

## Reports and automation

`mac scan` displays text by default and only saves a file when requested.
`mcp-scanner scan` emits JSON by default. Use `--output` to save JSON and
`--format text` or `--format json` to select terminal output.

```sh
mac scan ./snapshot --details --output report.json
mcp-scanner scan ./snapshot --output report.json
mcp-scanner scan ./collection --batch --output batch.json
```

Single-snapshot JSON follows the [v1.0 report schema](docs/schema-v1.0.json)
and includes coverage, redacted evidence, finding traces, a trust score, and
review status. See the [report contract](docs/data-contract-v1.0.md) and
[example reports](examples/schema-v1.0). Batch JSON contains a summary and
per-snapshot verdicts, finding counts, categories, and rule IDs.

| Exit code | Meaning for unified scan |
| --- | --- |
| 0 | Scan completed without a policy failure. |
| 1 | Scan completed with actionable findings that failed policy. |
| 2 | Scan was partial, failed, or unsupported. This takes precedence over a policy failure. |

## Offline dependency advisories

SCA is opt-in through `--osv-db PATH` or `MCP_SCANNER_OSV_DB`. It reports
`unmeasured` when disabled. Pass `--no-sca` to disable an environment-provided
configuration.

```sh
mac scan ./snapshot --osv-db ./osv-json
mac scan ./snapshot --osv-db ./osv-cache --osv-scanner /path/to/osv-scanner
```

Without a binary, MAC reads a directory of local OSV advisory JSON files. It
checks supported pinned npm and Python dependencies from files such as
`package-lock.json`, `npm-shrinkwrap.json`, `requirements*.txt`,
`poetry.lock`, and `uv.lock`. The optional binary mode was verified with OSV
Scanner 2.5.1 and uses an offline cache such as
`osv-cache/osv-scalibr/PyPI/all.zip`. Use `--osv-db-sha256` to verify an
expected database digest. Unresolved dependencies or missing coverage make
SCA partial. Database or engine errors can make it fail.

## Legacy commands

Inventory and discover static MCP configurations with the existing commands:

```sh
mcp-scanner inventory --config /path/to/mcp.json --output inventory.json
mcp-scanner discover --input inventory.json --output discovery.json
```

Inventory omits environment-variable values. The standalone Semgrep
`scan-code` command still emits a [v0.1 finding artifact](docs/data-contract-v0.1.md)
with its own exit codes (0 complete, 1 partial, 2 failed). See
[code rule scope and evaluation](docs/code-rule-evaluation.md).

## Tests and Windows notes

```sh
python -m pip install -e ".[dev]"
python -m pytest
```

Set `MCP_SCANNER_TEST_SEMGREP` to the Semgrep executable path to include the
real-engine tests. On Windows, if Semgrep reports `Invalid argument socketpair`,
pass `--windows-temp PATH` with a short local ASCII path without spaces, or
set `MCP_SCANNER_TEST_WINDOWS_TEMP` for the tests. Files blocked by antivirus
can leave a scan partial.
