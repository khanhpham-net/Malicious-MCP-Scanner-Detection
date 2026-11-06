# Malicious MCP Scanner Detection

Static-analysis tooling for identifying potentially malicious Model Context
Protocol (MCP) server configurations and packages.

## Development status

The project contains the scanner foundation, the proposed v0.1 interchange
contract, and a Semgrep adapter for local source files or directories.

## Quick start

```bash
python -m pip install -e '.[dev]'
mcp-scanner --help
```

`mcp-scanner scan` exits with a clear message until the Inventory milestone is
available. See [the handoff](docs/HANDOFF.md) for the next implementation step.

## Scan local source with Semgrep

The adapter was verified with Semgrep CE 1.183.0. Install Semgrep separately or
pass the existing executable with `--semgrep PATH`. From the installed
checkout, run the included rule and fixture:

```powershell
mcp-scanner scan-code tests/fixtures/mcp-shell-input.py --rules tests/fixtures/mcp-shell-input.yaml --server-id lab:semgrep
```

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
