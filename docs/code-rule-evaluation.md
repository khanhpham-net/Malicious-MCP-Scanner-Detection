# Python MCP code rules and evaluation

The [two-rule pack](../rules/mcp-code.yaml) uses the existing `scan-code`
adapter and v0.1 finding envelope. Both rules track data within a synchronous
Python handler decorated with `@mcp.tool(...)` and a `str` parameter. The
receiver name and decorator are the supported source pattern. Dynamic tool
registration and other receiver names are outside this version's scope.

| Rule | Supported behavior |
| --- | --- |
| `mcp-shell-input` ([CWE-78](https://cwe.mitre.org/data/definitions/78.html)) | A tool argument reaches the command in `subprocess.run` or `subprocess.Popen` with literal `shell=True`, or the argument to `os.system`. The command can be positional or passed as `args=` for subprocess. |
| `mcp-path-traversal-read` ([CWE-22](https://cwe.mitre.org/data/definitions/22.html)) | A tool argument is joined with `/` to a root declared as `Path("literal").resolve()` and reaches built-in `open` in the supported read forms. It recognizes `open(path)` and literal `r` or `rb` modes. The configured root is a static signal of intended confinement. |

The file-read rule recognizes the tested pattern where a canonical candidate
is assigned and a check against the same root raises on failure before the
read. The fixtures cover resolve-only, checks against the wrong root, checks
limited to absolute paths or parent components, reassignment after a check,
and a rejection that gets caught before the read.

The separate boundary file demonstrates the current limits for helper calls,
explicit `cmd.exe /c`, and `Path.read_text`. It also reproduces a **false
positive** at line 48 for the alternative form that puts the read inside
`if path.is_relative_to(ROOT)`. The detector recognizes one guard shape.
Filesystem races, write sinks, and arbitrary filesystem access are outside the
bounded-read rule. Treat a finding as a code-review lead.

## Windows reproduction

From the repository root, with the Semgrep CLI already installed:

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path
$env:PYTHONDONTWRITEBYTECODE = '1'
$python = '..\.venv\Scripts\python.exe'
$semgrep = '..\.venv\Scripts\semgrep.exe'
$socketTemp = '..\semgrep-lab\.socket-tmp'

& $python -m mcp_scanner scan-code .\tests\fixtures\mcp-code.py `
  --rules .\rules\mcp-code.yaml --server-id lab:code `
  --semgrep $semgrep --windows-temp $socketTemp

& $python .\evaluation\check_rules.py --semgrep $semgrep --windows-temp $socketTemp

# Optional audit of the five selected legacy Python files.
& $python .\evaluation\check_rules.py --semgrep $semgrep --windows-temp $socketTemp `
  --legacy-root '..\..\old data sample\Malicious-MCP-Servers-Detection'
```

The [evaluator](../evaluation/check_rules.py) scans the same synthetic corpus
with the original one-rule baseline and the expanded pack through the adapter.
It also runs each expanded rule separately with Semgrep and compares the
findings to the combined run. It requires engine-reported coverage of every
synthetic file and emits exact differences, engine version and SHA-256 hashes.

`ruleid` and `ok` annotations label the following line. The scoring unit is
`(file, line, rule ID)`. Unmatched findings within either scored split count
as false positives. The boundary cases and legacy files are reported
separately. The [reserved synthetic cases](../evaluation/reserved/mcp-code.py)
were recorded in commit `1e25a80` before rule implementation and first run
after the rules were frozen in `d0f8448`. They share the same authorship as
the development set. An independently labeled benchmark is still needed for
estimates on real projects.

## Recorded run

Native Windows, Semgrep CE 1.183.0. Results below are for the scoped fixtures.

| Split and mechanism | Positive cases | Negative cases | B0 hits | Expanded hits | Expanded FP / FN |
| --- | ---: | ---: | ---: | ---: | ---: |
| Development, command injection | 4 | 4 | 1 | 4 | 0 / 0 |
| Development, bounded file read | 7 | 4 | 0 | 7 | 0 / 0 |
| Reserved, command injection | 2 | 1 | 0 | 2 | 0 / 0 |
| Reserved, bounded file read | 2 | 2 | 0 | 2 | 0 / 0 |

B0 only had the original shell rule. Its path-read rows show the absence of
coverage for the second mechanism. The isolated and combined matches agreed
for each rule. The original fixture kept both finding IDs and source ranges.
The five boundary sites produced one finding, the guard false positive above.

## Legacy sample audit

The previous research repository was examined at commit
`1553bd70d8d5170c213ece05d46243d04d09b58c`. The evaluator scanned five named
Python files as text and each returned `complete` with zero findings from
this pack. The result is scoped to the two implemented mechanisms.

| Legacy source | Observed behavior and reuse |
| --- | --- |
| `file_manager_malicious_mcp/File_manager_MCP.py` | Direct user-controlled file access at lines 35 and 51, with no declared root in these tools. A future arbitrary file access corpus can use this distinction. Decoding followed by `exec` at line 15 is a separate detection candidate. |
| `SQL_malicous_MCP/sql_context_mcp.py` | Decoding followed by `exec` at line 27 and direct output-path use at line 147. Useful for future dynamic execution or file-write coverage. |
| `todo_malicous_MCP/todoMCP.py` | Reads files at lines 35 and 43 and makes an outbound request at line 89. A candidate for a separate data-flow audit. |
| Both `stager.py` files | Downloaded content reaches `exec` at line 16. Candidates for future download-to-execution detection and fixture design. |

The old Python sources stay in their original checkout. The
`virus_sample/key_logger_virus.exe` binary sits outside this Python-source
evaluation. Legacy examples can inform future fixture design and need
separate labels for their actual mechanisms.
