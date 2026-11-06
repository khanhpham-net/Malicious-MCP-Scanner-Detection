# Malicious MCP Scanner Detection

Static-analysis tooling for identifying potentially malicious Model Context
Protocol (MCP) server configurations and packages.

## Development status

The project currently contains the A0 foundation: a Python package, the
`mcp-scanner` command, and the proposed v0.1 interchange contract. Inventory
collection and scanning rules are intentionally not implemented yet.

## Quick start

```bash
python -m pip install -e '.[dev]'
mcp-scanner --help
```

`mcp-scanner scan` exits with a clear message until the Inventory milestone is
available. See [the handoff](docs/HANDOFF.md) for the next implementation step.
