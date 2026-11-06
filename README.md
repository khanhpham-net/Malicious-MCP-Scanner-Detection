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

Inventory an explicit MCP configuration file without executing it:

```bash
mcp-scanner inventory --config /path/to/mcp.json --output inventory.json
```

The command reads only the JSON structure needed to identify MCP configurations;
it does not run any configured commands or include environment-variable values
in its output. `mcp-scanner scan` remains unavailable until the later discovery
and analysis milestones are implemented.

Discover static `stdio` server definitions from the inventory:

```bash
mcp-scanner discover --input inventory.json --output discovery.json
```

Discovery reads the listed configuration files but does not start any MCP server.
