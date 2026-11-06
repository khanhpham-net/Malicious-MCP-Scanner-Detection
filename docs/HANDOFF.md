# A0 handoff

## Completed in A0

- Installable Python package named `mcp-scanner`.
- `mcp-scanner` console command and `python -m mcp_scanner` entry point.
- A proposed v0.1 JSON contract for pipeline boundaries.
- Tests covering package versioning, help, module execution, and the deliberate
  pre-Inventory `scan` failure.

## Deliberate limitation

The `scan` command has no scanning behavior. It returns an argparse error until
Inventory provides a concrete input artifact and storage boundary. This prevents
the CLI from implying that a scan was performed.

## Start the Inventory milestone

1. Decide which local sources are in scope (for example, Claude Desktop,
   Cursor, VS Code, and package-manager installations).
2. Implement an inventory collector that writes an `inventory` envelope from
   `data-contract-v0.1.md`.
3. Add a `mcp-scanner inventory` subcommand with an output-path option.
4. Make `scan --input PATH` validate and consume the inventory artifact only
   after discovery and analysis have defined their behavior.

The contract permits additive fields, but do not change existing field meanings
without creating a new contract version.
