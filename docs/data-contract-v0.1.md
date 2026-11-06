# Scanner data contract v0.1 (proposed)

This document defines the first stable boundary between inventory, discovery,
metadata extraction, analysis, reporting, and packaging. All artifact files use
UTF-8 JSON and carry the contract version explicitly.

## Envelope

Every artifact is an object with these fields:

| Field | Type | Requirement | Meaning |
| --- | --- | --- | --- |
| `contract_version` | string | required | Exact version: `0.1`. |
| `artifact_type` | string | required | `inventory`, `discovery`, `metadata`, `finding`, or `report`. |
| `generated_at` | string | required | RFC 3339 UTC timestamp. |
| `source` | object | required | Producer identity and provenance. |
| `items` | array | required | Artifact records of the declared type. |

`source` contains `name` (required string), `version` (optional string), and
`location` (optional string). Producers may add fields; consumers must ignore
unknown fields to preserve forward compatibility.

## Shared identifiers

- `asset_id`: stable producer-defined identifier for an installed package,
  configuration, or MCP server candidate.
- `server_id`: stable identifier for a discovered MCP server. It remains stable
  across reruns when the same source configuration is present.
- `evidence_id`: identifier for evidence referenced by a finding.

Identifiers are non-empty strings. A record may include both `asset_id` and
`server_id` when discovery is derived from an inventory asset.

## Artifact records

### Inventory item

```json
{
  "asset_id": "npm:@scope/server@1.2.3",
  "kind": "package",
  "name": "@scope/server",
  "version": "1.2.3",
  "location": "/path/to/package",
  "observed_at": "2026-11-06T00:00:00Z"
}
```

### Discovery item

```json
{
  "server_id": "sha256:...",
  "asset_id": "npm:@scope/server@1.2.3",
  "transport": "stdio",
  "command": "node",
  "arguments": ["server.js"],
  "location": "/path/to/config"
}
```

### Metadata item

```json
{
  "server_id": "sha256:...",
  "name": "example-server",
  "tools": [{"name": "search", "description": "Search local data."}],
  "prompts": [],
  "resources": []
}
```

### Finding item

```json
{
  "finding_id": "rule-id:server-id",
  "server_id": "sha256:...",
  "rule_id": "MCP001",
  "severity": "high",
  "title": "Suspicious behavior",
  "evidence_ids": ["evidence-1"]
}
```

`severity` is one of `info`, `low`, `medium`, `high`, or `critical`.

### Report item

```json
{
  "server_id": "sha256:...",
  "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
  "finding_ids": ["MCP001:sha256:..."]
}
```

## Processing rules

1. Inventory emits inventory envelopes only.
2. Discovery consumes inventory and emits discovery records linked by `asset_id`.
3. Metadata extraction consumes discovery and emits metadata linked by `server_id`.
4. Analysis emits findings and preserves the source `server_id`.
5. Reporting aggregates findings without changing finding identifiers.
