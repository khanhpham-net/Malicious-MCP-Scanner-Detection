"""Safe collection of MCP configuration-file inventory records."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__

CONTRACT_VERSION = "0.1"


class InventoryError(ValueError):
    """Raised when an explicit inventory source cannot be read safely."""


def _read_config(path: Path) -> dict[str, Any] | None:
    """Read an MCP config without extracting command or environment values."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise InventoryError(f"cannot read config '{path}': {error.strerror}") from error
    except json.JSONDecodeError as error:
        raise InventoryError(f"invalid JSON in config '{path}': {error.msg}") from error

    if not isinstance(payload, dict):
        raise InventoryError(f"config '{path}' must contain a JSON object")

    servers = payload.get("mcpServers")
    if servers is None:
        return None
    if not isinstance(servers, dict):
        raise InventoryError(f"config '{path}' has a non-object 'mcpServers' field")
    return payload


def _asset_id(location: Path) -> str:
    """Create a stable identifier without reading sensitive config values."""
    digest = hashlib.sha256(str(location).encode("utf-8")).hexdigest()
    return f"config:{digest}"


def collect(config_paths: Iterable[Path]) -> dict[str, Any]:
    """Create a contract v0.1 inventory from explicit MCP configuration files.

    The collector reads only the top-level ``mcpServers`` shape and server names.
    It never executes configured commands or serializes configuration values such
    as environment variables.
    """
    observed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    items: list[dict[str, Any]] = []
    seen_locations: set[Path] = set()

    for supplied_path in config_paths:
        location = supplied_path.expanduser().resolve()
        if location in seen_locations:
            continue
        seen_locations.add(location)

        payload = _read_config(location)
        if payload is None:
            continue
        servers = payload["mcpServers"]
        items.append(
            {
                "asset_id": _asset_id(location),
                "kind": "configuration",
                "name": location.name,
                "location": str(location),
                "observed_at": observed_at,
                "server_count": len(servers),
                "server_names": sorted(str(name) for name in servers),
            }
        )

    return {
        "contract_version": CONTRACT_VERSION,
        "artifact_type": "inventory",
        "generated_at": observed_at,
        "source": {"name": "mcp-scanner", "version": __version__},
        "items": items,
    }


def write_inventory(inventory: dict[str, Any], output: Path) -> None:
    """Write a formatted UTF-8 inventory artifact."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
