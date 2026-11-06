"""Static discovery of stdio MCP servers from inventory artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__

CONTRACT_VERSION = "0.1"
_SENSITIVE_ARGUMENT = re.compile(
    r"(?:api[-_]?key|authorization|password|secret|token)", re.IGNORECASE
)


class DiscoveryError(ValueError):
    """Raised when an inventory artifact or its configuration is invalid."""


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise DiscoveryError(f"cannot read {label} '{path}': {error.strerror}") from error
    except json.JSONDecodeError as error:
        raise DiscoveryError(f"invalid JSON in {label} '{path}': {error.msg}") from error
    if not isinstance(payload, dict):
        raise DiscoveryError(f"{label} '{path}' must contain a JSON object")
    return payload


def _load_inventory(path: Path) -> list[dict[str, Any]]:
    inventory = _read_json(path, "inventory")
    if inventory.get("contract_version") != CONTRACT_VERSION:
        raise DiscoveryError("inventory must use contract_version '0.1'")
    if inventory.get("artifact_type") != "inventory":
        raise DiscoveryError("input artifact_type must be 'inventory'")
    items = inventory.get("items")
    if not isinstance(items, list):
        raise DiscoveryError("inventory 'items' must be an array")
    if not all(isinstance(item, dict) for item in items):
        raise DiscoveryError("each inventory item must be an object")
    return items


def _server_id(asset_id: str, server_name: str) -> str:
    digest = hashlib.sha256(f"{asset_id}\0{server_name}".encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _redact_arguments(arguments: Iterable[Any]) -> list[str]:
    """Preserve ordinary command arguments while redacting likely credentials."""
    redacted: list[str] = []
    redact_next = False
    for argument in arguments:
        value = str(argument)
        if redact_next:
            redacted.append("***REDACTED***")
            redact_next = False
            continue
        if _SENSITIVE_ARGUMENT.search(value):
            if "=" in value:
                key, _ = value.split("=", 1)
                redacted.append(f"{key}=***REDACTED***")
            else:
                redacted.append(value)
                redact_next = True
            continue
        redacted.append(value)
    return redacted


def _discover_config(asset_id: str, location: Path) -> list[dict[str, Any]]:
    payload = _read_json(location, "configuration")
    servers = payload.get("mcpServers")
    if not isinstance(servers, dict):
        raise DiscoveryError(f"configuration '{location}' has no object 'mcpServers' field")

    discovered: list[dict[str, Any]] = []
    for name, definition in sorted(servers.items()):
        if not isinstance(name, str) or not name:
            raise DiscoveryError(f"configuration '{location}' has an invalid server name")
        if not isinstance(definition, dict):
            raise DiscoveryError(f"server '{name}' in '{location}' must be an object")
        command = definition.get("command")
        if not isinstance(command, str) or not command:
            raise DiscoveryError(
                f"server '{name}' in '{location}' is unsupported: only stdio command configs are supported"
            )
        arguments = definition.get("args", [])
        if not isinstance(arguments, list):
            raise DiscoveryError(f"server '{name}' in '{location}' has non-array 'args'")

        discovered.append(
            {
                "server_id": _server_id(asset_id, name),
                "asset_id": asset_id,
                "name": name,
                "transport": "stdio",
                "command": command,
                "arguments": _redact_arguments(arguments),
                "location": str(location),
            }
        )
    return discovered


def discover(inventory_path: Path) -> dict[str, Any]:
    """Discover static stdio MCP server definitions from an inventory artifact."""
    items = _load_inventory(inventory_path)
    discovered: list[dict[str, Any]] = []
    for item in items:
        if item.get("kind") != "configuration":
            continue
        asset_id = item.get("asset_id")
        location = item.get("location")
        if not isinstance(asset_id, str) or not asset_id:
            raise DiscoveryError("configuration inventory item is missing a non-empty 'asset_id'")
        if not isinstance(location, str) or not location:
            raise DiscoveryError("configuration inventory item is missing a non-empty 'location'")
        discovered.extend(_discover_config(asset_id, Path(location)))

    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "contract_version": CONTRACT_VERSION,
        "artifact_type": "discovery",
        "generated_at": generated_at,
        "source": {"name": "mcp-scanner", "version": __version__},
        "items": discovered,
    }


def write_discovery(artifact: dict[str, Any], output: Path) -> None:
    """Write a formatted UTF-8 discovery artifact."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
