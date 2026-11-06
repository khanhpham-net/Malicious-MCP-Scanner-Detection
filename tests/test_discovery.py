from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mcp_scanner.cli import main
from mcp_scanner.discovery import DiscoveryError, discover
from mcp_scanner.inventory import collect, write_inventory


class DiscoveryTests(unittest.TestCase):
    def _inventory_for(self, directory: Path, config: dict[object, object]) -> Path:
        config_path = directory / "mcp.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        inventory_path = directory / "inventory.json"
        write_inventory(collect([config_path]), inventory_path)
        return inventory_path

    def test_discovers_multiple_stdio_servers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            inventory = self._inventory_for(
                Path(temp_dir),
                {
                    "mcpServers": {
                        "filesystem": {"command": "npx", "args": ["server.js"]},
                        "time": {"command": "uvx"},
                    }
                },
            )
            artifact = discover(inventory)

        self.assertEqual(artifact["artifact_type"], "discovery")
        self.assertEqual([item["name"] for item in artifact["items"]], ["filesystem", "time"])
        self.assertEqual(artifact["items"][0]["transport"], "stdio")

    def test_redacts_sensitive_arguments_and_omits_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            inventory = self._inventory_for(
                Path(temp_dir),
                {
                    "mcpServers": {
                        "example": {
                            "command": "node",
                            "args": ["--api-key=super-secret", "--token", "also-secret"],
                            "env": {"TOKEN": "not-exported"},
                        }
                    }
                },
            )
            artifact = discover(inventory)

        serialized = json.dumps(artifact)
        self.assertNotIn("super-secret", serialized)
        self.assertNotIn("also-secret", serialized)
        self.assertNotIn("not-exported", serialized)
        self.assertEqual(
            artifact["items"][0]["arguments"],
            ["--api-key=***REDACTED***", "--token", "***REDACTED***"],
        )

    def test_rejects_wrong_input_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "input.json"
            path.write_text('{"artifact_type": "report", "items": []}', encoding="utf-8")
            with self.assertRaises(DiscoveryError):
                discover(path)

    def test_cli_writes_discovery_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            inventory = self._inventory_for(
                directory, {"mcpServers": {"server": {"command": "python"}}}
            )
            output = directory / "discovery.json"
            self.assertEqual(
                main(["discover", "--input", str(inventory), "--output", str(output)]),
                0,
            )
            artifact = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(artifact["contract_version"], "0.1")
        self.assertEqual(artifact["items"][0]["command"], "python")
