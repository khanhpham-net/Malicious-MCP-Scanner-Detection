from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mcp_scanner.cli import main
from mcp_scanner.inventory import InventoryError, collect


class InventoryTests(unittest.TestCase):
    def _config(self, directory: Path, content: str) -> Path:
        path = directory / "mcp.json"
        path.write_text(content, encoding="utf-8")
        return path

    def test_collects_mcp_configuration_without_secret_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._config(
                Path(temp_dir),
                '{"mcpServers": {"filesystem": {"env": {"TOKEN": "secret"}}}}',
            )
            inventory = collect([path])

        self.assertEqual(inventory["artifact_type"], "inventory")
        self.assertEqual(inventory["items"][0]["server_names"], ["filesystem"])
        self.assertNotIn("secret", json.dumps(inventory))

    def test_ignores_non_mcp_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = self._config(Path(temp_dir), '{"other": true}')
            self.assertEqual(collect([path])["items"], [])

    def test_rejects_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_directory() as temp_dir:
            path = self._config(Path(temp_dir), "{")
            with self.assertRaises(InventoryError):
                collect([path])

    def test_cli_writes_contract_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            path = self._config(directory, '{"mcpServers": {"server": {}}}')
            output = directory / "inventory.json"
            self.assertEqual(
                main(["inventory", "--config", str(path), "--output", str(output)]),
                0,
            )
            artifact = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(artifact["contract_version"], "0.1")
        self.assertEqual(artifact["items"][0]["name"], "mcp.json")
