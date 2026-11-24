"""Extraction checks through the existing inventory and Python discovery."""
from dataclasses import replace
from pathlib import Path
import time

import pytest

from mcp_scanner.p_surface import extract_python_tool_descriptions
from mcp_scanner.python_ast import analyze_python_snapshot
from mcp_scanner.source_inventory import collect_source_inventory


def extract(tmp_path, files):
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    inventory = collect_source_inventory(tmp_path)
    discovery = analyze_python_snapshot(inventory, server_id="fixture")
    return inventory, discovery, extract_python_tool_descriptions(inventory, discovery.discovered_servers)


BASE = "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('test')\n"


def test_only_registered_tool_and_literal_location(tmp_path):
    source = BASE + '''
def ordinary():
    """Not a tool."""
@mcp.tool(name="renamed")
async def inspect():
    """Giữ nguyên
    dòng thứ hai."""
    return 1
'''
    _, discovery, result = extract(tmp_path, {"server.py": source})
    item, = result.texts
    assert result.status == "complete"
    assert item.server_id == discovery.discovered_servers[0]["server_id"]
    assert item.component == "tool:renamed"
    assert item.text == "Giữ nguyên\n    dòng thứ hai."
    assert item.content_span.path == "server.py"
    assert item.content_span.start_line == 8
    assert item.content_span.end_line == 9
    assert item.declaration_span.start_line == 6


@pytest.mark.parametrize("argument,expected", [
    ('description="Explicit description"', "Explicit description"),
    ('description=None', "Fallback documentation."),
    ('description=""', "Fallback documentation."),
])
def test_description_precedence(tmp_path, argument, expected):
    _, _, result = extract(tmp_path, {"server.py": BASE + f'''
@mcp.tool({argument})
def inspect():
    """Fallback documentation."""
    return 1
'''})
    assert result.texts[0].text == expected
    assert result.status == "complete"


def test_dynamic_description_has_no_docstring_fallback(tmp_path):
    _, _, result = extract(tmp_path, {"server.py": BASE + '''
def description():
    raise RuntimeError("Source must never execute")
@mcp.tool(description=description())
def inspect():
    """Docstring cannot establish the dynamic description."""
    return 1
'''})
    assert not result.texts
    assert result.status == "partial"
    assert result.diagnostics[0]["code"] == "P_DYNAMIC_DESCRIPTION"


def test_registration_in_other_file_and_server_identity(tmp_path):
    _, discovery, result = extract(tmp_path, {
        "server.py": BASE + '''
from handler import inspect
other = FastMCP("other")
mcp.add_tool(inspect, name="first")
other.add_tool(inspect, name="second", description="Second server.")
''',
        "handler.py": 'def inspect():\n    """Handler documentation."""\n    return 1\n',
    })
    assert result.status == "complete"
    first, second = result.texts
    assert first.text == "Handler documentation."
    assert first.content_span.path == "handler.py"
    assert second.text == "Second server."
    assert second.content_span.path == "server.py"
    assert first.server_id != second.server_id
    assert {item.server_id for item in result.texts} == {s["server_id"] for s in discovery.discovered_servers}


def test_bare_decorator_empty_tool_and_keyword_unpacking(tmp_path):
    _, _, result = extract(tmp_path, {"server.py": BASE + '''
@mcp.tool
def empty():
    return 1
@mcp.tool(**options)
def unresolved():
    """A description could be overridden."""
    return 1
'''})
    item, = result.texts
    assert item.component == "tool:empty" and item.text == ""
    assert result.status == "partial"
    assert result.diagnostics[0]["code"] == "P_DESCRIPTION_KEYWORD_UNPACKING"


def test_partial_input_and_deadline(tmp_path):
    inventory, discovery, _ = extract(tmp_path, {"server.py": BASE + '''
@mcp.tool()
def inspect():
    """Inspect fixture."""
    return 1
'''})
    expired = extract_python_tool_descriptions(inventory, discovery.discovered_servers, deadline=time.monotonic()-1)
    assert expired.status == "partial"
    assert expired.diagnostics[0]["code"] == "P_EXTRACTION_DEADLINE"
    inventory.files = [replace(record, text=None) for record in inventory.files]
    missing = extract_python_tool_descriptions(inventory, discovery.discovered_servers)
    assert missing.status == "partial" and not missing.texts
    assert any(d["code"] == "P_SOURCE_UNAVAILABLE" for d in missing.diagnostics)

