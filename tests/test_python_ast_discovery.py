from dataclasses import dataclass
from textwrap import dedent
import time

from mcp_scanner.python_ast import analyze_python_snapshot


@dataclass
class Record:
    rel_path: str
    text: str | None


class Inventory:
    def __init__(self, texts):
        self.records = [Record(path, dedent(text) if text is not None else None) for path, text in texts.items()]

    def python_files(self):
        return self.records


def scan(texts, deadline=None):
    return analyze_python_snapshot(Inventory(texts), server_id="workspace", deadline=deadline)


def test_discovery_and_shared_helper_are_scoped_to_instance():
    result = scan({"pkg/service.py": '''
        from mcp.server.fastmcp import FastMCP as Server
        from mcp.types import ToolAnnotations as Hints
        from .actions import inspect as apply
        a = Server("first")
        b = Server("second")
        contract = Hints(readOnlyHint=True)
        @a.tool(annotations=contract)
        def first():
            apply()
        @b.prompt()
        def second():
            apply()
        @b.resource("demo://fixture")
        def resource():
            return "static"
        a.add_tool(apply, name="registered")
        ''', "pkg/actions.py": '''
        from pathlib import Path
        def inspect():
            Path("fixture.txt").write_text("fixture")
        '''})
    assert result.status == "complete"
    a, b = result.discovered_servers
    assert a["server_id"] != b["server_id"]
    assert a["tools"] == ["first", "registered"]
    assert b["prompts"] == ["second"] and b["resources"] == ["resource"]
    assert result.frameworks == ["fastmcp"]
    finding, = result.findings
    assert finding.category == "M" and finding.server_id == a["server_id"]
    assert finding.declaration_span.path == "pkg/service.py"
    assert finding.sink_span.path == "pkg/actions.py"
    assert [step.role for step in finding.trace] == ["source", "call", "sink"]


def test_partial_scan_preserves_other_files_and_skips_empty_inventory():
    result = scan({"bad.py": "def (:", "missing.py": None, "valid.py": '''
        from fastmcp import FastMCP
        server = FastMCP()
        @server.tool
        async def ping():
            return True
        '''})
    assert result.status == "partial"
    assert {d["path"] for d in result.diagnostics} == {"bad.py", "missing.py"}
    assert result.discovered_servers[0]["tools"] == ["ping"]
    assert scan({}).status == "skipped"
    exhausted = scan({"valid.py": "pass"}, time.monotonic() - 1)
    assert exhausted.status == "partial"
    assert exhausted.analysis_boundaries[0].kind == "budget_exceeded"


def test_called_factory_and_registration_helper_capture_local_service():
    result = scan({"app.py": """
        from fastmcp import FastMCP
        from pathlib import Path
        class Storage:
            def put(self):
                Path('fixture').touch()
        def attach(server):
            store = Storage()
            @server.tool(annotations={'readOnlyHint': True})
            def inspect():
                store.put()
        def create():
            s = FastMCP('fixture')
            attach(s)
            return s
        if __name__ == '__main__':
            app = create()
        """})
    assert result.discovered_servers[0]["tools"] == ["inspect"]
    assert [f.category for f in result.findings] == ["M"]


def test_utf8_bom_is_valid_python_source():
    result = scan({"service.py": "\ufefffrom fastmcp import FastMCP\nserver = FastMCP()"})
    assert result.status == "complete" and result.frameworks == ["fastmcp"]


def test_unresolved_registration_is_visible_and_foreign_decorator_is_ignored():
    result = scan({"app.py": '''
        from fastmcp import FastMCP
        s = FastMCP()
        s.add_tool(lookup())
        @other.tool()
        def unrelated(): pass
        '''})
    assert result.status == "partial"
    assert not result.discovered_servers[0]["tools"]
    assert result.analysis_boundaries[0].kind == "dynamic_dispatch"
