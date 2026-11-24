"""JS/TS acceptance for all five P behaviors and all five MCP surfaces."""
import json
import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_javascript")
pytest.importorskip("tree_sitter_typescript")

from mcp_scanner.p_js import extract_js_surfaces
from mcp_scanner.p_detector import detect_surface_instructions
from mcp_scanner.source_inventory import collect_source_inventory
from test_p_flow_acceptance import PATTERNS

SURFACES = ["description","tool-result","resource-body","schema","prompt-message"]

def registration(surface,body):
    tool='()=>'+body
    if surface=="description":
        return 'server.registerTool("inspect",{description:PAYLOAD},'+tool+');'
    if surface=="schema":
        return 'server.registerTool("inspect",{inputSchema:z.object({code:z.string().describe(PAYLOAD)})},'+tool+');'
    if surface=="resource-body":
        return 'server.registerResource("inspect","fixture://content",{},'+tool+');'
    if surface=="prompt-message":
        return 'server.registerPrompt("inspect",{},'+tool+');'
    return 'server.registerTool("inspect",{},'+tool+');'


@pytest.mark.parametrize("surface",SURFACES)
@pytest.mark.parametrize("rule,payload",PATTERNS)
@pytest.mark.parametrize("ext",["js","ts"])
@pytest.mark.parametrize("opaque",[False,True])
@pytest.mark.parametrize("quoted",[False,True],ids=["active","training-material"])
def test_js_ts_five_by_five_contract(tmp_path,surface,rule,payload,ext,opaque,quoted):
    if quoted:
        payload="The tutorial explains the phrase "+payload.lower()+" as an attack example."
    output=(
        '{contents:[{uri:"fixture://content",text:PAYLOAD}]}' if surface=="resource-body" else
        '{messages:[{role:"user",content:{type:"text",text:PAYLOAD}}]}' if surface=="prompt-message" else
        '{content:[{type:"text",text:PAYLOAD}]}' if surface=="tool-result" else
        '{content:[]}'
    )
    body='{external_event();return '+output+';}' if opaque else '('+output+')'
    source=(
        'import {McpServer} from "@modelcontextprotocol/server";\n'
        'import {z} from "zod";\n'
        'const PAYLOAD='+json.dumps(payload)+';\n'
        'const server=new McpServer({name:"matrix",version:"1"});\n'+registration(surface,body)
    )
    (tmp_path/("server."+ext)).write_text(source,encoding="utf-8")
    r=extract_js_surfaces(collect_source_inventory(tmp_path),server_id="matrix")
    findings=detect_surface_instructions(r.texts).findings
    assert r.status==("partial" if opaque else "complete")
    assert any(f.rule_id==f"mcp-p-{surface}-"+rule for f in findings)==(not quoted)
