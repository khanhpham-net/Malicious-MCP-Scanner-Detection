"""Validated length information is a type contract, never a P-safe text proof."""
import ast
import pytest
from mcp_scanner.models import SourceSpan
from mcp_scanner.p_domains import BoundedInputText, RuntimeInputText, SequenceDomain
from mcp_scanner.p_output_flow import OutputValueResolver
from mcp_scanner.source_inventory import collect_source_inventory
from test_p_output_flow import extract

def parameter(tmp_path, expression="Field(min_length=2,max_length=8)", files=None):
    source = ("from mcp.server.fastmcp import FastMCP\nfrom pydantic import Field\n"
              "from typing import Annotated\nmcp=FastMCP('bounds')\n"
              f"@mcp.tool()\ndef inspect(value:Annotated[str,{expression}]):\n    return value\n")
    (tmp_path/"service.py").write_text(source, encoding="utf-8")
    for name, text in (files or {}).items():
        (tmp_path/name).write_text(text, encoding="utf-8")
    inv=collect_source_inventory(tmp_path)
    resolver=OutputValueResolver(inv,None)
    resolver.input_kind="tool"
    module=resolver.parse(SourceSpan("service.py"))[0]
    handler=next(n for n in module.tree.body if isinstance(n,ast.FunctionDef))
    value=resolver.input_value(module,handler.args.args[0].annotation)
    return resolver,module,value

def test_validated_length_bounds_are_retained_but_text_remains_unknown(tmp_path):
    _,_,value=parameter(tmp_path)
    assert isinstance(value,BoundedInputText)
    assert (value.min_length,value.max_length)==(2,8)
    _,_,result=extract(tmp_path,"return value",
        extras="from typing import Annotated\nfrom pydantic import Field\n",
        signature="value:Annotated[str,Field(min_length=2,max_length=8)]")
    assert result.status=="partial"
    assert any(d.get("code")=="P_OUTPUT_RUNTIME_PARAMETER" for d in result.diagnostics)

@pytest.mark.parametrize("operation",["strip","lstrip","rstrip"])
def test_stripping_does_not_retain_the_original_minimum(tmp_path,operation):
    resolver,module,value=parameter(tmp_path)
    node=ast.parse(f"value.{operation}()").body[0].value
    result=resolver.method(module,node,value,operation,[],{})
    assert isinstance(result,BoundedInputText)
    assert (result.min_length,result.max_length)==(0,8)

@pytest.mark.parametrize("operation",["upper","lower","casefold"])
def test_unicode_case_changes_do_not_retain_length_certificate(tmp_path,operation):
    resolver,module,value=parameter(tmp_path)
    node=ast.parse(f"value.{operation}()").body[0].value
    result=resolver.method(module,node,value,operation,[],{})
    assert isinstance(result,RuntimeInputText) and not isinstance(result,BoundedInputText)

def test_split_piece_does_not_inherit_original_minimum(tmp_path):
    from mcp_scanner.p_static import StaticText
    resolver,module,value=parameter(tmp_path)
    node=ast.parse("value.split(',')").body[0].value
    result=resolver.method(module,node,value,"split",[StaticText(",",SourceSpan("service.py"))],{})
    assert isinstance(result,SequenceDomain)
    assert isinstance(result.element,BoundedInputText)
    assert result.element.min_length==0 and result.element.max_length==8

def test_length_domains_are_distinct_for_fixed_point_comparison(tmp_path):
    resolver,_,value=parameter(tmp_path)
    wider=BoundedInputText(value.code,value.span,0,16)
    assert resolver.semantic_key(value)!=resolver.semantic_key(wider)

def test_impossible_length_bounds_are_not_certified(tmp_path):
    _,_,value=parameter(tmp_path,"Field(min_length=9,max_length=2)")
    assert not isinstance(value,BoundedInputText)

def test_shadowed_field_module_cannot_grant_length_bounds(tmp_path):
    _,_,value=parameter(tmp_path,files={"pydantic.py":"def Field(**kwargs):\n    return None\n"})
    assert not isinstance(value,BoundedInputText)

