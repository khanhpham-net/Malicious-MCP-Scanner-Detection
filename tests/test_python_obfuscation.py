import pytest
from test_python_ast_discovery import scan

# These snippets are parsed as data; decoded input is not evaluated.
@pytest.mark.parametrize("transform", ["base64.b64decode(sample)", "bytes.fromhex(sample)",
                                      "zlib.decompress(sample)", "marshal.loads(sample)",
                                      "''.join([chr(n)])", "''.join(chr(n) for n in data)"])
def test_transform_to_compile_in_bootstrap(transform):
    r = scan({"fixture.py": "import base64, zlib, marshal\ntext = " + transform +
              "\ncompile(text, 'fixture', 'eval')"})
    f, = r.findings
    assert (f.category, f.component, f.mcp_surface) == ("dynamic_code_execution", "unknown", "A3")
    assert [s.role for s in f.trace][0] == "transform"


def test_alias_dynamic_builtin_and_stable_output():
    texts = {"fixture.py": "import base64 as codec\nread = getattr(__builtins__, 'eval')\n"
             "read(codec.b64decode(sample))"}
    a, b = scan(texts), scan(texts)
    assert len(a.findings) == 1
    assert [f.to_dict() for f in a.findings] == [f.to_dict() for f in b.findings]


def test_decode_entropy_and_literal_import_alone_produce_no_execution_finding():
    assert not scan({"fixture.py": "import base64, importlib\nlabel = base64.b64decode('Zml4dHVyZQ==')\n"
                     "importlib.import_module('json')\nidentifier = '846a31dc-b987-4bad-a434-65dd81152230'"}).findings
