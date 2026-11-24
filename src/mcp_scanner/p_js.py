"""Bounded JS/TS MCP metadata extraction using optional Tree-sitter parsers.

Only inventory text is parsed. No JS modules, callbacks, imports or SDK code run.
The supported profile is direct top-level McpServer registrations with literal
metadata, inline literal returns, and Zod .describe() schema annotations.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
import time

from .models import SourceSpan
from .p_surface import SurfaceExtractionResult, SurfaceText

SURFACES = (
    "tool_description", "input_schema_description", "resource_metadata",
    "resource_body", "prompt_metadata", "prompt_message", "tool_result",
)


@dataclass
class JsSurfaceResult(SurfaceExtractionResult):
    surfaces: dict[str, str] = field(default_factory=lambda: {s: "none_found" for s in SURFACES})


def _decode_string(raw):
    """Decode ordinary JS escapes without executing expressions or modules."""
    if len(raw) < 2 or raw[0] not in "\"'`" or raw[-1] != raw[0]:
        return None
    text = raw[1:-1]
    parts = []
    i = 0
    escapes = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}
    while i < len(text):
        c = text[i]
        i += 1
        if c != "\\":
            parts.append(c)
            continue
        if i == len(text):
            return None
        c = text[i]
        i += 1
        if c in "\r\n":
            if c == "\r" and text[i:i+1] == "\n":
                i += 1
            continue
        if c in {"x", "u"}:
            if c == "u" and text[i:i+1] == "{":
                end = text.find("}", i + 1)
                if end < 0:
                    return None
                digits = text[i+1:end]
                i = end + 1
            else:
                length = 2 if c == "x" else 4
                digits = text[i:i+length]
                i += length
                if len(digits) != length:
                    return None
            if not re.fullmatch("[0-9a-fA-F]{1,6}", digits):
                return None
            value = int(digits, 16)
            if value > 0x10ffff or 0xd800 <= value <= 0xdfff:
                return None
            parts.append(chr(value))
        elif c.isdigit() and c != "0":
            return None
        else:
            parts.append(escapes.get(c, c))
    return "".join(parts)


class Extractor:
    def __init__(self, result, path, data, server_id, deadline):
        self.result, self.path, self.data = result, path, data
        self.server_id, self.deadline = server_id, deadline
        self.remaining = 100000
        self.constants = {}
        self.zod = set()
        self.component = "module:" + path
        self.declaration = None

    def tick(self):
        self.remaining -= 1
        if self.remaining < 0 or self.deadline is not None and time.monotonic() >= self.deadline:
            raise TimeoutError

    def text(self, node):
        return self.data[node.start_byte:node.end_byte].decode("utf-8")

    def span(self, node):
        return SourceSpan(self.path, node.start_point.row+1, node.start_point.column+1,
                          node.end_point.row+1, node.end_point.column+1)

    def walk(self, node):
        self.tick()
        yield node
        for child in node.named_children:
            yield from self.walk(child)

    def literal(self, node):
        if node is None:
            return None
        if node.type == "identifier":
            return self.constants.get(self.text(node))
        if node.type not in {"string", "template_string"}:
            return None
        if any(c.type == "template_substitution" for c in node.named_children):
            return None
        return _decode_string(self.text(node))

    def gap(self, code, node, surface=None):
        self.result.status = "partial"
        for key in ([surface] if surface else SURFACES):
            self.result.surfaces[key] = "partial"
        self.result.diagnostics.append({
            "code": code, "server_id": self.server_id, "component": self.component,
            "location": self.span(node).to_dict(), "surface": surface,
        })

    def emit(self, node, surface, field_path):
        value = self.literal(node)
        if value is None:
            self.gap("P_JS_DYNAMIC_TEXT", node, surface)
            return
        self.result.texts.append(SurfaceText(
            self.server_id, self.component, surface, value, self.span(node),
            self.declaration, field_path=field_path,
            limitations=["JS/TS literal metadata profile; callback execution is unobserved.",
                         "Source spans cover original expressions, not decoded character offsets."],
        ))
        if self.result.surfaces[surface] != "partial":
            self.result.surfaces[surface] = "scanned"

    def properties(self, node):
        result = {}
        if node is None or node.type != "object":
            return result
        for child in node.named_children:
            self.tick()
            if child.type != "pair":
                self.gap("P_JS_DYNAMIC_OBJECT", child)
                continue
            key = child.child_by_field_name("key")
            value = child.child_by_field_name("value")
            name = self.literal(key) if key.type == "string" else self.text(key)
            if key.type not in {"property_identifier", "string", "identifier"}:
                self.gap("P_JS_DYNAMIC_PROPERTY", key)
                continue
            result[name] = value
        return result

    def schema(self, node):
        if node is None:
            return
        if node.type not in {"object", "call_expression"}:
            self.gap("P_JS_DYNAMIC_SCHEMA", node, "input_schema_description")
        for call in self.walk(node):
            if call.type != "call_expression":
                continue
            function = call.child_by_field_name("function")
            if function is None or function.type != "member_expression":
                self.gap("P_JS_SCHEMA_UNVERIFIED", call, "input_schema_description")
                continue
            prop = function.child_by_field_name("property")
            receiver = function.child_by_field_name("object")
            root = receiver
            while root is not None and root.type in {"call_expression", "member_expression"}:
                root = root.child_by_field_name("function") if root.type == "call_expression" else root.child_by_field_name("object")
            if root is None or root.type != "identifier" or self.text(root) not in self.zod:
                self.gap("P_JS_SCHEMA_UNVERIFIED", call, "input_schema_description")
                continue
            allowed = {"string","number","boolean","object","array","enum","literal","union",
                       "optional","nullable","default","describe","min","max","int","positive","nonnegative"}
            if prop is None or self.text(prop) not in allowed:
                self.gap("P_JS_DYNAMIC_SCHEMA", call, "input_schema_description")
                continue
            if self.text(prop) != "describe":
                continue
            args = call.child_by_field_name("arguments").named_children
            if len(args) != 1:
                self.gap("P_JS_SCHEMA_ARGUMENTS", call, "input_schema_description")
            else:
                self.emit(args[0], "input_schema_description", "schema.describe")
        # Spread/computed schema construction is outside the literal profile.
        for child in self.walk(node):
            if child.type in {"spread_element", "subscript_expression", "identifier"}:
                if child.type != "identifier":
                    self.gap("P_JS_DYNAMIC_SCHEMA", child, "input_schema_description")

    def output(self, node, surface, path="result"):
        if node.type in {"parenthesized_expression", "as_expression", "satisfies_expression"} and node.named_children:
            return self.output(node.named_children[0], surface, path)
        if node.type in {"string", "template_string"}:
            self.emit(node, surface, path)
        elif node.type == "identifier" and self.literal(node) is not None:
            self.emit(node, surface, path)
        elif node.type == "object":
            for key, value in self.properties(node).items():
                self.output(value, surface, path+"."+key)
        elif node.type == "array":
            for index, child in enumerate(node.named_children):
                self.output(child, surface, path+f"[{index}]")
        elif node.type not in {"number", "true", "false", "null", "undefined"}:
            self.gap("P_JS_DYNAMIC_OUTPUT", node, surface)

    def callback(self, node, surface):
        original = dict(self.constants)
        for part in self.walk(node):
            if part.type in {"formal_parameters", "required_parameter", "optional_parameter",
                             "variable_declarator"}:
                for binding in self.walk(part):
                    if binding.type in {"identifier", "shorthand_property_identifier_pattern"}:
                        self.constants.pop(self.text(binding), None)
        try:
            self.callback_body(node, surface)
        finally:
            self.constants = original

    def callback_body(self, node, surface):
        if node.type not in {"arrow_function", "function_expression"}:
            self.gap("P_JS_CALLBACK_BOUNDARY", node, surface)
            return
        body = node.child_by_field_name("body")
        if body is None:
            self.gap("P_JS_CALLBACK_BOUNDARY", node, surface)
        elif body.type != "statement_block":
            self.output(body, surface)
        else:
            for statement in body.named_children:
                if statement.type == "return_statement":
                    if statement.named_children:
                        self.output(statement.named_children[0], surface)
                elif statement.type != "comment":
                    self.gap("P_JS_CALLBACK_CONTROL_FLOW", statement, surface)
                    # Retain possible return text in unsupported branches.
                    def returns(current):
                        self.tick()
                        if current.type in {"function_declaration", "function_expression", "arrow_function"}:
                            return
                        if current.type == "return_statement" and current.named_children:
                            self.output(current.named_children[0], surface)
                        for child in current.named_children:
                            returns(child)
                    returns(statement)

    def registration(self, call, method):
        args = call.child_by_field_name("arguments").named_children
        if len(args) < 2:
            self.gap("P_JS_REGISTRATION_ARGUMENTS", call)
            return
        name = self.literal(args[0])
        self.component = ("tool" if method in {"tool", "registerTool"} else
                          "resource" if method in {"resource", "registerResource"} else "prompt") + ":" + (name or "<dynamic>")
        self.declaration = self.span(call)
        if name is None:
            self.gap("P_JS_DYNAMIC_NAME", args[0])
        kind = self.component.partition(":")[0]
        metadata = {"tool": "tool_description", "resource": "resource_metadata", "prompt": "prompt_metadata"}[kind]
        output = {"tool": "tool_result", "resource": "resource_body", "prompt": "prompt_message"}[kind]
        params = args[1:-1]
        if kind == "resource":
            if not params:
                self.gap("P_JS_REGISTRATION_ARGUMENTS", call)
            else:
                params = params[1:]  # URI / ResourceTemplate
        for param in params:
            if param.type in {"string", "template_string"} and kind != "resource":
                self.emit(param, metadata, "description")
            elif param.type == "object":
                props = self.properties(param)
                if any(key in props for key in ("description", "inputSchema", "argsSchema", "title")):
                    for field in ("description", "title"):
                        if field in props:
                            self.emit(props[field], metadata, field)
                    for field in ("inputSchema", "argsSchema"):
                        if field in props:
                            self.schema(props[field])
                elif kind == "resource":
                    for field in ("description", "title", "name"):
                        if field in props:
                            self.emit(props[field], metadata, field)
                else:
                    self.schema(param)
            else:
                self.gap("P_JS_REGISTRATION_BOUNDARY", param)
        self.callback(args[-1], output)


def extract_js_surfaces(inventory, *, server_id, deadline=None):
    result = JsSurfaceResult()
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_javascript as javascript
        import tree_sitter_typescript as typescript
    except ImportError:
        result.status = "partial"
        result.surfaces = {s: "unmeasured" for s in SURFACES}
        result.diagnostics.append({"code": "P_JS_PARSER_UNAVAILABLE", "server_id": server_id})
        return result
    for record in inventory.js_ts_files():
        if record.text is None:
            result.status = "partial"
            result.surfaces = {s: "partial" for s in SURFACES}
            result.diagnostics.append({"code": "P_JS_SOURCE_UNAVAILABLE", "path": record.rel_path})
            continue
        data = record.text.encode("utf-8")
        extractor = Extractor(result, record.rel_path, data, server_id, deadline)
        tree = None
        try:
            language = (typescript.language_tsx() if record.rel_path.endswith(".tsx") else
                        typescript.language_typescript() if record.language == "typescript" else javascript.language())
            tree = Parser(Language(language)).parse(data)
            root = tree.root_node
            extractor.tick()
            if root.has_error:
                extractor.gap("P_JS_PARSE_ERROR", root)
            constructors, servers = set(), set()
            sdk = False
            for statement in root.named_children:
                if statement.type == "import_statement":
                    source = statement.child_by_field_name("source")
                    module = extractor.literal(source)
                    if not module:
                        continue
                    sdk = sdk or module.startswith("@modelcontextprotocol/sdk/") or module == "@modelcontextprotocol/server"
                    for spec in extractor.walk(statement):
                        if spec.type == "import_specifier":
                            imported = spec.child_by_field_name("name")
                            alias = spec.child_by_field_name("alias") or imported
                            if imported is not None and alias is not None:
                                if (module in {"@modelcontextprotocol/sdk/server/mcp.js", "@modelcontextprotocol/server"}
                                        and extractor.text(imported) == "McpServer"
                                        and not extractor.text(statement).lstrip().startswith("import type ")
                                        and not extractor.text(spec).lstrip().startswith("type ")):
                                    constructors.add(extractor.text(alias))
                                if module in {"zod", "zod/v4"} and extractor.text(imported) == "z":
                                    extractor.zod.add(extractor.text(alias))
            invalid = set()
            for node in extractor.walk(root):
                if node.type == "string" and ((extractor.literal(node) or "").startswith("@modelcontextprotocol/sdk/") or extractor.literal(node) == "@modelcontextprotocol/server"):
                    sdk = True
                if node.type in {"assignment_expression", "augmented_assignment_expression", "update_expression"}:
                    target = node.child_by_field_name("left") or node.child_by_field_name("argument")
                    if target is not None and target.type == "identifier":
                        invalid.add(extractor.text(target))
                    elif target is not None and target.type == "member_expression":
                        owner = target.child_by_field_name("object")
                        if owner is not None and owner.type == "identifier":
                            invalid.add(extractor.text(owner))
            constructors -= invalid
            extractor.zod -= invalid
            for statement in root.named_children:
                if statement.type not in {"lexical_declaration", "variable_declaration"}:
                    continue
                for decl in statement.named_children:
                    if decl.type != "variable_declarator":
                        continue
                    name, value = decl.child_by_field_name("name"), decl.child_by_field_name("value")
                    if name is None or value is None or name.type != "identifier":
                        continue
                    symbol = extractor.text(name)
                    if symbol in invalid:
                        continue
                    if extractor.text(statement).startswith("const ") and value.type in {"string", "template_string"}:
                        literal = extractor.literal(value)
                        if literal is not None:
                            extractor.constants[symbol] = literal
                    if value.type == "new_expression":
                        constructor = value.child_by_field_name("constructor")
                        if constructor is not None and extractor.text(constructor) in constructors:
                            servers.add(symbol)
            found = False
            methods = {"tool", "registerTool", "resource", "registerResource", "prompt", "registerPrompt"}
            direct_calls = set()
            for statement in root.named_children:
                if statement.type != "expression_statement" or not statement.named_children:
                    continue
                call = statement.named_children[0]
                if call.type != "call_expression":
                    continue
                function = call.child_by_field_name("function")
                if function is None or function.type != "member_expression":
                    continue
                obj, prop = function.child_by_field_name("object"), function.child_by_field_name("property")
                if obj is not None and prop is not None and extractor.text(obj) in servers and extractor.text(prop) in methods:
                    direct_calls.add(call.id)
                    extractor.registration(call, extractor.text(prop))
                    found = True
            for node in extractor.walk(root):
                if node.type == "call_expression" and node.id not in direct_calls:
                    function = node.child_by_field_name("function")
                    if function is not None and function.type == "member_expression":
                        obj, prop = function.child_by_field_name("object"), function.child_by_field_name("property")
                        if obj is not None and prop is not None and extractor.text(prop) in methods and extractor.text(obj) in servers:
                            extractor.gap("P_JS_NESTED_REGISTRATION", node)
            if sdk and not found:
                extractor.gap("P_JS_DISCOVERY_BOUNDARY", root)
            elif not sdk and not result.texts and result.status == "complete":
                result.surfaces = {s: "unmeasured" for s in SURFACES}
        except (TimeoutError, RecursionError):
            result.status = "partial"
            result.surfaces = {s: "partial" for s in SURFACES}
            result.diagnostics.append({"code":"P_JS_EXTRACTION_BUDGET","path":record.rel_path})
    return result
