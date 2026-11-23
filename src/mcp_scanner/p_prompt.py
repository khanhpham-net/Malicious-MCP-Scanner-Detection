"""Static prompt metadata and message text from resolved Python MCP handlers."""
from __future__ import annotations

import ast
from copy import deepcopy
import time

from .models import SourceSpan, TraceStep
from .p_static import StaticValueResolver, StaticText
from .p_surface import SurfaceExtractionResult, SurfaceText
from .python_ast.index import Module, dotted, location, module_name


_MESSAGES = {
    "mcp.server.fastmcp.prompts.base.UserMessage": "user",
    "mcp.server.fastmcp.prompts.base.AssistantMessage": "assistant",
}
_PROMPT_MESSAGE = "mcp.types.PromptMessage"
_TEXT_CONTENT = "mcp.types.TextContent"


class _PromptExtractor:
    def __init__(self, inventory, deadline):
        self.records = inventory.by_rel_path()
        self.deadline = deadline
        self.remaining = 100000
        self.parsed = {}
        self.result = SurfaceExtractionResult()
        self.static = StaticValueResolver(inventory,deadline)
        self.static_texts = {}

    def tick(self):
        self.remaining -= 1
        if self.remaining < 0 or self.deadline is not None and time.monotonic() >= self.deadline:
            raise TimeoutError

    def problem(self, code, path, node):
        self.result.status = "partial"
        self.result.diagnostics.append({"code": code, "location": location(path, node).to_dict()})

    def parse(self, span):
        self.tick()
        if span.path not in self.parsed:
            record = self.records.get(span.path)
            if record is None or record.text is None:
                self.result.status = "partial"
                self.result.diagnostics.append({"code": "P_PROMPT_SOURCE_UNAVAILABLE", "location": span.to_dict()})
                self.parsed[span.path] = None
            else:
                try:
                    tree = ast.parse(record.text.removeprefix("\ufeff"), filename=span.path)
                    module = Module(span.path, module_name(span.path), tree)
                    for node in tree.body:
                        if isinstance(node, (ast.Import, ast.ImportFrom)):
                            module.add_import(node, module.aliases)
                    nodes = {}
                    for node in ast.walk(tree):
                        self.tick()
                        if isinstance(node, (ast.Call, ast.Attribute, ast.FunctionDef, ast.AsyncFunctionDef)):
                            nodes.setdefault((node.lineno, node.col_offset + 1), node)
                    self.parsed[span.path] = module, nodes
                except (SyntaxError, ValueError, RecursionError):
                    self.result.status = "partial"
                    self.result.diagnostics.append({"code": "P_PROMPT_PARSE_ERROR", "location": span.to_dict()})
                    self.parsed[span.path] = None
        return self.parsed[span.path]

    def resolve_name(self, node, env, active):
        self.tick()
        if isinstance(node, ast.Name):
            if node.id not in env or node.id in active:
                return None
            return self.resolve_name(env[node.id], env, active | {node.id})
        return node

    def keywords(self, module, call):
        if any(kw.arg is None for kw in call.keywords):
            self.problem("P_PROMPT_DYNAMIC_MESSAGE", module.path, call)
            return None
        return {kw.arg: kw.value for kw in call.keywords}

    def content(self, module, node, env):
        resolved = self.resolve_name(node, env, set())
        if isinstance(resolved, ast.Constant) and isinstance(resolved.value, str):
            return resolved.value, location(module.path, resolved)
        if isinstance(resolved, ast.Call) and module.qualify(dotted(resolved.func)) == _TEXT_CONTENT:
            keywords = self.keywords(module, resolved)
            if keywords is not None and "text" in keywords:
                kind = keywords.get("type")
                if isinstance(kind, ast.Constant) and kind.value == "text":
                    text = self.resolve_name(keywords["text"], env, set())
                    if isinstance(text, ast.Constant) and isinstance(text.value, str):
                        return text.value, location(module.path, text)
        if isinstance(resolved, ast.Dict) and all(isinstance(k, ast.Constant) for k in resolved.keys):
            fields = {k.value: v for k, v in zip(resolved.keys, resolved.values)}
            kind, text = fields.get("type"), fields.get("text")
            if isinstance(kind, ast.Constant) and kind.value == "text":
                text = self.resolve_name(text, env, set())
                if isinstance(text, ast.Constant) and isinstance(text.value, str):
                    return text.value, location(module.path, text)
        if resolved is not None:
            static = self.static_content(module,resolved)
            if static is not None:
                return static.value,static.span
        self.problem("P_PROMPT_DYNAMIC_CONTENT", module.path, node)
        return None

    def static_content(self,module,node):
        value = self.static.expression_text(module.path,node)
        if isinstance(value,StaticText):
            key = (value.span.path,value.span.start_line,value.span.start_col,value.value)
            self.static_texts[key] = value
            return value
        return None

    def messages(self, module, node, env, field_path="messages"):
        resolved = self.resolve_name(node, env, set())
        if resolved is None:
            resolved = node
        static = self.static_content(module,resolved)
        if static is not None:
            return [(static.value,static.span,f"{field_path}.content","user")]
        if isinstance(resolved, ast.List):
            if field_path != "messages":
                self.problem("P_PROMPT_UNSUPPORTED_MESSAGE", module.path, resolved)
                return []
            result = []
            for index, item in enumerate(resolved.elts):
                self.tick()
                result.extend(self.messages(module, item, env, f"{field_path}[{index}]"))
            return result
        role, content = "user", resolved
        if isinstance(resolved, ast.Call):
            name = module.qualify(dotted(resolved.func))
            keywords = self.keywords(module, resolved)
            if keywords is None:
                return []
            if name in _MESSAGES:
                role = _MESSAGES[name]
                content = keywords.get("content", resolved.args[0] if resolved.args else None)
            elif name == _PROMPT_MESSAGE:
                role_node = keywords.get("role")
                role = role_node.value if isinstance(role_node, ast.Constant) else None
                content = keywords.get("content")
            else:
                self.problem("P_PROMPT_UNSUPPORTED_MESSAGE", module.path, resolved)
                return []
        elif isinstance(resolved, ast.Dict):
            if not all(isinstance(k, ast.Constant) and isinstance(k.value, str) for k in resolved.keys):
                self.problem("P_PROMPT_DYNAMIC_MESSAGE", module.path, resolved)
                return []
            fields = {k.value: v for k, v in zip(resolved.keys, resolved.values)}
            role_node = fields.get("role")
            role = role_node.value if isinstance(role_node, ast.Constant) else None
            content = fields.get("content")
        if role not in {"user", "assistant"} or content is None:
            self.problem("P_PROMPT_DYNAMIC_MESSAGE", module.path, node)
            return []
        value = self.content(module, content, env)
        return [(value[0], value[1], f"{field_path}.content", role)] if value else []

    def bind_value(self, module, expression, env):
        # Message construction captures argument values at assignment time.
        # Keep literal spans from their original definitions when substituting.
        class BindLocals(ast.NodeTransformer):
            def visit_Name(self, node):
                self_outer.tick()
                if node.id in env:
                    return deepcopy(env[node.id])
                if node.id in module.aliases or node.id == "__file__":
                    return node
                parsed = self_outer.static.parse(SourceSpan(module.path))
                if parsed and isinstance(parsed[2].get(node.id),StaticText):
                    value = parsed[2][node.id]
                    return ast.copy_location(ast.Constant(value=value.value),node)
                return ast.copy_location(ast.Constant(value=None), node)

        self_outer = self
        return BindLocals().visit(deepcopy(expression))

    def body(self, module, handler):
        env = {}
        for index, statement in enumerate(handler.body):
            self.tick()
            if index == 0 and isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
                if isinstance(statement.value.value, str):
                    continue
            if isinstance(statement, ast.Assign) and all(isinstance(t, ast.Name) for t in statement.targets):
                value = self.bind_value(module, statement.value, env)
                for target in statement.targets:
                    env[target.id] = value
            elif isinstance(statement, ast.Return) and statement.value is not None:
                return self.messages(module, statement.value, env), location(module.path, statement)
            else:
                self.problem("P_PROMPT_UNSUPPORTED_BODY", module.path, statement)
                return [], None
        self.problem("P_PROMPT_NO_STATIC_RETURN", module.path, handler)
        return [], None

    def run(self, servers, metadata):
        try:
            for server in servers:
                for reg in server.get("registrations", []):
                    self.tick()
                    if reg["kind"] != "prompt":
                        continue
                    declaration = SourceSpan.from_dict(reg["declaration_span"])
                    handler_span = SourceSpan.from_dict(reg["handler_span"])
                    parsed = self.parse(handler_span)
                    handler = parsed[1].get((handler_span.start_line, handler_span.start_col)) if parsed else None
                    if not isinstance(handler, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.result.status = "partial"
                        self.result.diagnostics.append({"code": "P_PROMPT_HANDLER_UNRESOLVED", "location": handler_span.to_dict()})
                        continue
                    module, _ = parsed
                    fragments, returned = [], None
                    if metadata:
                        parsed_declaration = self.parse(declaration)
                        call = parsed_declaration[1].get((declaration.start_line, declaration.start_col)) if parsed_declaration else None
                        if not isinstance(call, (ast.Call, ast.Attribute)):
                            self.result.status = "partial"
                            self.result.diagnostics.append({"code": "P_PROMPT_DECLARATION_UNRESOLVED", "location": declaration.to_dict()})
                            continue
                        keywords = self.keywords(parsed_declaration[0], call) if isinstance(call, ast.Call) else {}
                        if keywords is None:
                            continue
                        doc = handler.body[0].value if handler.body and isinstance(handler.body[0], ast.Expr) else None
                        explicit = keywords.get("description")
                        if explicit is None or isinstance(explicit, ast.Constant) and explicit.value in (None, ""):
                            if isinstance(doc, ast.Constant) and isinstance(doc.value, str):
                                fragments.append((doc.value, location(module.path, doc), "description", None))
                        elif isinstance(explicit, ast.Constant) and isinstance(explicit.value, str):
                            fragments.append((explicit.value, location(declaration.path, explicit), "description", None))
                        else:
                            self.problem("P_PROMPT_DYNAMIC_METADATA", declaration.path, explicit)
                        name = keywords.get("name")
                        if isinstance(name, ast.Constant) and isinstance(name.value, str):
                            fragments.append((name.value, location(declaration.path, name), "name", None))
                        elif name is not None:
                            self.problem("P_PROMPT_DYNAMIC_METADATA", declaration.path, name)
                    else:
                        fragments, returned = self.body(module, handler)
                    for text, span, field_path, role in fragments:
                        origin = self.static_texts.get((span.path,span.start_line,span.start_col,text))
                        trace = list(origin.trace) if origin and origin.trace else [
                            TraceStep("artifact",span,symbol=f"prompt {field_path}",note=f"role={role}" if role else None)]
                        if returned:
                            trace.append(TraceStep("sink", returned, symbol="prompt return"))
                        self.result.texts.append(SurfaceText(
                            server_id=server["server_id"], component=f"prompt:{reg['name']}",
                            surface_kind="prompt_metadata" if metadata else "prompt_message",
                            text=text, content_span=span, declaration_span=declaration,
                            trace=trace, field_path=field_path,
                            limitations=list(origin.limitations) if origin else [],
                        ))
        except (TimeoutError, RecursionError):
            self.result.status = "partial"
            self.result.diagnostics.append({"code": "P_PROMPT_EXTRACTION_BUDGET"})
        return self.result


def extract_python_prompt_metadata(inventory, discovered_servers, *, deadline=None):
    """Read literal registered prompt names/descriptions and docstrings."""
    return _PromptExtractor(inventory, deadline).run(discovered_servers, metadata=True)


def extract_python_prompt_messages(inventory, discovered_servers, *, deadline=None):
    """Read literal strings and supported text message constructors/lists.

    Supports statically resolved local aliases, SDK UserMessage/AssistantMessage,
    PromptMessage with TextContent, and equivalent literal text dictionaries.
    Dynamic interpolation, branches, helper/file reads and non-text content are
    marked partial. Declared templates are observed; target code is never run.
    """
    return _PromptExtractor(inventory, deadline).run(discovered_servers, metadata=False)

