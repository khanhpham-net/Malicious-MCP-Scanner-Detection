"""Extract supported Pydantic input descriptions without importing target code."""
from __future__ import annotations

import ast
from dataclasses import dataclass
import time

from .models import SourceSpan, TraceStep
from .p_static import StaticValueResolver, StaticText
from .p_surface import SurfaceExtractionResult, SurfaceText
from .python_ast.index import Module, dotted, location, module_name


_PRIMITIVES = {"str", "int", "float", "bool", "bytes", "None", "object"}
_CONTAINERS = {
    "list", "dict", "tuple", "set", "frozenset",
    "typing.List", "typing.Dict", "typing.Tuple", "typing.Set",
    "typing.Optional", "typing.Union", "typing.Sequence", "typing.Mapping",
    "collections.abc.Sequence", "collections.abc.Mapping",
}
_ANNOTATED = {"typing.Annotated", "typing_extensions.Annotated"}


@dataclass
class _ParsedModule:
    module: Module
    classes: dict[str, ast.ClassDef]
    assignments: dict[str, ast.expr]
    functions: dict[tuple[int, int], ast.AST]


class _SchemaExtractor:
    def __init__(self, inventory, deadline):
        self.inventory = inventory
        self.deadline = deadline
        self.remaining = 100000
        self.modules = {}
        self.result = SurfaceExtractionResult()
        self.static = StaticValueResolver(inventory,deadline)

    def tick(self):
        self.remaining -= 1
        if self.remaining < 0 or self.deadline is not None and time.monotonic() >= self.deadline:
            raise TimeoutError

    def problem(self, code, module, node):
        self.result.status = "partial"
        self.result.diagnostics.append({
            "code": code, "location": location(module.path, node).to_dict(),
        })

    def load_modules(self):
        for record in self.inventory.python_files():
            self.tick()
            if record.text is None:
                continue
            try:
                tree = ast.parse(record.text.removeprefix("\ufeff"), filename=record.rel_path)
            except (SyntaxError, ValueError, RecursionError):
                # The discovery stage owns parse diagnostics for these files.
                continue
            module = Module(record.rel_path, module_name(record.rel_path), tree)
            classes, assignments, functions = {}, {}, {}
            for node in tree.body:
                self.tick()
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    module.add_import(node, module.aliases)
                elif isinstance(node, ast.ClassDef):
                    classes[node.name] = node
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            assignments[target.id] = node.value
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
                    assignments[node.target.id] = node.value
            for node in ast.walk(tree):
                self.tick()
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions[node.lineno, node.col_offset + 1] = node
            self.modules[record.rel_path] = _ParsedModule(module, classes, assignments, functions)

    def resolve(self, parsed, node):
        name = dotted(node)
        head = name.partition(".")[0]
        qualified=parsed.module.qualify(name) if head in parsed.module.aliases else (
            name if name in _PRIMITIVES | _CONTAINERS else f"{parsed.module.name}.{name}")
        seen=set()
        while qualified not in seen:
            seen.add(qualified)
            target=self.lookup(qualified)
            if not target:break
            owner,member=target
            if member not in owner.module.aliases:break
            qualified=owner.module.qualify(member)
        return qualified

    def lookup(self, qualified):
        module_name_, _, name = qualified.rpartition(".")
        candidates = [p for p in self.modules.values() if p.module.name == module_name_]
        if len(candidates) != 1:
            return None
        parsed = candidates[0]
        return parsed, name

    def is_model(self, parsed, node, seen):
        self.tick()
        key = parsed.module.name, node.name
        if key in seen:
            return False
        for base in node.bases:
            qualified = self.resolve(parsed, base)
            if qualified == "pydantic.BaseModel":
                return True
            target = self.lookup(qualified)
            if target:
                owner, name = target
                parent = owner.classes.get(name)
                if parent and self.is_model(owner, parent, seen | {key}):
                    return True
        return False

    def fields(self, parsed, model, seen):
        self.tick()
        key = parsed.module.name, model.name
        if key in seen:
            return {}
        fields = {}
        for base in model.bases:
            target = self.lookup(self.resolve(parsed, base))
            if target:
                owner, name = target
                parent = owner.classes.get(name)
                if parent:
                    fields.update(self.fields(owner, parent, seen | {key}))
        for node in model.body:
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                origin = node.annotation.value if isinstance(node.annotation, ast.Subscript) else node.annotation
                if node.target.id.startswith("_") or self.resolve(parsed, origin) in {
                    "typing.ClassVar", "typing_extensions.ClassVar",
                }:
                    continue
                fields[node.target.id] = parsed, node
        return fields

    def field_description(self, parsed, call, context, field_path):
        self.tick()
        if self.resolve(parsed, call.func) != "pydantic.Field":
            self.problem("P_SCHEMA_UNSUPPORTED_METADATA", parsed.module, call)
            return
        description = next((kw.value for kw in call.keywords if kw.arg == "description"), None)
        unpacked = any(kw.arg is None for kw in call.keywords)
        if description is None and not unpacked:
            return
        # Later Field metadata overrides the same field's earlier description.
        # Unresolved overrides must not leave a superseded literal in analysis.
        self.result.texts = [
            item for item in self.result.texts
            if (item.server_id, item.component, item.field_path) !=
               (context["server_id"], context["component"], field_path)
        ]
        if unpacked:
            self.problem("P_SCHEMA_DYNAMIC_FIELD", parsed.module, call)
            return
        if isinstance(description, ast.Constant) and description.value is None:
            return
        value = self.static.expression_text(parsed.module.path,description)
        if not isinstance(value,StaticText):
            self.problem("P_SCHEMA_DYNAMIC_DESCRIPTION", parsed.module, description)
            return
        span = value.span
        self.result.texts.append(SurfaceText(
            server_id=context["server_id"], component=context["component"],
            surface_kind="input_schema_description", text=value.value,
            content_span=span, declaration_span=context["declaration"],
            trace=[TraceStep("artifact", span, symbol=f"input field: {field_path}")],
            field_path=field_path, limitations=list(value.limitations),
        ))

    def annotation(self, parsed, node, context, field_path, active):
        self.tick()
        if node is None:
            return
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                # Forward references are parsed as syntax, never evaluated.
                try:
                    referenced = ast.parse(node.value, mode="eval").body
                except (SyntaxError, ValueError, RecursionError):
                    self.problem("P_SCHEMA_UNRESOLVED_TYPE", parsed.module, node)
                    return
                if any(isinstance(n, ast.Call) for n in ast.walk(referenced)):
                    self.problem("P_SCHEMA_UNRESOLVED_TYPE", parsed.module, node)
                    return
                self.annotation(parsed, referenced, context, field_path, active)
            return
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            self.annotation(parsed, node.left, context, field_path, active)
            self.annotation(parsed, node.right, context, field_path, active)
            return
        if isinstance(node, ast.Subscript):
            origin = self.resolve(parsed, node.value)
            arguments = list(node.slice.elts) if isinstance(node.slice, ast.Tuple) else [node.slice]
            if origin in _ANNOTATED:
                self.annotation(parsed, arguments[0], context, field_path, active)
                for metadata in arguments[1:]:
                    if isinstance(metadata, ast.Call):
                        self.field_description(parsed, metadata, context, field_path)
                    else:
                        self.problem("P_SCHEMA_UNSUPPORTED_METADATA", parsed.module, metadata)
            elif origin in _CONTAINERS:
                for argument in arguments:
                    self.annotation(parsed, argument, context, field_path, active)
            elif origin not in {"typing.Literal", "typing_extensions.Literal"}:
                self.problem("P_SCHEMA_UNRESOLVED_TYPE", parsed.module, node)
            return
        if not isinstance(node, (ast.Name, ast.Attribute)):
            self.problem("P_SCHEMA_UNRESOLVED_TYPE", parsed.module, node)
            return
        qualified = self.resolve(parsed, node)
        if qualified in _PRIMITIVES or qualified in {
            "datetime.datetime","datetime.date","datetime.time","datetime.timedelta",
            "decimal.Decimal","uuid.UUID"
        }:
            return
        if qualified in {"mcp.server.fastmcp.Context", "fastmcp.Context"}:
            return
        target = self.lookup(qualified)
        if target is None:
            self.problem("P_SCHEMA_UNRESOLVED_TYPE", parsed.module, node)
            return
        owner, name = target
        key = owner.module.name, name
        if key in active:
            if name in owner.assignments:
                self.problem("P_SCHEMA_UNRESOLVED_TYPE", parsed.module, node)
            return
        if name in owner.assignments:
            self.annotation(owner, owner.assignments[name], context, field_path, active | {key})
        elif name in owner.classes and self.is_model(owner, owner.classes[name], set()):
            cls=owner.classes[name]
            hooks={"__get_pydantic_json_schema__","__get_pydantic_core_schema__","__modify_schema__"}
            if any(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name in hooks for n in cls.body):
                self.problem("P_SCHEMA_CUSTOM_MODEL_SCHEMA",owner.module,cls)
            for statement in cls.body:
                if isinstance(statement,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="model_config" for t in statement.targets):
                    if isinstance(statement.value,ast.Call) and any(k.arg=="json_schema_extra" for k in statement.value.keywords):
                        self.problem("P_SCHEMA_CUSTOM_MODEL_SCHEMA",owner.module,statement)
            if cls.body and isinstance(cls.body[0],ast.Expr) and isinstance(cls.body[0].value,ast.Constant) and isinstance(cls.body[0].value.value,str):
                text_node=cls.body[0].value
                span=location(owner.module.path,text_node)
                self.result.texts.append(SurfaceText(
                    server_id=context["server_id"],component=context["component"],
                    surface_kind="input_schema_description",text=text_node.value,content_span=span,
                    declaration_span=context["declaration"],
                    trace=[TraceStep("artifact",span,symbol="declared Pydantic model description")],
                    field_path=field_path+".__model_description__",
                    limitations=["Model description is read from source; runtime schema hooks are unobserved."]))
            for field_name, (field_module, field_node) in self.fields(owner, owner.classes[name], set()).items():
                path = f"{field_path}.{field_name}"
                self.annotation(field_module, field_node.annotation, context, path, active | {key})
                if isinstance(field_node.value, ast.Call):
                    self.field_description(field_module, field_node.value, context, path)
        else:
            self.problem("P_SCHEMA_UNRESOLVED_TYPE", parsed.module, node)

    def run(self, servers):
        try:
            self.load_modules()
            for server in servers:
                for registration in server.get("registrations", []):
                    self.tick()
                    if registration["kind"] != "tool":
                        continue
                    span = SourceSpan.from_dict(registration["handler_span"])
                    parsed = self.modules.get(span.path)
                    fn = parsed.functions.get((span.start_line, span.start_col)) if parsed else None
                    if fn is None:
                        self.result.status = "partial"
                        self.result.diagnostics.append({"code": "P_SCHEMA_HANDLER_UNAVAILABLE", "location": span.to_dict()})
                        continue
                    context = {
                        "server_id": server["server_id"], "component": f"tool:{registration['name']}",
                        "declaration": SourceSpan.from_dict(registration["declaration_span"]),
                    }
                    positional = [*fn.args.posonlyargs, *fn.args.args]
                    defaults = dict(zip([arg.arg for arg in positional[-len(fn.args.defaults):]],
                                        fn.args.defaults)) if fn.args.defaults else {}
                    defaults.update({arg.arg: value for arg, value in zip(fn.args.kwonlyargs, fn.args.kw_defaults)})
                    for arg in [*positional, *fn.args.kwonlyargs]:
                        if arg.arg in {"self", "cls"}:
                            continue
                        if arg.annotation is None:
                            self.problem("P_SCHEMA_UNANNOTATED_PARAMETER", parsed.module, arg)
                        else:
                            self.annotation(parsed, arg.annotation, context, arg.arg, set())
                        default = defaults.get(arg.arg)
                        if isinstance(default, ast.Call):
                            self.field_description(parsed, default, context, arg.arg)
                    if fn.args.vararg or fn.args.kwarg:
                        self.problem("P_SCHEMA_VARIADIC_PARAMETER", parsed.module, fn)
        except (TimeoutError, RecursionError):
            self.result.status = "partial"
            self.result.diagnostics.append({"code": "P_SCHEMA_EXTRACTION_BUDGET"})
        return self.result


def extract_python_input_schema_descriptions(inventory, discovered_servers, *, deadline=None):
    """Extract literals from supported Pydantic Field/Annotated/model syntax.

    Dynamic metadata, unresolved types, and unsupported schema mechanisms produce
    partial coverage. This reads declared source metadata, not runtime JSON Schema.
    """
    return _SchemaExtractor(inventory, deadline).run(discovered_servers)

