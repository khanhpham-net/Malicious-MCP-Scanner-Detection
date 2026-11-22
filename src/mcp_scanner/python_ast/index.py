"""Index first-party Python modules and MCP declarations without importing target code."""
from __future__ import annotations

import ast
import posixpath
from dataclasses import dataclass, field
from typing import Callable

from ..models import SourceSpan, stable_sha256_id

Function = ast.FunctionDef | ast.AsyncFunctionDef
SERVER_TYPES = {"fastmcp.FastMCP": "fastmcp", "mcp.server.fastmcp.FastMCP": "fastmcp",
                "mcp.server.Server": "mcp", "mcp.server.lowlevel.Server": "mcp"}
REGISTRATIONS = {"tool", "resource", "prompt", "add_tool"}


def dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else ""
    return ""


def location(path: str, node: ast.AST) -> SourceSpan:
    return SourceSpan(path, node.lineno, node.col_offset + 1,
                      node.end_lineno, node.end_col_offset + 1 if node.end_col_offset is not None else None)


def literal(node: ast.AST | None):
    return node.value if isinstance(node, ast.Constant) else None


def argument(call: ast.Call, name: str, position: int | None = None):
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    if position is not None and position < len(call.args):
        return call.args[position]
    return None


@dataclass
class Module:
    path: str
    name: str
    tree: ast.Module
    aliases: dict[str, str] = field(default_factory=dict)
    definitions: dict[str, Function] = field(default_factory=dict)
    assignments: dict[str, ast.expr] = field(default_factory=dict)

    def qualify(self, name: str) -> str:
        head, sep, tail = name.partition(".")
        return self.aliases.get(head, head) + sep + tail

    def add_import(self, node: ast.Import | ast.ImportFrom, aliases: dict[str, str]):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.partition(".")[0]] = item.name if item.asname else item.name.partition(".")[0]
            return
        prefix = node.module or ""
        if node.level:
            package = self.name.split(".")
            if not self.path.endswith("__init__.py"):
                package = package[:-1]
            if node.level > 1:
                package = package[:max(0, len(package) + 1 - node.level)]
            prefix = ".".join(part for part in [*package, prefix] if part)
        for item in node.names:
            aliases[item.asname or item.name] = ".".join(x for x in [prefix, item.name] if x)


@dataclass
class Registration:
    module: Module
    handler_module: Module
    function: Function
    declaration: ast.AST
    instance: str
    kind: str
    name: str
    readonly: bool | None
    destructive: bool | None
    scope_calls: tuple = ()


class Index:
    def __init__(self, modules: list[Module], tick: Callable):
        self.modules = {m.name: m for m in modules}
        self.by_path = {m.path: m for m in modules}
        self.functions: dict[str, tuple[Module, Function]] = {}
        self.classes: dict[str, tuple[Module, ast.ClassDef]] = {}
        self.method_owners = {}
        self.instances: dict[str, tuple[Module, str, str]] = {}
        self.registrations: list[Registration] = []
        self.unresolved: list[tuple[str, int]] = []
        for mod in modules:
            for node in mod.tree.body:
                tick()
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    mod.add_import(node, mod.aliases)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    mod.definitions[node.name] = node
                    self.functions[f"{mod.name}.{node.name}"] = mod, node
                elif isinstance(node, ast.ClassDef):
                    owner = f"{mod.name}.{node.name}"
                    self.classes[owner] = mod, node
                    for method in node.body:
                        if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            self.method_owners[(mod.name, method.lineno)] = owner
                elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, ast.Name):
                            mod.assignments[target.id] = node.value
        for mod in modules:
            for name, value in mod.assignments.items():
                tick()
                if not isinstance(value, ast.Call):
                    continue
                framework = SERVER_TYPES.get(mod.qualify(dotted(value.func)))
                if framework:
                    title = literal(argument(value, "name", 0))
                    self.instances[f"{mod.name}.{name}"] = mod, framework, title if isinstance(title, str) else name
        self.instance_aliases = {}
        for mod in modules:
            for name, value in mod.assignments.items():
                if isinstance(value, (ast.Name, ast.Attribute)):
                    target = self.resolve(mod, dotted(value))
                    if target in self.instances:
                        self.instance_aliases[f"{mod.name}.{name}"] = target
        self._known_regs = set()
        self.tick = tick
        for mod in modules:
            self._scope(mod, mod.tree.body, {}, (), ())

    def _scope(self, mod, statements, supplied, calls, active):
        """Resolve registration inside explicitly called first-party server factories."""
        env = supplied.copy()
        functions = {}
        for stmt in statements:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                symbol = f"{mod.name}.@{stmt.lineno}.{stmt.name}" if calls else f"{mod.name}.{stmt.name}"
                functions[stmt.name] = symbol
                self.functions[symbol] = mod, stmt

        def symbol(expr):
            name = dotted(expr)
            return env.get(name, functions.get(name, self.resolve(mod, name)))

        def resolve_call(call, binding):
            qn = mod.qualify(dotted(call.func))
            if qn in SERVER_TYPES and binding:
                instance = f"{mod.name}.{calls!r}.{binding}" if calls else f"{mod.name}.{binding}"
                title = literal(argument(call, "name", 0))
                self.instances.setdefault(instance, (mod, SERVER_TYPES[qn], title if isinstance(title, str) else binding))
                return instance
            target = self.functions.get(symbol(call.func))
            if target and len(calls) < 12:
                owner, fn = target
                ident = owner.path, fn.lineno
                if ident not in active:
                    params = [*fn.args.posonlyargs, *fn.args.args]
                    args = {p.arg: symbol(a) for p, a in zip(params, call.args)}
                    args.update({kw.arg: symbol(kw.value) for kw in call.keywords if kw.arg})
                    site = (mod.path, call.lineno, call.col_offset + 1)
                    return self._scope(owner, fn.body, args, (*calls, site), (*active, ident))
            return None

        for stmt in statements:
            self.tick()
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value is not None:
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                for t in targets:
                    if isinstance(t, ast.Name):
                        value = resolve_call(stmt.value, t.id) if isinstance(stmt.value, ast.Call) else symbol(stmt.value)
                        if value:
                            env[t.id] = value
                            if not calls and value in self.instances:
                                self.instance_aliases[f"{mod.name}.{t.id}"] = value
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in stmt.decorator_list:
                    self.register(mod, dec, (mod, stmt), bindings=env, scope_calls=calls)
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call = stmt.value
                if isinstance(call.func, ast.Attribute) and call.func.attr == "add_tool":
                    handler = self.functions.get(symbol(argument(call, "fn", 0) or argument(call, "tool")))
                    self.register(mod, call, handler, bindings=env, scope_calls=calls)
                else:
                    resolve_call(call, None)
            elif isinstance(stmt, ast.If):
                known = literal(stmt.test)
                paths = (stmt.body if known else stmt.orelse,) if isinstance(known, bool) else (stmt.body, stmt.orelse)
                for body in paths:
                    self._scope(mod, body, env, calls, active)
            elif isinstance(stmt, ast.Return):
                return resolve_call(stmt.value, None) if isinstance(stmt.value, ast.Call) else symbol(stmt.value)
        return None

    def resolve(self, mod: Module, name: str) -> str:
        return mod.qualify(name) if name.partition(".")[0] in mod.aliases else f"{mod.name}.{name}"

    def register(self, mod: Module, node: ast.expr, handler, *, bindings=None, scope_calls=()):
        call = node if isinstance(node, ast.Call) else None
        fn = node.func if call else node
        if not isinstance(fn, ast.Attribute) or fn.attr not in REGISTRATIONS:
            return
        owner = dotted(fn.value)
        instance = (bindings or {}).get(owner, self.resolve(mod, owner))
        instance = self.instance_aliases.get(instance, instance)
        if instance not in self.instances:
            return
        key = (instance, mod.path, node.lineno, node.col_offset)
        if key in self._known_regs:
            return
        if fn.attr == "add_tool" and call and handler is None:
            target = argument(call, "fn", 0) or argument(call, "tool")
            handler = self.functions.get(self.resolve(mod, dotted(target)))
        if not handler:
            if (mod.path, node.lineno) not in self.unresolved:
                self.unresolved.append((mod.path, node.lineno))
            return
        kind = "tool" if fn.attr == "add_tool" else fn.attr
        handler_module, function = handler
        name = literal(argument(call, "name")) if call else None
        annotation = argument(call, "annotations") if call else None
        if isinstance(annotation, ast.Name):
            annotation = mod.assignments.get(annotation.id)
        hints = {}
        if isinstance(annotation, ast.Call) and mod.qualify(dotted(annotation.func)).rsplit(".", 1)[-1] in {"ToolAnnotations", "dict"}:
            hints = {kw.arg: literal(kw.value) for kw in annotation.keywords}
        elif isinstance(annotation, ast.Dict):
            hints = {literal(k): literal(v) for k, v in zip(annotation.keys, annotation.values)}
        self.registrations.append(Registration(mod, handler_module, function, node, instance, kind,
            name if isinstance(name, str) else function.name,
            hints.get("readOnlyHint"), hints.get("destructiveHint"), scope_calls))
        self._known_regs.add(key)

    def class_lineage(self, name):
        pending = [name]
        visited = set()
        while pending:
            current = pending.pop()
            if current in visited or current not in self.classes:
                continue
            visited.add(current)
            module, cls = self.classes[current]
            yield module, cls
            pending.extend(self.resolve(module, dotted(base)) for base in reversed(cls.bases))

    def method(self, owner, name, *, after=""):
        for module, cls in self.class_lineage(owner):
            if after:
                if after == f"{module.name}.{cls.name}":
                    after = ""
                continue
            for stmt in cls.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name == name:
                    return module, stmt
        return None

    def server_ids(self, snapshot_id: str) -> dict[str, str]:
        return {key: snapshot_id if len(self.instances) == 1 else stable_sha256_id([snapshot_id, mod.path, key])
                for key, (mod, _, _) in self.instances.items()}


def module_name(path: str) -> str:
    name = posixpath.splitext(path)[0].replace("/", ".")
    if name.startswith("src."):
        name = name[4:]
    return name.removesuffix(".__init__")
