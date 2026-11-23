"""Resolve bounded static values and file content from approved inventory."""
from __future__ import annotations

import ast
from dataclasses import dataclass
import json
from pathlib import PurePosixPath, PureWindowsPath
import time

from .models import SourceSpan, TraceStep
from .p_surface import SurfaceExtractionResult
from .python_ast.index import Module, dotted, location, module_name


@dataclass(frozen=True)
class StaticText:
    value: str
    span: SourceSpan
    trace: tuple[TraceStep, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class StaticPath:
    value: str
    anchored: bool = False


@dataclass(frozen=True)
class StaticFile:
    path: StaticPath


@dataclass(frozen=True)
class UnresolvedValue:
    code: str
    span: SourceSpan


class StaticValueResolver:
    def __init__(self, inventory, deadline):
        self.records = inventory.by_rel_path()
        self.deadline = deadline
        self.remaining = 100000
        self.parsed = {}
        self.parsing = {}
        self.parsing_cutoffs = {}
        self.result = SurfaceExtractionResult()
        self.module_paths = {}
        for record in inventory.python_files():
            self.module_paths.setdefault(module_name(record.rel_path), []).append(record.rel_path)

    def tick(self):
        self.remaining -= 1
        if self.remaining < 0 or self.deadline is not None and time.monotonic() >= self.deadline:
            raise TimeoutError

    def unknown(self, code, module, node):
        return UnresolvedValue(code, location(module.path, node))

    def literal(self, value):
        return value.value if isinstance(value, StaticText) else value

    def parse(self, span):
        if span.path not in self.parsed:
            # Break import cycles before resolving module-level constants.
            self.parsed[span.path] = None
            record = self.records.get(span.path)
            if record is None or record.text is None:
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
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            nodes[node.lineno, node.col_offset + 1] = node
                    env = {"__file__": StaticPath(module.path, True)}
                    self.parsing[span.path]=(module,nodes,env)
                    for node in tree.body:
                        self.parsing_cutoffs[span.path]=getattr(node,"lineno",0)
                        if isinstance(node, ast.Assign):
                            value = self.value(module, node.value, env)
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    env[target.id] = value
                        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                            if node.value is not None:
                                env[node.target.id] = self.value(module, node.value, env)
                        elif isinstance(node, (ast.If, ast.For, ast.While, ast.Try, ast.With)):
                            for nested in ast.walk(node):
                                if isinstance(nested, ast.Name) and isinstance(nested.ctx, ast.Store):
                                    env[nested.id] = self.unknown("P_OUTPUT_DYNAMIC_GLOBAL", module, nested)
                    self.parsed[span.path] = module, nodes, env
                except (SyntaxError, ValueError, RecursionError):
                    self.parsed[span.path] = None
                finally:
                    self.parsing.pop(span.path,None)
                    self.parsing_cutoffs.pop(span.path,None)
        return self.parsed[span.path]

    def read(self, path, module, node):
        if not isinstance(path, StaticPath):
            return self.unknown("P_OUTPUT_DYNAMIC_PATH", module, node)
        raw = path.value.replace("\\", "/")
        candidate = PurePosixPath(raw)
        if (candidate.is_absolute() or PureWindowsPath(raw).drive or
                ".." in candidate.parts or candidate.suffix.lower() not in {".txt", ".md", ".json"}):
            return self.unknown("P_OUTPUT_FILE_PATH_UNSUPPORTED", module, node)
        record = self.records.get(candidate.as_posix())
        if record is None or record.text is None:
            return self.unknown("P_OUTPUT_FILE_UNAVAILABLE", module, node)
        lines = record.text.splitlines()
        span = SourceSpan(record.rel_path, start_line=1, start_col=1,
                          end_line=max(1, len(lines)), end_col=(len(lines[-1]) + 1) if lines else 1)
        limitations = ("File text uses the inventory UTF-8 snapshot; runtime contents and encoding are unobserved.",)
        if not path.anchored:
            limitations += ("Literal relative path was resolved against snapshot root; runtime CWD is unverified.",)
        return StaticText(record.text, span, (
            TraceStep("artifact", span, symbol="snapshot text file"),
            TraceStep("call", location(module.path, node), symbol="static text read"),
        ), limitations)

    def value(self, module, node, env):
        self.tick()
        if isinstance(node, ast.Constant):
            return StaticText(node.value, location(module.path, node)) if isinstance(node.value, str) else node.value
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            return self.imported_value(module, node)
        if isinstance(node, (ast.List, ast.Tuple)):
            return [self.value(module, item, env) for item in node.elts]
        if isinstance(node, ast.Dict):
            if any(key is None for key in node.keys):
                return self.unknown("P_OUTPUT_DYNAMIC_MAPPING", module, node)
            entries = {}
            for key_node, value_node in zip(node.keys, node.values):
                key = self.value(module, key_node, env)
                raw_key = self.literal(key)
                if not isinstance(raw_key, (str, int, float, bool, type(None))):
                    return self.unknown("P_OUTPUT_DYNAMIC_MAPPING", module, key_node)
                original_key = entries[raw_key][0] if raw_key in entries else key
                entries[raw_key] = original_key, self.value(module, value_node, env)
            # Duplicate keys retain only the value actually returned by Python.
            return [part for pair in entries.values() for part in pair]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.value(module, node.left, env)
            right = self.value(module, node.right, env)
            if isinstance(left, StaticText) and isinstance(right, StaticText):
                if len(left.value)+len(right.value) <= 65536:
                    return StaticText(left.value+right.value, location(module.path,node),
                                      left.trace+right.trace,
                                      left.limitations+right.limitations+(
                                          "Concatenated text uses the source expression span.",))
            return self.unknown("P_OUTPUT_DYNAMIC_VALUE", module, node)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            left = self.value(module, node.left, env)
            right = self.literal(self.value(module, node.right, env))
            if isinstance(left, StaticPath) and isinstance(right, str):
                return StaticPath((PurePosixPath(left.value) / right).as_posix(), left.anchored)
            return self.unknown("P_OUTPUT_DYNAMIC_PATH", module, node)
        if isinstance(node, ast.Attribute):
            if dotted(node).partition(".")[0] not in env:
                imported = self.imported_value(module, node)
                if not isinstance(imported, UnresolvedValue):
                    return imported
            receiver = self.value(module, node.value, env)
            if isinstance(receiver, StaticPath) and node.attr == "parent":
                return StaticPath(PurePosixPath(receiver.value).parent.as_posix(), receiver.anchored)
            return self.unknown("P_OUTPUT_UNRESOLVED_VALUE", module, node)
        if not isinstance(node, ast.Call):
            return self.unknown("P_OUTPUT_DYNAMIC_VALUE", module, node)
        if any(kw.arg is None for kw in node.keywords):
            return self.unknown("P_OUTPUT_DYNAMIC_CALL", module, node)
        keywords = {kw.arg: self.value(module, kw.value, env) for kw in node.keywords}
        args = [self.value(module, arg, env) for arg in node.args]
        symbol = dotted(node.func)
        head = symbol.partition(".")[0]
        name = module.qualify(symbol) if head not in env else ""
        if name in {"pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath"}:
            if len(args) == 1 and isinstance(args[0], StaticPath):
                return args[0]
            pieces = [self.literal(arg) for arg in args]
            if pieces and all(isinstance(piece, str) for piece in pieces):
                return StaticPath(PurePosixPath(*pieces).as_posix())
            return self.unknown("P_OUTPUT_DYNAMIC_PATH", module, node)
        if name == "open":
            path = keywords.get("file", args[0] if args else None)
            if isinstance(path, StaticText):
                path = StaticPath(path.value)
            mode = self.literal(keywords.get("mode", args[1] if len(args)>1 else "r"))
            encoding = self.literal(keywords.get("encoding", "utf-8"))
            if mode not in {"r", "rt"} or encoding not in {"utf-8", "utf8", "UTF-8"}:
                return self.unknown("P_OUTPUT_UNSUPPORTED_READ", module, node)
            if set(keywords)-{"file", "mode", "encoding"} or len(args)>2:
                return self.unknown("P_OUTPUT_UNSUPPORTED_READ", module, node)
            return StaticFile(path) if isinstance(path, StaticPath) else self.unknown("P_OUTPUT_DYNAMIC_PATH", module, node)
        if name == "mcp.types.TextContent":
            text = keywords.get("text")
            if self.literal(keywords.get("type")) == "text" and isinstance(text, StaticText):
                return text
            return self.unknown("P_OUTPUT_UNSUPPORTED_CONTENT", module, node)
        if name == "mcp.types.CallToolResult":
            if "content" not in keywords:
                return self.unknown("P_OUTPUT_UNSUPPORTED_CONTENT", module, node)
            return [keywords["content"], keywords.get("structuredContent")]
        if name in {"json.loads", "json.load"}:
            value = args[0] if args else None
            if name == "json.load" and isinstance(value, StaticFile):
                value = self.read(value.path, module, node)
            if len(args) != 1 or keywords or not isinstance(value, StaticText):
                return self.unknown("P_OUTPUT_DYNAMIC_JSON", module, node)
            if len(value.value)>65536:
                return self.unknown("P_OUTPUT_TEXT_LIMIT", module, node)
            try:
                decoded = json.loads(value.value)
            except (ValueError, RecursionError):
                return self.unknown("P_OUTPUT_INVALID_JSON", module, node)
            return self.json_text(decoded, value)
        if isinstance(node.func, ast.Attribute):
            receiver = self.value(module, node.func.value, env)
            method = node.func.attr
            if isinstance(receiver, StaticPath) and method in {"open", "read_text"}:
                mode = self.literal(args[0]) if args else self.literal(keywords.get("mode", "r"))
                encoding = self.literal(keywords.get("encoding", "utf-8"))
                if (method=="open" and mode not in {"r", "rt"} or args and method=="read_text"
                        or encoding not in {"utf-8", "utf8", "UTF-8"}
                        or set(keywords)-({"encoding"} if method=="read_text" else {"encoding","mode"})):
                    return self.unknown("P_OUTPUT_UNSUPPORTED_READ", module, node)
                return StaticFile(receiver) if method=="open" else self.read(receiver, module, node)
            if isinstance(receiver, StaticPath):
                if method == "joinpath" and args and not keywords:
                    pieces = [self.literal(arg) for arg in args]
                    if all(isinstance(piece,str) for piece in pieces):
                        return StaticPath(PurePosixPath(receiver.value,*pieces).as_posix(),receiver.anchored)
                    return self.unknown("P_OUTPUT_DYNAMIC_PATH",module,node)
                if method == "resolve" and not args and not keywords:
                    # No filesystem operation: read() still requires inventory membership.
                    return receiver
                if method in {"with_name", "with_suffix"} and len(args)==1 and not keywords:
                    name = self.literal(args[0])
                    if isinstance(name,str):
                        try:
                            updated = getattr(PurePosixPath(receiver.value),method)(name)
                            return StaticPath(updated.as_posix(),receiver.anchored)
                        except ValueError:
                            pass
                    return self.unknown("P_OUTPUT_DYNAMIC_PATH",module,node)
            if isinstance(receiver, StaticFile) and method == "read" and not args and not keywords:
                return self.read(receiver.path, module, node)
        return self.unknown("P_OUTPUT_UNSUPPORTED_CALL", module, node)

    def json_text(self, value, source):
        self.tick()
        if isinstance(value, str):
            return StaticText(value, source.span, source.trace, source.limitations + (
                "JSON text locations cover the whole source artifact, not exact decoded string offsets.",))
        if isinstance(value, dict):
            return [self.json_text(part, source) for pair in value.items() for part in pair]
        if isinstance(value, list):
            return [self.json_text(part, source) for part in value]
        return value

    def imported_value(self, module, node):
        self.tick()
        qualified = module.qualify(dotted(node))
        owner, _, name = qualified.rpartition(".")
        paths = self.module_paths.get(owner, [])
        if len(paths)==1:
            parsed = self.parse(SourceSpan(paths[0]))
            if parsed and name in parsed[2]:
                return parsed[2][name]
            # Resolve an explicit re-export without evaluating target code.
            if parsed and name in parsed[0].aliases:
                alias = ast.copy_location(ast.Name(id=name, ctx=ast.Load()),node)
                return self.value(parsed[0],alias,parsed[2])
        return self.unknown("P_OUTPUT_UNRESOLVED_VALUE",module,node)

    def expression_text(self, path, expression):
        self.tick()
        parsed = self.parse(SourceSpan(path))
        if parsed:
            return self.value(parsed[0],expression,parsed[2])
        return UnresolvedValue("P_OUTPUT_HANDLER_UNAVAILABLE",location(path,expression))
