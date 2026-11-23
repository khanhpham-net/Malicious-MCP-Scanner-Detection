"""Literal Python resource metadata and bodies from resolved MCP handlers."""
from __future__ import annotations

import ast
import time

from .models import SourceSpan, TraceStep
from .p_surface import SurfaceExtractionResult, SurfaceText
from .python_ast.index import location


def _extract_resources(inventory, servers, *, metadata, deadline):
    result = SurfaceExtractionResult()
    records = inventory.by_rel_path()
    parsed = {}
    remaining = 100000

    def tick():
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError

    def problem(code, span):
        result.status = "partial"
        result.diagnostics.append({
            "code": code, "part": "metadata" if metadata else "body",
            "location": span.to_dict(),
        })

    def node_at(span):
        tick()
        if span.path not in parsed:
            record = records.get(span.path)
            nodes = {}
            if record is None or record.text is None:
                problem("P_RESOURCE_SOURCE_UNAVAILABLE", span)
            else:
                try:
                    tree = ast.parse(record.text.removeprefix("\ufeff"), filename=span.path)
                    for node in ast.walk(tree):
                        tick()
                        if isinstance(node, (ast.Call, ast.Attribute, ast.FunctionDef, ast.AsyncFunctionDef)):
                            nodes.setdefault((node.lineno, node.col_offset+1), node)
                except (SyntaxError, ValueError, RecursionError):
                    problem("P_RESOURCE_PARSE_ERROR", span)
            parsed[span.path] = nodes
        return parsed[span.path].get((span.start_line, span.start_col))

    def body_text(handler, path):
        # Resolve only literal local assignments on a straight-line path.
        # Each value retains its original literal span for source grounding.
        values = {}
        for index, statement in enumerate(handler.body):
            tick()
            if index == 0 and isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
                if isinstance(statement.value.value, str):
                    continue
            if isinstance(statement, ast.Assign) and all(isinstance(t, ast.Name) for t in statement.targets):
                value = statement.value
                if isinstance(value, ast.Name):
                    resolved = values.get(value.id)
                elif isinstance(value, ast.Constant) and isinstance(value.value, str):
                    resolved = value.value, location(path, value)
                else:
                    resolved = None
                for target in statement.targets:
                    values[target.id] = resolved
            elif isinstance(statement, ast.Return):
                value = statement.value
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    return value.value, location(path, value), location(path, statement)
                if isinstance(value, ast.Name) and values.get(value.id) is not None:
                    text, span = values[value.id]
                    return text, span, location(path, statement)
                problem("P_RESOURCE_DYNAMIC_BODY", location(path, statement))
                return None
            else:
                problem("P_RESOURCE_UNSUPPORTED_BODY", location(path, statement))
                return None
        problem("P_RESOURCE_NO_STATIC_RETURN", location(path, handler))
        return None

    try:
        for server in servers:
            for registration in server.get("registrations", []):
                tick()
                if registration["kind"] != "resource":
                    continue
                declaration = SourceSpan.from_dict(registration["declaration_span"])
                handler_span = SourceSpan.from_dict(registration["handler_span"])
                handler = node_at(handler_span)
                if not isinstance(handler, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    problem("P_RESOURCE_HANDLER_UNRESOLVED", handler_span)
                    continue
                fragments = []
                if metadata:
                    registered = node_at(declaration)
                    if not isinstance(registered, ast.Call):
                        problem("P_RESOURCE_REGISTRATION_UNRESOLVED", declaration)
                        continue
                    if any(kw.arg is None for kw in registered.keywords):
                        problem("P_RESOURCE_DYNAMIC_METADATA", declaration)
                        continue
                    explicit = next((kw.value for kw in registered.keywords if kw.arg == "description"), None)
                    docstring = None
                    if handler.body and isinstance(handler.body[0], ast.Expr):
                        value = handler.body[0].value
                        if isinstance(value, ast.Constant) and isinstance(value.value, str):
                            docstring = value
                    if explicit is None or isinstance(explicit, ast.Constant) and explicit.value in (None, ""):
                        description = docstring
                        path = handler_span.path
                    elif isinstance(explicit, ast.Constant) and isinstance(explicit.value, str):
                        description = explicit
                        path = declaration.path
                    else:
                        problem("P_RESOURCE_DYNAMIC_METADATA", declaration)
                        description = None
                    if description is not None:
                        fragments.append(("description", description.value, location(path, description), None))
                    for kw in registered.keywords:
                        if kw.arg == "name":
                            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                                fragments.append(("name", kw.value.value, location(declaration.path, kw.value), None))
                            else:
                                problem("P_RESOURCE_DYNAMIC_METADATA", location(declaration.path, kw.value))
                else:
                    content = body_text(handler, handler_span.path)
                    if content:
                        text, span, returned = content
                        fragments.append(("body", text, span, returned))
                for field_path, text, span, returned in fragments:
                    trace = [TraceStep("artifact", span, symbol=f"resource {field_path}")]
                    if returned:
                        trace.append(TraceStep("sink", returned, symbol="resource return"))
                    result.texts.append(SurfaceText(
                        server_id=server["server_id"], component=f"resource:{registration['name']}",
                        surface_kind="resource_metadata" if metadata else "resource_body",
                        text=text, content_span=span, declaration_span=declaration,
                        trace=trace, field_path=field_path,
                    ))
    except (TimeoutError, RecursionError):
        result.status = "partial"
        result.diagnostics.append({
            "code": "P_RESOURCE_EXTRACTION_BUDGET", "part": "metadata" if metadata else "body",
        })
    return result


def extract_python_resource_metadata(inventory, discovered_servers, *, deadline=None):
    """Extract literal registered names and descriptions/docstrings.

    URIs and MIME types identify resources but are not treated as natural-language
    instruction fields by this extractor. Runtime metadata mutations are unobserved.
    """
    return _extract_resources(inventory, discovered_servers, metadata=True, deadline=deadline)


def extract_python_resource_bodies(inventory, discovered_servers, *, deadline=None):
    """Extract direct string returns and local literal assignments.

    Branches, helper calls, external/file reads, formatted strings and structured
    content require later analysis and produce partial coverage. No target runs.
    """
    from .p_tool_result import extract_python_resource_results
    return extract_python_resource_results(inventory, discovered_servers, deadline=deadline)

