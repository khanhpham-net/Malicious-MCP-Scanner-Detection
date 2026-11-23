"""Text and source evidence extracted from MCP surfaces for P analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, get_args

from .models import SourceSpan, TraceStep


SurfaceKind = Literal[
    "tool_description",
    "input_schema_description",
    "resource_body",
    "resource_metadata",
    "prompt_message",
    "prompt_metadata",
    "tool_result",
]


@dataclass
class SurfaceText:
    """One original text fragment associated with an MCP component.

    content_span locates the original source literal or snapshot field. It may
    cover an entire string expression. Character-level mapping after decoding
    or normalization must be recorded separately by the extractor.

    An empty text is valid. It records an observed empty field without implying
    that extraction failed. The text is internal analysis input and may contain
    secrets, so report writers must redact it before emitting evidence.
    """

    server_id: str
    component: str
    surface_kind: SurfaceKind
    text: str
    content_span: SourceSpan
    declaration_span: SourceSpan | None = None
    trace: list[TraceStep] = field(default_factory=list)
    field_path: str | None = None
    limitations: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.server_id, str) or not self.server_id.strip():
            raise ValueError("SurfaceText.server_id must be a non-empty string")
        if not isinstance(self.component, str) or not self.component.strip():
            raise ValueError("SurfaceText.component must be a non-empty string")
        if self.surface_kind not in get_args(SurfaceKind):
            raise ValueError(f"Unsupported P surface kind: {self.surface_kind!r}")
        if not isinstance(self.text, str):
            raise TypeError("SurfaceText.text must be a string")


@dataclass
class SurfaceExtractionResult:
    """Extracted text and coverage diagnostics for this extraction step."""

    texts: list[SurfaceText] = field(default_factory=list)
    diagnostics: list[dict[str, object]] = field(default_factory=list)
    status: str = "complete"


def extract_python_tool_descriptions(
    inventory,
    discovered_servers: list[dict],
    *,
    deadline: float | None = None,
) -> SurfaceExtractionResult:
    """Read literal descriptions/docstrings for tools resolved by discovery.

    Only inventory-approved text is parsed. Registration and handler spans come
    from analyze_python_snapshot(). Dynamic descriptions and keyword unpacking
    are reported as partial. This step does not infer prompt-injection verdicts.
    SourceSpan columns use the Python AST convention (UTF-8 byte offsets plus 1).
    """
    import ast
    import time

    from .python_ast.index import location

    result = SurfaceExtractionResult()
    records = inventory.by_rel_path()
    nodes_by_path = {}

    def problem(code, span):
        result.status = "partial"
        result.diagnostics.append({"code": code, "location": span.to_dict()})

    def find_node(span):
        if span.path not in nodes_by_path:
            record = records.get(span.path)
            if record is None or record.text is None:
                problem("P_SOURCE_UNAVAILABLE", span)
                nodes_by_path[span.path] = {}
            else:
                try:
                    tree = ast.parse(record.text.removeprefix("\ufeff"), filename=span.path)
                    nodes = {}
                    for node in ast.walk(tree):
                        if isinstance(node, (ast.Call, ast.Attribute, ast.FunctionDef, ast.AsyncFunctionDef)):
                            # A Call and its Attribute share a start position.
                            # Preserve the outer Call, including its keywords.
                            nodes.setdefault((node.lineno, node.col_offset + 1), node)
                    nodes_by_path[span.path] = nodes
                except (SyntaxError, ValueError, RecursionError):
                    problem("P_SOURCE_PARSE_ERROR", span)
                    nodes_by_path[span.path] = {}
        return nodes_by_path[span.path].get((span.start_line, span.start_col))

    for server in discovered_servers:
        for registration in server.get("registrations", []):
            if registration["kind"] != "tool":
                continue
            declaration = SourceSpan.from_dict(registration["declaration_span"])
            if deadline is not None and time.monotonic() >= deadline:
                problem("P_EXTRACTION_DEADLINE", declaration)
                return result
            handler_span = SourceSpan.from_dict(registration["handler_span"])
            registered = find_node(declaration)
            handler = find_node(handler_span)
            if registered is None or not isinstance(handler, (ast.FunctionDef, ast.AsyncFunctionDef)):
                problem("P_REGISTRATION_UNRESOLVED", declaration)
                continue
            keywords = registered.keywords if isinstance(registered, ast.Call) else []
            if any(keyword.arg is None for keyword in keywords):
                problem("P_DESCRIPTION_KEYWORD_UNPACKING", declaration)
                continue
            explicit = next((keyword.value for keyword in keywords if keyword.arg == "description"), None)
            docstring = None
            if handler.body and isinstance(handler.body[0], ast.Expr):
                candidate = handler.body[0].value
                if isinstance(candidate, ast.Constant) and isinstance(candidate.value, str):
                    docstring = candidate
            # FastMCP's description-or-docstring fallback uses falsy literals.
            if explicit is None or isinstance(explicit, ast.Constant) and explicit.value in (None, ""):
                text_node = docstring
                text_path = handler_span.path
            elif isinstance(explicit, ast.Constant) and isinstance(explicit.value, str):
                text_node = explicit
                text_path = declaration.path
            else:
                problem("P_DYNAMIC_DESCRIPTION", declaration)
                continue
            if text_node is None:
                # A tool with no description is an observed empty surface.
                text = ""
                content_span = handler_span
            else:
                text = text_node.value
                content_span = location(text_path, text_node)
            result.texts.append(SurfaceText(
                server_id=server["server_id"],
                component=f"tool:{registration['name']}",
                surface_kind="tool_description",
                text=text,
                content_span=content_span,
                declaration_span=declaration,
                trace=[TraceStep("artifact", content_span, symbol="tool description")],
            ))
    return result

