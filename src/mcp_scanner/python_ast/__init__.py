"""Static MCP Python analysis over text approved by the source inventory."""
from __future__ import annotations

import ast
import time
import warnings
from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol

from ..models import AnalysisBoundary, Finding
from .engine import Engine
from .index import Index, Module, location, module_name


class PythonFile(Protocol):
    @property
    def rel_path(self) -> str: ...
    @property
    def text(self) -> str | None: ...


class PythonInventory(Protocol):
    def python_files(self) -> Iterable[PythonFile]: ...


@dataclass
class PythonAnalysisResult:
    discovered_servers: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    surfaces: dict[str, str] = field(default_factory=dict)
    analysis_boundaries: list[AnalysisBoundary] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    status: str = "complete"


class BudgetReached(Exception):
    pass


def analyze_python_snapshot(inventory: PythonInventory, *, server_id: str,
                            deadline: float | None = None) -> PythonAnalysisResult:
    result = PythonAnalysisResult()
    remaining = 1_000_000
    path = None

    def tick():
        nonlocal remaining
        remaining -= 1
        if remaining <= 0 or (deadline is not None and time.monotonic() >= deadline):
            raise BudgetReached

    modules = []
    try:
        records = sorted(inventory.python_files(), key=lambda rec: rec.rel_path)
        if not records:
            result.status = "skipped"
            return result
        for rec in records:
            path = rec.rel_path
            tick()
            if rec.text is None:
                result.status = "partial"
                result.diagnostics.append({"code": "PYTHON_TEXT_UNAVAILABLE", "path": path})
                continue
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", SyntaxWarning)
                    tree = ast.parse(rec.text.removeprefix("\ufeff"), filename=path)
            except (SyntaxError, ValueError, RecursionError) as exc:
                result.status = "partial"
                result.diagnostics.append({"code": "PYTHON_PARSE_ERROR", "path": path,
                                           "line": getattr(exc, "lineno", None),
                                           "message": "Python source could not be parsed."})
                continue
            modules.append(Module(path, module_name(path), tree))
        path = None
        index = Index(modules, tick)
        ids = index.server_ids(server_id)
        by_instance = {}
        for registration in index.registrations:
            by_instance.setdefault(registration.instance, []).append(registration)
        for instance, (mod, framework, name) in index.instances.items():
            tick()
            registrations = by_instance.get(instance, ())
            record = {"server_id": ids[instance], "name": name, "framework": framework,
                      "language": "python", "path": mod.path, "registrations": []}
            if instance in index.unverified_instances:
                record["discovery_status"] = "unverified_import"
                result.status = "partial"
                result.analysis_boundaries.append(AnalysisBoundary(
                    "external_lib", mod.path, "MCP constructor import is declared but its export is unverified."
                ))
            for kind in ("tool", "resource", "prompt"):
                record[kind + "s"] = sorted({r.name for r in registrations if r.kind == kind})
            for reg in registrations:
                record["registrations"].append({"kind": reg.kind, "name": reg.name,
                    "handler": reg.function.name, "declaration_span": location(reg.module.path, reg.declaration).to_dict(),
                    "handler_span": location(reg.handler_module.path, reg.function).to_dict(),
                    "readOnlyHint": reg.readonly, "destructiveHint": reg.destructive})
            result.discovered_servers.append(record)
        result.frameworks = sorted({framework for _, framework, _ in index.instances.values()})
        for filename, line in index.unresolved:
            result.status = "partial"
            result.analysis_boundaries.append(AnalysisBoundary("dynamic_dispatch", f"{filename}:{line}",
                                                              "MCP registration target is unresolved."))
        Engine(index, result, server_id, tick).run()
    except (BudgetReached, RecursionError):
        result.status = "partial"
        result.analysis_boundaries.append(AnalysisBoundary("budget_exceeded", path, "Python AST analysis budget reached."))
    surface_state = "scanned" if result.status == "complete" else "partial"
    result.surfaces = {key: surface_state for key in ("tools", "resources", "prompts", "bootstrap")}
    return result
