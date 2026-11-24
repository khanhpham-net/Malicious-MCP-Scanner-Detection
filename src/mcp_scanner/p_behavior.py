"""Offline, evidence-bound handler summaries and literal-call specialization.

This module reuses the Python abstract interpreter. It never imports a target
module, invokes a target callable, or treats an empty effect list as a safe
verdict. Its summaries describe only effects already supported by that engine.
"""
from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import dataclass, field
import time

from .models import Finding, SourceSpan, redact_secrets
from .python_ast import PythonAnalysisResult
from .python_ast.engine import Engine, Frame
from .python_ast.flow import Value, joined
from .python_ast.index import Index, Module, SERVER_TYPES, dotted, location, module_name
from .python_ast import rules


MAX_HANDLERS = 512
MAX_FINDINGS = 4096
MAX_SPECIALIZATION_STEPS = 100_000


def _redact(value):
    if isinstance(value, str):
        return redact_secrets(value)[0]
    if isinstance(value, dict):
        return {key: _redact(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return value


@dataclass(frozen=True)
class HandlerSummary:
    server_id: str
    component: str
    declaration_span: SourceSpan
    handler_span: SourceSpan
    findings: tuple[Finding, ...] = ()
    limitations: tuple[str, ...] = (
        "Effects are limited to the existing Python AST models; no effect is not a safety verdict.",
    )

    def to_dict(self):
        """Export grounded effects without raw source, arguments, or credentials."""
        return _redact({
            "server_id": self.server_id,
            "component": self.component,
            "declaration_span": self.declaration_span.to_dict(),
            "handler_span": self.handler_span.to_dict(),
            "effects": [
                {
                    "finding_id": finding.finding_id,
                    "rule_id": finding.rule_id,
                    "category": finding.category,
                    "kind": finding.kind,
                    "evidence_strength": finding.evidence_strength,
                    "sink_span": finding.sink_span.to_dict(),
                    "trace": [step.to_dict() for step in finding.trace],
                    "source_spans": [step.span.to_dict() for step in finding.trace if step.role == "source"],
                    "guard_spans": [step.span.to_dict() for step in finding.trace if step.role == "guard"],
                    "limitations": finding.limitations,
                }
                for finding in self.findings if finding.sink_span is not None
            ],
            "limitations": self.limitations,
        })


@dataclass
class BehaviorSummaryResult:
    summaries: list[HandlerSummary] = field(default_factory=list)
    diagnostics: list[dict] = field(default_factory=list)
    status: str = "complete"


@dataclass
class SpecializationResult:
    findings: list[Finding] = field(default_factory=list)
    diagnostics: list[dict] = field(default_factory=list)
    status: str = "complete"
    bound_arguments: tuple[str, ...] = ()
    limitations: list[str] = field(default_factory=lambda: [
        "Literal arguments were interpreted statically; no server or SDK validation was executed.",
        "A possible agent-mediated invocation is not evidence that an agent executed it.",
    ])

    def to_dict(self):
        return _redact({
            "status": self.status,
            "bound_arguments": list(self.bound_arguments),
            "findings": [finding.to_dict() for finding in self.findings],
            "diagnostics": self.diagnostics,
            "limitations": self.limitations,
        })


def summarize_handlers(inventory, discovered_servers, findings, *, deadline=None):
    """Bind supported effects to exact registered capabilities, never name alone."""
    result = BehaviorSummaryResult()
    records = {record.rel_path: record for record in inventory.python_files()}
    if len(findings) > MAX_FINDINGS:
        result.status = "partial"
        result.diagnostics.append({"code": "P_BEHAVIOR_FINDING_BUDGET"})
        findings = findings[:MAX_FINDINGS]
    for server in discovered_servers:
        for registration in server.get("registrations", ()):
            if deadline is not None and time.monotonic() >= deadline:
                result.status = "partial"
                result.diagnostics.append({"code": "P_BEHAVIOR_DEADLINE"})
                return result
            if len(result.summaries) >= MAX_HANDLERS:
                result.status = "partial"
                result.diagnostics.append({"code": "P_BEHAVIOR_HANDLER_BUDGET"})
                return result
            try:
                declaration = SourceSpan.from_dict(registration["declaration_span"])
                handler = SourceSpan.from_dict(registration["handler_span"])
                server_id = server["server_id"]
                component = f"{registration['kind']}:{registration['name']}"
                if registration["kind"] not in {"tool", "resource", "prompt"}:
                    raise ValueError("Unsupported capability kind")
                if not isinstance(server_id, str) or not server_id:
                    raise ValueError("Missing server identity")
                if any(span.path not in records or records[span.path].text is None
                       for span in (declaration, handler)):
                    raise ValueError("Unapproved or unavailable handler source")
                if handler.start_line is None or declaration.start_line is None:
                    raise ValueError("Unlocated capability")
            except (KeyError, TypeError, ValueError):
                result.status = "partial"
                result.diagnostics.append({"code": "P_BEHAVIOR_UNRESOLVED_HANDLER"})
                continue
            effects = tuple(finding for finding in findings
                            if finding.server_id == server_id
                            and finding.component == component
                            and finding.declaration_span == declaration
                            and finding.sink_span is not None
                            and finding.evidence_strength == "traced_or_grounded")
            limitations = HandlerSummary.__dataclass_fields__["limitations"].default
            if server.get("discovery_status"):
                result.status = "partial"
                result.diagnostics.append({"code": "P_BEHAVIOR_UNVERIFIED_DISCOVERY",
                                           "server_id": server_id, "component": component})
                limitations += ("Capability discovery is unverified.",)
            result.summaries.append(HandlerSummary(server_id, component, declaration, handler,
                                                   effects, limitations))
    return result


class _BudgetReached(Exception):
    pass


class _SpecializedFrame(Frame):
    """Keep unresolved predicates/effects explicit without changing the core engine."""

    def branch(self, node):
        condition = self.value(node.test)
        if not isinstance(condition.constant, bool):
            self.incomplete("dynamic_dispatch", "A specialized handler predicate remains unresolved.")
        initial = self.env
        continuing = []
        for truth, body in ((True, node.body), (False, node.orelse)):
            if isinstance(condition.constant, bool) and condition.constant != truth:
                continue
            self.env = initial.copy()
            self.apply_guard(node.test, truth)
            if self.block(body):
                continuing.append(self.env)
        return self.merge_paths(initial, continuing)

    def match(self, node):
        if any(isinstance(item, (ast.Call, ast.NamedExpr, ast.Await)) for item in ast.walk(node.subject)):
            self.incomplete("dynamic_dispatch", "An effectful match subject is not proven in specialization.")
        if self.value(node.subject).constant is None:
            self.incomplete("dynamic_dispatch", "A specialized match subject remains unresolved.")
        return super().match(node)

    def loop(self, node):
        self.incomplete("dynamic_dispatch", "Loop feasibility is not proven for literal-call specialization.")
        return super().loop(node)

    def _block(self, nodes):
        uncertain_control = (ast.Try, ast.With, ast.AsyncWith, ast.Assert, ast.Raise)
        if hasattr(ast, "TryStar"):
            uncertain_control += (ast.TryStar,)
        if any(isinstance(node, uncertain_control) for node in nodes):
            self.incomplete("dynamic_dispatch", "Exception, assertion, or context-manager control flow is not proven in specialization.")
        return super()._block(nodes)

    def value(self, node):
        if isinstance(node, ast.IfExp) and not isinstance(self.value(node.test).constant, bool):
            self.incomplete("dynamic_dispatch", "A specialized conditional expression remains unresolved.")
        if isinstance(node, ast.IfExp) and any(isinstance(item, (ast.Call, ast.NamedExpr, ast.Await))
                                               for item in ast.walk(node.test)):
            self.incomplete("dynamic_dispatch", "An effectful conditional expression is not proven in specialization.")
        if isinstance(node, ast.Call):
            if any(isinstance(item, (ast.Call, ast.NamedExpr, ast.Await)) for item in ast.walk(node.func)):
                self.incomplete("dynamic_dispatch", "An effectful callable receiver is not proven in specialization.")
            callee = super().value(node.func)
            name = callee.ref
            network_call = (name.rpartition(".")[0] in {
                "requests", "requests.Session", "requests.session", "httpx", "httpx.Client",
                "httpx.AsyncClient", "aiohttp", "aiohttp.ClientSession"
            } and name.rpartition(".")[2] in {
                "request", "get", "post", "put", "patch", "delete", "head", "options"
            })
            known = (name in self.engine.index.functions or name in self.engine.index.classes
                     or bool(callee.bound_to and callee.bound_to.ref in self.engine.index.classes)
                     or name in rules.PRESERVE | rules.CONSTRUCTORS | rules.DECODE | rules.PROCESS
                     or name in SERVER_TYPES
                     or name in {"mcp.types.ToolAnnotations", "int", "float", "bool", "len", "abs", "min", "max",
                                 "os.getenv", "os.environ.get", "os.environ.__getitem__", "open", "shlex.quote"}
                     or network_call
                     or name in {"urllib.request.Request", "urllib.request.urlopen",
                                 "urllib.request.Request.add_header", "io.file.read", "io.file.readline",
                                 "io.file.readlines", "io.file.write", "io.file.writelines", "io.file.truncate",
                                 "pathlib.Path.read_text", "pathlib.Path.read_bytes", "pathlib.Path.write_text",
                                 "pathlib.Path.write_bytes", "pathlib.Path.open", "pathlib.Path.unlink",
                                 "pathlib.Path.rmdir", "pathlib.Path.mkdir", "pathlib.Path.touch"})
            registered_site = (self.mod.path, node.lineno, node.col_offset) in getattr(
                self.engine, "approved_registration_sites", set())
            startup = (isinstance(node.func, ast.Attribute) and node.func.attr == "run"
                       and self.engine.index.resolve(self.mod, dotted(node.func.value)) in self.engine.index.instances)
            if not known and not (self.reg is None and (registered_site or startup)):
                self.incomplete("external_lib", "An opaque call may affect a literal-call specialization.")
            if any(isinstance(arg, ast.Starred) for arg in node.args) or any(kw.arg is None for kw in node.keywords):
                self.incomplete("dynamic_dispatch", "Unpacked call arguments are not proven in specialization.")
        return super().value(node)

    def evaluate_function(self, module, fn, args, kw, step):
        # Same binding semantics as Frame.evaluate_function, with this stricter
        # frame propagated across first-party helper calls as well.
        key = module.name, fn.lineno
        params = [*fn.args.posonlyargs, *fn.args.args]
        positional_names = [param.arg for param in params]
        kw_names = {param.arg for param in fn.args.kwonlyargs}
        required_positional = positional_names[:len(positional_names)-len(fn.args.defaults)]
        assigned_positionally = set(positional_names[:len(args)])
        invalid = (bool(fn.decorator_list) or fn.args.vararg is not None or fn.args.kwarg is not None
                   or len(args) > len(params)
                   or bool(set(kw) - set(positional_names) - kw_names)
                   or bool(assigned_positionally & set(kw))
                   or bool({param.arg for param in fn.args.posonlyargs} & set(kw))
                   or bool(set(required_positional) - assigned_positionally - set(kw))
                   or any(default is None and param.arg not in kw
                          for param, default in zip(fn.args.kwonlyargs, fn.args.kw_defaults))
                   or any(not isinstance(default, ast.Constant) for default in fn.args.defaults)
                   or any(default is not None and not isinstance(default, ast.Constant)
                          for default in fn.args.kw_defaults))
        if invalid:
            self.incomplete("dynamic_dispatch", "Helper argument binding or default evaluation is not proven in specialization.")
            return Value()
        env = self.engine.module_env(module.name).copy()
        if self.worker_effects is not None:
            if "sys.argv" in self.env:
                env["sys.argv"] = self.env["sys.argv"]
            if module is self.mod and "__name__" in self.env:
                env["__name__"] = self.env["__name__"]
        env.update({p.arg: Value() for p in [*params, *fn.args.kwonlyargs]})
        defaults = [*zip(reversed(params), reversed(fn.args.defaults)),
                    *zip(fn.args.kwonlyargs, fn.args.kw_defaults)]
        for param, default in defaults:
            if isinstance(default, ast.Constant):
                env[param.arg] = Value(constant=default.value)
        env.update({p.arg: a.through(step) for p, a in zip(params, args)})
        env.update({k: v.through(step) for k, v in kw.items() if k is not None})
        if fn.args.vararg:
            from dataclasses import replace
            from .python_ast.flow import combine
            rest = tuple(args[len(params):])
            env[fn.args.vararg.arg] = replace(combine(*rest), items=rest)
        frame = _SpecializedFrame(self.engine, module, env, reg=self.reg, stack=(*self.stack, key),
                                  calls=(*self.calls, step), worker_effects=self.worker_effects,
                                  control_steps=self.control_steps)
        if key in self.engine.index.method_owners and args:
            frame.method_self = args[0]
        if frame.block(fn.body):
            frame.returns.append(Value())
        if not frame.returns:
            return None if frame.deferred else Value()
        returned = frame.returns[0]
        for other in frame.returns[1:]:
            returned = joined(returned, other)
        return returned


def specialize_handler(inventory, summary, arguments, *, deadline=None):
    """Reinterpret one exact handler with bound scalar literals.

    No generated Python is executed. Unsupported bindings and opaque effects
    stay partial; callers must not read partial/no-findings as proof of safety.
    """
    result = SpecializationResult()
    remaining = MAX_SPECIALIZATION_STEPS

    def tick():
        nonlocal remaining
        remaining -= 1
        if remaining <= 0 or (deadline is not None and time.monotonic() >= deadline):
            raise _BudgetReached

    def problem(code):
        result.status = "partial"
        result.diagnostics.append({"code": code, "server_id": summary.server_id,
                                   "component": summary.component})

    try:
        tick()
        if not isinstance(arguments, dict) or len(arguments) > 32:
            problem("P_BEHAVIOR_ARGUMENTS_UNSUPPORTED")
            return result
        if any(not isinstance(name, str) or type(value) not in {str, int, float, bool, type(None)}
               or isinstance(value, str) and len(value) > 4096
               for name, value in arguments.items()):
            problem("P_BEHAVIOR_ARGUMENTS_UNSUPPORTED")
            return result
        modules = []
        for record in sorted(inventory.python_files(), key=lambda item: item.rel_path):
            tick()
            if record.text is None:
                problem("P_BEHAVIOR_SOURCE_UNAVAILABLE")
                continue
            tree = ast.parse(record.text.removeprefix("\ufeff"), filename=record.rel_path)
            modules.append(Module(record.rel_path, module_name(record.rel_path), tree))
        index = Index(modules, tick)
        matches = [registration for registration in index.registrations
                   if f"{registration.kind}:{registration.name}" == summary.component
                   and location(registration.module.path, registration.declaration) == summary.declaration_span
                   and location(registration.handler_module.path, registration.function) == summary.handler_span]
        if len(matches) != 1 or "Capability discovery is unverified." in summary.limitations:
            problem("P_BEHAVIOR_REGISTRATION_UNRESOLVED")
            return result
        registration, = matches
        function = registration.function
        if any(location(registration.handler_module.path, decorator) != summary.declaration_span
               for decorator in function.decorator_list):
            problem("P_BEHAVIOR_DECORATOR_UNMODELED")
            return result
        params = [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]
        if function.args.vararg or function.args.kwarg or function.args.posonlyargs:
            problem("P_BEHAVIOR_SIGNATURE_UNSUPPORTED")
            return result
        if (any(not isinstance(default, ast.Constant) for default in function.args.defaults)
                or any(default is not None and not isinstance(default, ast.Constant)
                       for default in function.args.kw_defaults)):
            # Field()/factory defaults can carry SDK constraints even when
            # the proposed invocation supplies an explicit argument value.
            problem("P_BEHAVIOR_VALIDATION_UNMODELED")
            return result
        allowed = {param.arg for param in params}
        if set(arguments) - allowed:
            problem("P_BEHAVIOR_UNKNOWN_ARGUMENT")
            return result
        bindings = {}
        for param in params:
            tick()
            if param.arg in arguments:
                value = arguments[param.arg]
            else:
                # An omitted prose binding does not prove that the agent will
                # omit that argument when it constructs the actual MCP call.
                problem("P_BEHAVIOR_ARGUMENT_UNBOUND")
                return result
            annotation = dotted(param.annotation)
            if annotation in {"str", "int", "bool", "float"}:
                expected = {"str": str, "int": int, "bool": bool, "float": float}[annotation]
                if type(value) is not expected and not (expected is float and type(value) is int):
                    problem("P_BEHAVIOR_ARGUMENT_TYPE_UNSUPPORTED")
                    return result
            elif param.annotation is not None:
                problem("P_BEHAVIOR_VALIDATION_UNMODELED")
                return result
            bindings[param.arg] = Value(constant=value, text_kind="str" if isinstance(value, str) else "")
        result.bound_arguments = tuple(sorted(arguments))
        interpreted = PythonAnalysisResult()
        engine = Engine(index, interpreted, summary.server_id, tick)
        # Module initialization is interpreted statically. Bootstrap findings
        # are not evidence about this particular proposed handler invocation.
        engine.approved_registration_sites = {
            (item.module.path, item.declaration.lineno, item.declaration.col_offset)
            for item in index.registrations
        }
        index.registrations = []
        for module in index.by_path.values():
            env = {"__file__": Value(constant=module.path), "__name__": Value(constant=module.name)}
            engine.globals[module.name] = env
            _SpecializedFrame(engine, module, env).block(module.tree.body)
            main_env = {**env, "__name__": Value(constant="__main__")}
            main_frame = _SpecializedFrame(engine, module, main_env)
            for statement in module.tree.body:
                if isinstance(statement, ast.If) and any(isinstance(node, ast.Name) and node.id == "__name__"
                                                        for node in ast.walk(statement.test)):
                    main_frame.block([statement])
        engine.findings.clear()
        interpreted.findings.clear()
        engine.ids[registration.instance] = summary.server_id
        engine.handler_globals = {}
        engine.copy_memo = {}
        module = registration.handler_module
        env = engine.module_env(module.name).copy()
        captured = engine.closures.get((module.name, function.lineno, registration.scope_calls), {})
        env.update(deepcopy(captured, engine.copy_memo))
        env.update(bindings)
        frame = _SpecializedFrame(engine, module, env, reg=registration, stack=((module.name, function.lineno),))
        frame.block(function.body)
        result.findings = interpreted.findings
        if interpreted.status != "complete" or interpreted.analysis_boundaries or interpreted.diagnostics:
            problem("P_BEHAVIOR_SPECIALIZATION_INCOMPLETE")
        result.limitations.extend(boundary.detail for boundary in interpreted.analysis_boundaries)
    except _BudgetReached:
        problem("P_BEHAVIOR_SPECIALIZATION_BUDGET")
    except (SyntaxError, ValueError, RecursionError, TypeError, KeyError, AttributeError):
        problem("P_BEHAVIOR_SPECIALIZATION_UNSUPPORTED")
    return result
