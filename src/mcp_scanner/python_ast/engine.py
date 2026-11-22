"""Bounded, context-sensitive walk of statically resolvable handler and bootstrap paths."""
from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import PurePosixPath
import posixpath
import re
from dataclasses import replace

from ..models import (AnalysisBoundary, Finding, RedactedEvidence, TraceStep,
                      make_finding_id, make_root_cause_group_id)
from . import rules
from .flow import Value, combine, joined
from .index import Module, Registration, dotted, literal, location

# rule id, category, kind, severity, title, CWE
RULES = {
    "contract_mutation": ("mcp-py-contract-mutation", "M", "semantic_indicator", "high",
                          "Declared tool contract conflicts with a persistent mutation", []),
    "command_injection": ("mcp-py-command-injection", "C", "vulnerability", "high",
                          "Handler input controls a shell command or executable", ["CWE-78"]),
    "worker_mutation": ("mcp-py-worker-mutation", "C", "semantic_indicator", "high",
                        "A launched Python worker changes state under a restrictive contract", []),
    "unannotated_worker_mutation": ("mcp-py-unannotated-worker-mutation", "C", "semantic_indicator", "medium",
                                   "A Python worker changes state without an explicit effect annotation", []),
    "local_disclosure": ("mcp-py-sensitive-local-output", "other", "semantic_indicator", "medium",
                         "Credential data reaches a log or handler response", ["CWE-200"]),
    "worker_capability": ("mcp-py-process-capability", "other", "capability_info", "info",
                          "Handler launches a process", []),
    "sensitive_network_flow": ("mcp-py-sensitive-network-flow", "S", "semantic_indicator", "high",
                               "Credential data reaches a network operation", ["CWE-200"]),
    "dynamic_code_execution": ("mcp-py-dynamic-code-execution", "dynamic_code_execution",
                               "semantic_indicator", "high", "Transformed data or handler input reaches a dynamic code sink", ["CWE-94"]),
}


REMEDIATION = {
    "M": "Remove the persistent operation or disclose the effect and correct the tool annotations.",
    "C": "Constrain executable selection, pass arguments separately, and declare worker effects.",
    "S": "Verify the destination and audience before sending credentials; minimize outbound fields.",
    "dynamic_code_execution": "Use a fixed parser or a trusted callable in place of executing transformed input.",
    "other": "Review the recorded data or process capability and restrict it to the declared purpose.",
}


def evidence_shape(symbol, node):
    if not isinstance(node, ast.Call):
        return symbol
    def shape(arg):
        if isinstance(arg, ast.Constant):
            return "<literal>"
        if isinstance(arg, ast.Call):
            return "<call>"
        return "<value>"
    args = [shape(arg) for arg in node.args[:6]]
    args.extend("<keyword>=" + shape(k.value) for k in node.keywords[:6])
    return symbol + "(" + ", ".join(args) + ")"


def quoted_argument(prefix, argument):
    # A fixed executable/argv prefix, followed by exactly one entire quoted shell word.
    return (isinstance(prefix, str) and bool(re.fullmatch(r"[A-Za-z0-9_./-]+(?: [A-Za-z0-9_./-]+)* ", prefix))
            and "quoted" in argument.marks and "input" not in argument.marks)


class Engine:
    def __init__(self, index, result, snapshot, tick):
        self.index = index
        self.result = result
        self.snapshot = snapshot
        self.ids = index.server_ids(snapshot)
        self.tick = tick
        self.globals: dict[str, dict[str, Value]] = {}
        self.closures = {}
        self.handler_globals = None
        self.copy_memo = {}
        self.findings = {}
        self.boundaries = set()

    def module_env(self, name):
        if self.handler_globals is None or name not in self.globals:
            return self.globals.get(name, {})
        if name not in self.handler_globals:
            self.handler_globals[name] = deepcopy(self.globals[name], self.copy_memo)
        return self.handler_globals[name]

    def boundary(self, kind, path, detail):
        key = kind, path, detail
        if key not in self.boundaries:
            self.result.analysis_boundaries.append(AnalysisBoundary(*key))
            self.boundaries.add(key)

    def run(self):
        for module in self.index.by_path.values():
            env = {"__file__": Value(constant=module.path), "__name__": Value(constant=module.name)}
            self.globals[module.name] = env
            Frame(self, module, env).block(module.tree.body)
            # A file can be an entrypoint as well as an imported module.
            main_env = {**env, "__name__": Value(constant="__main__")}
            main_frame = Frame(self, module, main_env)
            for stmt in module.tree.body:
                if isinstance(stmt, ast.If) and any(isinstance(n, ast.Name) and n.id == "__name__"
                                                    for n in ast.walk(stmt.test)):
                    main_frame.block([stmt])
        for reg in self.index.registrations:
            self.tick()
            module, fn = reg.handler_module, reg.function
            self.handler_globals = {}
            self.copy_memo = {}
            env = self.module_env(module.name).copy()
            captured = self.closures.get((module.name, fn.lineno, reg.scope_calls), {})
            env.update(deepcopy(captured, self.copy_memo))
            frame = Frame(self, module, env, reg=reg, stack=((module.name, fn.lineno),))
            params = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs, fn.args.vararg, fn.args.kwarg]
            for param in filter(None, params):
                if dotted(param.annotation).split(".")[-1] == "Context":
                    env[param.arg] = Value()
                else:
                    env[param.arg] = Value().mark("input", frame.step(param, "source", "handler argument"))
            frame.block(fn.body)


class Frame:
    def __init__(self, engine: Engine, module: Module, env, *, reg: Registration | None = None,
                 calls=(), stack=(), worker_effects=None):
        self.engine, self.mod, self.env = engine, module, env
        self.reg, self.calls, self.stack = reg, calls, stack
        self.worker_effects = worker_effects
        self.returns: list[Value] = []
        self.method_self = None

    def step(self, node, role, symbol):
        return TraceStep(role, location(self.mod.path, node), symbol=symbol)

    def emit(self, node, behavior, steps=(), *, symbol, detail="", extra=()):
        if self.worker_effects is not None:
            return
        reg = self.reg
        server = self.engine.ids[reg.instance] if reg else self.engine.snapshot
        component = f"{reg.kind}:{reg.name}" if reg else "unknown"
        declaration = location(reg.module.path, reg.declaration) if reg else None
        sink = location(self.mod.path, node)
        rid, category, kind, severity, title, cwes = RULES[behavior]
        fid = make_finding_id(server, rid, sink, declaration)
        if fid in self.engine.findings:
            return
        group = make_root_cause_group_id(server, component, behavior, sink)
        trace = []
        if reg and category == "M":
            trace.append(TraceStep("source", declaration, symbol="MCP contract"))
        for step in (*steps, *self.calls, self.step(node, "sink", symbol), *extra):
            if step not in trace:
                trace.append(step)
        limits = ["Network destination and credential audience are unverified."] if category == "S" else []
        possible = any(step.edge_kind == "possible" for step in trace)
        if possible:
            limits.append("Runtime selection among statically known call targets is unresolved.")
        confidence = 0.65 if possible else (0.85 if severity == "high" else 0.7)
        finding = Finding(fid, group, server, component, rid, "0.5", "python_ast", kind, category,
            severity, "traced_or_grounded", confidence,
            ("A4" if category == "M" else "A5") if reg else "A3", title,
            detail or title, REMEDIATION[category],
            cwe_ids=list(cwes), declaration_span=declaration, sink_span=sink, trace=trace,
            redacted_evidence=RedactedEvidence.from_raw(evidence_shape(symbol, node)), limitations=limits,
            review_status="pending" if severity in {"high", "critical"} or kind == "malicious_behavior" else "not_required")
        self.engine.findings[fid] = finding
        self.engine.result.findings.append(finding)

    def effect(self, node, name, effect):
        if self.worker_effects is not None:
            self.worker_effects.append((effect, self.step(node, "sink", name)))
        elif self.reg and (self.reg.readonly is True or (self.reg.destructive is False and effect != "write")):
            self.emit(node, "contract_mutation", symbol=name, detail=f"Observed persistent operation: {effect}.")

    def worker(self, node, name, argv):
        if self.worker_effects is not None:
            return
        target = None
        rest = ()
        if len(argv) > 1 and (argv[0].ref == "sys.executable" or
                              argv[0].constant in {"python", "python3", "python.exe"}):
            cursor = 1
            while cursor < len(argv) and argv[cursor].constant in {"-I", "-B", "-u", "-s", "-O", "-OO", "-E", "-S"}:
                cursor += 1
            argv = (argv[0], *argv[cursor:])
            script = argv[1].constant if len(argv) > 1 else None
            if script == "-m" and len(argv) > 2:
                target = self.engine.index.modules.get(argv[2].constant)
                rest = argv[3:]
            elif isinstance(script, str):
                paths = self.engine.index.by_path
                target = paths.get(script) or paths.get(posixpath.normpath(posixpath.join(posixpath.dirname(self.mod.path), script)))
                rest = argv[2:]
        if target:
            effects = []
            env = {"__file__": Value(constant=target.path), "__name__": Value(constant="__main__"),
                   "sys.argv": Value(ref="list", items=(Value(constant=target.path), *rest))}
            frame = Frame(self.engine, target, env, stack=self.stack, worker_effects=effects)
            frame.block(target.tree.body)
            for effect, step in effects:
                if self.reg.readonly is True or (self.reg.destructive is False and effect != "write"):
                    self.emit(node, "worker_mutation", symbol=name, extra=(step,))
                    return
            if effects and self.reg.readonly is None and self.reg.destructive is None:
                self.emit(node, "unannotated_worker_mutation", symbol=name, extra=(effects[0][1],))
                return
        else:
            self.engine.boundary("external_lib", self.mod.path, "Worker effects outside the resolved Python call graph.")
        self.emit(node, "worker_capability", symbol=name)

    def concatenate(self, first, second):
        if len(first.items) + len(second.items) > 512:
            self.engine.boundary("budget_exceeded", self.mod.path, "Sequence summary exceeds 512 elements.")
            self.engine.result.status = "partial"
            return combine(first, second)
        return replace(combine(first, second), ref=first.ref, items=first.items + second.items)

    def bind(self, target, value):
        if isinstance(target, ast.Name):
            self.env[target.id] = value
        elif isinstance(target, ast.Attribute):
            obj = self.value(target.value)
            if obj.ref in self.engine.index.classes:
                obj.fields[target.attr] = value
        elif isinstance(target, (ast.List, ast.Tuple)):
            for i, child in enumerate(target.elts):
                self.bind(child, value.items[i] if i < len(value.items) else Value())
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            key = literal(target.slice)
            old = self.env.get(target.value.id, Value())
            if isinstance(key, str):
                fields = {**old.fields, key: value}
                self.env[target.value.id] = replace(combine(*fields.values()), fields=fields)

    def branch_guard(self, test, truth):
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self.branch_guard(test.operand, not truth)
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.left, ast.Name):
            rhs = test.comparators[0]
            if not isinstance(rhs, (ast.Name, ast.Tuple, ast.List, ast.Set, ast.Constant)):
                return None
            other = self.value(rhs)
            positive = (isinstance(test.ops[0], ast.In) and truth) or (isinstance(test.ops[0], ast.NotIn) and not truth)
            if positive and other.items and all(isinstance(v.constant, (str, int)) for v in other.items):
                return test.left.id, "allowlisted"
            if truth and isinstance(test.ops[0], ast.Eq) and isinstance(other.constant, (str, int)):
                return test.left.id, "allowlisted"
        if truth and isinstance(test, ast.Call) and isinstance(test.func, ast.Attribute) and test.func.attr == "is_relative_to":
            if isinstance(test.func.value, ast.Name):
                return test.func.value.id, "contained_path"
        return None

    def branch(self, node):
        cond = self.value(node.test)
        initial = self.env
        continuing = []
        for truth, body in ((True, node.body), (False, node.orelse)):
            if isinstance(cond.constant, bool) and cond.constant != truth:
                continue
            self.env = initial.copy()
            guard = self.branch_guard(node.test, truth)
            if guard and guard[0] in self.env:
                key, kind = guard
                val = self.env[key]
                step = self.step(node.test, "guard", kind)
                # Containment is path evidence, not a shell sanitizer.
                self.env[key] = val.through(step) if kind == "contained_path" else val.guarded(kind, step)
            if self.block(body):
                continuing.append(self.env)
        self.env = initial
        if continuing:
            initial.clear()
            initial.update(continuing[0])
            for branch in continuing[1:]:
                for key in initial.keys() | branch.keys():
                    initial[key] = joined(initial.get(key, Value()), branch.get(key, Value()))
        return bool(continuing)

    def block(self, nodes):
        for node in nodes:
            self.engine.tick()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and self.calls:
                chain = tuple((s.span.path, s.span.start_line, s.span.start_col) for s in self.calls)
                self.engine.closures[(self.mod.name, node.lineno, chain)] = self.env
                self.env[node.name] = Value(ref=f"{self.mod.name}.@{node.lineno}.{node.name}")
                continue
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                aliases = {}
                self.mod.add_import(node, aliases)
                self.env.update({k: Value(ref=v) for k, v in aliases.items()})
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                v = self.value(node.value)
                for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                    self.bind(target, v)
            elif isinstance(node, ast.AugAssign):
                self.bind(node.target, combine(self.value(node.target), self.value(node.value)))
            elif isinstance(node, ast.Expr):
                self.value(node.value)
            elif isinstance(node, ast.Return):
                returned = self.value(node.value)
                if self.reg and len(self.stack) == 1 and "secret" in returned.marks:
                    self.emit(node, "local_disclosure", returned.marks["secret"], symbol="handler response")
                self.returns.append(returned)
                return False
            elif isinstance(node, ast.Raise):
                return False
            elif isinstance(node, ast.If):
                if not self.branch(node):
                    return False
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    v = self.value(item.context_expr)
                    if item.optional_vars:
                        self.bind(item.optional_vars, v)
                if not self.block(node.body):
                    return False
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                before = self.env.copy()
                if isinstance(node, ast.While):
                    self.value(node.test)
                else:
                    contents = self.value(node.iter)
                    self.bind(node.target, combine(*contents.items) if contents.items else contents)
                self.block(node.body)
                for key, val in before.items():
                    self.env[key] = joined(val, self.env.get(key, Value()))
                self.block(node.orelse)
            elif isinstance(node, ast.Try):
                before = self.env.copy()
                self.block(node.body)
                self.block(node.orelse)
                after = self.env.copy()
                for handler in node.handlers:
                    self.env = before.copy()
                    self.block(handler.body)
                    for key, val in self.env.items():
                        after[key] = joined(after.get(key, Value()), val)
                self.env.update(after)
                self.block(node.finalbody)
        return True

    def resolve(self, node):
        path = dotted(node)
        head, sep, tail = path.partition(".")
        if head in self.env:
            name = self.env[head].ref
            return name + sep + tail if name else ""
        qualified = self.mod.qualify(path)
        if head in self.mod.definitions or f"{self.mod.name}.{head}" in self.engine.index.classes:
            qualified = f"{self.mod.name}.{path}"
        return qualified

    def invoke(self, node, module, fn, args, kw, *, possible=False):
        key = module.name, fn.lineno
        if key in self.stack or len(self.stack) >= 14:
            self.engine.boundary("dynamic_dispatch", self.mod.path, "Recursive or deep call summary truncated.")
            self.engine.result.status = "partial"
            return Value()
        step = replace(self.step(node, "call", fn.name), edge_kind="possible" if possible else "definite")
        env = self.engine.module_env(module.name).copy()
        if self.worker_effects is not None:
            if "sys.argv" in self.env:
                env["sys.argv"] = self.env["sys.argv"]
            if module is self.mod and "__name__" in self.env:
                env["__name__"] = self.env["__name__"]
        params = [*fn.args.posonlyargs, *fn.args.args]
        env.update({p.arg: Value() for p in [*params, *fn.args.kwonlyargs]})
        defaults = [*zip(reversed(params), reversed(fn.args.defaults)), *zip(fn.args.kwonlyargs, fn.args.kw_defaults)]
        for param, default in defaults:
            if isinstance(default, ast.Constant):
                env[param.arg] = Value(constant=default.value)
        env.update({p.arg: a.through(step) for p, a in zip(params, args)})
        env.update({k: v.through(step) for k, v in kw.items() if k is not None})
        if fn.args.vararg:
            rest = tuple(args[len(params):])
            env[fn.args.vararg.arg] = replace(combine(*rest), items=rest)
        frame = Frame(self.engine, module, env, reg=self.reg, stack=(*self.stack, key),
                      calls=(*self.calls, step), worker_effects=self.worker_effects)
        if key in self.engine.index.method_owners and args:
            frame.method_self = args[0]
        frame.block(fn.body)
        if not frame.returns:
            return Value()
        ret = frame.returns[0]
        for other in frame.returns[1:]:
            ret = joined(ret, other)
        return ret.through(step)

    def first_party_call(self, node, callee, args, kw, *, possible=False):
        index = self.engine.index
        name = callee.ref
        if name == "super":
            anchor = index.method_owners.get(self.stack[-1]) if self.stack else None
            receiver = self.method_self
            if len(args) == 2:
                anchor, receiver = args[0].ref, args[1]
            if anchor and receiver:
                return Value(ref=receiver.ref, super_after=anchor, bound_to=receiver)
            return Value()
        if name in index.classes:
            instance = Value(ref=name)
            initializer = index.method(name, "__init__")
            if initializer:
                self.invoke(node, *initializer, [instance, *args], kw, possible=possible)
            else:
                annotations = []
                for _, cls in reversed(list(index.class_lineage(name))):
                    annotations.extend(s.target.id for s in cls.body if isinstance(s, ast.AnnAssign)
                                       and isinstance(s.target, ast.Name))
                instance.fields.update(zip(annotations, args))
                instance.fields.update(kw)
            instance.marks = combine(*instance.fields.values()).marks
            return instance
        if name in index.functions:
            return self.invoke(node, *index.functions[name], args, kw, possible=possible)
        if callee.bound_to:
            receiver = callee.bound_to
            method = index.method(receiver.ref, name.rpartition(".")[2], after=receiver.super_after)
            if method:
                decorators = {dotted(d).split(".")[-1] for d in method[1].decorator_list}
                bound = [] if "staticmethod" in decorators else [receiver.bound_to if receiver.super_after else receiver]
                return self.invoke(node, *method, [*bound, *args], kw, possible=possible)
        return None

    def value(self, node) -> Value:
        self.engine.tick()
        if node is None:
            return Value()
        if isinstance(node, ast.Constant):
            return Value(constant=node.value)
        if isinstance(node, ast.Name):
            val = self.env.get(node.id)
            if val is None:
                return Value(ref=self.resolve(node))
            if val.ref and val.ref != node.id and val.ref in self.env:
                return self.env[val.ref]
            base, _, member = val.ref.rpartition(".")
            return self.engine.module_env(base).get(member, val) if base else val
        if isinstance(node, ast.Attribute):
            recv = self.value(node.value)
            if node.attr in recv.fields and recv.ref in self.engine.index.classes:
                return recv.fields[node.attr]
            if node.attr == "parents" and recv.ref == "pathlib.Path" and isinstance(recv.constant, str):
                parents = tuple(Value(ref="pathlib.Path", constant=str(p)) for p in PurePosixPath(recv.constant).parents)
                return Value(ref="tuple", items=parents, marks=recv.marks)
            if node.attr == "parent" and recv.ref == "pathlib.Path":
                parent = posixpath.dirname(recv.constant) if isinstance(recv.constant, str) else None
                return replace(recv, constant=parent)
            ref = (recv.ref + "." + node.attr) if recv.ref else self.resolve(node)
            if recv.ref in self.engine.index.classes:
                return Value(ref=ref, bound_to=recv, marks=recv.marks)
            if ref in self.env:
                return self.env[ref]
            if ref == "os.environ":
                return replace(rules.env_value(self, node, None), ref=ref)
            module, _, key = ref.rpartition(".")
            namespace = self.engine.module_env(module)
            if key in namespace:
                return namespace[key]
            return Value(ref=ref, marks=recv.marks)
        if isinstance(node, ast.Call):
            recv = self.value(node.func.value) if isinstance(node.func, ast.Attribute) else Value()
            if isinstance(node.func, ast.Attribute):
                name = recv.ref + "." + node.func.attr if recv.ref else self.resolve(node.func)
                callee = Value(ref=name, bound_to=recv)
            else:
                callee = self.value(node.func)
                name = callee.ref
            args = []
            for arg in node.args:
                value = self.value(arg)
                if isinstance(arg, ast.Starred) and value.items:
                    args.extend(value.items)
                else:
                    args.append(value)
            kw = {}
            for keyword in node.keywords:
                value = self.value(keyword.value)
                if keyword.arg is None:
                    kw.update(value.fields)
                else:
                    kw[keyword.arg] = value
            if callee.choices:
                returns = []
                for choice in callee.choices:
                    resolved = self.first_party_call(node, choice, args, kw, possible=True)
                    if resolved is not None:
                        returns.append(resolved)
                if returns:
                    result = returns[0]
                    for alternative in returns[1:]:
                        result = joined(result, alternative)
                    return result
            if not name and isinstance(node.func, ast.Name) and node.func.id in self.env and self.reg:
                self.engine.boundary("dynamic_dispatch", self.mod.path, "Indirect callable could not be resolved.")
            resolved = self.first_party_call(node, callee, args, kw)
            if resolved is not None:
                return resolved
            if recv.ref in self.engine.index.classes:
                self.engine.boundary("dynamic_dispatch", self.mod.path, "Unresolved first-party method.")
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                owner = node.func.value.id
                if node.func.attr == "update" and owner in self.env and (recv.ref == "dict" or recv.fields):
                    fields = dict(recv.fields)
                    if args:
                        fields.update(args[0].fields)
                    fields.update({k: v for k, v in kw.items() if k})
                    self.env[owner] = replace(combine(*fields.values()), ref="dict", fields=fields)
                    return Value()
                if recv.ref == "list" and args and node.func.attr in {"append", "extend"}:
                    other = args[0]
                    if node.func.attr == "append":
                        other = replace(other, items=(other,))
                    self.env[owner] = self.concatenate(recv, other)
                    return Value()
            return rules.call(self, node, name, recv, args, kw)
        if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
            items = tuple(self.value(e) for e in node.elts)
            return replace(combine(*items), ref=type(node).__name__.lower(), items=items)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            outer = self.env
            self.env = outer.copy()
            try:
                for clause in node.generators:
                    sequence = self.value(clause.iter)
                    self.bind(clause.target, combine(*sequence.items) if sequence.items else sequence)
                    for condition in clause.ifs:
                        self.value(condition)
                if isinstance(node, ast.DictComp):
                    return combine(self.value(node.key), self.value(node.value))
                return self.value(node.elt)
            finally:
                self.env = outer
        if isinstance(node, ast.Dict):
            fields = {}
            values = []
            for k, v in zip(node.keys, node.values):
                val = self.value(v)
                values.append(val)
                if k is None:
                    fields.update(val.fields)
                elif isinstance(literal(k), str):
                    fields[literal(k)] = val
                else:
                    values.append(self.value(k))
            return replace(combine(*values), ref="dict", fields=fields)
        if isinstance(node, ast.Subscript):
            val = self.value(node.value)
            if isinstance(node.slice, ast.Slice) and val.ref in {"list", "tuple"}:
                bounds = (node.slice.lower, node.slice.upper, node.slice.step)
                indices = [self.value(b).constant if b is not None else None for b in bounds]
                if all(b is None or isinstance(i, int) or isinstance(b, ast.Constant) and b.value is None
                       for b, i in zip(bounds, indices)) and indices[2] != 0:
                    sliced = val.items[slice(*indices)]
                    return replace(combine(*sliced), ref=val.ref, items=sliced)
                return combine(val)
            key = self.value(node.slice).constant
            if val.ref == "os.environ":
                return rules.env_value(self, node, key)
            if isinstance(key, str) and val.fields:
                return val.fields.get(key, Value())
            if key is None and val.fields:
                options = tuple(v for v in val.fields.values() if v.ref in self.engine.index.functions or v.bound_to)
                if 0 < len(options) <= 8:
                    return replace(combine(val), choices=options)
                if len(options) > 8:
                    self.engine.boundary("dynamic_dispatch", self.mod.path, "Dispatch table exceeds the static candidate limit.")
            if isinstance(key, int) and -len(val.items) <= key < len(val.items):
                return val.items[key]
            return combine(val)
        if isinstance(node, ast.BinOp):
            a, b = self.value(node.left), self.value(node.right)
            value = combine(a, b)
            if isinstance(node.op, ast.Div) and a.ref == "pathlib.Path":
                const = posixpath.join(a.constant, b.constant) if isinstance(a.constant, str) and isinstance(b.constant, str) else None
                return replace(value, ref=a.ref, constant=const)
            if isinstance(node.op, ast.Add):
                if a.ref in {"list", "tuple"} and a.ref == b.ref:
                    return self.concatenate(a, b)
                value.posix_quoted_command = quoted_argument(a.constant, b)
            if isinstance(node.op, ast.Add) and isinstance(a.constant, str) and isinstance(b.constant, str):
                if len(a.constant) + len(b.constant) <= 4096:
                    value.constant = a.constant + b.constant
            return value
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left, right = self.value(node.left), self.value(node.comparators[0])
            if left.constant is not None and right.constant is not None and isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
                return Value(constant=(left.constant == right.constant) == isinstance(node.ops[0], ast.Eq))
            if left.constant is not None and right.ref in {"list", "tuple", "set"} and isinstance(node.ops[0], (ast.In, ast.NotIn)):
                if all(item.constant is not None for item in right.items):
                    member = any(left.constant == item.constant for item in right.items)
                    return Value(constant=member == isinstance(node.ops[0], ast.In))
            return Value()
        if isinstance(node, ast.IfExp):
            return joined(self.value(node.body), self.value(node.orelse))
        if isinstance(node, (ast.Await, ast.FormattedValue, ast.Starred)):
            return self.value(node.value)
        if isinstance(node, ast.JoinedStr):
            parts = [self.value(v) for v in node.values]
            result = combine(*parts)
            if len(parts) == 2 and isinstance(node.values[1], ast.FormattedValue):
                slot = node.values[1]
                result.posix_quoted_command = (slot.conversion == -1 and slot.format_spec is None
                                               and quoted_argument(parts[0].constant, parts[1]))
            return result
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
            constant = self.value(node.operand).constant
            if type(constant) is int:
                return Value(constant=-constant if isinstance(node.op, ast.USub) else constant)
            return Value()
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            val = self.value(node.operand)
            return Value(constant=not val.constant) if isinstance(val.constant, bool) else Value()
        if isinstance(node, ast.BoolOp):
            vals = [self.value(v) for v in node.values]
            if all(isinstance(v.constant, bool) for v in vals):
                return Value(constant=(all if isinstance(node.op, ast.And) else any)(v.constant for v in vals))
            return combine(*vals)
        return Value()
