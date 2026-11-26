"""Bounded return-value flow for MCP text extraction; never executes target code."""
from __future__ import annotations

import ast
from dataclasses import dataclass, field, replace
from copy import deepcopy

from .models import SourceSpan, TraceStep
from .p_static import StaticValueResolver, StaticText, StaticPath, UnresolvedValue
from .python_ast.index import dotted, location
from .p_domains import RaisedValue
from .p_flow_summary import FlowSummaryMixin
from .p_control_flow import ControlFlowMixin
from .p_expression_flow import ExpressionFlowMixin
from .p_structured_flow import StructuredFlowMixin
from .p_pure_api import PureApiMixin
from .p_snapshot_io import SnapshotIoMixin


@dataclass
class StaticMapping:
    entries: dict
    # Entries retain original key/value text evidence, including duplicate-key semantics.


@dataclass(frozen=True)
class PossibleValues:
    values: tuple
    uncertainty: UnresolvedValue | None


@dataclass
class StaticSet:
    values: list = field(default_factory=list)


@dataclass
class StaticInstance:
    path: str
    class_name: str
    fields: dict = field(default_factory=dict)


class OutputValueResolver(StructuredFlowMixin, PureApiMixin, ExpressionFlowMixin, ControlFlowMixin, FlowSummaryMixin, SnapshotIoMixin, StaticValueResolver):
    """Interpret a deliberately small subset of first-party return flows.

    Unknown runtime branches preserve possible text with partial coverage.
    Unsupported helper bodies remain unresolved; arbitrary globals, imports,
    constructors, filesystem calls, and external library code are never run.
    """
    MAX_CALL_DEPTH = 12

    def __init__(self, inventory, deadline):
        super().__init__(inventory, deadline)
        self.active_calls = []
        self.expression_caches = []
        self.awaited_calls = set()
        self.handler_envs = None
        self.copy_memo = {}
        self.pending_gaps = []
        self.pending_error_texts = []
        self.raise_frames = []
        self.snapshot_dirty = False

    def begin_handler(self):
        self.handler_envs = {}
        self.copy_memo = {}
        self.pending_gaps = []
        self.pending_error_texts = []
        self.raise_frames = []
        self.snapshot_dirty = False

    def module_environment(self, path):
        parsed = self.parse(SourceSpan(path))
        if not parsed:
            progress=self.parsing.get(path)
            return progress[2] if progress else {}
        if self.handler_envs is None:
            return parsed[2]
        if path not in self.handler_envs:
            self.handler_envs[path] = deepcopy(parsed[2], self.copy_memo)
        return self.handler_envs[path]

    def imported_value(self, module, node):
        value = super().imported_value(module, node)
        return deepcopy(value, self.copy_memo) if self.handler_envs is not None else value

    def instantiate(self, caller, call, target, cls, args=(), keywords=None):
        keywords = keywords or {}
        if cls.bases or cls.decorator_list or cls.keywords:
            return self.unknown("P_OUTPUT_UNMODELED_CONSTRUCTOR", caller, call)
        if any(not (isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Pass)) or
                isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str))
                for n in cls.body):
            return self.unknown("P_OUTPUT_DYNAMIC_CLASS_BODY", caller, call)
        methods = [n for n in reversed(cls.body) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        if any(n.decorator_list for n in methods):
            return self.unknown("P_OUTPUT_UNMODELED_CONSTRUCTOR", caller, call)
        if any(n.name.startswith("__") and n.name.endswith("__") and n.name!="__init__" for n in methods):
            return self.unknown("P_OUTPUT_UNMODELED_CONSTRUCTOR", caller, call)
        init = next((n for n in methods if n.name=="__init__"), None)
        instance = StaticInstance(target.path, cls.name)
        if init is None:
            return instance if not args and not keywords else self.unknown("P_OUTPUT_ARGUMENT_BINDING", caller, call)
        if init.decorator_list or isinstance(init, ast.AsyncFunctionDef):
            return self.unknown("P_OUTPUT_UNMODELED_CONSTRUCTOR", caller, call)
        # The same bounded interpreter handles arguments, aliases and branches;
        # custom descriptors, inheritance and metaclasses remain outside scope.
        value = self.invoke(caller, call, target, init, [instance, *args], dict(keywords))
        valid = value is None or isinstance(value, PossibleValues) and value.uncertainty is None and all(v is None for v in value.values)
        if not valid:
            return self.unknown("P_OUTPUT_UNMODELED_CONSTRUCTOR", caller, call)
        return instance


    def lookup(self, module, symbol):
        owner, _, member = symbol.rpartition(".")
        if not owner:
            owner, member = module.name, symbol
        if owner == module.name:
            target = module
        else:
            paths = self.module_paths.get(owner, [])
            parsed = self.parse(SourceSpan(paths[0])) if len(paths) == 1 else None
            target = parsed[0] if parsed else None
        if target:
            for node in reversed(target.tree.body):
                self.tick()
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == member:
                    return target, node
        return None

    def decorate(self, value, call_step):
        self.tick()
        if isinstance(value, RaisedValue):
            return replace(value, message=self.decorate(value.message, call_step))
        if isinstance(value, StaticText):
            origin = value.trace or (TraceStep("artifact", value.span, symbol="static output text"),)
            return replace(value, trace=origin + (call_step,))
        if isinstance(value, StaticMapping):
            value.entries = {key: (self.decorate(k, call_step), self.decorate(v, call_step))
                             for key, (k, v) in value.entries.items()}
            return value
        if isinstance(value, list):
            value[:] = [self.decorate(v, call_step) for v in value]
            return value
        if isinstance(value, tuple):
            return tuple(self.decorate(v, call_step) for v in value)
        from .p_domains import MappingDomain, SequenceDomain
        if isinstance(value, MappingDomain):
            value.key = self.decorate(value.key, call_step)
            value.value = self.decorate(value.value, call_step)
            return value
        if isinstance(value, SequenceDomain):
            element = self.decorate(value.element, call_step)
            from .p_loop_domains import LoopSequence
            if isinstance(value, LoopSequence):
                value.update_element(element)
                return value
            return replace(value, element=element)
        if isinstance(value, PossibleValues):
            return replace(value, values=tuple(self.decorate(v, call_step) for v in value.values))
        return value

    def invoke(self, caller, call, target, function, args, keywords):
        from itertools import product
        choices=[("arg",i,v) for i,v in enumerate(args) if isinstance(v,PossibleValues)]
        choices += [("kw",k,v) for k,v in keywords.items() if isinstance(v,PossibleValues)]
        if choices:
            size=1
            for _,_,choice in choices:size*=len(choice.values)
            if size>self.MAX_ALTERNATIVES:return self.unknown("P_OUTPUT_ALTERNATIVE_LIMIT",caller,call)
            original_env={f"a{i}":v for i,v in enumerate(args)}
            original_env.update({f"k{k}":v for k,v in keywords.items()})
            origin=self.outcome("next",original_env)
            values=[];states=[]
            for indices in product(*(range(len(v.values)) for _,_,v in choices)):
                self.activate(origin)
                local=self.fork_environment(original_env)
                local_args=[local[f"a{i}"] for i in range(len(args))]
                local_kw={k:local[f"k{k}"] for k in keywords}
                for (kind,key,_),index in zip(choices,indices):
                    if kind=="arg":local_args[key]=local_args[key].values[index]
                    else:local_kw[key]=local_kw[key].values[index]
                values.append(self.invoke(caller,call,target,function,local_args,local_kw))
                states.append(self.outcome("next",local))
            self.merge_branch_effects(caller,call,original_env,states)
            self.activate(origin)
            uncertainty=next((v.uncertainty for _,_,v in choices if v.uncertainty is not None),None)
            return PossibleValues(tuple(values),uncertainty)
        if isinstance(function, ast.AsyncFunctionDef) and id(call) not in self.awaited_calls:
            return self.unknown("P_OUTPUT_UNAWAITED_HELPER", caller, call)
        if not isinstance(function, ast.AsyncFunctionDef) and id(call) in self.awaited_calls:
            return self.unknown("P_OUTPUT_NONAWAITABLE_HELPER", caller, call)
        key = target.path, function.lineno
        if key in self.active_calls or len(self.active_calls) >= self.MAX_CALL_DEPTH:
            return self.unknown("P_OUTPUT_CALL_BOUNDARY", caller, call)
        # Decorators can replace or alter function behavior. Do not assume purity.
        if function.decorator_list:
            return self.unknown("P_OUTPUT_DECORATED_HELPER", caller, call)
        parsed = self.parse(SourceSpan(target.path))
        if not parsed:
            parsed=self.parsing.get(target.path)
            if parsed and function.lineno>self.parsing_cutoffs.get(target.path,0):
                return self.unknown("P_OUTPUT_UNRESOLVED_INITIALIZER",caller,call)
        if not parsed:
            return self.unknown("P_OUTPUT_HANDLER_UNAVAILABLE", caller, call)
        params = [*function.args.posonlyargs, *function.args.args]
        if len(args) > len(params) and function.args.vararg is None:
            return self.unknown("P_OUTPUT_ARGUMENT_BINDING", caller, call)
        names = {p.arg for p in [*params, *function.args.kwonlyargs]}
        if (set(keywords) - names and function.args.kwarg is None) or set(keywords) & {p.arg for p in function.args.posonlyargs}:
            return self.unknown("P_OUTPUT_ARGUMENT_BINDING", caller, call)
        env = dict(self.module_environment(target.path))
        defaults = dict(zip([p.arg for p in params[len(params)-len(function.args.defaults):]],
                            function.args.defaults))
        defaults.update({p.arg: d for p, d in zip(function.args.kwonlyargs, function.args.kw_defaults)
                         if d is not None})
        for param in [*params, *function.args.kwonlyargs]:
            if param.arg in defaults:
                env[param.arg] = self.value(target, defaults[param.arg], parsed[2])
            elif param.arg in keywords or param in params[:len(args)]:
                env[param.arg] = self.unknown("P_OUTPUT_ARGUMENT_BINDING", caller, call)
            else:
                return self.unknown("P_OUTPUT_ARGUMENT_BINDING", caller, call)
        for param, arg in zip(params, args):
            if param.arg in keywords:
                return self.unknown("P_OUTPUT_ARGUMENT_BINDING", caller, call)
            env[param.arg] = arg
        env.update({k:v for k,v in keywords.items() if k in names})
        if function.args.vararg:
            env[function.args.vararg.arg] = list(args[len(params):])
        if function.args.kwarg:
            env[function.args.kwarg.arg] = StaticMapping({k:(StaticText(k,location(caller.path,call)),v) for k,v in keywords.items() if k not in names})
        self.active_calls.append(key)
        try:
            value, _ = self.body(target, function.body, env)
        finally:
            self.active_calls.pop()
        def collect(member,seen=None):
            seen=set() if seen is None else seen
            if id(member) in seen:return
            seen.add(id(member))
            if isinstance(member,UnresolvedValue):
                if member.code not in {"P_OUTPUT_RUNTIME_PARAMETER","P_OUTPUT_DYNAMIC_VALUE","P_OUTPUT_DYNAMIC_SUBSCRIPT","P_OUTPUT_DYNAMIC_ATTRIBUTE","P_OUTPUT_DYNAMIC_CONDITION"}:
                    self.pending_gaps.append(member)
            elif isinstance(member,PossibleValues):
                if member.uncertainty is not None:collect(member.uncertainty,seen)
                for child in member.values:collect(child,seen)
            elif isinstance(member,StaticMapping):
                for _,child in member.entries.values():collect(child,seen)
            elif isinstance(member,(list,tuple)):
                for child in member:collect(child,seen)
            else:
                from .p_domains import MappingDomain, SequenceDomain
                if isinstance(member, MappingDomain):
                    collect(member.key, seen)
                    collect(member.value, seen)
                elif isinstance(member, SequenceDomain):
                    collect(member.element, seen)
        collect(value)
        return self.decorate(value, TraceStep("call", location(caller.path, call), symbol=function.name))

    def base_value(self, module, node, env):
        self.tick()
        if isinstance(node, ast.Await):
            if not isinstance(node.value, ast.Call):
                return self.unknown("P_OUTPUT_UNSUPPORTED_AWAIT", module, node)
            self.awaited_calls.add(id(node.value))
            try:
                return self.value(module, node.value, env)
            finally:
                self.awaited_calls.discard(id(node.value))
        if isinstance(node, ast.Dict):
            entries = {}
            for key_node, val_node in zip(node.keys, node.values):
                if key_node is None:
                    return self.unknown("P_OUTPUT_DYNAMIC_MAPPING", module, node)
                key = self.value(module, key_node, env)
                raw = self.literal(key)
                if not isinstance(raw, (str, int, float, bool, type(None))):
                    return self.unknown("P_OUTPUT_DYNAMIC_MAPPING", module, node)
                old_key = entries[raw][0] if raw in entries else key
                entries[raw] = old_key, self.value(module, val_node, env)
            return StaticMapping(entries)
        if isinstance(node, ast.Attribute):
            receiver = self.value(module, node.value, env)
            if isinstance(receiver, StaticInstance):
                return receiver.fields.get(node.attr, self.unknown("P_OUTPUT_DYNAMIC_ATTRIBUTE", module, node))
        if isinstance(node, ast.IfExp):
            test = self.value(module, node.test, env)
            if isinstance(test, bool):
                return self.value(module, node.body if test else node.orelse, env)
            return PossibleValues((self.value(module, node.body, env), self.value(module, node.orelse, env)),
                                  self.unknown("P_OUTPUT_RUNTIME_BRANCH", module, node.test))
        if isinstance(node, ast.Subscript):
            receiver = self.value(module, node.value, env)
            key = self.literal(self.value(module, node.slice, env))
            if isinstance(receiver, StaticMapping) and isinstance(key, (str, int, float, bool, type(None))):
                return receiver.entries.get(key, (None, self.unknown("P_OUTPUT_MISSING_KEY", module, node)))[1]
            if isinstance(receiver, list) and type(key) is int and -len(receiver) <= key < len(receiver):
                return receiver[key]
            return self.unknown("P_OUTPUT_DYNAMIC_SUBSCRIPT", module, node)
        if isinstance(node, ast.Call):
            if any(isinstance(arg, ast.Starred) for arg in node.args) or any(k.arg is None for k in node.keywords):
                return self.unknown("P_OUTPUT_DYNAMIC_CALL", module, node)
            symbol = dotted(node.func)
            head = symbol.partition(".")[0]
            name = module.qualify(symbol) if head not in env else ""
            # Only resolve known functions/classes from the approved snapshot.
            found = self.lookup(module, name) if name else None
            if found:
                target, definition = found
                args = [self.value(module, a, env) for a in node.args]
                kw = {k.arg: self.value(module, k.value, env) for k in node.keywords}
                if isinstance(definition, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return self.invoke(module, node, target, definition, args, kw)
                if id(node) in self.awaited_calls:
                    return self.unknown("P_OUTPUT_UNSUPPORTED_AWAIT", module, node)
                return self.instantiate(module, node, target, definition, args, kw)
            if id(node) in self.awaited_calls and not isinstance(node.func, ast.Attribute):
                return self.unknown("P_OUTPUT_UNSUPPORTED_AWAIT", module, node)
            if name == "set" and not node.args and not node.keywords:
                return StaticSet()
            if name == "dict":
                if len(node.args) > 1:
                    return self.unknown("P_OUTPUT_DYNAMIC_MAPPING", module, node)
                base = self.value(module, node.args[0], env) if node.args else StaticMapping({})
                if not isinstance(base, StaticMapping):
                    return self.unknown("P_OUTPUT_DYNAMIC_MAPPING", module, node)
                entries = dict(base.entries)
                for kw in node.keywords:
                    entries[kw.arg] = StaticText(kw.arg, location(module.path, kw.value)), self.value(module, kw.value, env)
                return StaticMapping(entries)
            if isinstance(node.func, ast.Attribute):
                receiver = self.value(module, node.func.value, env)
                method = node.func.attr
                if id(node) in self.awaited_calls and not isinstance(receiver, StaticInstance):
                    return self.unknown("P_OUTPUT_UNSUPPORTED_AWAIT", module, node)
                if isinstance(receiver, StaticText) and method in {"strip", "lstrip", "rstrip"} and len(node.args) <= 1 and not node.keywords:
                    chars = self.literal(self.value(module, node.args[0], env)) if node.args else None
                    if chars is None or isinstance(chars, str):
                        # Apply only a known str operation to extracted data, never target code.
                        text = {"strip": str.strip, "lstrip": str.lstrip, "rstrip": str.rstrip}[method](receiver.value, chars)
                        return replace(receiver, value=text)
                if isinstance(receiver, StaticMapping) and method == "copy" and not node.args and not node.keywords:
                    return StaticMapping(dict(receiver.entries))
                if isinstance(receiver, StaticMapping) and method == "get" and 1 <= len(node.args) <= 2 and not node.keywords:
                    key = self.literal(self.value(module, node.args[0], env))
                    if isinstance(key, (str, int, float, bool, type(None))):
                        default = self.value(module, node.args[1], env) if len(node.args) == 2 else None
                        return receiver.entries.get(key, (None, default))[1]
                if isinstance(receiver, StaticSet) and method == "add" and len(node.args) == 1 and not node.keywords:
                    receiver.values.append(self.value(module, node.args[0], env))
                    return None
                if isinstance(receiver, StaticInstance):
                    if method in receiver.fields:
                        return self.unknown("P_OUTPUT_DYNAMIC_DISPATCH", module, node)
                    parsed = self.parse(SourceSpan(receiver.path))
                    cls = next((n for n in parsed[0].tree.body if isinstance(n, ast.ClassDef)
                                and n.name == receiver.class_name), None) if parsed else None
                    fn = next((n for n in reversed(cls.body) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                               and n.name == method), None) if cls else None
                    if fn:
                        args = [receiver, *[self.value(module, a, env) for a in node.args]]
                        kw = {k.arg: self.value(module, k.value, env) for k in node.keywords}
                        return self.invoke(module, node, parsed[0], fn, args, kw)
        if isinstance(node, ast.Call) and id(node) in self.awaited_calls:
            return self.unknown("P_OUTPUT_UNSUPPORTED_AWAIT", module, node)
        value = StaticValueResolver.value(self, module, node, env)
        if isinstance(node, ast.Call) and isinstance(value, UnresolvedValue):
            # An unsupported call may mutate a passed container. Do not retain
            # its old text as if a later return still necessarily contained it.
            references = [*node.args, *[kw.value for kw in node.keywords]]
            if isinstance(node.func, ast.Attribute):
                references.append(node.func.value)
            for reference in references:
                if isinstance(reference, ast.Name):
                    receiver = env.get(reference.id)
                    if isinstance(receiver, StaticMapping):
                        receiver.entries.clear()
                        receiver.entries[None] = (None, self.unknown("P_OUTPUT_MUTATION_UNOBSERVED", module, node))
                    elif isinstance(receiver, list):
                        receiver[:] = [self.unknown("P_OUTPUT_MUTATION_UNOBSERVED", module, node)]
        return value

    def base_body(self, module, statements, env):
        for index, statement in enumerate(statements):
            self.tick()
            if index == 0 and isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
                if isinstance(statement.value.value, str):
                    continue
            if isinstance(statement, ast.Assign) and all(isinstance(t, ast.Name) for t in statement.targets):
                value = self.value(module, statement.value, env)
                for target in statement.targets:
                    env[target.id] = value
            elif isinstance(statement, (ast.Assign, ast.AnnAssign)) and isinstance(
                    statement.targets[0] if isinstance(statement, ast.Assign) and len(statement.targets) == 1
                    else statement.target if isinstance(statement, ast.AnnAssign) else None, ast.Attribute):
                target = statement.targets[0] if isinstance(statement, ast.Assign) else statement.target
                receiver = self.value(module, target.value, env)
                if not isinstance(receiver, StaticInstance):
                    return self.unknown("P_OUTPUT_UNSUPPORTED_BODY", module, statement), None
                if statement.value is not None:
                    receiver.fields[target.attr] = self.value(module, statement.value, env)
            elif isinstance(statement, ast.AugAssign):
                target = statement.target
                receiver = self.value(module, target.value, env) if isinstance(target, ast.Attribute) else None
                if isinstance(target, ast.Name):
                    old = env.get(target.id)
                elif isinstance(target, ast.Attribute) and isinstance(receiver, StaticInstance):
                    old = receiver.fields.get(target.attr)
                else:
                    return self.unknown("P_OUTPUT_UNSUPPORTED_BODY", module, statement), None
                right = self.value(module, statement.value, env)
                if type(old) is int and type(right) is int and isinstance(statement.op, (ast.Add, ast.Sub)):
                    updated = old + right if isinstance(statement.op, ast.Add) else old - right
                else:
                    updated = self.unknown("P_OUTPUT_DYNAMIC_VALUE", module, statement)
                if isinstance(target, ast.Name):
                    env[target.id] = updated
                else:
                    receiver.fields[target.attr] = updated
            elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
                call = statement.value
                receiver = self.value(module, call.func.value, env) if isinstance(call.func, ast.Attribute) else None
                if (not isinstance(receiver, StaticSet) or call.func.attr != "add" or len(call.args) != 1 or call.keywords):
                    return self.unknown("P_OUTPUT_UNSUPPORTED_BODY", module, statement), None
                self.value(module, call, env)
            elif isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Subscript):
                target = statement.targets[0]
                receiver = self.value(module, target.value, env)
                key = self.value(module, target.slice, env)
                raw = self.literal(key)
                if not isinstance(receiver, StaticMapping) or not isinstance(raw, (str, int, float, bool, type(None))):
                    return self.unknown("P_OUTPUT_UNSUPPORTED_BODY", module, statement), None
                original_key = receiver.entries[raw][0] if raw in receiver.entries else key
                receiver.entries[raw] = original_key, self.value(module, statement.value, env)
            elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                if statement.value is not None:
                    env[statement.target.id] = self.value(module, statement.value, env)
            elif isinstance(statement, ast.With) and len(statement.items) == 1:
                from .p_static import StaticFile
                item = statement.items[0]
                value = self.value(module, item.context_expr, env)
                if not isinstance(value, StaticFile) or not isinstance(item.optional_vars, ast.Name):
                    return self.unknown("P_OUTPUT_UNSUPPORTED_BODY", module, statement), None
                env[item.optional_vars.id] = value
                output, returned = self.body(module, statement.body, env)
                if returned is not None or not (isinstance(output, UnresolvedValue) and output.code == "P_OUTPUT_NO_STATIC_RETURN"):
                    return output, returned
                closed = self.unknown("P_OUTPUT_CLOSED_FILE", module, statement)
                visited = set()
                def close_aliases(member):
                    if member is value:
                        return closed
                    if id(member) in visited:
                        return member
                    visited.add(id(member))
                    if isinstance(member, StaticMapping):
                        member.entries = {k: (key, close_aliases(v)) for k, (key, v) in member.entries.items()}
                    elif isinstance(member, list):
                        member[:] = [close_aliases(v) for v in member]
                    elif isinstance(member, StaticInstance):
                        member.fields = {k: close_aliases(v) for k, v in member.fields.items()}
                    return member
                for key in env:
                    env[key] = close_aliases(env[key])
                return self.body(module, statements[index+1:], env)
            elif isinstance(statement, ast.Return):
                return (self.value(module, statement.value, env) if statement.value is not None else None,
                        location(module.path, statement))
            else:
                return self.unknown("P_OUTPUT_UNSUPPORTED_BODY", module, statement), None
        anchor = statements[-1] if statements else module.tree
        return self.unknown("P_OUTPUT_NO_STATIC_RETURN", module, anchor), None
