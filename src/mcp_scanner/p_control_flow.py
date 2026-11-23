"""Bounded statement-path exploration for P return text; no target execution."""
from __future__ import annotations

import ast
from copy import deepcopy

from .models import TraceStep
from .p_domains import FlowOutcome, NonTextValue, SequenceDomain, RuntimeInputText
from .p_static import StaticFile, StaticText, UnresolvedValue
from .p_snapshot_io import BinaryFile
from .python_ast.index import dotted, location

_NO_ITERABLE = object()


class ControlFlowMixin:
    MAX_PATHS = 32
    MAX_LOOP_ITEMS = 64

    def outcome(self, kind, env, value=None, span=None, exception=None):
        return FlowOutcome(kind, env, self.handler_envs, self.copy_memo, value, span, exception)

    def activate(self, state):
        self.handler_envs, self.copy_memo = state.globals, state.memo

    def fork_environment(self, env):
        forked, globals_, memo = deepcopy((env, self.handler_envs, self.copy_memo))
        self.handler_envs, self.copy_memo = globals_, memo
        return forked

    def truth(self, value):
        from .p_output_flow import StaticMapping, StaticSet
        if isinstance(value, StaticText):
            return bool(value.value)
        if value is None or type(value) in {bool, int, float}:
            return bool(value)
        if isinstance(value, (list, tuple)):
            return bool(value)
        if isinstance(value, StaticMapping):
            return bool(value.entries)
        if isinstance(value, StaticSet):
            return bool(value.values)
        return None

    def conditional_gap(self, value):
        from .p_output_flow import PossibleValues
        if isinstance(value,RuntimeInputText):
            return None
        if isinstance(value, UnresolvedValue):
            return value
        if isinstance(value, PossibleValues):
            return value.uncertainty
        return None

    def bind_target(self, module, target, value, env):
        from .p_output_flow import StaticInstance, StaticMapping
        if isinstance(target, ast.Name):
            env[target.id] = value
            return True
        if isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, (list, tuple)) and len(target.elts) == len(value):
                return all(self.bind_target(module, t, v, env) for t, v in zip(target.elts, value))
            if isinstance(value, SequenceDomain):
                return all(self.bind_target(module, t, value.element, env) for t in target.elts)
            return False
        if isinstance(target, ast.Attribute):
            receiver = self.value(module, target.value, env)
            if isinstance(receiver, StaticInstance):
                receiver.fields[target.attr] = value
                return True
        if isinstance(target, ast.Subscript):
            receiver = self.value(module, target.value, env)
            source_key = self.value(module, target.slice, env)
            key = self.literal(source_key)
            if isinstance(receiver, StaticMapping) and type(key) in {str, int, float, bool, type(None)}:
                original = receiver.entries[key][0] if key in receiver.entries else source_key
                receiver.entries[key] = original, value
                return True
            if isinstance(receiver, list) and type(key) is int and -len(receiver) <= key < len(receiver):
                receiver[key] = value
                return True
        return False

    def sequence_items(self, value):
        from .p_output_flow import StaticMapping, StaticSet
        if isinstance(value, (list, tuple)):
            return list(value)
        if isinstance(value, StaticText) and len(value.value) <= self.MAX_LOOP_ITEMS:
            return [StaticText(c,value.span,value.trace,value.limitations) for c in value.value]
        if isinstance(value, StaticMapping):
            return [key for key, _ in value.entries.values()]
        if isinstance(value, StaticSet):
            return list(value.values)
        return None

    def block_paths(self, module, statements, env):
        states = [self.outcome("next", env)]
        for statement in statements:
            self.tick()
            following = []
            for state in states:
                if state.kind != "next":
                    following.append(state)
                    continue
                self.activate(state)
                following.extend(self.statement_paths(module, statement, state.env))
                if len(following) > self.MAX_PATHS:
                    gap = self.unknown("P_OUTPUT_PATH_LIMIT", module, statement)
                    return [s for s in following if s.kind == "return"][:self.MAX_PATHS] + [
                        self.outcome("unknown", state.env, gap, location(module.path, statement))]
            states = following
        return states

    def branch_paths(self, module, statement, env):
        condition = self.value(module, statement.test, env)
        truth = self.truth(condition)
        if truth is not None:
            return self.block_paths(module, statement.body if truth else statement.orelse, env)
        origin = self.outcome("next", env)
        results = []
        for selected, statements in ((True, statement.body), (False, statement.orelse)):
            self.activate(origin)
            local = self.fork_environment(env)
            if isinstance(statement.test, ast.Name):
                old = local.get(statement.test.id)
                if isinstance(old, NonTextValue) and old.kind == "bool":
                    local[statement.test.id] = selected
            test=statement.test
            if isinstance(test,ast.Compare) and len(test.ops)==1 and isinstance(test.left,ast.Name) and isinstance(test.comparators[0],ast.Constant):
                from .p_output_flow import PossibleValues
                name=test.left.id;literal=test.comparators[0].value;old=local.get(name)
                equality=isinstance(test.ops[0],(ast.Eq,ast.Is))
                inequality=isinstance(test.ops[0],(ast.NotEq,ast.IsNot))
                if equality or inequality:
                    wanted=selected if equality else not selected
                    if isinstance(old,PossibleValues):
                        options=[v for v in old.values if (self.literal(v)==literal)==wanted]
                        if options:local[name]=options[0] if len(options)==1 else PossibleValues(tuple(options),old.uncertainty)
                    elif wanted and isinstance(old,RuntimeInputText) and isinstance(literal,str):
                        local[name]=StaticText(literal,location(module.path,test.comparators[0]))
            results.extend(self.block_paths(module, statements, local))
        gap = self.conditional_gap(condition)
        if gap is not None:
            results.append(self.outcome("unknown", env, gap, location(module.path, statement.test)))
        return results

    def for_paths(self, module, statement, env, iterable=_NO_ITERABLE):
        from .p_output_flow import PossibleValues
        iterable = self.value(module, statement.iter, env) if iterable is _NO_ITERABLE else iterable
        if isinstance(iterable, PossibleValues):
            origin = self.outcome("next", env)
            results = []
            for option in iterable.values:
                self.activate(origin)
                local = self.fork_environment(env)
                results.extend(self.for_paths(module, statement, local, option))
            if iterable.uncertainty is not None:
                results.append(self.outcome("unknown", env, iterable.uncertainty))
            return results
        items = self.sequence_items(iterable)
        if items is None or len(items) > self.MAX_LOOP_ITEMS:
            gap = self.unknown("P_OUTPUT_LOOP_BOUNDARY", module, statement)
            # Keep the gap. An unbounded loop is never certified by one iteration.
            return [self.outcome("unknown", env, gap, location(module.path, statement))]
        states = [self.outcome("next", env)]
        finished = []
        for item in items:
            next_states = []
            for state in states:
                self.activate(state)
                if not self.bind_target(module, statement.target, item, state.env):
                    finished.append(self.outcome("unknown", state.env,
                        self.unknown("P_OUTPUT_LOOP_BINDING", module, statement.target)))
                    continue
                for result in self.block_paths(module, statement.body, state.env):
                    if result.kind in {"next", "continue"}:
                        result.kind = "next"
                        next_states.append(result)
                    elif result.kind == "break":
                        result.kind = "next"
                        finished.append(result)
                    else:
                        finished.append(result)
            if len(next_states) + len(finished) > self.MAX_PATHS:
                finished.append(self.outcome("unknown", env,
                    self.unknown("P_OUTPUT_PATH_LIMIT", module, statement)))
                return finished
            states = next_states
        for state in states:
            self.activate(state)
            finished.extend(self.block_paths(module, statement.orelse, state.env))
        return finished

    def while_paths(self, module, statement, env):
        states = [self.outcome("next", env)]
        finished = []
        for _ in range(self.MAX_LOOP_ITEMS):
            continuing = []
            for state in states:
                self.activate(state)
                test = self.value(module, statement.test, state.env)
                truth = self.truth(test)
                if truth is False:
                    finished.extend(self.block_paths(module, statement.orelse, state.env))
                    continue
                if truth is None:
                    # Unknown iteration count requires a loop summary, not a clean verdict.
                    finished.append(self.outcome("unknown", state.env,
                        self.unknown("P_OUTPUT_LOOP_BOUNDARY", module, statement)))
                    continue
                for result in self.block_paths(module, statement.body, state.env):
                    if result.kind in {"next", "continue"}:
                        result.kind = "next"
                        continuing.append(result)
                    elif result.kind == "break":
                        result.kind = "next"
                        finished.append(result)
                    else:
                        finished.append(result)
            if not continuing:
                return finished
            if len(continuing) + len(finished) > self.MAX_PATHS:
                break
            states = continuing
        finished.append(self.outcome("unknown", env,
            self.unknown("P_OUTPUT_LOOP_BOUNDARY", module, statement)))
        return finished

    def close_file_aliases(self, env, value, gap):
        from .p_output_flow import StaticMapping, StaticInstance
        seen = set()
        def close(member):
            if member is value:
                return gap
            if id(member) in seen:
                return member
            seen.add(id(member))
            if isinstance(member, StaticMapping):
                member.entries = {k: (key, close(v)) for k, (key, v) in member.entries.items()}
            elif isinstance(member, list):
                member[:] = [close(v) for v in member]
            elif isinstance(member, StaticInstance):
                member.fields = {k: close(v) for k, v in member.fields.items()}
            return member
        for key in env:
            env[key] = close(env[key])

    def statement_paths(self, module, statement, env):
        self.tick()
        if isinstance(statement, ast.Assign):
            value=self.value(module,statement.value,env)
            if all(self.bind_target(module,t,value,env) for t in statement.targets):
                return [self.outcome("next",env)]
            return [self.outcome("unknown",env,self.unknown("P_OUTPUT_ASSIGNMENT_BINDING",module,statement))]
        if isinstance(statement, ast.Expr) and isinstance(statement.value,ast.Call):
            value=self.value(module,statement.value,env)
            if isinstance(value,UnresolvedValue):
                return [self.outcome("unknown",env,value,location(module.path,statement))]
            return [self.outcome("next",env)]
        if isinstance(statement, ast.If):
            return self.branch_paths(module, statement, env)
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            if isinstance(statement, ast.AsyncFor):
                return [self.outcome("unknown", env, self.unknown("P_OUTPUT_ASYNC_ITERATION", module, statement))]
            return self.for_paths(module, statement, env)
        if isinstance(statement, ast.While):
            return self.while_paths(module, statement, env)
        if isinstance(statement, ast.Return):
            value = self.value(module, statement.value, env) if statement.value is not None else None
            return [self.outcome("return", env, value, location(module.path, statement))]
        if isinstance(statement, ast.Raise):
            exc = statement.exc
            name = module.qualify(dotted(exc.func)) if isinstance(exc, ast.Call) else ""
            builtin_errors={"Exception","ValueError","TypeError","RuntimeError","KeyError","IndexError","LookupError","AssertionError","OSError","PermissionError","FileNotFoundError"}
            leaf=name.removeprefix("builtins.")
            if leaf not in builtin_errors or self.lookup(module,name) or not isinstance(exc,ast.Call) or exc.keywords or len(exc.args)>1:
                gap=self.unknown("P_OUTPUT_UNSUPPORTED_EXCEPTION",module,statement)
                return [self.outcome("unknown",env,gap,location(module.path,statement))]
            message = self.value(module, exc.args[0], env) if exc.args else None
            return [self.outcome("raise", env, message, location(module.path, statement), name)]
        if isinstance(statement, ast.Break):
            return [self.outcome("break", env)]
        if isinstance(statement, ast.Continue):
            return [self.outcome("continue", env)]
        if isinstance(statement, ast.Pass):
            return [self.outcome("next", env)]
        if isinstance(statement, ast.With):
            if len(statement.items) != 1:
                return [self.outcome("unknown", env, self.unknown("P_OUTPUT_UNSUPPORTED_BODY", module, statement))]
            item = statement.items[0]
            value = self.value(module, item.context_expr, env)
            if not isinstance(value, (StaticFile,BinaryFile)) or not isinstance(item.optional_vars, ast.Name):
                return [self.outcome("unknown", env, self.unknown("P_OUTPUT_UNSUPPORTED_BODY", module, statement))]
            env[item.optional_vars.id] = value
            results = self.block_paths(module, statement.body, env)
            for result in results:
                if result.kind == "next":
                    self.close_file_aliases(result.env, value, self.unknown("P_OUTPUT_CLOSED_FILE", module, statement))
            return results
        value, returned = self.base_body(module, [statement], env)
        if isinstance(value, UnresolvedValue) and value.code == "P_OUTPUT_NO_STATIC_RETURN":
            return [self.outcome("next", env)]
        if isinstance(value, UnresolvedValue):
            return [self.outcome("unknown", env, value, returned)]
        return [self.outcome("next", env)]

    def semantic_key(self,value,seen=None):
        from .p_output_flow import StaticMapping,StaticInstance,StaticSet,PossibleValues
        self.tick()
        seen=set() if seen is None else seen
        if isinstance(value,StaticText):return ("text",value.value)
        if value is None or type(value) in {str,int,float,bool}:return (type(value).__name__,value)
        if id(value) in seen:return ("cycle",type(value).__name__)
        seen=seen|{id(value)}
        if isinstance(value,StaticMapping):return ("map",tuple((k,self.semantic_key(v,seen)) for k,(_,v) in value.entries.items()))
        if isinstance(value,StaticInstance):return ("instance",value.path,value.class_name,tuple((k,self.semantic_key(v,seen)) for k,v in value.fields.items()))
        if isinstance(value,(list,tuple)):return ("list",tuple(self.semantic_key(v,seen) for v in value))
        if isinstance(value,StaticSet):return ("set",tuple(self.semantic_key(v,seen) for v in value.values))
        if isinstance(value,PossibleValues):return ("choices",tuple(self.semantic_key(v,seen) for v in value.values))
        if isinstance(value,UnresolvedValue):return ("unknown",value.code,value.span.path,value.span.start_line)
        if isinstance(value,NonTextValue):return ("numeric",value.kind)
        return ("domain",type(value).__name__)

    def merge_branch_effects(self,module,anchor,env,outcomes):
        from .p_output_flow import StaticMapping,StaticInstance,StaticSet,PossibleValues
        def merged(values):
            signatures=[self.semantic_key(v) for v in values]
            if all(k==signatures[0] for k in signatures):return values[0]
            if all(self.numeric(v) for v in values):return NonTextValue("number")
            return PossibleValues(tuple(values),None)
        seen=set()
        for name,original in env.items():
            self.tick()
            if id(original) in seen:continue
            seen.add(id(original))
            variants=[state.env.get(name,original) for state in outcomes]
            if not variants or all(self.semantic_key(v)==self.semantic_key(original) for v in variants):continue
            if isinstance(original,StaticMapping) and all(isinstance(v,StaticMapping) for v in variants):
                keys=list(dict.fromkeys(k for v in variants for k in v.entries))
                entries={}
                for key in keys:
                    source=next(v.entries[key][0] for v in variants if key in v.entries)
                    entries[key]=(source,merged([v.entries.get(key,(None,None))[1] for v in variants]))
                original.entries=entries
            elif isinstance(original,StaticInstance) and all(isinstance(v,StaticInstance) for v in variants):
                keys=list(dict.fromkeys(k for v in variants for k in v.fields))
                original.fields={k:merged([v.fields.get(k) for v in variants]) for k in keys}
            elif isinstance(original,list):
                original[:]=[self.unknown("P_OUTPUT_BRANCH_MUTATION",module,anchor)]
            elif isinstance(original,StaticSet):
                original.values[:]=[self.unknown("P_OUTPUT_BRANCH_MUTATION",module,anchor)]

    def body(self, module, statements, env):
        from .p_output_flow import PossibleValues
        origin=self.outcome("next",env)
        outcomes = self.block_paths(module, statements, env)
        if self.active_calls:
            for state in outcomes:
                if state.kind=="raise":
                    self.pending_error_texts.append(state.value)
                    self.pending_gaps.append(self.unknown("P_OUTPUT_HELPER_EXCEPTION",module,statements[-1]))
        if len(outcomes) == 1:
            state = outcomes[0]
            self.activate(state)
            if state.kind in {"return", "raise", "unknown"}:
                return state.value, state.span
            if state.kind == "next":
                return None, None
        values = []
        for outcome in outcomes:
            self.activate(outcome)
            value = outcome.value
            if outcome.kind in {"next", "return", "raise", "unknown"}:
                if outcome.span and outcome.kind in {"return", "raise"}:
                    step = TraceStep("sink", outcome.span, symbol="possible return path", edge_kind="possible")
                    value = self.decorate(value, step)
                values.append(value)
            else:
                values.append(self.unknown("P_OUTPUT_INVALID_CONTROL_FLOW", module, statements[-1]))
        self.merge_branch_effects(module,statements[-1],env,outcomes)
        self.activate(origin)
        return PossibleValues(tuple(values), None), None
