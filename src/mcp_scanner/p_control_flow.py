"""Bounded statement-path exploration for P return text; no target execution."""
from __future__ import annotations

import ast
from copy import deepcopy

from .models import TraceStep
from .p_domains import FlowOutcome, NonTextValue, SequenceDomain, MappingDomain, RuntimeInputText, BoundedInputText, RaisedValue, StaticRaised, CaughtException
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
        if isinstance(value, (MappingDomain, SequenceDomain)):
            return False if value.max_length == 0 else True if value.min_length > 0 else None
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
                if value.min_length != len(target.elts) or value.max_length != len(target.elts):
                    return False
                return all(self.bind_target(module, t, value.element, env) for t in target.elts)
            return False
        if isinstance(target, ast.Attribute):
            receiver = self.value(module, target.value, env)
            if isinstance(receiver, StaticInstance):
                if getattr(receiver, "p_loop_readonly", False):
                    return False
                if getattr(receiver, "p_frozen", False):
                    return False
                receiver.fields[target.attr] = value
                return True
        if isinstance(target, ast.Subscript):
            receiver = self.value(module, target.value, env)
            source_key = self.value(module, target.slice, env)
            key = self.literal(source_key)
            if getattr(receiver, "p_loop_readonly", False):
                return False
            loop_assignment = getattr(self, "loop_bind_subscript", None)
            if loop_assignment is not None:
                result = loop_assignment(module, target, receiver, source_key, value)
                if result is not NotImplemented:
                    return result
            if isinstance(receiver, MappingDomain):
                return self.structured_bind_subscript(module, target, receiver, source_key, value)
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
                raised = []
                self.raise_frames.append(raised)
                try:
                    following.extend(self.statement_paths(module, statement, state.env))
                except StaticRaised as transfer:
                    value = transfer.value
                    following.append(self.outcome("raise", state.env, value.message,
                                                  value.span, value.exception))
                finally:
                    self.raise_frames.pop()
                following.extend(raised)
                if len(following) > self.MAX_PATHS:
                    gap = self.unknown("P_OUTPUT_PATH_LIMIT", module, statement)
                    return [s for s in following if s.kind == "return"][:self.MAX_PATHS] + [
                        self.outcome("unknown", state.env, gap, location(module.path, statement))]
            states = following
        return states

    def refine_none_guard(self, test, selected, env):
        """Refine identity guards without borrowing equality or truth coercion.

        True conjunctions and false disjunctions imply every operand. Other
        boolean paths do not, so no fact is inferred from those expressions.
        Unknown domains/uncertainty are retained instead of mistaken for None.
        """
        from .p_output_flow import PossibleValues
        self.tick()
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self.refine_none_guard(test.operand, not selected, env)
        if isinstance(test, ast.BoolOp):
            # A later operand may change state. Do not reuse an earlier guard
            # as a fact about the environment after an effectful expression.
            if any(isinstance(node, (ast.Call, ast.NamedExpr, ast.Await, ast.Yield, ast.YieldFrom))
                   for node in ast.walk(test)):
                return True
            implied = isinstance(test.op, ast.And) and selected or isinstance(test.op, ast.Or) and not selected
            return not implied or all(self.refine_none_guard(term, selected, env) for term in test.values)
        if not (isinstance(test, ast.Compare) and len(test.ops) == 1
                and isinstance(test.ops[0], (ast.Is, ast.IsNot))):
            return True
        left, right = test.left, test.comparators[0]
        if isinstance(left, ast.Constant) and left.value is None:
            left, right = right, left
        if not (isinstance(left, ast.Name) and isinstance(right, ast.Constant) and right.value is None
                and left.id in env):
            return True
        old = env[left.id]
        pending = [old]
        while pending:
            self.tick()
            value = pending.pop()
            if isinstance(value, PossibleValues):
                if value.uncertainty is not None:
                    return True
                pending.extend(value.values)
        wanted_none = selected == isinstance(test.ops[0], ast.Is)
        options = self._summary_parts([old])
        kept = [v for v in options if isinstance(v, UnresolvedValue) or (v is None) == wanted_none]
        if not kept:
            return False
        env[left.id] = kept[0] if len(kept) == 1 else PossibleValues(tuple(kept), None)
        return True

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
            if not self.refine_none_guard(statement.test, selected, local):
                continue
            if isinstance(statement.test, ast.Name):
                old = local.get(statement.test.id)
                if isinstance(old, NonTextValue) and old.kind == "bool":
                    local[statement.test.id] = selected
            test=statement.test
            if (isinstance(test,ast.Compare) and len(test.ops)==1 and isinstance(test.left,ast.Name)
                    and isinstance(test.comparators[0],ast.Constant)
                    and not (test.comparators[0].value is None and isinstance(test.ops[0],(ast.Is,ast.IsNot)))):
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
        if isinstance(iterable, MappingDomain):
            iterable = SequenceDomain(iterable.key, iterable.min_length, iterable.max_length)
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
            summary = self.summarize_for(module,statement,env,iterable)
            if summary is not None:
                return summary
            return self.resume_unknown(module,statement,env,gap)
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
                    gap=self.unknown("P_OUTPUT_LOOP_BOUNDARY",module,statement)
                    # Zero iterations or a later normal exit remain possible;
                    # retain the boundary and inspect independent tail returns.
                    finished.extend(self.resume_unknown(module,statement,state.env,gap))
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

    def exception_names(self, module, node):
        """Resolve only unshadowed builtin catch types; None means unknown."""
        if node is None:
            return ("BaseException",)
        nodes = node.elts if isinstance(node, ast.Tuple) else [node]
        names = []
        known = {"BaseException", "Exception", "ValueError", "TypeError",
                 "RuntimeError", "KeyError", "IndexError", "LookupError",
                 "AssertionError", "OSError", "PermissionError", "FileNotFoundError"}
        for item in nodes:
            qualified = module.qualify(dotted(item))
            leaf = qualified.removeprefix("builtins.")
            if leaf not in known or self.lookup(module, qualified):
                return None
            names.append(leaf)
        return tuple(names)

    def exception_matches(self, actual, expected):
        parents = {"KeyError": "LookupError", "IndexError": "LookupError",
                   "PermissionError": "OSError", "FileNotFoundError": "OSError"}
        name = actual.removeprefix("builtins.")
        return any(n in {name, parents.get(name), "Exception", "BaseException"} for n in expected)

    def try_paths(self, module, statement, env):
        outcomes = self.block_paths(module, statement.body, env)
        handled = []
        for state in outcomes:
            self.activate(state)
            if state.kind == "next":
                handled.extend(self.block_paths(module, statement.orelse, state.env))
                continue
            def uncertain(value):
                from .p_output_flow import PossibleValues, StaticMapping
                if isinstance(value, UnresolvedValue):
                    return value.code != "P_OUTPUT_RUNTIME_PARAMETER"
                if isinstance(value, PossibleValues):
                    return value.uncertainty is not None or any(uncertain(v) for v in value.values)
                if isinstance(value, StaticMapping):
                    return any(uncertain(v) for _,v in value.entries.values())
                if isinstance(value, list):
                    return any(uncertain(v) for v in value)
                return False
            unresolved = state.kind == "unknown" or state.kind == "return" and uncertain(state.value)
            if state.kind != "raise" and not unresolved:
                handled.append(state)
                continue
            matched = False
            for handler in statement.handlers:
                expected = self.exception_names(module, handler.type)
                if expected is None:
                    handled.append(self.outcome("unknown", state.env,
                        self.unknown("P_OUTPUT_EXCEPTION_TYPE", module, handler)))
                if unresolved or expected is None or self.exception_matches(state.exception or "", expected):
                    self.activate(state)
                    local = self.fork_environment(state.env)
                    if handler.name:
                        local[handler.name] = (self.unknown("P_OUTPUT_EXCEPTION_OBJECT", module, handler)
                            if unresolved or expected is None else
                            CaughtException(state.exception, state.value, state.span))
                    handled.extend(self.block_paths(module, handler.body, local))
                    if not unresolved and expected is not None:
                        matched = True
                        break
            if unresolved or not matched:
                handled.append(state)
        finished = []
        for state in handled:
            self.activate(state)
            if not statement.finalbody:
                finished.append(state)
                continue
            for final in self.block_paths(module, statement.finalbody, state.env):
                if final.kind == "next":
                    final.kind, final.value, final.span, final.exception = (
                        state.kind, state.value, state.span, state.exception)
                finished.append(final)
        if len(finished) > self.MAX_PATHS:
            gap = self.unknown("P_OUTPUT_PATH_LIMIT", module, statement)
            return finished[:self.MAX_PATHS] + [self.outcome("unknown", env, gap)]
        return finished

    def statement_paths(self, module, statement, env):
        self.tick()
        if isinstance(statement, ast.Try):
            return self.try_paths(module, statement, env)
        if isinstance(statement, ast.AugAssign):
            left = self.value(module, statement.target, env)
            right = self.value(module, statement.value, env)
            expression = ast.copy_location(ast.BinOp(left=statement.target, op=statement.op, right=statement.value), statement)
            value = self.lift(module, expression, lambda a, b: self.binary(module, expression, a, b), left, right)
            from .p_output_flow import StaticSet
            if isinstance(left, list) and isinstance(right, list) and isinstance(statement.op, ast.Add) and isinstance(value, list):
                left[:] = value
                value = left
            elif isinstance(left, StaticSet) and isinstance(value, StaticSet):
                left.values[:] = value.values
                value = left
            if isinstance(value, UnresolvedValue):
                self.pending_gaps.append(value)
            if self.bind_target(module, statement.target, value, env):
                return [self.outcome("next", env)]
            return [self.outcome("unknown", env, self.unknown("P_OUTPUT_ASSIGNMENT_BINDING", module, statement))]
        if isinstance(statement, ast.Assign):
            value=self.value(module,statement.value,env)
            if all(self.bind_target(module,t,value,env) for t in statement.targets):
                return [self.outcome("next",env)]
            return [self.outcome("unknown",env,self.unknown("P_OUTPUT_ASSIGNMENT_BINDING",module,statement))]
        if isinstance(statement, ast.Expr) and isinstance(statement.value,ast.Call):
            value=self.value(module,statement.value,env)
            if isinstance(value,UnresolvedValue):
                return self.resume_unknown(module,statement,env,value)
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
                gap = self.unknown("P_OUTPUT_UNSUPPORTED_BODY",module,statement)
                states = self.resume_unknown(module,statement,env,gap)
                results = [states[0]]
                if isinstance(item.optional_vars,ast.Name):
                    env[item.optional_vars.id] = gap
                results.extend(self.block_paths(module,statement.body,env))
                return results
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
        if isinstance(value,SequenceDomain):
            return ("sequence",self.semantic_key(value.element,seen),value.min_length,value.max_length)
        if isinstance(value,MappingDomain):
            return ("mapping-domain",self.semantic_key(value.key,seen),self.semantic_key(value.value,seen),value.min_length,value.max_length)
        if isinstance(value,(RaisedValue,CaughtException)):
            return ("exception",value.exception,self.semantic_key(value.message,seen))
        if isinstance(value,StaticText):return ("text",value.value)
        if isinstance(value,BoundedInputText):
            return ("bounded-input-text",value.code,value.span.path,value.span.start_line,value.min_length,value.max_length)
        if value is None or type(value) in {str,int,float,bool}:return (type(value).__name__,value)
        if id(value) in seen:return ("cycle",type(value).__name__)
        seen=seen|{id(value)}
        if isinstance(value,StaticMapping):return ("map",getattr(value,"p_loop_readonly",False),tuple((k,self.semantic_key(v,seen)) for k,(_,v) in value.entries.items()))
        if isinstance(value,StaticInstance):return ("instance",value.path,value.class_name,getattr(value,"p_frozen",False),getattr(value,"p_loop_readonly",False),tuple((k,self.semantic_key(v,seen)) for k,v in value.fields.items()))
        if isinstance(value,(list,tuple)):return (type(value).__name__,getattr(value,"p_loop_readonly",False),tuple(self.semantic_key(v,seen) for v in value))
        if isinstance(value,StaticSet):return ("set",tuple(self.semantic_key(v,seen) for v in value.values))
        if isinstance(value,PossibleValues):return ("choices",tuple(self.semantic_key(v,seen) for v in value.values),self.semantic_key(value.uncertainty,seen))
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
            elif isinstance(original,MappingDomain) and all(isinstance(v,MappingDomain) for v in variants):
                original.key=merged([v.key for v in variants])
                original.value=merged([v.value for v in variants])
                original.min_length=min(v.min_length for v in variants)
                original.max_length=(None if any(v.max_length is None for v in variants)
                                     else max(v.max_length for v in variants))
            elif isinstance(original,StaticInstance) and all(isinstance(v,StaticInstance) for v in variants):
                keys=list(dict.fromkeys(k for v in variants for k in v.fields))
                original.fields={k:merged([v.fields.get(k) for v in variants]) for k in keys}
            elif isinstance(original,list):
                original[:]=[self.unknown("P_OUTPUT_BRANCH_MUTATION",module,anchor)]
            elif isinstance(original,StaticSet):
                original.values[:]=[self.unknown("P_OUTPUT_BRANCH_MUTATION",module,anchor)]

    def body(self, module, statements, env):
        from .p_output_flow import PossibleValues
        origin = self.outcome("next", env)
        outcomes = self.block_paths(module, statements, env)
        values = []
        for state in outcomes:
            self.activate(state)
            value = state.value
            if state.kind == "raise":
                if self.active_calls:
                    value = RaisedValue(state.exception, value, state.span)
                else:
                    self.pending_error_texts.append(value)
                    value = None
            elif state.kind not in {"next", "return", "unknown"}:
                value = self.unknown("P_OUTPUT_INVALID_CONTROL_FLOW", module, statements[-1])
            if len(outcomes) > 1 and state.span and state.kind in {"return", "raise"}:
                value = self.decorate(value, TraceStep(
                    "sink", state.span, symbol="possible return/exception path", edge_kind="possible"))
            values.append(value)
        if len(outcomes) == 1:
            self.activate(outcomes[0])
            return values[0], outcomes[0].span
        if statements:
            self.merge_branch_effects(module, statements[-1], env, outcomes)
        self.activate(origin)
        return PossibleValues(tuple(values), None), None
