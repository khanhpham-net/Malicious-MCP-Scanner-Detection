"""Conservative fixed points for finite loops and private accumulators."""
from __future__ import annotations

import ast
from copy import deepcopy

from .p_domains import NonTextValue, RuntimeInputText, SequenceDomain, MappingDomain
from .p_static import StaticText, UnresolvedValue
from .p_text_constraints import ValidatedToken
from .p_loop_domains import LoopMapping, LoopSequence
from .python_ast.index import dotted


class FlowSummaryMixin:
    SUMMARY_ITERATIONS = 8

    def resume_unknown(self, module, statement, env, gap):
        """Observe possible later returns without treating opaque effects as safe."""
        from .p_output_flow import StaticInstance, StaticMapping, StaticSet, PossibleValues
        self.pending_gaps.append(gap)
        self.snapshot_dirty = True
        assigned = {n.id for n in ast.walk(statement) if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Store)}
        globals_ = set(self.module_environment(module.path))
        for name,value in list(env.items()):
            if name in assigned or name in globals_ or isinstance(value,(list,dict,StaticInstance,StaticMapping,StaticSet,MappingDomain)):
                dependency=self.unknown("P_OUTPUT_EFFECT_DEPENDENCY",module,statement)
                env[name] = PossibleValues((deepcopy(value),),dependency)
        # Both failure/unknown behavior and a normal continuation remain possible.
        return [self.outcome("unknown",env,gap),self.outcome("next",env)]

    def summary_pure(self, module, statements):
        allowed = (ast.Assign,ast.AnnAssign,ast.AugAssign,ast.If,ast.Return,ast.Pass,ast.Break,ast.Continue)
        pure = {"abs","len","round","int","float","bool","str","min","max","sum","any","all"}
        for statement in statements:
            for node in ast.walk(statement):
                self.tick()
                if isinstance(node,ast.stmt):
                    if not isinstance(node,allowed):
                        return False
                    targets = node.targets if isinstance(node,ast.Assign) else (
                        [node.target] if isinstance(node,(ast.AnnAssign,ast.AugAssign)) else [])
                    if any(not isinstance(t,ast.Name) for t in targets):
                        return False
                if isinstance(node,(ast.NamedExpr,ast.Lambda,ast.Await,ast.Yield,ast.YieldFrom)):
                    return False
                if isinstance(node,ast.Call):
                    name = dotted(node.func)
                    if not isinstance(node.func,ast.Name) or name not in pure or self.lookup(module,module.qualify(name)):
                        return False
        return True

    def _summary_parts(self, values):
        """Flatten alternative nodes, retaining every uncertainty and tuple record.

        Conditional expressions may nest alternatives to arbitrary AST depth.
        They are not mutable heap objects.  Flattening only the outer level
        incorrectly rejects an otherwise immutable loop invariant.
        """
        from .p_output_flow import PossibleValues
        parts = []
        pending = list(reversed(values))
        while pending:
            self.tick()
            value = pending.pop()
            if isinstance(value,PossibleValues):
                if value.uncertainty is not None:
                    pending.append(value.uncertainty)
                pending.extend(reversed(value.values))
            else:
                parts.append(value)
        return parts

    def join_summary_value(self, module, anchor, values):
        from .p_output_flow import PossibleValues
        parts = self._summary_parts(values)
        unique = {}
        for value in parts:
            self.tick()
            unique[self.semantic_key(value)] = value
        parts = list(unique.values())
        if len(parts)==1:
            return parts[0]
        if all(self.numeric(v) for v in parts):
            kinds = {v.kind if isinstance(v,NonTextValue) else type(v).__name__ for v in parts}
            return NonTextValue("bool" if kinds=={"bool"} else "int" if kinds<={"bool","int"} else "number")
        # Mutable data are not certified by an independent per-name join: doing
        # so would lose alias relations and can hide mutation.
        if any(not (isinstance(v,(StaticText,NonTextValue,RuntimeInputText,UnresolvedValue,type(None),int,float,bool))
                    or isinstance(v, tuple) and self.immutable_loop_element(v))
               for v in parts):
            return self.unknown("P_OUTPUT_LOOP_JOIN",module,anchor)
        if len(parts)>self.MAX_ALTERNATIVES:
            return self.unknown("P_OUTPUT_LOOP_JOIN",module,anchor)
        return PossibleValues(tuple(parts),None)

    def _loop_unresolved(self, value):
        return isinstance(value, UnresolvedValue) and not isinstance(value, (RuntimeInputText, ValidatedToken))

    def immutable_loop_element(self, value):
        """A representative may be read, but never strongly mutated as an item."""
        from .p_output_flow import PossibleValues, StaticMapping
        if isinstance(value, PossibleValues):
            return value.uncertainty is None and all(self.immutable_loop_element(v) for v in value.values)
        if isinstance(value, tuple):
            return all(self.immutable_loop_element(v) for v in value)
        from .p_loop_domains import LoopLiteralList
        if isinstance(value, LoopLiteralList):
            return value.p_loop_readonly and all(self.immutable_loop_element(v) for v in value)
        if isinstance(value, StaticMapping):
            return getattr(value, "p_loop_readonly", False) and all(
                self.immutable_loop_element(k) and self.immutable_loop_element(v)
                for k, v in value.entries.values())
        return value is None or type(value) in {int, float, bool} or isinstance(
            value, (StaticText, NonTextValue, RuntimeInputText, ValidatedToken))

    def join_loop_element(self, module, anchor, values):
        from .p_output_flow import PossibleValues
        parts = self._summary_parts(values)
        if not all(self.immutable_loop_element(v) for v in parts):
            return self.unknown("P_OUTPUT_LOOP_JOIN", module, anchor)
        unique = {self.semantic_key(v): v for v in parts}
        parts = list(unique.values())
        if not parts:
            return PossibleValues((), None)
        if len(parts) == 1:
            return parts[0]
        if all(self.numeric(v) for v in parts):
            return self.join_summary_value(module, anchor, parts)
        if len(parts) > self.MAX_ALTERNATIVES:
            return self.unknown("P_OUTPUT_LOOP_JOIN", module, anchor)
        # Alternatives of complete tuples retain tag/value correlations.
        return PossibleValues(tuple(parts), None)

    def _loop_freeze_literal(self, value, expression):
        """Only fresh literal records may become read-only element snapshots."""
        from .p_output_flow import StaticMapping
        if self.immutable_loop_element(value):
            return True
        if isinstance(value, tuple) and isinstance(expression, (ast.Tuple, ast.List)):
            return len(value) == len(expression.elts) and all(
                self._loop_freeze_literal(v, e) for v, e in zip(value, expression.elts))
        from .p_loop_domains import LoopLiteralList
        if isinstance(value, LoopLiteralList) and isinstance(expression, ast.List):
            if len(value) != len(expression.elts) or not all(
                    self._loop_freeze_literal(v, e) for v, e in zip(value, expression.elts)):
                return False
            value.p_loop_readonly = True
            return True
        if not isinstance(value, StaticMapping) or not isinstance(expression, ast.Dict):
            return False
        if any(k is None for k in expression.keys):
            return False
        # Dictionary evaluation already retains the last duplicate key.
        syntax = {}
        for key, member in zip(expression.keys, expression.values):
            if not isinstance(key, ast.Constant) or type(key.value) not in {str, int, float, bool, type(None)}:
                return False
            syntax[key.value] = member
        if set(syntax) != set(value.entries):
            return False
        if not all(self.immutable_loop_element(k) and self._loop_freeze_literal(v, syntax[raw])
                   for raw, (k, v) in value.entries.items()):
            return False
        value.p_loop_readonly = True
        return True

    def loop_collection_method(self, module, node, receiver, name, args, kw):
        """Handle only proved local writes; guard other calls during transfer."""
        from .p_output_flow import StaticMapping
        active = getattr(self, "_loop_transfer", None)
        if isinstance(receiver, LoopSequence):
            if name not in {"append", "extend"}:
                return NotImplemented
            if len(args) != 1 or kw:
                return self.unknown("P_OUTPUT_ARGUMENT_BINDING", module, node)
            value = args[0]
            if name == "append":
                expression = node.args[0] if node.args else None
                if not self._loop_freeze_literal(value, expression):
                    return self.unknown("P_OUTPUT_LOOP_JOIN", module, node)
                values, lower, upper = [value], 1, 1
            elif isinstance(value, SequenceDomain):
                values, lower, upper = [value.element], value.min_length, value.max_length
            else:
                values = self.sequence_items(value)
                if values is None:
                    return self.unknown("P_OUTPUT_LOOP_BOUNDARY", module, node)
                lower = upper = len(values)
            joined = self.join_loop_element(module, node, [receiver.element, *values])
            if self._loop_unresolved(joined):
                return joined
            receiver.update_element(joined)
            receiver.update_bounds(receiver.min_length + lower,
                None if receiver.max_length is None or upper is None else receiver.max_length + upper)
            return None
        if active is None:
            return NotImplemented
        # Do not let a first-party object method borrow a pure builtin's name.
        if isinstance(receiver, (StaticText, RuntimeInputText)) and name in {
                "lower", "upper", "casefold", "strip", "lstrip", "rstrip", "replace",
                "split", "join", "startswith", "endswith", "isdigit", "isdecimal", "isalnum"}:
            return NotImplemented
        if isinstance(receiver, (StaticMapping, MappingDomain)) and name in {
                "get", "keys", "values", "items", "copy"}:
            return NotImplemented
        return self.unknown("P_OUTPUT_LOOP_EFFECT", module, node)

    def loop_bind_subscript(self, module, node, receiver, key, value):
        """A weak write cannot erase previous keys or values of a local map."""
        if not isinstance(receiver, LoopMapping):
            return NotImplemented
        active = getattr(self, "_loop_transfer", None)
        expression = active.get("stores", {}).get(id(node)) if active is not None else None
        if not self._loop_freeze_literal(value, expression):
            return False
        keys = self.join_loop_element(module, node, [receiver.key, key])
        values = self.join_loop_element(module, node, [receiver.value, value])
        if self._loop_unresolved(keys) or self._loop_unresolved(values):
            return False
        receiver.key, receiver.value = keys, values
        receiver.min_length = max(1, receiver.min_length)
        if receiver.max_length is not None:
            receiver.max_length += 1
        return True

    def _loop_references(self, value, seen=None):
        from .p_output_flow import StaticMapping, StaticInstance, StaticSet, PossibleValues
        seen = set() if seen is None else seen
        if id(value) in seen:
            return seen
        seen.add(id(value))
        if isinstance(value, StaticMapping):
            children = [v for pair in value.entries.values() for v in pair]
        elif isinstance(value, StaticInstance):
            children = list(value.fields.values())
        elif isinstance(value, StaticSet):
            children = value.values
        elif isinstance(value, PossibleValues):
            children = [*value.values, value.uncertainty]
        elif isinstance(value, SequenceDomain):
            children = [value.element]
        elif isinstance(value, MappingDomain):
            children = [value.key, value.value]
        elif isinstance(value, dict):
            children = list(value.values())
        elif isinstance(value, (list, tuple)):
            children = value
        else:
            children = ()
        for child in children:
            self._loop_references(child, seen)
        return seen

    def _loop_replace(self, value, replacements, memo=None):
        """Replace abstract heap roots throughout direct and nested aliases."""
        from .p_output_flow import StaticMapping, StaticInstance, StaticSet, PossibleValues
        memo = {} if memo is None else memo
        identity = id(value)
        if identity in replacements:
            return replacements[identity]
        if identity in memo:
            return memo[identity]
        memo[identity] = value
        if isinstance(value, dict):
            for key, member in list(value.items()):
                value[key] = self._loop_replace(member, replacements, memo)
        elif isinstance(value, list):
            value[:] = [self._loop_replace(v, replacements, memo) for v in value]
        elif isinstance(value, tuple):
            value = tuple(self._loop_replace(v, replacements, memo) for v in value)
        elif isinstance(value, StaticMapping):
            value.entries = {k: (self._loop_replace(key, replacements, memo),
                                  self._loop_replace(v, replacements, memo))
                             for k, (key, v) in value.entries.items()}
        elif isinstance(value, StaticInstance):
            value.fields = {k: self._loop_replace(v, replacements, memo) for k, v in value.fields.items()}
        elif isinstance(value, StaticSet):
            value.values[:] = [self._loop_replace(v, replacements, memo) for v in value.values]
        elif isinstance(value, PossibleValues):
            value = type(value)(tuple(self._loop_replace(v, replacements, memo) for v in value.values),
                                self._loop_replace(value.uncertainty, replacements, memo))
        elif isinstance(value, MappingDomain):
            value.key = self._loop_replace(value.key, replacements, memo)
            value.value = self._loop_replace(value.value, replacements, memo)
        memo[identity] = value
        return value

    def _loop_target_names(self, target):
        if isinstance(target, ast.Name):
            return {target.id}
        if isinstance(target, (ast.Tuple, ast.List)):
            names = [self._loop_target_names(t) for t in target.elts]
            return None if any(n is None for n in names) else set().union(*names)
        return None

    def _loop_plan(self, module, statement, env, iterable):
        """Prove mutation destinations before widening any heap object."""
        for operation in ast.walk(statement):
            if isinstance(operation, ast.BinOp) and isinstance(operation.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                denominator = operation.right
                if not (isinstance(denominator, ast.Constant) and type(denominator.value) in {int, float}
                        and denominator.value != 0):
                    return None
        from .p_output_flow import StaticMapping
        target_names = self._loop_target_names(statement.target)
        if target_names is None:
            return None
        aliases, assigned, stores = {}, set(target_names), {}
        assignments = {}
        for child in statement.body:
            for node in ast.walk(child):
                if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Subscript):
                        if isinstance(node, ast.AugAssign) or not isinstance(target.value, ast.Name):
                            return None
                        stores[id(target)] = node.value
                        continue
                    names = self._loop_target_names(target)
                    if names is None:
                        return None
                    assigned.update(names)
                    for name in names:
                        assignments.setdefault(name, []).append(node.value)
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Name) and not isinstance(node, ast.AugAssign):
                        aliases.setdefault(target.id, set()).add(node.value.id)
        def origin(name, seen=None):
            seen = set() if seen is None else seen
            if name in seen or name in target_names:
                return None
            if name in env:
                return name
            choices = aliases.get(name, ())
            if len(choices) != 1 or any(not isinstance(v, ast.Name) for v in assignments.get(name, ())):
                return None
            return origin(next(iter(choices)), seen | {name})
        allowed = (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.If, ast.Return,
                   ast.Pass, ast.Break, ast.Continue, ast.Expr, ast.Raise)
        pure = {"abs", "len", "round", "int", "float", "bool", "str", "min", "max",
                "sum", "any", "all", "list", "tuple", "set", "enumerate", "zip", "range", "sorted", "isinstance"}
        errors = {"Exception", "ValueError", "TypeError", "RuntimeError", "KeyError", "IndexError",
                  "LookupError", "AssertionError", "OSError", "PermissionError", "FileNotFoundError"}
        mutators = []
        for child in statement.body:
            for node in ast.walk(child):
                self.tick()
                if isinstance(node, ast.stmt) and not isinstance(node, allowed):
                    return None
                if isinstance(node, (ast.NamedExpr, ast.Lambda, ast.Await, ast.Yield, ast.YieldFrom,
                                     ast.Delete, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                    return None
                if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store):
                    root = origin(node.value.id)
                    if root is None or not isinstance(env[root], (StaticMapping, LoopMapping)):
                        return None
                    mutators.append(root)
                if not isinstance(node, ast.Call):
                    continue
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                    if name not in pure | errors or name in env or name in assigned or \
                            self.canonical_symbol(module, name) != name or self.lookup(module, name):
                        return None
                elif isinstance(node.func, ast.Attribute):
                    if node.func.attr in {"append", "extend"}:
                        if not isinstance(node.func.value, ast.Name):
                            return None
                        root = origin(node.func.value.id)
                        if root is None or not isinstance(env[root], (list, LoopSequence)):
                            return None
                        mutators.append(root)
                    # Remaining methods are guarded by receiver type before dispatch.
                else:
                    return None
        if assigned & set(self.module_environment(module.path)):
            return None
        global_refs = self._loop_references(self.handler_envs)
        input_refs = self._loop_references(iterable)
        roots = []
        for root in mutators:
            value = env[root]
            if id(value) in global_refs or id(value) in input_refs or getattr(value, "p_loop_readonly", False):
                return None
            # An alias may be re-assigned only to the same proved heap root.
            for name in assigned:
                if name in env and env[name] is value:
                    for rhs in assignments.get(name, ()):
                        if not isinstance(rhs, ast.Name):
                            return None
                        source = origin(rhs.id)
                        if source is None or env[source] is not value:
                            return None
            if not any(env[r] is value for r in roots):
                roots.append(root)
        return {"targets": target_names, "assigned": assigned, "roots": roots, "stores": stores}

    def _loop_merge(self, module, statement, entry, states, plan):
        """Join a whole environment with one shared object for every heap root."""
        from .p_output_flow import PossibleValues
        joined = deepcopy(entry)
        roots, assigned = plan["roots"], plan["assigned"]
        replacements = {}
        for root in roots:
            values = [state[root] for state in states]
            if isinstance(entry[root], LoopSequence) and all(isinstance(v, LoopSequence) for v in values):
                element = self.join_loop_element(module, statement, [v.element for v in values])
                merged = LoopSequence(element, min(v.min_length for v in values), None)
                domains = [element]
            elif isinstance(entry[root], LoopMapping) and all(isinstance(v, LoopMapping) for v in values):
                key = self.join_loop_element(module, statement, [v.key for v in values])
                value = self.join_loop_element(module, statement, [v.value for v in values])
                merged = LoopMapping(key, value, min(v.min_length for v in values), None)
                domains = [key, value]
            else:
                return None
            if any(self._loop_unresolved(v) for v in domains):
                return None
            replacements[id(joined[root])] = merged
        joined = self._loop_replace(joined, replacements)
        missing = self.unknown("P_OUTPUT_POSSIBLY_UNBOUND", module, statement)
        for name in assigned:
            values = [state.get(name, missing) for state in states]
            aliases = []
            for root in roots:
                if all(value is state[root] for value, state in zip(values, states)):
                    aliases.append(root)
            if aliases:
                joined[name] = joined[aliases[0]]
                continue
            # Internal aliases can be unbound on the zero-iteration path.
            for root in roots:
                if all(value is missing or value is state[root] for value, state in zip(values, states)):
                    joined[name] = PossibleValues((joined[root],), missing)
                    break
            else:
                joined[name] = self.join_summary_value(module, statement, values)
                if isinstance(joined[name], UnresolvedValue) and joined[name].code == "P_OUTPUT_LOOP_JOIN":
                    # Read-only representatives are intentionally unavailable
                    # after the loop; a later use retains this boundary.
                    if not all(not self.immutable_loop_element(v) for v in values if v is not missing):
                        return None
        return joined

    def summarize_for(self, module, statement, env, iterable):
        """Prove an inductive transfer; never certify one representative run."""
        from .p_output_flow import PossibleValues, StaticMapping
        if not isinstance(iterable, SequenceDomain):
            items = self.sequence_items(iterable)
            if items is None:
                return None
            element = self.join_loop_element(module, statement, items)
            if self._loop_unresolved(element):
                return None
            iterable = SequenceDomain(element, len(items), len(items))
        if iterable.max_length == 0:
            return self.block_paths(module, statement.orelse, env)
        # Load global aliases before taking the transactional origin snapshot.
        self.module_environment(module.path)
        origin = self.outcome("next", env)
        pending, errors, dirty = len(self.pending_gaps), len(self.pending_error_texts), self.snapshot_dirty
        previous = getattr(self, "_loop_transfer", None)
        succeeded = False
        try:
            plan = self._loop_plan(module, statement, env, iterable)
            if plan is None:
                return None
            entry = self.fork_environment(env)
            replacements = {}
            for root in plan["roots"]:
                value = entry[root]
                if isinstance(value, (LoopSequence, LoopMapping)):
                    continue
                if isinstance(value, list):
                    element = self.join_loop_element(module, statement, value)
                    if self._loop_unresolved(element):
                        return None
                    replacements[id(value)] = LoopSequence(element, len(value), None)
                elif isinstance(value, StaticMapping):
                    key = self.join_loop_element(module, statement, [k for k, _ in value.entries.values()])
                    member = self.join_loop_element(module, statement, [v for _, v in value.entries.values()])
                    if self._loop_unresolved(key) or self._loop_unresolved(member):
                        return None
                    replacements[id(value)] = LoopMapping(key, member, len(value.entries), None)
            entry = self._loop_replace(entry, replacements)
            invariant, terminals = entry, []
            self._loop_transfer = plan
            for _ in range(self.SUMMARY_ITERATIONS):
                self.tick()
                self.activate(origin)
                local = self.fork_environment(invariant)
                if not self.bind_target(module, statement.target, deepcopy(iterable.element), local):
                    return None
                outcomes = self.block_paths(module, statement.body, local)
                if len(self.pending_gaps) != pending or self.snapshot_dirty != dirty:
                    return None
                back = []
                for state in outcomes:
                    if state.kind in {"next", "continue"}:
                        back.append(state.env)
                    elif state.kind in {"break", "return", "raise"}:
                        if state.kind == "break":
                            state.kind = "next"
                        terminals.append(state)
                    else:
                        return None
                # Drop repeated observations before applying the path budget.
                unique = {}
                for state in terminals:
                    key = (state.kind, self.semantic_key(state.value), state.exception,
                           tuple((n, self.semantic_key(state.env.get(n))) for n in sorted(plan["assigned"] | set(plan["roots"]))))
                    unique[key] = state
                terminals = list(unique.values())
                if len(terminals) > self.MAX_PATHS:
                    return None
                joined = self._loop_merge(module, statement, entry, [entry, *back], plan)
                if joined is None:
                    return None
                names = plan["assigned"] | set(plan["roots"])
                stable = all(self.semantic_key(joined.get(n)) == self.semantic_key(invariant.get(n)) for n in names)
                if stable or not back:
                    exits = []
                    if back or iterable.min_length == 0:
                        states = ([entry] if iterable.min_length == 0 else []) + back
                        exiting = self._loop_merge(module, statement, entry, states, plan)
                        if exiting is None:
                            return None
                        self.activate(origin)
                        # Else runs once, only on the no-break exhaustion path.
                        self._loop_transfer = previous
                        exits = self.block_paths(module, statement.orelse, exiting)
                    succeeded = True
                    return terminals + exits
                invariant = joined
            return None
        finally:
            self._loop_transfer = previous
            if not succeeded:
                self.activate(origin)
                del self.pending_gaps[pending:]
                del self.pending_error_texts[errors:]
                self.snapshot_dirty = dirty
