"""Conservative effect continuation and fixed points for pure scalar loops."""
from __future__ import annotations

import ast
from copy import deepcopy

from .p_domains import NonTextValue, RuntimeInputText, SequenceDomain
from .p_static import StaticText, UnresolvedValue
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
            if name in assigned or name in globals_ or isinstance(value,(list,dict,StaticInstance,StaticMapping,StaticSet)):
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

    def join_summary_value(self, module, anchor, values):
        from .p_output_flow import PossibleValues
        parts = []
        for value in values:
            if isinstance(value,PossibleValues):
                parts.extend(value.values)
                if value.uncertainty is not None:
                    parts.append(value.uncertainty)
            else:
                parts.append(value)
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
        if any(not isinstance(v,(StaticText,NonTextValue,RuntimeInputText,UnresolvedValue,type(None),int,float,bool))
               for v in parts):
            return self.unknown("P_OUTPUT_LOOP_JOIN",module,anchor)
        if len(parts)>self.MAX_ALTERNATIVES:
            return self.unknown("P_OUTPUT_LOOP_JOIN",module,anchor)
        return PossibleValues(tuple(parts),None)

    def summarize_for(self, module, statement, env, iterable):
        """Inductive fixed point over typed finite-sequence elements.

        This certifies only the restricted pure transfer above. One iteration,
        an increased unroll limit, and unexamined mutable effects never suffice.
        """
        if not isinstance(iterable,SequenceDomain) or not isinstance(statement.target,ast.Name):
            return None
        if not self.summary_pure(module,statement.body):
            return None
        origin = self.outcome("next",env)
        entry = self.fork_environment(env)
        names = {n.id for s in statement.body for n in ast.walk(s) if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Store)}
        names.add(statement.target.id)
        if names & set(self.module_environment(module.path)):
            self.activate(origin)
            return None
        invariant = dict(entry)
        terminals = []
        for _ in range(self.SUMMARY_ITERATIONS):
            self.tick()
            self.activate(origin)
            local = self.fork_environment(invariant)
            local[statement.target.id] = iterable.element
            outcomes = self.block_paths(module,statement.body,local)
            back = []
            for state in outcomes:
                if state.kind in {"next","continue"}:
                    back.append(state.env)
                elif state.kind=="break":
                    state.kind="next"
                    terminals.append(state)
                else:
                    terminals.append(state)
            if len(terminals)>self.MAX_PATHS:
                return None
            joined = dict(entry)
            for name in names:
                missing = self.unknown("P_OUTPUT_POSSIBLY_UNBOUND",module,statement)
                values = [entry.get(name,missing)]+[state.get(name,missing) for state in back]
                joined[name] = self.join_summary_value(module,statement,values)
                for value in values:
                    if isinstance(value,UnresolvedValue) and not isinstance(value,RuntimeInputText) and value.code!="P_OUTPUT_POSSIBLY_UNBOUND":
                        self.pending_gaps.append(value)
            stable = all(self.semantic_key(joined.get(n))==self.semantic_key(invariant.get(n)) for n in names)
            if stable or not back:
                self.activate(origin)
                for name,value in joined.items():
                    if name in names:
                        env[name]=value
                exits=self.block_paths(module,statement.orelse,env)
                # De-duplicate repeated abstract return/raise observations.
                seen=set();result=[]
                for state in terminals+exits:
                    key=(state.kind,self.semantic_key(state.value),state.exception,
                         tuple((n,self.semantic_key(state.env.get(n))) for n in sorted(names)))
                    if key not in seen:
                        seen.add(key);result.append(state)
                return result
            invariant = joined
        self.activate(origin)
        return None
