"""Bounded static proofs for reviewed Pydantic annotation constraints.

No target regex, validator, model constructor or import is executed. Pattern
checks use only the existing reviewed ASCII concatenation subset.
"""
from __future__ import annotations

import ast
import math

from .models import SourceSpan
from .p_domains import NonTextValue, RuntimeInputText, SequenceDomain, MappingDomain
from .p_static import StaticText, UnresolvedValue
from .p_text_constraints import ValidatedToken, ascii_token_pattern
from .python_ast.index import dotted

_UNRESOLVED = object()


class ModelConstraintMixin:
    MAX_MODEL_ALIAS_DEPTH = 16

    def _matches_model_pattern(self, pattern, text):
        """Linear-space bounded NFA for a reviewed ASCII concatenation grammar.

        Target patterns never enter Python's backtracking regex engine. Rust
        character-class set operations and non-ASCII semantics are unsupported.
        """
        if not ascii_token_pattern(pattern) or len(text) > 4096:
            return None
        body = pattern[1:-1]
        atoms = []
        i = 0
        while i < len(body):
            self.tick()
            if body[i] == "[":
                end = body.index("]", i + 1)
                content = body[i + 1:end]
                if "--" in content or any(not (c.isascii() and (c.isalnum() or c in "_-")) for c in content):
                    return None
                chars = set()
                j = 0
                while j < len(content):
                    if j + 2 < len(content) and content[j + 1] == "-":
                        low, high = ord(content[j]), ord(content[j + 2])
                        if low > high or content[j] == "-" or content[j + 2] == "-":
                            return None
                        chars.update(chr(c) for c in range(low, high + 1))
                        j += 3
                    else:
                        chars.add(content[j]); j += 1
                i = end + 1
            elif body[i] == "\\":
                chars = {body[i + 1]}; i += 2
            else:
                chars = {body[i]}; i += 1
            lower, upper = 1, 1
            if i < len(body) and body[i] in "?*+":
                mark = body[i]; i += 1
                lower, upper = (0, 1) if mark == "?" else (0, None) if mark == "*" else (1, None)
            elif i < len(body) and body[i] == "{":
                end = body.index("}", i + 1)
                parts = body[i + 1:end].split(",")
                lower = int(parts[0])
                upper = lower if len(parts) == 1 else int(parts[1]) if parts[1] else None
                if upper is not None and lower > upper:
                    return None
                i = end + 1
            atoms.append((chars, lower, upper))
        n = len(text)
        positions = {0}
        for chars, lower, upper in atoms:
            self.tick()
            run = [0] * (n + 1)
            for j in range(n - 1, -1, -1):
                run[j] = run[j + 1] + 1 if text[j] in chars else 0
            changes = [0] * (n + 2)
            for start in positions:
                maximum = run[start] if upper is None else min(run[start], upper)
                if maximum >= lower:
                    changes[start + lower] += 1
                    changes[start + maximum + 1] -= 1
            active = 0
            positions = set()
            for j in range(n + 1):
                active += changes[j]
                if active:
                    positions.add(j)
            if not positions:
                return False
        return n in positions

    def _model_alias_expression(self, module, node, active=()):
        """Resolve immutable annotation/constant aliases to their owning module."""
        name = dotted(node)
        if not name:
            return module, node
        qualified = module.qualify(name)
        owner, _, member = qualified.rpartition(".")
        target = module
        if owner and owner != module.name:
            paths = self.module_paths.get(owner, [])
            if len(paths) != 1:
                return module, node
            parsed = self.parse(SourceSpan(paths[0]))
            parsed = parsed or self.parsing.get(paths[0])
            if not parsed:
                return None
            target = parsed[0]
        elif not owner:
            member = qualified
        marker = (target.path, member)
        if marker in active or len(active) >= self.MAX_MODEL_ALIAS_DEPTH:
            return None
        stores = []
        classes = []
        unsafe = False
        for statement in target.tree.body:
            self.tick()
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                if any(isinstance(t, ast.Name) and t.id == member for t in targets):
                    stores.append(statement)
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if statement.name == member:
                    unsafe = True
            elif isinstance(statement, ast.ClassDef) and statement.name == member:
                classes.append(statement)
            elif isinstance(statement, (ast.If, ast.For, ast.While, ast.Try, ast.With, ast.AugAssign, ast.Delete)):
                if any(isinstance(n, ast.Name) and n.id == member and isinstance(n.ctx, (ast.Store, ast.Del))
                       for n in ast.walk(statement)):
                    unsafe = True
        if unsafe or len(stores) > 1 or len(classes) > 1 or classes and stores:
            return None
        if classes:
            return target, node
        if stores:
            # Rebinding builtin scalar/container annotations is outside this
            # proof; the ordinary input resolver has the same restriction.
            if member in {"str", "int", "float", "bool", "list", "tuple", "dict", "set"}:
                return None
            if member in target.aliases or stores[0].value is None:
                return None
            return self._model_alias_expression(target, stores[0].value, (*active, marker))
        if member in target.aliases:
            alias = target.qualify(member)
            if alias != qualified or target is not module:
                alias_node = ast.copy_location(ast.Name(id=alias), node)
                return self._model_alias_expression(target, alias_node, (*active, marker))
        return target, node

    def _model_metadata_literal(self, module, expression):
        resolved = self._model_alias_expression(module, expression)
        if resolved is None:
            return _UNRESOLVED
        _, expression = resolved
        if isinstance(expression, ast.Constant):
            return expression.value
        if isinstance(expression, ast.UnaryOp) and isinstance(expression.op, (ast.USub, ast.UAdd)):
            operand = expression.operand
            if isinstance(operand, ast.Constant) and type(operand.value) in {int, float}:
                return -operand.value if isinstance(expression.op, ast.USub) else operand.value
        return _UNRESOLVED

    def _model_constraint_failure(self, module, node):
        return self.unknown("P_OUTPUT_MODEL_VALIDATION", module, node)

    def _model_union_value(self, module, node, arms, value, active):
        """Do not guess a smart-union winner from the declaration order.

        Unknown coercion/model arms are not equivalent to rejected arms. Only
        null-vs-nonnull failures are discarded here; all other unproved arms
        preserve uncertainty. Identical successful outcomes are order-neutral.
        """
        successful = []
        for arm in arms:
            resolved = self._model_alias_expression(module, arm)
            if resolved is None:
                return self._model_constraint_failure(module, node)
            owner, annotation = resolved
            null_arm = isinstance(annotation, ast.Constant) and annotation.value is None
            if null_arm and value is not None:
                continue
            checked = self._model_field_value(owner, annotation, value, active)
            if self._contains_invalid_model_value(checked):
                # None cannot become a supported primitive without a custom
                # validator; such validators are deliberately not modeled.
                symbol = self.canonical_symbol(owner, dotted(annotation))
                if value is None and symbol in {"str", "int", "float", "bool"}:
                    continue
                if value is None and isinstance(annotation, ast.Subscript) and self.canonical_symbol(
                        owner, dotted(annotation.value)) in {"typing.Literal", "typing_extensions.Literal"}:
                    members = annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else [annotation.slice]
                    if members and all(isinstance(a, ast.Constant) and a.value is not None for a in members):
                        continue
                return self._model_constraint_failure(module, node)
            successful.append(checked)
        if not successful:
            return self._model_constraint_failure(module, node)
        key = self.semantic_key(successful[0])
        if any(self.semantic_key(v) != key for v in successful[1:]):
            return self._model_constraint_failure(module, node)
        return successful[0]

    def _apply_model_metadata(self, module, metadata, value):
        """Require every supported constraint to be proved on every alternative."""
        from .p_output_flow import PossibleValues, StaticMapping
        if isinstance(value, PossibleValues):
            return PossibleValues(tuple(self._apply_model_metadata(module, metadata, v) for v in value.values),
                                  value.uncertainty)
        if isinstance(value, UnresolvedValue) and not isinstance(value, RuntimeInputText):
            return value
        for expression in metadata:
            resolved = self._model_alias_expression(module, expression)
            if resolved is None:
                return self._model_constraint_failure(module, expression)
            owner, field = resolved
            if isinstance(field, ast.Constant):
                # Primitive metadata is inert in Annotated; no callbacks run.
                continue
            if not isinstance(field, ast.Call) or self.canonical_symbol(owner, dotted(field.func)) not in {
                    "pydantic.Field", "pydantic.fields.Field"} or self._annotation_shadowed("pydantic"):
                return self._model_constraint_failure(owner, field)
            if not self.safe_annotation_metadata(owner, field):
                return self._model_constraint_failure(owner, field)
            names = [k.arg for k in field.keywords]
            if None in names or len(set(names)) != len(names) or len(field.args) > 1:
                return self._model_constraint_failure(owner, field)
            ignored = {"default", "default_factory", "description", "title"}
            supported = {"ge", "le", "gt", "lt", "min_length", "max_length", "pattern",
                         "multiple_of", "allow_inf_nan", "strict", "frozen"}
            for keyword in field.keywords:
                self.tick()
                key = keyword.arg
                if key in ignored:
                    continue
                if key not in supported:
                    return self._model_constraint_failure(owner, field)
                bound = self._model_metadata_literal(owner, keyword.value)
                if bound is _UNRESOLVED:
                    return self._model_constraint_failure(owner, field)
                if key in {"strict", "frozen"}:
                    if type(bound) is not bool or key == "frozen" and bound:
                        return self._model_constraint_failure(owner, field)
                    # Scalar conversion has already been checked separately.
                    continue
                raw = self.literal(value)
                if key in {"ge", "le", "gt", "lt", "multiple_of"}:
                    if type(raw) not in {int, float} or type(bound) not in {int, float}:
                        return self._model_constraint_failure(owner, field)
                    if type(raw) is float and not math.isfinite(raw) or type(bound) is float and not math.isfinite(bound):
                        return self._model_constraint_failure(owner, field)
                    if key == "multiple_of":
                        # Floating multiple tolerance differs across engines;
                        # admit exact integers only.
                        passed = type(raw) is int and type(bound) is int and bound > 0 and raw % bound == 0
                    else:
                        passed = {"ge": lambda: raw >= bound, "le": lambda: raw <= bound,
                                  "gt": lambda: raw > bound, "lt": lambda: raw < bound}[key]()
                    if not passed:
                        return self._model_constraint_failure(owner, field)
                elif key == "allow_inf_nan":
                    if type(bound) is not bool or not (
                            type(raw) is float or isinstance(raw, NonTextValue) and raw.kind == "float"):
                        return self._model_constraint_failure(owner, field)
                    if not bound and (type(raw) is not float or not math.isfinite(raw)):
                        return self._model_constraint_failure(owner, field)
                elif key in {"min_length", "max_length"}:
                    if type(bound) is not int or bound < 0:
                        return self._model_constraint_failure(owner, field)
                    if isinstance(value, StaticText):
                        lower = upper = len(value.value)
                    elif isinstance(value, (list, tuple)):
                        lower = upper = len(value)
                    elif isinstance(value, StaticMapping):
                        lower = upper = len(value.entries)
                    elif isinstance(value, (SequenceDomain, MappingDomain)) or (
                            isinstance(value, RuntimeInputText) and hasattr(value, "min_length")):
                        lower, upper = value.min_length, value.max_length
                    else:
                        return self._model_constraint_failure(owner, field)
                    if key == "min_length" and lower < bound or key == "max_length" and (upper is None or upper > bound):
                        return self._model_constraint_failure(owner, field)
                elif key == "pattern":
                    if not isinstance(bound, str) or not ascii_token_pattern(bound):
                        return self._model_constraint_failure(owner, field)
                    if isinstance(value, ValidatedToken) and value.pattern == bound:
                        continue
                    if not isinstance(value, StaticText) or len(value.value) > 4096:
                        return self._model_constraint_failure(owner, field)
                    if self._matches_model_pattern(bound, value.value) is not True:
                        return self._model_constraint_failure(owner, field)
        return value

