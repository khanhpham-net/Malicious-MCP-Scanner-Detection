"""Structured input shapes and finite selection; no target models are executed."""
from __future__ import annotations

import ast
from copy import deepcopy

from .models import SourceSpan
from .p_domains import MappingDomain, NonTextValue, RuntimeInputText, SequenceDomain, RaisedValue
from .p_static import StaticText, UnresolvedValue
from .python_ast.index import dotted, location
from .p_model_constraints import ModelConstraintMixin

_MISSING = object()


class StructuredFlowMixin(ModelConstraintMixin):
    """Extend reviewed abstract operations, never infer safety from a type name."""

    def _annotation_shadowed(self, *roots):
        return any(name == root or name.startswith(root + ".")
                   for name in self.module_paths for root in roots)

    def input_value(self, module, node, active=None):
        active = set() if active is None else active
        if isinstance(node, ast.Subscript):
            origin = self.canonical_symbol(module, dotted(node.value))
            args = list(node.slice.elts) if isinstance(node.slice, ast.Tuple) else [node.slice]
            if origin in {"dict", "typing.Dict", "typing.Mapping", "typing.MutableMapping",
                          "collections.abc.Mapping", "collections.abc.MutableMapping"}:
                if self._annotation_shadowed("mcp", "fastmcp", "typing", "collections"):
                    return self.unknown("P_OUTPUT_UNVERIFIED_INPUT_CONTRACT", module, node)
                if origin == "dict" and not self.safe_builtin_factory(module, node.value):
                    return self.unknown("P_OUTPUT_UNVERIFIED_INPUT_CONTRACT", module, node)
                if len(args) != 2:
                    return self.unknown("P_OUTPUT_UNMODELED_MAPPING_INPUT", module, node)
                return MappingDomain(self.input_value(module, args[0], active),
                                     self.input_value(module, args[1], active))
            if origin in {"tuple", "typing.Tuple"} and not (
                    len(args) == 2 and isinstance(args[1], ast.Constant) and args[1].value is Ellipsis):
                if self._annotation_shadowed("mcp", "fastmcp", "typing"):
                    return self.unknown("P_OUTPUT_UNVERIFIED_INPUT_CONTRACT", module, node)
                if origin == "tuple" and not self.safe_builtin_factory(module, node.value):
                    return self.unknown("P_OUTPUT_UNVERIFIED_INPUT_CONTRACT", module, node)
                if len(args) > self.MAX_ALTERNATIVES:
                    return self.unknown("P_OUTPUT_TUPLE_DOMAIN_LIMIT", module, node)
                return tuple(self.input_value(module, arg, active) for arg in args)
            if origin in {"typing.Optional", "typing.Union"}:
                if self._annotation_shadowed("typing"):
                    return self.unknown("P_OUTPUT_UNVERIFIED_INPUT_CONTRACT", module, node)
                if origin == "typing.Optional" and len(args) != 1 or not args:
                    return self.unknown("P_OUTPUT_UNMODELED_INPUT", module, node)
                from .p_output_flow import PossibleValues
                values = [self.input_value(module, arg, active) for arg in args]
                if origin == "typing.Optional":
                    values.append(None)
                return PossibleValues(tuple(values), None)
        return super().input_value(module, node, active)

    def simple_model(self, module, cls):
        # Pydantic field aliases/extra allow/default validation have different
        # binding semantics. Do not silently accept these as ordinary fields.
        if any(not isinstance(k.value, ast.Constant) or type(k.value.value) is not bool
               or k.arg not in {"frozen", "strict"} for k in cls.keywords):
            return False
        clone = deepcopy(cls)
        clone.keywords = []
        if not super().simple_model(module, clone):
            return False
        for stmt in cls.body:
            if isinstance(stmt, ast.AnnAssign):
                if not isinstance(stmt.target, ast.Name) or stmt.target.id.startswith("_"):
                    return False
                if any(isinstance(n, ast.Call) and any(
                        k.arg == "alias" and not (isinstance(k.value, ast.Constant) and isinstance(k.value.value, str))
                        or k.arg == "frozen" and not (
                            isinstance(k.value, ast.Constant) and k.value.value is False)
                        for k in n.keywords)
                       for expr in (stmt.annotation, stmt.value) if expr is not None
                       for n in ast.walk(expr)):
                    return False
                if self.canonical_symbol(module, dotted(
                        stmt.annotation.value if isinstance(stmt.annotation, ast.Subscript) else stmt.annotation)) in {
                            "typing.ClassVar", "typing.Final"}:
                    return False
                if isinstance(stmt.value, ast.Call):
                    for kw in stmt.value.keywords:
                        if kw.arg in {"alias", "default_factory"}:
                            if kw.arg == "alias":
                                if not isinstance(kw.value, ast.Constant) or not isinstance(kw.value.value, str):
                                    return False
                            elif not self.safe_builtin_factory(module, kw.value):
                                return False
            if isinstance(stmt, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "model_config" for t in stmt.targets):
                config = stmt.value
                if not isinstance(config, ast.Call):
                    return False
                for kw in config.keywords:
                    if kw.arg == "extra" and not (isinstance(kw.value, ast.Constant)
                                                 and kw.value.value in {"forbid", "ignore"}):
                        return False
                    if kw.arg in {"strict", "frozen"} and not (
                            isinstance(kw.value, ast.Constant) and type(kw.value.value) is bool):
                        return False
        return True

    def _model_frozen(self, cls):
        for kw in cls.keywords:
            if kw.arg == "frozen" and isinstance(kw.value, ast.Constant):
                return kw.value.value is True
        for stmt in cls.body:
            if isinstance(stmt, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "model_config" for t in stmt.targets):
                if isinstance(stmt.value, ast.Call):
                    for kw in stmt.value.keywords:
                        if kw.arg == "frozen" and isinstance(kw.value, ast.Constant):
                            return kw.value.value is True
        return False

    def model_input(self, module, cls, active):
        result = super().model_input(module, cls, active)
        from .p_output_flow import StaticInstance
        if isinstance(result, StaticInstance):
            result.p_frozen = self._model_frozen(cls)
        return result

    def _model_field_value(self, module, annotation, value, active):
        """Only identity-preserving validated field assignments are certified.

        Unsupported coercions and validators stay unresolved rather than
        claiming the constructor succeeded with a different runtime value.
        """
        from .p_output_flow import PossibleValues, StaticMapping, StaticInstance
        if isinstance(value, PossibleValues):
            parts = [self._model_field_value(module, annotation, v, active) for v in value.values]
            return PossibleValues(tuple(parts), value.uncertainty)
        resolved = self._model_alias_expression(module, annotation)
        if resolved is None:
            return self.unknown("P_OUTPUT_MODEL_VALIDATION", module, annotation)
        owner, resolved_annotation = resolved
        if owner is not module or resolved_annotation is not annotation:
            return self._model_field_value(owner, resolved_annotation, value, active)
        if isinstance(annotation, ast.Constant) and annotation.value is None:
            return None if value is None else self.unknown("P_OUTPUT_MODEL_VALIDATION", module, annotation)
        if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
            return self._model_union_value(module, annotation,
                                           (annotation.left, annotation.right), value, active)
        if isinstance(annotation, ast.Subscript):
            origin = self.canonical_symbol(module, dotted(annotation.value))
            args = list(annotation.slice.elts) if isinstance(annotation.slice, ast.Tuple) else [annotation.slice]
            if origin in {"list", "tuple", "dict"} and not self.safe_builtin_factory(module, annotation.value):
                return self.unknown("P_OUTPUT_MODEL_VALIDATION", module, annotation)
            if any(origin.startswith(root + ".") and self._annotation_shadowed(root)
                   for root in ("typing", "typing_extensions", "collections")):
                return self.unknown("P_OUTPUT_MODEL_VALIDATION", module, annotation)
            if origin in {"typing.Annotated", "typing_extensions.Annotated"} and args:
                if not self.safe_annotation_metadata(module, annotation):
                    return self.unknown("P_OUTPUT_MODEL_VALIDATION", module, annotation)
                checked = self._model_field_value(module, args[0], value, active)
                return self._apply_model_metadata(module, args[1:], checked)
            if origin in {"typing.Optional", "typing.Union"}:
                if origin == "typing.Optional":
                    if len(args) != 1:
                        return self.unknown("P_OUTPUT_MODEL_VALIDATION", module, annotation)
                    args = [args[0], ast.copy_location(ast.Constant(value=None), annotation)]
                return self._model_union_value(module, annotation, args, value, active)
            if origin in {"typing.Literal", "typing_extensions.Literal"}:
                raw = self.literal(value)
                if all(isinstance(a, ast.Constant) for a in args) and type(raw) in {str, int, float, bool, type(None)}:
                    if any(type(a.value) is type(raw) and a.value == raw for a in args):
                        return value
                return self.unknown("P_OUTPUT_MODEL_VALIDATION", module, annotation)
            if origin in {"list", "typing.List", "typing.Sequence"} and len(args) == 1:
                if isinstance(value, list):
                    return [self._model_field_value(module, args[0], v, active) for v in value]
                if isinstance(value, SequenceDomain):
                    return SequenceDomain(self._model_field_value(module, args[0], value.element, active),
                                          value.min_length, value.max_length)
            if origin in {"tuple", "typing.Tuple"}:
                if len(args) == 2 and isinstance(args[1], ast.Constant) and args[1].value is Ellipsis:
                    if isinstance(value, tuple):
                        return tuple(self._model_field_value(module, args[0], v, active) for v in value)
                    if isinstance(value, SequenceDomain):
                        return SequenceDomain(self._model_field_value(module, args[0], value.element, active),
                                              value.min_length, value.max_length)
                elif isinstance(value, tuple) and len(value) == len(args):
                    return tuple(self._model_field_value(module, a, v, active) for a, v in zip(args, value))
            if origin in {"dict", "typing.Dict", "typing.Mapping", "typing.MutableMapping",
                          "collections.abc.Mapping", "collections.abc.MutableMapping"} and len(args) == 2:
                if isinstance(value, StaticMapping):
                    fields = {}
                    for raw, (key, member) in value.entries.items():
                        new_key = self._model_field_value(module, args[0], key, active)
                        new_value = self._model_field_value(module, args[1], member, active)
                        fields[raw] = (new_key, new_value)
                    return StaticMapping(fields)
                if isinstance(value, MappingDomain):
                    return MappingDomain(self._model_field_value(module, args[0], value.key, active),
                                         self._model_field_value(module, args[1], value.value, active),
                                         value.min_length, value.max_length)
        symbol = self.canonical_symbol(module, dotted(annotation))
        if symbol in {"str", "int", "float", "bool"}:
            domain = self.input_value(module, annotation, active)
            if symbol == "str":
                known = isinstance(domain, RuntimeInputText)
            else:
                known = isinstance(domain, NonTextValue) and domain.kind == symbol
            if not known:
                return self.unknown("P_OUTPUT_MODEL_VALIDATION", module, annotation)
        if symbol == "str" and isinstance(value, (StaticText, RuntimeInputText)):
            return value
        if symbol in {"int", "float", "bool"}:
            compatible = type(value).__name__ == symbol or symbol == "float" and type(value) is int
            if isinstance(value, NonTextValue):
                compatible = value.kind == symbol or symbol == "float" and value.kind == "int"
            if compatible:
                if symbol == "float" and type(value) is int:
                    try:
                        return float(value)
                    except OverflowError:
                        return self.unknown("P_OUTPUT_MODEL_VALIDATION", module, annotation)
                if symbol == "float" and isinstance(value, NonTextValue) and value.kind == "int":
                    return NonTextValue("float")
                return value
        found = self.lookup(module, symbol)
        if found and isinstance(found[1], ast.ClassDef) and self.simple_model(*found):
            target, cls = found
            if isinstance(value, StaticInstance) and value.path == target.path and value.class_name == cls.name:
                return value
            if isinstance(value, StaticMapping) and (target.path, cls.name) not in active:
                return self._construct_checked_model(module, annotation, target, cls, [], {
                    key: member for key, (_, member) in value.entries.items()},
                    active | {(target.path, cls.name)})
        return self.unknown("P_OUTPUT_MODEL_VALIDATION", module, annotation)

    def _construct_checked_model(self, caller, node, target, cls, args, kw, active):
        from .p_output_flow import StaticInstance
        if args or not self.simple_model(target, cls):
            return self.unknown("P_OUTPUT_UNMODELED_CONSTRUCTOR", caller, node)
        if isinstance(node, ast.Call):
            names = [k.arg for k in node.keywords]
            if None in names or len(names) != len(set(names)):
                return self.unknown("P_OUTPUT_ARGUMENT_BINDING", caller, node)
        fields = {}
        for field in cls.body:
            if not isinstance(field, ast.AnnAssign) or not isinstance(field.target, ast.Name):
                continue
            if any(isinstance(n, ast.Call) and any(k.arg == "alias" for k in n.keywords)
                   for expr in (field.annotation, field.value) if expr is not None for n in ast.walk(expr)):
                return self.unknown("P_OUTPUT_MODEL_FIELD_ALIAS", caller, node)
            name = field.target.id
            if name in kw:
                value = self._model_field_value(target, field.annotation, kw[name], active)
                if isinstance(field.value, ast.Call):
                    value = self._apply_model_metadata(target, [field.value], value)
                # An invalid or unmodeled field cannot make an instance that
                # later returns a different field look completely understood.
                if self._contains_invalid_model_value(value):
                    return self.unknown("P_OUTPUT_MODEL_VALIDATION", caller, node)
                fields[name] = value
            elif field.value is not None and not (
                    isinstance(field.value, ast.Constant) and field.value.value is Ellipsis):
                if isinstance(field.value, ast.Call):
                    value = self.field_default(target, field.value)
                else:
                    value = self.value(target, field.value, self.module_environment(target.path))
                if isinstance(value, UnresolvedValue):
                    return self.unknown("P_OUTPUT_MODEL_VALIDATION", caller, node)
                fields[name] = value
            else:
                return self.unknown("P_OUTPUT_ARGUMENT_BINDING", caller, node)
        if set(kw) - set(fields):
            return self.unknown("P_OUTPUT_ARGUMENT_BINDING", caller, node)
        result = StaticInstance(target.path, cls.name, fields)
        result.p_frozen = self._model_frozen(cls)
        return result

    def _contains_invalid_model_value(self, value):
        from .p_output_flow import PossibleValues, StaticMapping
        if isinstance(value, RuntimeInputText):
            return False
        if isinstance(value, UnresolvedValue):
            return True
        if isinstance(value, PossibleValues):
            return value.uncertainty is not None or any(self._contains_invalid_model_value(v) for v in value.values)
        if isinstance(value, SequenceDomain):
            return self._contains_invalid_model_value(value.element)
        if isinstance(value, MappingDomain):
            return self._contains_invalid_model_value(value.key) or self._contains_invalid_model_value(value.value)
        if isinstance(value, StaticMapping):
            return any(self._contains_invalid_model_value(v) for pair in value.entries.values() for v in pair)
        if isinstance(value, (list, tuple)):
            return any(self._contains_invalid_model_value(v) for v in value)
        return False

    def construct_model(self, caller, node, target, cls, args, kw):
        return self._construct_checked_model(caller, node, target, cls, args, kw, set())

    def _key_matches_domain(self, key, raw):
        if isinstance(key, RuntimeInputText):
            return type(raw) is str
        if isinstance(key, NonTextValue):
            return type(raw) in {int, float, bool}
        literal = self.literal(key)
        return type(literal) in {str, int, float, bool, type(None)} and literal == raw

    def finite_mapping_lookup(self, module, node, receiver, key, default=_MISSING):
        """All stored candidates plus a genuine absent-key/error alternative."""
        from .p_output_flow import PossibleValues
        if isinstance(key, (list, MappingDomain)):
            return RaisedValue("TypeError", StaticText("unhashable key", location(module.path, node)),
                               location(module.path, node))
        literal = self.literal(key)
        scalar = type(literal) in {str, int, float, bool, type(None)}
        if scalar:
            if literal in receiver.entries:
                return receiver.entries[literal][1]
            return default if default is not _MISSING else RaisedValue(
                "KeyError", key, location(module.path, node))
        if isinstance(key, (RuntimeInputText, NonTextValue)):
            candidates = [v for raw, (_, v) in receiver.entries.items() if self._key_matches_domain(key, raw)]
            absent = default if default is not _MISSING else RaisedValue(
                "KeyError", key, location(module.path, node))
            return PossibleValues(tuple(candidates + [absent]), None)
        return PossibleValues(tuple(v for _, v in receiver.entries.values()),
                              self.unknown("P_OUTPUT_DYNAMIC_SUBSCRIPT", module, node))

    def structured_subscript(self, module, node, receiver, key):
        from .p_output_flow import StaticMapping, PossibleValues
        if isinstance(receiver, StaticMapping) and not isinstance(node.slice, ast.Slice):
            return self.finite_mapping_lookup(module, node, receiver, key)
        if isinstance(receiver, MappingDomain) and not isinstance(node.slice, ast.Slice):
            if isinstance(key, (list, MappingDomain, StaticMapping)):
                return RaisedValue("TypeError", StaticText("unhashable key", location(module.path, node)),
                                   location(module.path, node))
            if not isinstance(key, (StaticText, RuntimeInputText, NonTextValue)) and type(key) not in {int, float, bool, type(None)}:
                return self.unknown("P_OUTPUT_DYNAMIC_SUBSCRIPT", module, node)
            missing = RaisedValue("KeyError", key, location(module.path, node))
            if receiver.max_length == 0:
                return missing
            return PossibleValues((receiver.value, missing), None)
        if isinstance(receiver, (list, tuple)):
            if isinstance(node.slice, ast.Slice):
                return receiver[key] if isinstance(key, slice) else NotImplemented
            if type(key) is int:
                return receiver[key] if -len(receiver) <= key < len(receiver) else RaisedValue(
                    "IndexError", StaticText("tuple index out of range", location(module.path, node)),
                    location(module.path, node))
            if isinstance(key, NonTextValue) and key.kind == "int":
                return PossibleValues(tuple(receiver) + (RaisedValue(
                    "IndexError", StaticText("tuple index out of range", location(module.path, node)),
                    location(module.path, node)),), None)
        if isinstance(receiver, SequenceDomain) and not isinstance(node.slice, ast.Slice):
            if type(key) is int:
                distance = key + 1 if key >= 0 else -key
                missing = RaisedValue("IndexError", StaticText("list index out of range", location(module.path, node)),
                                      location(module.path, node))
                if receiver.max_length is not None and distance > receiver.max_length:
                    return missing
                if distance <= receiver.min_length:
                    return receiver.element
                return PossibleValues((receiver.element, missing), None)
            if isinstance(key, NonTextValue) and key.kind == "int":
                return PossibleValues((receiver.element, RaisedValue(
                    "IndexError", StaticText("list index out of range", location(module.path, node)),
                    location(module.path, node))), None)
        return NotImplemented

    def structured_bind_subscript(self, module, node, receiver, key, value):
        """Weak update of an unknown mapping shape; aliases keep object identity."""
        from .p_output_flow import PossibleValues
        if not isinstance(receiver, MappingDomain):
            return False
        if not isinstance(key, (StaticText, RuntimeInputText, NonTextValue)) and type(key) not in {int, float, bool, type(None)}:
            return False
        def union(previous, assigned):
            values = []
            for part in (previous, assigned):
                if isinstance(part, PossibleValues) and part.uncertainty is None:
                    values.extend(part.values)
                else:
                    values.append(part)
            unique = {}
            for part in values:
                unique[self.semantic_key(part)] = part
            return next(iter(unique.values())) if len(unique) == 1 else PossibleValues(tuple(unique.values()), None)
        receiver.key = union(receiver.key, key)
        receiver.value = union(receiver.value, value)
        receiver.min_length = max(1, receiver.min_length)
        if receiver.max_length is not None:
            receiver.max_length += 1
        return True

    def expression_value(self, module, node, env):
        if not isinstance(node, ast.Subscript):
            return super().expression_value(module, node, env)
        receiver = self.value(module, node.value, env)
        if isinstance(node.slice, ast.Slice):
            bounds = [self.value(module, v, env) if v is not None else None
                      for v in (node.slice.lower, node.slice.upper, node.slice.step)]
            if isinstance(receiver, tuple) and all(v is None or type(v) is int for v in bounds):
                if bounds[2] == 0:
                    return RaisedValue("ValueError", StaticText("slice step cannot be zero", location(module.path, node)),
                                       location(module.path, node))
                return receiver[slice(*bounds)]
            key = None
            cache = {(id(node.value), id(env)): receiver}
            cache.update({(id(v), id(env)): value for v, value in zip(
                (node.slice.lower, node.slice.upper, node.slice.step), bounds) if v is not None})
        else:
            key = self.value(module, node.slice, env)
            cache = {(id(node.value), id(env)): receiver, (id(node.slice), id(env)): key}
            from .p_output_flow import PossibleValues
            if isinstance(receiver, PossibleValues) or isinstance(key, PossibleValues):
                def selected(r, k):
                    value = self.structured_subscript(module, node, r, k)
                    return value if value is not NotImplemented else self.unknown("P_OUTPUT_DYNAMIC_SUBSCRIPT", module, node)
                return self.lift(module, node, selected, receiver, key)
            result = self.structured_subscript(module, node, receiver, key)
            if result is not NotImplemented:
                return result
        self.expression_caches.append(cache)
        try:
            return super().expression_value(module, node, env)
        finally:
            self.expression_caches.pop()

