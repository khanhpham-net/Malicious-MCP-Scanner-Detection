"""Reviewed pure API transfer functions for the P abstract interpreter.

Only primitive abstract values are inspected. No target callable is invoked.
Unverified call shapes and lazy-iteration failures retain explicit boundaries.
"""
from __future__ import annotations
import ast
from .models import TraceStep
from .p_domains import NonTextValue, RuntimeInputText, BoundedInputText, SequenceDomain, MappingDomain
from .p_static import StaticText, UnresolvedValue
from .python_ast.index import location


class PureApiMixin:
    def api_unknown(self, module, node, code="P_OUTPUT_UNSUPPORTED_CALL"):
        return self.unknown(code, module, node)

    @staticmethod
    def duplicate_api_keywords(node):
        names = [k.arg for k in getattr(node, "keywords", ()) if k.arg is not None]
        return len(names) != len(set(names))

    def api_element(self, items):
        from .p_output_flow import PossibleValues
        return items[0] if len(items) == 1 else PossibleValues(tuple(items), None)

    def api_bounds(self, value):
        if isinstance(value, (SequenceDomain, MappingDomain)):
            return value.min_length, value.max_length
        items = self.sequence_items(value)
        return (len(items), len(items)) if items is not None else (None, None)

    def api_sequence(self, value):
        if isinstance(value, MappingDomain):
            return SequenceDomain(value.key, value.min_length, value.max_length)
        if isinstance(value, SequenceDomain):
            return value
        items = self.sequence_items(value)
        if items is None:
            return None
        return SequenceDomain(self.api_element(items), len(items), len(items))

    def builtin(self, module, node, name, args, kw):
        from .p_output_flow import StaticMapping, StaticSet, PossibleValues
        if self.duplicate_api_keywords(node):
            return self.api_unknown(module, node, "P_OUTPUT_INVALID_API_ARGUMENTS")
        if any(isinstance(v, PossibleValues) for v in kw.values()):
            names = tuple(kw)
            return self.lift(module, node, lambda *vs: self.builtin(
                module, node, name, args, dict(zip(names, vs))), *kw.values())

        invalid = lambda: self.api_unknown(module, node, "P_OUTPUT_INVALID_API_ARGUMENTS")
        unknown = lambda: self.api_unknown(module, node)

        # Validate call shapes before the inherited numeric summaries can
        # mistakenly choose a branch using an ignored keyword or argument.
        if name in {"len", "abs", "any", "all"} and (len(args) != 1 or kw):
            return invalid()
        if name in {"float", "bool", "list", "tuple", "set"} and (len(args) > 1 or kw):
            return invalid()
        if name == "range" and (not 1 <= len(args) <= 3 or kw):
            return invalid()
        if name == "isinstance" and (len(args) != 2 or kw):
            return invalid()

        if name == "bool" and not args:
            return False
        if name == "float":
            if not args:
                return 0.0
            value = args[0]
            if type(value) in {int, float, bool} or isinstance(value, StaticText):
                try:
                    return float(self.literal(value))
                except (ValueError, OverflowError):
                    return unknown()
            if isinstance(value, NonTextValue) and value.kind in {"float", "bool"}:
                return NonTextValue("float")
            return unknown()
        if name == "int":
            if len(args) > 2 or set(kw) - {"base"} or len(args) == 2 and "base" in kw:
                return invalid()
            base = args[1] if len(args) == 2 else kw.get("base")
            value = args[0] if args else 0
            if len(args) == 2 or "base" in kw:
                if not isinstance(value, StaticText) or type(base) is not int:
                    return unknown()
                try:
                    return int(value.value, base)
                except (ValueError, TypeError):
                    return unknown()
            if type(value) in {int, float, bool} or isinstance(value, StaticText):
                try:
                    return int(self.literal(value))
                except (ValueError, OverflowError):
                    return unknown()
            if isinstance(value, NonTextValue) and value.kind in {"int", "bool"}:
                return NonTextValue("int")
            return unknown()
        if name == "str":
            # Binary decoding/encoding overloads have separate semantics.
            if len(args) > 1 or kw:
                return unknown()
            if not args:
                return self.text_result(module, node, "")
        if name == "round":
            if len(args) > 2 or set(kw) - {"number", "ndigits"}:
                return invalid()
            if args and "number" in kw or len(args) == 2 and "ndigits" in kw:
                return invalid()
            if not args and "number" not in kw:
                return invalid()
            number = args[0] if args else kw["number"]
            digits = args[1] if len(args) == 2 else kw.get("ndigits")
            if digits is not None and not (type(digits) in {int, bool} or isinstance(digits, NonTextValue) and digits.kind in {"int", "bool"}):
                return invalid()
            if not self.numeric(number):
                return unknown()
            if type(number) in {int, float, bool} and (digits is None or type(digits) in {int, bool}):
                try:
                    return round(number, digits)
                except (ValueError, OverflowError):
                    return unknown()
            if isinstance(number, NonTextValue):
                if digits is None and number.kind not in {"int", "bool"}:
                    return unknown()
                return NonTextValue("int" if digits is None or number.kind in {"int", "bool"} else "number")
            return NonTextValue("number")
        if name == "len" and isinstance(args[0], (SequenceDomain, MappingDomain)):
            bounds = self.api_bounds(args[0])
            return bounds[0] if bounds[0] == bounds[1] else NonTextValue("int")
        if name in {"list", "tuple", "set"} and args and isinstance(args[0], (SequenceDomain, MappingDomain)):
            seq = self.api_sequence(args[0])
            if name == "set":
                element = seq.element
                if not isinstance(element, (StaticText, RuntimeInputText, NonTextValue)) and type(element) not in {int, float, bool, type(None)}:
                    return unknown()
                return SequenceDomain(element, 1 if seq.min_length else 0, seq.max_length)
            # A fresh outer container shares nested elements, as Python does.
            return SequenceDomain(seq.element, seq.min_length, seq.max_length)
        if name == "enumerate":
            if not 1 <= len(args) <= 2 or set(kw) - {"start"} or len(args) == 2 and "start" in kw:
                return invalid()
            start = args[1] if len(args) == 2 else kw.get("start", 0)
            if not (type(start) in {int, bool} or isinstance(start, NonTextValue) and start.kind in {"int", "bool"}):
                return invalid()
            items = self.sequence_items(args[0])
            if items is not None and type(start) in {int, bool}:
                return [(i, value) for i, value in enumerate(items, start)]
            seq = self.api_sequence(args[0])
            if seq is None:
                return unknown()
            return SequenceDomain((NonTextValue("int"), seq.element), seq.min_length, seq.max_length)
        if name == "zip":
            if set(kw) - {"strict"}:
                return invalid()
            strict = kw.get("strict", False)
            if not (type(strict) in {bool, int} or isinstance(strict, NonTextValue) and strict.kind in {"bool", "int"}):
                return unknown()
            if not args:
                return []
            lists = [self.sequence_items(value) for value in args]
            exact = all(value is not None for value in lists)
            bounds = [self.api_bounds(value) for value in args]
            equal = all(a is not None and a == b and a == bounds[0][0] for a, b in bounds)
            known_false = type(strict) in {bool, int} and not strict
            if not known_false and not equal:
                # zip is lazy: mismatch is an iteration boundary, not a raise
                # at construction. Retain a possible prefix and uncertainty.
                gap = self.api_unknown(module, node, "P_OUTPUT_STRICT_ZIP_LENGTH")
                if exact:
                    return PossibleValues((list(zip(*lists)),), gap)
                seqs = [self.api_sequence(value) for value in args]
                if all(v is not None for v in seqs):
                    element = tuple(v.element for v in seqs)
                    return PossibleValues((SequenceDomain(element),), gap)
                return gap
            if exact:
                return list(zip(*lists))
            seqs = [self.api_sequence(value) for value in args]
            if not all(v is not None for v in seqs):
                return unknown()
            lower = min(v.min_length for v in seqs)
            finite = [v.max_length for v in seqs if v.max_length is not None]
            upper = min(finite) if finite else None
            return SequenceDomain(tuple(v.element for v in seqs), lower, upper)
        if name in {"sum", "any", "all", "min", "max", "sorted", "collections.Counter"} and args and isinstance(args[0], MappingDomain):
            args = [self.api_sequence(args[0]), *args[1:]]
        return super().builtin(module, node, name, args, kw)

    def method(self, module, node, receiver, name, args, kw):
        from .p_output_flow import StaticMapping, PossibleValues
        if getattr(receiver, "p_loop_readonly", False) and name in {
                "append", "extend", "pop", "clear", "reverse", "update", "setdefault"}:
            return self.api_unknown(module, node, "P_OUTPUT_LOOP_REPRESENTATIVE_MUTATION")
        if isinstance(receiver, BoundedInputText):
            if name in {"strip", "lstrip", "rstrip", "split"}:
                receiver = BoundedInputText(receiver.code, receiver.span, 0, receiver.max_length)
            elif name in {"lower", "upper", "casefold", "replace"}:
                # Unicode case changes and replacement can change length.
                receiver = RuntimeInputText(receiver.code, receiver.span)
        if self.duplicate_api_keywords(node):
            return self.api_unknown(module, node, "P_OUTPUT_INVALID_API_ARGUMENTS")
        if isinstance(receiver, MappingDomain):
            if name == "copy" and not args and not kw:
                return MappingDomain(receiver.key, receiver.value, receiver.min_length, receiver.max_length)
            if name in {"keys", "values", "items"} and not args and not kw:
                element = receiver.key if name == "keys" else receiver.value if name == "values" else (receiver.key, receiver.value)
                return SequenceDomain(element, receiver.min_length, receiver.max_length)
            if name == "get" and 1 <= len(args) <= 2 and not kw:
                default = args[1] if len(args) == 2 else None
                if receiver.max_length == 0:
                    return default
                raw = self.literal(args[0])
                if isinstance(receiver.key, RuntimeInputText) and type(raw) in {int, float, bool, type(None)}:
                    return default
                if isinstance(receiver.key, NonTextValue) and isinstance(args[0], StaticText):
                    return default
                if not isinstance(args[0], (StaticText, RuntimeInputText, NonTextValue)) and type(raw) not in {int, float, bool, type(None)}:
                    return self.api_unknown(module, node, "P_OUTPUT_DYNAMIC_MAPPING_KEY")
                return PossibleValues((receiver.value, default), None)
            if name in {"copy", "get", "keys", "values", "items"}:
                return self.api_unknown(module, node, "P_OUTPUT_INVALID_API_ARGUMENTS")
        if isinstance(receiver, StaticMapping):
            if name == "copy" and not args and not kw:
                return StaticMapping(dict(receiver.entries))
            if name == "get" and 1 <= len(args) <= 2 and not kw:
                default = args[1] if len(args) == 2 else None
                lookup = getattr(self, "finite_mapping_lookup", None)
                if lookup is not None:
                    return lookup(module, node, receiver, args[0], default)
            if name == "setdefault" and 1 <= len(args) <= 2 and not kw:
                key = args[0]
                raw = self.literal(key)
                if type(raw) not in {str, int, float, bool, type(None)}:
                    return self.api_unknown(module, node, "P_OUTPUT_DYNAMIC_MAPPING_KEY")
                if raw not in receiver.entries:
                    receiver.entries[raw] = key, args[1] if len(args) == 2 else None
                return receiver.entries[raw][1]
            if name in {"copy", "get", "setdefault", "keys", "values", "items"} and (
                    kw or len(args) not in ({1, 2} if name in {"get", "setdefault"} else {0})):
                return self.api_unknown(module, node, "P_OUTPUT_INVALID_API_ARGUMENTS")
        loop_method = getattr(self, "loop_collection_method", None)
        if loop_method is not None:
            value = loop_method(module, node, receiver, name, args, kw)
            if value is not NotImplemented:
                return value
        if isinstance(receiver, (StaticText, RuntimeInputText)):
            noarg = {"lower", "upper", "casefold", "isdigit", "isdecimal", "isalnum"}
            if name in noarg and (args or kw):
                return self.api_unknown(module, node, "P_OUTPUT_INVALID_API_ARGUMENTS")
            if name in {"strip", "lstrip", "rstrip"} and (kw or len(args) > 1):
                return self.api_unknown(module, node, "P_OUTPUT_INVALID_API_ARGUMENTS")
            if name == "join" and (len(args) != 1 or kw):
                return self.api_unknown(module, node, "P_OUTPUT_INVALID_API_ARGUMENTS")
            if name == "replace" and (kw or not 2 <= len(args) <= 3):
                return self.api_unknown(module, node, "P_OUTPUT_INVALID_API_ARGUMENTS")
            if name == "split":
                if len(args) > 2 or set(kw) - {"sep", "maxsplit"} or args and "sep" in kw or len(args) == 2 and "maxsplit" in kw:
                    return self.api_unknown(module, node, "P_OUTPUT_INVALID_API_ARGUMENTS")
                sep = args[0] if args else kw.get("sep")
                limit = args[1] if len(args) == 2 else kw.get("maxsplit", -1)
                if not (sep is None or isinstance(sep, StaticText)) or type(limit) not in {int, bool}:
                    return self.api_unknown(module, node)
                if isinstance(sep, StaticText) and not sep.value:
                    return self.api_unknown(module, node)
                if isinstance(receiver, StaticText):
                    try:
                        return [StaticText(v, receiver.span, receiver.trace, receiver.limitations) for v in receiver.value.split(self.literal(sep), limit)]
                    except ValueError:
                        return self.api_unknown(module, node)
                return SequenceDomain(receiver)
            if name in {"startswith", "endswith"}:
                if kw or not 1 <= len(args) <= 3:
                    return self.api_unknown(module, node, "P_OUTPUT_INVALID_API_ARGUMENTS")
                if not isinstance(args[0], (StaticText, RuntimeInputText)) and not (
                        isinstance(args[0], tuple) and all(isinstance(v, (StaticText, RuntimeInputText)) for v in args[0])):
                    return self.api_unknown(module, node, "P_OUTPUT_INVALID_API_ARGUMENTS")
                if any(v is not None and type(v) not in {int, bool} and not (
                        isinstance(v, NonTextValue) and v.kind in {"int", "bool"}) for v in args[1:]):
                    return self.api_unknown(module, node, "P_OUTPUT_INVALID_API_ARGUMENTS")
                if isinstance(receiver, StaticText):
                    prefix = args[0]
                    if isinstance(prefix, StaticText):
                        prefix = prefix.value
                    elif isinstance(prefix, tuple) and all(isinstance(v, StaticText) for v in prefix):
                        prefix = tuple(v.value for v in prefix)
                    else:
                        return self.api_unknown(module, node)
                    rest = args[1:]
                    if any(v is not None and type(v) not in {int, bool} for v in rest):
                        return self.api_unknown(module, node)
                    return getattr(receiver.value, name)(prefix, *rest)
                return NonTextValue("bool")
        return super().method(module, node, receiver, name, args, kw)

