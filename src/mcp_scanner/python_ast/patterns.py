"""Conservative pattern matching for the subset visible in the abstract value domain."""

import ast

from .flow import Value, combine, joined


def match_pattern(pattern: ast.pattern, subject: Value) -> tuple[bool | None, dict[str, Value]]:
    """Return feasibility and bindings for a single pattern."""
    if isinstance(pattern, ast.MatchAs):
        feasible, names = match_pattern(pattern.pattern, subject) if pattern.pattern else (True, {})
        if pattern.name:
            names[pattern.name] = subject
        return feasible, names
    if isinstance(pattern, ast.MatchOr):
        candidates: list[dict[str, Value]] = []
        for option in pattern.patterns:
            feasible, names = match_pattern(option, subject)
            if feasible is not False:
                candidates.append(names)
            if feasible is True:
                break
        if not candidates:
            return False, {}
        merged = candidates[0].copy()
        for candidate in candidates[1:]:
            for key in merged.keys() | candidate.keys():
                merged[key] = joined(merged.get(key, Value()), candidate.get(key, Value()))
        return feasible if feasible is True else None, merged
    if isinstance(pattern, ast.MatchValue):
        if isinstance(pattern.value, ast.Constant) and subject.constant is not None:
            return subject.constant == pattern.value.value, {}
        return None, {}
    if isinstance(pattern, ast.MatchSingleton):
        return subject.constant is pattern.value if subject.constant is not None else None, {}
    if isinstance(pattern, ast.MatchStar):
        return True, {pattern.name: subject} if pattern.name else {}
    if isinstance(pattern, ast.MatchSequence):
        if isinstance(subject.constant, (str, bytes)):
            return False, {}
        star = next((i for i, item in enumerate(pattern.patterns) if isinstance(item, ast.MatchStar)), None)
        if subject.items:
            size = len(pattern.patterns)
            if len(subject.items) < size - (star is not None) or (star is None and len(subject.items) != size):
                return False, {}
            if star is None:
                values = subject.items
            else:
                end = len(subject.items) - (size - star - 1)
                captured = subject.items[star:end]
                sequence = Value(ref="list", items=captured, marks=combine(*captured).marks)
                values = (*subject.items[:star], sequence, *subject.items[end:])
            return _match_children(zip(pattern.patterns, values))
        return _match_children(((child, combine(subject)) for child in pattern.patterns), exact=False)
    if isinstance(pattern, ast.MatchMapping):
        children = (
            (child, subject.fields.get(key.value, combine(subject)) if isinstance(key, ast.Constant)
             and isinstance(key.value, str) else combine(subject))
            for key, child in zip(pattern.keys, pattern.patterns)
        )
        feasible, names = _match_children(children, exact=False)
        if pattern.rest:
            consumed = {key.value for key in pattern.keys if isinstance(key, ast.Constant) and isinstance(key.value, str)}
            fields = {key: value for key, value in subject.fields.items() if key not in consumed}
            names[pattern.rest] = Value(ref="dict", fields=fields, marks=combine(*fields.values()).marks
                                        if subject.fields else subject.marks)
        return feasible, names
    if isinstance(pattern, ast.MatchClass):
        children = [(child, combine(subject)) for child in pattern.patterns]
        children.extend((child, subject.fields.get(attr, combine(subject)))
                        for attr, child in zip(pattern.kwd_attrs, pattern.kwd_patterns))
        return _match_children(children, exact=False)
    return None, {}


def _match_children(children, *, exact=True):
    names = {}
    for pattern, value in children:
        feasible, bindings = match_pattern(pattern, value)
        if feasible is False:
            return False, {}
        exact = exact and feasible is True
        names.update(bindings)
    return True if exact else None, names


def pattern_constants(pattern: ast.pattern) -> tuple[str | int, ...]:
    if isinstance(pattern, ast.MatchValue) and isinstance(pattern.value, ast.Constant):
        value = pattern.value.value
        return (value,) if type(value) in (str, int) else ()
    if isinstance(pattern, ast.MatchOr):
        choices = [pattern_constants(child) for child in pattern.patterns]
        if all(choices):
            values = tuple(value for choice in choices for value in choice)
            return values if len(values) <= 8 else ()
    return ()
