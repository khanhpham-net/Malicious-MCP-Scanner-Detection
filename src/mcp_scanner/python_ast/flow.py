"""Small abstract values for static source, guard and call evidence."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from ..models import TraceStep


@dataclass
class Value:
    constant: Any = None
    ref: str = ""
    marks: dict[str, tuple[TraceStep, ...]] = field(default_factory=dict)
    posix_quoted_command: bool = False
    bound_to: Value | None = None
    super_after: str = ""
    choices: tuple[Value, ...] = ()
    items: tuple[Value, ...] = ()
    fields: dict[str, Value] = field(default_factory=dict)

    def mark(self, name: str, step: TraceStep) -> Value:
        return replace(self, marks={**self.marks, name: (step,)})

    def through(self, step: TraceStep) -> Value:
        return replace(self, marks={k: (v + (step,))[:24] for k, v in self.marks.items()})

    def guarded(self, name: str, step: TraceStep) -> Value:
        marks = dict(self.marks)
        if "input" in marks:
            marks[name] = (marks.pop("input") + (step,))[:24]
        return replace(self, marks=marks)


def combine(*values: Value) -> Value:
    marks = {}
    for value in values:
        for kind, steps in value.marks.items():
            marks.setdefault(kind, steps)
    return Value(marks=marks)


def joined(left: Value, right: Value) -> Value:
    if left is right:
        return left
    result = combine(left, right)
    result.posix_quoted_command = left.posix_quoted_command and right.posix_quoted_command
    if left.ref == right.ref:
        result.ref = left.ref
    if left.constant == right.constant:
        result.constant = left.constant
    if left.items and len(left.items) == len(right.items):
        result.items = tuple(joined(a, b) for a, b in zip(left.items, right.items))
    if left.fields or right.fields:
        result.fields = {k: joined(left.fields.get(k, Value()), right.fields.get(k, Value()))
                         for k in left.fields.keys() | right.fields.keys()}
    return result
