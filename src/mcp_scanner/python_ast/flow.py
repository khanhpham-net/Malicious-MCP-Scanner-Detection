"""Small abstract values for static source, guard and call evidence."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from pathlib import PureWindowsPath
import re
from typing import Any

from ..models import TraceStep

_SHELL_WORD = re.compile(r"[A-Za-z0-9_.:\-]+")

@dataclass
class Value:
    constant: Any = None
    ref: str = ""
    marks: dict[str, tuple[TraceStep, ...]] = field(default_factory=dict)
    temporary_path: bool = False
    string_options: tuple[str, ...] = ()
    text_kind: str = ""
    shell_word: bool = False
    shell_parts: tuple[str | Value, ...] = ()
    unresolved_callable: bool = False
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
        return replace(self, marks=marks, shell_word=self.shell_word or name == "shell_safe_arg")

    def is_shell_word(self) -> bool:
        if isinstance(self.constant, str):
            return bool(_SHELL_WORD.fullmatch(self.constant))
        return self.text_kind == "str" and self.shell_word

    def text_type(self) -> str:
        return type(self.constant).__name__ if isinstance(self.constant, (str, bytes)) else self.text_kind

    def without_shell_guard(self) -> Value:
        if not self.shell_word and "shell_safe_arg" not in self.marks:
            return self
        marks = dict(self.marks)
        guarded = marks.pop("shell_safe_arg", None)
        if guarded is not None:
            marks.setdefault("input", guarded)
        return replace(self, marks=marks, shell_word=False)


def combine(*values: Value) -> Value:
    marks = {}
    for value in values:
        for kind, steps in value.marks.items():
            marks.setdefault(kind, steps)
    return Value(marks=marks)


def within_temporary_path(base: Value, components: Iterable[Value]) -> bool:
    if not base.temporary_path:
        return False
    for component in components:
        if not isinstance(component.constant, str):
            return False
        # Windows path parsing recognizes drive and UNC roots as well as both separators.
        path = PureWindowsPath(component.constant)
        if path.anchor or ".." in path.parts:
            return False
    return True


def joined(left: Value, right: Value) -> Value:
    if left is right:
        return left
    result = combine(left, right)
    result.temporary_path = left.temporary_path and right.temporary_path
    result.unresolved_callable = left.unresolved_callable or right.unresolved_callable
    result.shell_word = (
        (left.shell_word or left.is_shell_word()) and (right.shell_word or right.is_shell_word())
    )
    if left.text_type() == right.text_type():
        result.text_kind = left.text_type()
    if left.ref == right.ref:
        result.ref = left.ref
    if left.constant == right.constant:
        result.constant = left.constant
    if result.constant is None:
        options_left = (left.constant,) if isinstance(left.constant, str) else left.string_options
        options_right = (right.constant,) if isinstance(right.constant, str) else right.string_options
        if options_left and options_right:
            alternatives = tuple(dict.fromkeys((*options_left, *options_right)))
            if len(alternatives) <= 8 and all(len(option) <= 4096 for option in alternatives):
                result.string_options = alternatives
    if left.items and len(left.items) == len(right.items):
        result.items = tuple(joined(a, b) for a, b in zip(left.items, right.items))
    if left.fields or right.fields:
        result.fields = {k: joined(left.fields.get(k, Value()), right.fields.get(k, Value()))
                         for k in left.fields.keys() | right.fields.keys()}
    return result
