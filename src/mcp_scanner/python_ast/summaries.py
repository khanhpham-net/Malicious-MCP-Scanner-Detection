"""Bounded, context-sensitive return and worker-effect summaries for first-party calls."""

from dataclasses import dataclass, field
from typing import Callable

from .flow import Value, joined


class DeferredCall(Exception):
    """A recursive context has not produced a return value in the current approximation."""


class SummaryBudgetReached(Exception):
    """The configured recursion summary bound was exceeded."""


def value_key(value: Value, depth: int = 0):
    """Compare abstract semantics and source locations, without recursion-dependent trace prefixes."""
    sources = tuple(sorted(
        (name, steps[0].span.path, steps[0].span.start_line, steps[0].span.start_col)
        for name, steps in value.marks.items() if steps
    ))
    scalar = (type(value.constant).__name__, repr(value.constant))
    if depth >= 4:
        return scalar, value.ref, sources
    nested = depth + 1
    return (
        scalar, value.ref, sources, value.text_kind, value.shell_word, value.temporary_path,
        value.string_options, value.unresolved_callable,
        tuple(value_key(item, nested) for item in value.items[:32]),
        tuple((key, value_key(v, nested)) for key, v in sorted(value.fields.items())[:32]),
        tuple(part if isinstance(part, str) else value_key(part, nested) for part in value.shell_parts),
        tuple(value_key(choice, nested) for choice in value.choices[:8]),
        value_key(value.bound_to, nested) if value.bound_to is not None else (),
    )


@dataclass
class Summary:
    returned: Value | None = None
    effects: list = field(default_factory=list)


class SummarySolver:
    def __init__(self, tick: Callable[[], None]):
        self.tick = tick
        self.memo: dict[tuple, Summary] = {}
        self.active: set[tuple] = set()
        self.visited: set[tuple] = set()
        self.recursion = False
        self.changed = False

    def solve(self, root: Callable[[], Value]) -> Value:
        latest = None
        for _ in range(6):
            self.tick()
            self.visited.clear()
            self.changed = False
            try:
                latest = root()
            except DeferredCall:
                pass
            if not self.recursion or not self.changed:
                if latest is not None:
                    return latest
                break
        raise SummaryBudgetReached

    def evaluate(self, key: tuple, evaluate, effect_output: list | None) -> Value:
        self.tick()
        if key not in self.memo:
            if len(self.memo) >= 64:
                raise SummaryBudgetReached
            self.memo[key] = Summary()
        summary = self.memo[key]
        cycle = key in self.active
        if cycle:
            self.recursion = True
        if not cycle and key not in self.visited:
            if len(self.active) >= 24:
                raise SummaryBudgetReached
            self.active.add(key)
            self.visited.add(key)
            boundary = len(effect_output) if effect_output is not None else 0
            try:
                returned = evaluate()
            finally:
                self.active.remove(key)
            if returned is not None and (
                summary.returned is None or value_key(summary.returned) != value_key(returned)
            ):
                merged = returned if summary.returned is None else joined(summary.returned, returned)
                if summary.returned is None or value_key(summary.returned) != value_key(merged):
                    summary.returned = merged
                    self.changed = True
            if effect_output is not None:
                for effect in effect_output[boundary:]:
                    if effect not in summary.effects:
                        summary.effects.append(effect)
                        self.changed = True
        if effect_output is not None:
            effect_output.extend(effect for effect in summary.effects if effect not in effect_output)
        if summary.returned is None:
            raise DeferredCall
        return summary.returned
