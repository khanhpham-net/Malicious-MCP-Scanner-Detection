"""Private, alias-preserving accumulator domains for proved finite loops."""
from __future__ import annotations

from dataclasses import dataclass

from .p_domains import MappingDomain, SequenceDomain


class LoopLiteralList(list):
    """A fresh list expression, eligible for a guarded read-only snapshot."""

    p_loop_readonly = False


@dataclass(frozen=True)
class LoopSequence(SequenceDomain):
    """A local list's possible elements, with shared abstract heap identity."""

    def update_element(self, value):
        object.__setattr__(self, "element", value)

    def update_bounds(self, lower, upper):
        object.__setattr__(self, "min_length", lower)
        object.__setattr__(self, "max_length", upper)


@dataclass
class LoopMapping(MappingDomain):
    """Weak key/value updates for a private local dictionary accumulator."""
