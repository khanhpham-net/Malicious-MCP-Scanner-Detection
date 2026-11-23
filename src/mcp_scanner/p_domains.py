"""Small abstract domains for bounded P text coverage, independent of M/C/S."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import SourceSpan
from .p_static import UnresolvedValue


@dataclass(frozen=True)
class NonTextValue:
    """A value proven numeric/bool on any successful supported operation."""
    kind: str


@dataclass(frozen=True)
class SequenceDomain:
    """Unbounded sequence with an analyzed element domain."""
    element: Any


@dataclass(frozen=True)
class ClassSymbol:
    path: str
    name: str


@dataclass
class StaticLambda:
    path: str
    node: Any
    env: dict


@dataclass
class FlowOutcome:
    kind: str
    env: dict
    globals: Any
    memo: dict
    value: Any = None
    span: SourceSpan | None = None
    exception: str | None = None


@dataclass(frozen=True)
class RuntimeInputText(UnresolvedValue):
    """Unobserved text from a declared validated str input; not a safe output."""
    pass


@dataclass(frozen=True)
class BuiltinType:
    name: str


@dataclass(frozen=True)
class BuiltinFunction:
    name: str
