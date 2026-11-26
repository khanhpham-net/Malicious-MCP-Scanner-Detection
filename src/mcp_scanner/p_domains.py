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
    """Validated finite sequence with an element domain and optional bounds."""
    element: Any
    min_length: int = 0
    max_length: int | None = None


@dataclass
class MappingDomain:
    """Validated mapping shape; membership and runtime key text remain unknown.

    This is mutable so aliases share the same abstract object. Neither a key
    nor a value domain certifies that unobserved strings contain no directive.
    """
    key: Any
    value: Any
    min_length: int = 0
    max_length: int | None = None


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
class BoundedInputText(RuntimeInputText):
    """Unobserved input text with validated length bounds, never safe text."""
    min_length: int = 0
    max_length: int | None = None


@dataclass(frozen=True)
class BuiltinType:
    name: str


@dataclass(frozen=True)
class BuiltinFunction:
    name: str


@dataclass(frozen=True)
class RaisedValue:
    """A modeled builtin exception, distinct from successful returned data."""
    exception: str
    message: Any
    span: SourceSpan


class StaticRaised(Exception):
    """Internal interpreter control transfer; never an executed target raise."""
    def __init__(self, value):
        self.value = value
        super().__init__("modeled static exception")


@dataclass(frozen=True)
class CaughtException:
    """A caught builtin exception; not interchangeable with its string value."""
    exception: str
    message: Any
    span: SourceSpan


@dataclass(frozen=True)
class AnnotationValue:
    """Pure trusted Field metadata; not a modeled MCP output object."""
    kind: str = "pydantic-field"
