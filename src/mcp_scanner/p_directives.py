"""Bounded extraction of explicit English MCP invocation facts.

This is a small lexical grammar, not a natural-language intent classifier.
Ordinary workflows produce the same facts as suspicious instructions. Consumers
must obtain independent code evidence before treating a fact as a risk finding.
Offsets always refer to the supplied, unnormalised text. Target code is never run.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
import math
import re
import time


MAX_TEXT_CHARS = 65536
MAX_TOKENS = 12000
MAX_DIRECTIVE_TOKENS = 256
MAX_DIRECTIVES = 128


class DirectiveBudgetExceeded(Exception):
    """Input size, token budget, or the supplied analysis deadline was exceeded."""


@dataclass(frozen=True)
class Directive:
    action: str
    target: str
    arguments: dict[str, object]
    start: int
    end: int
    evidence: str
    arguments_complete: bool = True
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Token:
    kind: str
    text: str
    start: int
    end: int
    value: object = None


_URI = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'`<>()\[\]{},;]+")
_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)*(?:'[A-Za-z]+)?")
_NUMBER = re.compile(r"-?(?:[0-9]+(?:\.[0-9]+)?)(?:[eE][+-]?[0-9]+)?")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.:-]*\Z")
_TOOL_VERBS = {"call", "invoke", "execute", "run", "use"}
_RESOURCE_VERBS = {"read", "fetch", "access", "retrieve", "get", "load"}
_NEGATIONS = {"not", "never", "don't", "cannot", "can't", "mustn't", "shouldn't", "avoid"}
_REPORT_NOUNS = {"example", "tutorial", "glossary", "guide", "documentation", "exercise"}
_REPORT_VERBS = {"quotes", "quote", "describes", "discusses", "explains", "illustrates", "warns"}
_SKIP = {"the", "a", "an", "mcp", "tool", "function", "named", "called"}
_RESERVED = _SKIP | _TOOL_VERBS | _RESOURCE_VERBS | {
    "this", "that", "it", "another", "next", "previous", "all", "each", "any", "your", "our",
}


def _check(deadline):
    if deadline is not None and time.monotonic() >= deadline:
        raise DirectiveBudgetExceeded("Directive analysis deadline reached")


def _tokens(text, deadline):
    tokens = []
    pos = 0
    while pos < len(text):
        if len(tokens) >= MAX_TOKENS:
            raise DirectiveBudgetExceeded("Directive token budget reached")
        if pos % 128 == 0:
            _check(deadline)
        ch = text[pos]
        if ch.isspace():
            if ch in "\r\n" and (not tokens or tokens[-1].kind != "break"):
                tokens.append(_Token("break", ch, pos, pos + 1))
            pos += 1
            continue
        if ch in "\"'`":
            end = pos + 1
            while end < len(text):
                if end % 128 == 0:
                    _check(deadline)
                if text[end] == "\\" and ch != "`":
                    end += 2
                elif text[end] == ch:
                    end += 1
                    break
                else:
                    end += 1
            raw = text[pos:end]
            value = None
            if len(raw) >= 2 and raw[-1] == ch:
                if ch == "`":
                    value = raw[1:-1]
                else:
                    try:
                        value = ast.literal_eval(raw)
                    except (ValueError, SyntaxError, RecursionError):
                        pass
            tokens.append(_Token("string", raw, pos, min(end, len(text)), value))
            pos = min(end, len(text))
            continue
        match = _URI.match(text, pos)
        if match:
            raw = match.group().rstrip(".!?")
            tokens.append(_Token("uri", raw, pos, pos + len(raw), raw))
            pos += len(raw)
            continue
        match = _WORD.match(text, pos)
        if match:
            tokens.append(_Token("word", match.group(), pos, match.end()))
            pos = match.end()
            continue
        match = _NUMBER.match(text, pos)
        if match:
            raw = match.group()
            try:
                value = float(raw) if any(c in raw.lower() for c in ".e") else int(raw)
                if isinstance(value, float) and not math.isfinite(value):
                    value = None
            except ValueError:
                value = None
            tokens.append(_Token("number", raw, pos, match.end(), value))
            pos = match.end()
            continue
        attribute_dot = (ch == "." and tokens and tokens[-1].end == pos
                         and tokens[-1].kind in {"string", "number"}
                         and pos + 1 < len(text) and (text[pos + 1].isalpha() or text[pos + 1] == "_"))
        comparison = ch in "!?" and pos + 1 < len(text) and text[pos + 1] == "="
        tokens.append(_Token("break" if ch in ".!?;" and not attribute_dot and not comparison else "punct", ch, pos, pos + 1))
        pos += 1
    return tokens


def _word(token):
    return token.text.lower() if token.kind == "word" else ""


def _name(token):
    name = token.value if token.kind == "string" else token.text if token.kind == "word" else None
    return name if isinstance(name, str) and _NAME.fullmatch(name) else None


def _inactive(tokens, index):
    start = index
    # Reporting/negation context has a fixed window, so repeated candidate
    # verbs in one long paragraph cannot cause quadratic backwards scans.
    while start > max(0, index - 32) and tokens[start - 1].kind != "break":
        start -= 1
    prefix = tokens[max(start, index - 32):index]
    words = [_word(t) for t in prefix if t.kind == "word"]
    if any(w in _NEGATIONS for w in words[-4:]):
        return True
    if words and words[-1] in {"can", "could", "may", "might", "will", "would"}:
        return True
    if words and words[-1] == "to" and not any(w in {"must", "should", "need", "required"} for w in words[-4:]):
        return True
    if words and words[0] in {"if", "when", "whether"} and not any(t.text == "," for t in prefix):
        return True
    if words and words[0] in {"if", "whether"} and "should" in words:
        return True
    if any(w in _REPORT_NOUNS for w in words) and (
        any(w in _REPORT_VERBS for w in words)
        or any(t.text == ":" for t in prefix)
        or words[:2] == ["for", "example"]
    ):
        return True
    return False


def _invocation(tokens, index):
    verb = _word(tokens[index])
    if verb == "invoked" and any(_word(t) in {"must", "should"} for t in tokens[max(0, index - 4):index]):
        # Some published PoCs use this grammatical error after a modal.
        verb = "invoke"
    if verb not in _TOOL_VERBS | _RESOURCE_VERBS or _inactive(tokens, index):
        return None
    # A caller supplies actual imperative wording. Inflected reporting forms
    # such as "calls" and "invokes" are deliberately not treated as directives.
    if verb in _RESOURCE_VERBS:
        limit = min(len(tokens), index + 11)
        resource = next((j for j in range(index + 1, limit)
                         if _word(tokens[j]) in {"resource", "resources"}), None)
        if resource is None or any(t.kind == "break" for t in tokens[index + 1:resource]):
            return None
        cursor = resource + 1
        while cursor < min(len(tokens), resource + 8):
            token = tokens[cursor]
            if token.kind == "break":
                return None
            target = token.value if token.kind in {"uri", "string"} else None
            if isinstance(target, str) and target:
                return "read_resource", target, cursor
            if token.kind == "word" and _word(token) not in {"at", "by", "with", "uri", "url", "named", "called", "the"}:
                return None
            cursor += 1
        return None
    cursor = index + 1
    explicit_tool = False
    while cursor < len(tokens) and _word(tokens[cursor]) in _SKIP:
        explicit_tool |= _word(tokens[cursor]) in {"tool", "function"}
        cursor += 1
    if cursor >= len(tokens):
        return None
    target = _name(tokens[cursor])
    if not target or target.lower() in _RESERVED:
        return None
    following = _word(tokens[cursor + 1]) if cursor + 1 < len(tokens) else ""
    if verb == "use" and not explicit_tool and following not in {"tool", "function"}:
        return None
    return "call_tool", target, cursor


def _literal(token):
    if token.kind in {"string", "number"}:
        return token.value, token.value is not None
    if token.kind == "word":
        literals = {"true": True, "false": False, "none": None, "null": None}
        word = _word(token)
        if word in literals:
            return literals[word], True
    return None, False


def _arguments(tokens):
    found = {}
    conflicts = set()
    unsupported = False

    def bind(name, value_index):
        if not name or value_index >= len(tokens):
            return
        value, valid = _literal(tokens[value_index])
        after = tokens[value_index + 1:value_index + 5]
        # An expression or choice is not a literal binding. Reject rather than
        # guessing which alternative the agent would choose.
        if after and (after[0].text in {"+", "-", "*", "/", "%", "|", "&", "^", "!", "=", "<", ">", ".", "["}
                      or _word(after[0]) in {"or", "and/or", "if", "else", "in", "is"}
                      or _literal(after[0])[1]
                      or (after[0].kind == "word" and _word(after[0]) not in {"and", "then", "please", "parameter", "argument"})
                      or (after[0].start == tokens[value_index].end and after[0].kind == "word")
                      or (after[0].text in {",", "("} and len(after) > 1 and _word(after[1]) == "or")
                      or (after[0].text == "," and len(after) > 1 and _literal(after[1])[1]
                          and (len(after) < 3 or after[2].text not in {":", "="}))
                      or (_word(after[0]) == "and" and len(after) > 1 and _literal(after[1])[1])):
            conflicts.add(name)
            return
        if not valid:
            conflicts.add(name)
        elif name in found and (type(found[name]) is not type(value) or found[name] != value):
            conflicts.add(name)
        else:
            found[name] = value

    for i, token in enumerate(tokens):
        name = _name(token)
        if name and i + 1 < len(tokens) and tokens[i + 1].text in {"=", ":"}:
            bind(name, i + 2)
        if _word(token) in {"set", "setting", "pass", "provide"}:
            cursor = i + 1
            while cursor < len(tokens) and _word(tokens[cursor]) in {"the", "parameter", "argument", "field"}:
                cursor += 1
            if cursor >= len(tokens):
                continue
            name = _name(tokens[cursor])
            cursor += 1
            while cursor < len(tokens) and _word(tokens[cursor]) in {"parameter", "argument", "field"}:
                cursor += 1
            if cursor < len(tokens) and (_word(tokens[cursor]) in {"to", "as"} or tokens[cursor].text in {"=", ":"}):
                bind(name, cursor + 1)
        if name and i + 3 < len(tokens) and _word(tokens[i + 1]) == "set" and _word(tokens[i + 2]) == "to":
            bind(name, i + 3)
    # A binding introducer we did not understand is not an assertion that no
    # argument was supplied. Likewise positional/nested invocation expressions
    # must not accidentally become keyword bindings to a handler.
    has_introducer = any(_word(t) in {"with", "using", "set", "setting", "provide", "pass"} for t in tokens)
    if has_introducer and not found:
        unsupported = True
    if tokens and tokens[0].text == "(":
        depth = 0
        for i, token in enumerate(tokens):
            if token.text in {"(", "{", "["}:
                depth += 1
            elif token.text in {")", "}", "]"}:
                depth -= 1
            elif depth == 1 and token.kind in {"string", "number", "uri"}:
                # A scalar immediately after '(' or ',' is positional.
                if i and tokens[i - 1].text in {"(", ","}:
                    unsupported = True
            if depth > 1:
                unsupported = True
        if depth != 0:
            unsupported = True
    complete = not conflicts and not unsupported
    return ({name: value for name, value in found.items() if name not in conflicts}, complete)


def extract_directives(text: str, *, deadline: float | None = None) -> list[Directive]:
    """Extract bounded invocation facts, without judging safety or execution.

    Only explicit English verbs and scalar literal bindings are recognised.
    Missing facts do not prove that the text has no instructions. Ambiguous or
    computed bindings are omitted and arguments_complete is false; consumers
    must not specialize such directives using default argument values. Even a
    complete fact does not prove an agent omits unspecified arguments.
    """
    if not isinstance(text, str):
        raise TypeError("Directive input must be text")
    _check(deadline)
    if len(text) > MAX_TEXT_CHARS:
        raise DirectiveBudgetExceeded("Directive input size limit reached")
    tokens = _tokens(text, deadline)
    invocations = []
    for i in range(len(tokens)):
        if i % 128 == 0:
            _check(deadline)
        invocation = _invocation(tokens, i)
        if invocation:
            invocations.append((i, *invocation))
            if len(invocations) > MAX_DIRECTIVES:
                raise DirectiveBudgetExceeded("Directive count limit reached")
    results = []
    for n, (start, action, target, target_index) in enumerate(invocations):
        end = invocations[n + 1][0] if n + 1 < len(invocations) else len(tokens)
        for j in range(target_index + 1, end):
            if tokens[j].kind == "break":
                end = j
                break
        if end - start > MAX_DIRECTIVE_TOKENS:
            raise DirectiveBudgetExceeded("Directive clause limit reached")
        last = tokens[max(target_index, end - 1)].end
        first = tokens[start].start
        arguments, complete = _arguments(tokens[target_index + 1:end]) if action == "call_tool" else ({}, True)
        limitations = () if complete else ("Explicit argument syntax is ambiguous, computed, or unsupported.",)
        results.append(Directive(action, target, arguments, first, last, text[first:last], complete, limitations))
    _check(deadline)
    return results
