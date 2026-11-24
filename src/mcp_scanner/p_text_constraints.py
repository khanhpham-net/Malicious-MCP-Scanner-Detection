"""A narrow, non-executing proof for validated ASCII token constraints.

Only anchored concatenations of ASCII literals/classes and simple repetition
are accepted. Negation, Unicode classes, wildcards, groups and unanchored
patterns are deliberately unsupported. No target regex is compiled or run.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re

from .p_domains import RuntimeInputText


@dataclass(frozen=True)
class ValidatedToken(RuntimeInputText):
    pattern: str = ""


def ascii_token_pattern(pattern):
    if not isinstance(pattern,str) or len(pattern)>256 or not pattern.startswith("^") or not pattern.endswith("$"):
        return False
    body=pattern[1:-1]
    i=0
    atoms=0
    while i<len(body):
        char=body[i]
        if char=="[":
            end=body.find("]",i+1)
            if end<0:
                return False
            chars=body[i+1:end]
            if not chars or any(not 33<=ord(c)<=126 or c in "^\\[" for c in chars):
                return False
            i=end+1
        elif char=="\\":
            i+=1
            if i>=len(body) or not 33<=ord(body[i])<=126 or body[i].isalnum():
                return False
            i+=1
        elif 33<=ord(char)<=126 and char not in ".^$|?*+(){}[]":
            i+=1
        else:
            return False
        atoms+=1
        if i<len(body) and body[i] in "+*?":
            i+=1
        elif i<len(body) and body[i]=="{":
            repeat=re.match(r"\{[0-9]+(?:,[0-9]*)?\}",body[i:])
            if repeat is None:
                return False
            i+=len(repeat.group())
    return atoms>0


# All seven reviewed rules require internal whitespace. This certificate is
# bound to exact rule patterns: changing the rule language disables the proof
# until its no-whitespace property is reviewed again.
TOKEN_RULESET_SHA256 = "23242374bb6cd94729b5462af5f815d9783230f7bae4544c7524d218751a7e21"


def token_profile_digest():
    import inspect
    from .p_detector import _RULES, normalize_p_text
    profile="\n".join(pattern.pattern for _,pattern,_ in _RULES)+"\n"+inspect.getsource(normalize_p_text)
    return hashlib.sha256(profile.encode()).hexdigest()


def token_proof_available():
    try:
        return token_profile_digest()==TOKEN_RULESET_SHA256
    except (OSError,TypeError):
        return False
