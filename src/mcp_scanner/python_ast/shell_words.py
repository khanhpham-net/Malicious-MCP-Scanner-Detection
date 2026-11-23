"""Recover argv only for shell templates with statically bounded words."""

import re
import shlex

from .flow import Value

_LITERAL = re.compile(r"""[A-Za-z0-9_./:\-+=@'" \t]*""")
_SLOT = re.compile(r"\x00([0-9]+)\x00")
_SAFE_REGEX = re.compile(r"\[(?:A-Z|a-z|0-9|_|\.|\\-)+-?\]\+")
_EVALUATORS = {"sh", "bash", "zsh", "dash", "ksh", "cmd", "cmd.exe", "powershell",
               "pwsh", "eval", "exec", "env", "command", "xargs", "source", "."}


def safe_word_regex(pattern: str) -> bool:
    pattern = pattern.removeprefix("^").removesuffix("$")
    return _SAFE_REGEX.fullmatch(pattern) is not None


def shell_fragments(value: Value):
    if isinstance(value.constant, str):
        return (value.constant,)
    return value.shell_parts or (value,)


def plain_shell_argv(command: Value, *, posix_shell: bool) -> tuple[Value, ...]:
    """Recognize only a fixed executable and separate, literal or proven-safe argument words."""
    parts = shell_fragments(command)
    if len(parts) > 32:
        return ()
    chunks: list[str] = []
    slots: list[Value] = []
    for part in parts:
        if isinstance(part, str):
            if not _LITERAL.fullmatch(part):
                return ()
            chunks.append(part)
        else:
            chunks.append(f"\0{len(slots)}\0")
            slots.append(part)
    source = "".join(chunks)
    if len(source) > 4096:
        return ()
    try:
        words = shlex.split(source, comments=False, posix=True)
    except ValueError:
        return ()
    # shlex strips enclosing quotes. A pre-quoted value needs an unquoted position
    # in the original template so its quoting is interpreted exactly once.
    raw_words = set(source.split())
    argv = []
    for i, word in enumerate(words):
        match = _SLOT.fullmatch(word)
        if match:
            slot = slots[int(match[1])]
            if i == 0:
                if slot.ref != "sys.executable" or not source.lstrip().startswith('"'+word+'"'):
                    return ()
            elif not slot.is_shell_word() and not (
                posix_shell and word in raw_words and "quoted" in slot.marks and "input" not in slot.marks
            ):
                return ()
            argv.append(slot)
        elif "\0" in word or not word and i == 0:
            return ()
        else:
            argv.append(Value(constant=word))
    if not argv:
        return ()
    program = (argv[0].constant or "").rsplit("/", 1)[-1].lower()
    if program in _EVALUATORS or any(arg.constant in {"-c", "-e", "--eval", "/c"} for arg in argv[1:]):
        return ()
    return tuple(argv)
