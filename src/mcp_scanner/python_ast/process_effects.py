"""Recognize high-confidence effects in bounded, statically resolved process arguments."""

import re
import shlex
import posixpath
from collections.abc import Sequence
from urllib.parse import urlsplit

_TOKEN = re.compile(
    r"""(?P<operator>\|\||&&|>>|>&|<&|<>|[|;&<>]|\n)"""
    r"""|(?P<descriptor>[0-9]+(?=[<>]))"""
    r"""|(?P<comment>\#[^\r\n]*)"""
    r"""|(?P<word>(?:[^\s|;&<>"'\\]+|'[^']*'|"(?:[^"\\]|\\.)*"|\\[^\n])+)"""
    r"""|(?P<invalid>\S)"""
)
_SHELLS = {"bash", "dash", "sh", "zsh", "ksh"}
_PIPE_INTERPRETERS = _SHELLS | {"python", "python3", "node", "perl", "ruby"}
_REDIRECTS = {">", ">>", ">&", "<&", "<>", "<"}
_NETWORK_IO = re.compile(r"^/dev/(?:tcp|udp)/[^/\s]+/[0-9]+$")
_KEY_FILE = re.compile(r"(?:^|/)\.ssh/authorized_keys2?$")
_KEY_TYPE = re.compile(r"^(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-[a-z0-9-]+)(?:\s|$)")
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9_./-]+$")
_CREDENTIAL = re.compile(r"(?:TOKEN|SECRET|PASSWORD|CREDENTIAL|API_?KEY|PRIVATE_?KEY)", re.I)
_SENSITIVE_PATH = re.compile(r"(?:^/etc/g?shadow$|(?:^|/)\.ssh/id_[^/]+$|(?:^|/)\.env$)")
SENSITIVE_TRANSFER = "credential or environment data piped to a network client"
_WIPE_ROOTS = {"/", "/*", "/**", "/home", "/home/*", "/etc", "/etc/*", "/usr", "/usr/*",
               "/var", "/var/*", "/root", "/root/*", "/dev", "/dev/*", "/boot", "/boot/*",
               "/bin", "/bin/*", "/sbin", "/sbin/*"}


def is_ssh_access_file(path: object) -> bool:
    return isinstance(path, str) and bool(_KEY_FILE.search(path.replace("\\", "/")))


def _program(word: str) -> str:
    return word.replace("\\", "/").rsplit("/", 1)[-1]


def _downloads_to_stdout(argv: list[str]) -> bool:
    if not argv or not any(word.startswith(("http://", "https://")) for word in argv[1:]):
        return False
    program = _program(argv[0])
    args = argv[1:]
    if program == "wget":
        return (
            any(re.fullmatch(r"-[qnv]*O-", word) or word == "--output-document=-" for word in args)
            or any(option in {"-O", "--output-document"} and path == "-"
                   for option, path in zip(args, args[1:]))
        )
    if program == "curl":
        return not any(
            word in {"--output", "--remote-name", "--remote-name-all", "--head"}
            or word.startswith(("-o", "-O", "-I", "--output="))
            for word in args
        )
    return False


def _local_name(path: str) -> str | None:
    if not _SAFE_FILENAME.fullmatch(path) or path == "-":
        return None
    return posixpath.normpath(path)


def _download_target(argv: list[str]) -> str | None:
    if not argv:
        return None
    program = _program(argv[0])
    if program not in {"curl", "wget"}:
        return None
    urls = [arg for arg in argv[1:] if arg.startswith(("http://", "https://"))]
    if len(urls) != 1:
        return None
    flags = {"-o", "--output"} if program == "curl" else {"-O", "--output-document"}
    for flag, arg in zip(argv[1:], argv[2:]):
        if flag in flags:
            return _local_name(arg)
    for flag in argv[1:]:
        prefix, equals, target = flag.partition("=")
        if equals and prefix in flags:
            return _local_name(target)
    if program == "curl" and "-O" in argv[1:]:
        try:
            return _local_name(posixpath.basename(urlsplit(urls[0]).path))
        except ValueError:
            return None
    return None


def _executes_file(argv: list[str], filename: str) -> bool:
    if not argv:
        return False
    if "/" in argv[0] and _local_name(argv[0]) == filename:
        return True
    return len(argv) >= 2 and _program(argv[0]) in _PIPE_INTERPRETERS and _local_name(argv[1]) == filename


def _sends_sensitive_data(source: list[str], sink: list[str]) -> bool:
    if not source or len(sink) < 3 or _program(sink[0]) not in {"nc", "ncat", "netcat"}:
        return False
    host, port = sink[-2:]
    if host.startswith("-") or not port.isascii() or not port.isdigit() or "-l" in sink[1:-2]:
        return False
    program, *args = source
    name = _program(program)
    return (
        name == "env" and not args
        or name == "printenv" and (not args or any(_CREDENTIAL.search(arg) for arg in args))
        or name == "export" and args == ["-p"]
        or name == "cat" and any(_SENSITIVE_PATH.search(arg) for arg in args)
    )


def _base_effect(argv: Sequence[str], redirects: Sequence[tuple[str, str]]) -> str | None:
    if not argv:
        return None
    name, *args = argv
    program = _program(name)
    options = args[:args.index("--")] if "--" in args else args
    if "--help" in options or "--version" in options:
        return None
    if program in _SHELLS and any(
        flag == "--interactive" or re.fullmatch(r"-[a-zA-Z]*i[a-zA-Z]*", flag)
        for flag in options
    ):
        if any(_NETWORK_IO.fullmatch(path) for _, path in redirects):
            return "interactive shell redirected to a network socket"
    if program in {"nc", "ncat", "netcat"}:
        for flag, operand in zip(options, options[1:]):
            if (flag == "-e" or program == "ncat" and flag in {"-c", "--exec", "--sh-exec"}) and _program(operand) in _SHELLS:
                return "network client configured to launch a shell"
    if program in {"echo", "printf"} and any(_KEY_TYPE.match(arg) for arg in args):
        destinations = [path for op, path in redirects if op in {">", ">>"}]
        if any(is_ssh_access_file(path) for path in destinations):
            return "writes an SSH public key to an access-control file"
    if program == "rm" and any(arg.rstrip("/") in _WIPE_ROOTS or arg == "/" for arg in args):
        recursive = any(
            flag == "--recursive" or re.fullmatch(r"-[rRfFiIvVd]+", flag) and ("r" in flag or "R" in flag)
            for flag in options
        )
        if recursive:
            return "recursive deletion targets a broad system location"
    return None


def _shell_effect(command: str) -> str | None:
    if len(command) > 8192:
        return None
    argv: list[str] = []
    redirects: list[tuple[str, str]] = []
    pending_redirect = ""
    pending_descriptor: int | None = None
    redirects_pipe_output = False
    redirects_pipe_input = False
    piped_download = False
    pipe_source: list[str] = []
    downloaded: str | None = None
    for token in _TOKEN.finditer(command + "\n"):
        value = token.group()
        if token.lastgroup == "invalid":
            return None
        if token.lastgroup == "comment":
            continue
        if token.lastgroup == "descriptor":
            if len(value) > 3 or pending_descriptor is not None or pending_redirect:
                return None
            pending_descriptor = int(value)
            continue
        if token.lastgroup == "operator":
            if value in _REDIRECTS:
                if pending_redirect:
                    return None
                pending_redirect = value
                continue
            if pending_redirect:
                return None
            effect = _base_effect(argv, redirects)
            if effect:
                return effect
            if argv and piped_download and not redirects_pipe_input and _program(argv[0]) in _PIPE_INTERPRETERS:
                args = argv[1:]
                if not args or args == ["-"] or (
                    _program(argv[0]) in _SHELLS
                    and (args[0] == "-s" or all(flag in {"-x", "-e", "-u"} for flag in args))
                ):
                    return "remote download piped directly into an interpreter"
            if not redirects_pipe_input and _sends_sensitive_data(pipe_source, argv):
                return SENSITIVE_TRANSFER
            if downloaded and _executes_file(argv, downloaded):
                return "downloaded file invoked by the same shell command"
            if value in {"&&", ";", "\n"}:
                fetched = _download_target(argv)
                if fetched is not None:
                    downloaded = fetched
                elif not argv or _program(argv[0]) != "chmod" or not any(
                    _local_name(arg) == downloaded for arg in argv[1:]
                ):
                    downloaded = None
            else:
                downloaded = None
            uses_pipe = value == "|" and not redirects_pipe_output
            piped_download = uses_pipe and _downloads_to_stdout(argv)
            pipe_source = argv.copy() if uses_pipe else []
            argv.clear()
            redirects.clear()
            redirects_pipe_output = False
            redirects_pipe_input = False
            continue
        try:
            word, = shlex.split(value)
        except ValueError:
            return None
        if pending_redirect:
            redirects.append((pending_redirect, word))
            if pending_descriptor in {None, 1} and pending_redirect.startswith(">"):
                redirects_pipe_output = True
            if pending_descriptor in {None, 0} and pending_redirect.startswith("<"):
                redirects_pipe_input = True
            pending_redirect = ""
            pending_descriptor = None
        else:
            argv.append(word)
    return None


def fixed_process_effect(
    command: str | None, argv: Sequence[str], *, shell: bool, executable: str | None = None,
) -> str | None:
    """Inspect a supported shell command or fixed argument vector without running it."""
    if shell:
        if command is None or executable is not None and _program(executable) not in _SHELLS:
            return None
        return _shell_effect(command)
    if not argv:
        return None
    if executable is not None:
        argv = (executable, *argv[1:])
    if _program(argv[0]) in _SHELLS and len(argv) >= 3 and argv[1] in {"-c", "-lc"}:
        return _shell_effect(argv[2])
    return _base_effect(argv, ())
