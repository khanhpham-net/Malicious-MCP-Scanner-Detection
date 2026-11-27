"""Behavior predicates for resolved Python APIs. All inputs are abstract values."""
from __future__ import annotations

import ast
from dataclasses import replace
import posixpath
from pathlib import PurePosixPath
import re

from .flow import Value, combine, within_temporary_path
from .process_effects import (
    SENSITIVE_TRANSFER,
    destructive_or_mutating_process_effect,
    fixed_process_effect,
    is_ssh_access_file,
)
from .shell_words import plain_shell_argv

DECODE = {"base64.b64decode", "base64.standard_b64decode", "base64.urlsafe_b64decode",
          "base64.b32decode", "bytes.fromhex", "bytearray.fromhex", "binascii.unhexlify",
          "zlib.decompress", "gzip.decompress", "marshal.loads", "chr", "codecs.decode"}
DYNAMIC = {"eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile",
           "__import__", "builtins.__import__", "importlib.import_module", "importlib.util.spec_from_file_location"}
PROCESS = {"os.system", "os.popen", "subprocess.run", "subprocess.Popen", "subprocess.call",
           "subprocess.check_call", "subprocess.check_output", "subprocess.getoutput",
           "subprocess.getstatusoutput", "asyncio.create_subprocess_shell", "asyncio.create_subprocess_exec"}
SHELL = {"os.system", "os.popen", "asyncio.create_subprocess_shell", "subprocess.getoutput",
         "subprocess.getstatusoutput"}
CONSTRUCTORS = {"pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath", "subprocess.Popen",
                "sqlite3.connect", "socket.socket", "socket.create_connection", "requests.Session",
                "requests.session", "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession",
                "http.client.HTTPConnection", "http.client.HTTPSConnection"}
GENERIC_CONTAINERS = {"dict", "list", "tuple", "set"}
PRESERVE = GENERIC_CONTAINERS | {"str", "bytes", "bytearray", "json.dumps", "json.loads",
            "urllib.parse.urlencode", "urllib.parse.quote", "os.path.expanduser", "os.path.join"}
TEXT_TRANSFORMS = {
    "strip", "lstrip", "rstrip", "lower", "upper", "casefold", "title", "capitalize",
    "swapcase", "removeprefix", "removesuffix", "replace", "translate", "ljust", "rjust",
    "center", "zfill", "expandtabs", "format", "format_map", "join", "encode", "decode",
    "split", "rsplit", "splitlines", "partition", "rpartition",
}
SCALAR_METHODS = {
    "startswith", "endswith", "isalnum", "isalpha", "isdigit", "isdecimal", "isnumeric",
    "isascii", "isspace", "isidentifier", "islower", "isupper", "istitle", "isprintable",
    "find", "rfind", "index", "rindex", "count",
}
SECRET_KEY = re.compile(r"(?:TOKEN|PASS(?:WORD|WD)?|SECRET|CREDENTIAL|API.?KEY|PRIVATE.?KEY|ACCESS.?KEY|AUTH|COOKIE|SESSION.?KEY)", re.I)
SECRET_PATH = re.compile(r"(?:^|/)(?:\.env(?:\.[^/]*)?|\.(?:ssh|aws|gnupg)(?:/|$)|\.npmrc$|\.netrc$|credentials(?:\.[^/]*)?$|(?:tokens?|wallet|keystore)(?:[./]|$))", re.I)
SQL_WRITE = re.compile(r"^\s*(INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER|TRUNCATE)\b", re.I)
_READONLY_LEAD_RE = re.compile(
    r"\b(?:check|checks|verify|verifies|list|lists|traverse|traverses|read|reads|get|gets|fetch|fetches|"
    r"inspect|inspects|scan|scans|analyz(?:e|es)|analysis|search|searches|find|finds|lookup|query|queries|"
    r"show|shows|display|displays|describe|describes|view|views|count|counts|calculate|calculates|"
    r"compute|computes|validate|validates|audit|audits|retrieve|retrieves|browse|browses|explore|explores)\b",
    re.I,
)
_MUTATION_DISCLOSURE_RE = re.compile(
    r"\b(?:delet(?:e|es|ed|ing|ion)|remov(?:e|es|ed|ing|al)|unlink(?:s|ing)?|eras(?:e|es|ed|ing)|"
    r"purg(?:e|es|ed|ing)|wip(?:e|es|ed|ing)|clean(?:up|s|ed|ing)?|clear(?:s|ed|ing)?|destroy(?:s|ed|ing)?|"
    r"prun(?:e|es|ed|ing)|truncat(?:e|es|ed|ing)|overwrit(?:e|es|ing)|uninstall(?:s|ed|ing)?|"
    r"re-?index(?:es|ing)?|teardown|destructiv(?:e|ely)|expir(?:e|es|ing)|evict(?:s|ed|ing)?|"
    r"drop(?:s|ped|ping)?|rotat(?:e|es|ing)|mov(?:e|es|ed|ing)|renam(?:e|es|ed|ing)|replac(?:e|es|ed|ing)|"
    r"modif(?:y|ies|ied|ying)|alter(?:s|ed|ing)?|reset(?:s|ting)?|creat(?:e|es|ed|ing)|writ(?:e|es|ing)|"
    r"sav(?:e|es|ed|ing)|updat(?:e|es|ed|ing)|edit(?:s|ed|ing)?|patch(?:es|ed|ing)?|"
    r"compress(?:es|ed|ing)?|convert(?:s|ed|ing)?|build(?:s|ing)?|deploy(?:s|ed|ing)?|install(?:s|ed|ing)?)\b",
    re.I,
)


def is_readonly_tool_description(reg) -> bool:
    """Return True conservatively when an unannotated tool clearly describes read-only inspection."""
    if reg is None or reg.kind != "tool" or reg.readonly is not None or reg.destructive is not None:
        return False
    text = (getattr(reg, "description", "") or "").strip()
    if not text:
        return False
    first_sentence = re.split(r"(?<=[.!?])\s+|\n\s*\n", text, maxsplit=1)[0]
    lead = first_sentence[:240]
    if not _READONLY_LEAD_RE.search(lead):
        return False
    if _MUTATION_DISCLOSURE_RE.search(f"{reg.name} {text}"):
        return False
    return True


def secret_path(value) -> bool:
    if not isinstance(value, str):
        return False
    path = value.replace("\\", "/")
    return path in {"/etc/shadow", "/etc/gshadow"} or bool(SECRET_PATH.search(path))


def env_value(frame, node, key):
    if isinstance(key, str) and not (SECRET_KEY.search(key) or
            re.search(r"(?:^|_)(?:PAT|SIGNING|DSN|PWD|BEARER)(?:_|$)", key, re.I)):
        return Value()
    return Value().mark("secret", frame.step(node, "source", "environment credential" if key else "environment values"))


def network_fields(name, args, kw):
    base, _, method = name.rpartition(".")
    fields = {}
    if base in {"socket.socket", "socket.create_connection"} and method in {"send", "sendall", "sendto"}:
        if args:
            fields["body"] = args[0]
    elif base == "http.client.connection" and method in {"request", "putrequest", "send", "putheader"}:
        names = {"request": ("method", "url", "body", "headers"), "putrequest": ("method", "url"),
                 "send": ("body",), "putheader": ("header_name", "headers")}[method]
        fields.update(zip(names, args))
    elif name in {"urllib.request.urlopen", "urllib.request.Request"}:
        fields.update(zip(("url", "body", "headers"), args))
    elif base in {"requests", "requests.Session", "requests.session", "httpx", "httpx.Client",
                  "httpx.AsyncClient", "aiohttp", "aiohttp.ClientSession"} and method in {
                     "request", "get", "post", "put", "patch", "delete", "head", "options"}:
        positional = ("method", "url", "body") if method == "request" else ("url", "query" if method == "get" else "body")
        fields.update(zip(positional, args))
    else:
        return {}
    renames = {"data": "body", "json": "body", "content": "body", "files": "body", "params": "query",
               "headers": "headers", "url": "url", "body": "body", "fullurl": "url"}
    fields.update({renames[k]: v for k, v in kw.items() if k in renames})
    return {k: v for k, v in fields.items() if k in {"url", "body", "headers", "query"}}


def mutation(name, recv, args, kw):
    mode = None
    if name in {"open", "builtins.open", "io.open", "pathlib.Path.open"}:
        pos = 0 if name == "pathlib.Path.open" else 1
        mode = kw.get("mode", args[pos] if pos < len(args) else Value()).constant
        if isinstance(mode, str) and any(ch in mode for ch in "wax"):
            return "truncate" if "w" in mode else "write"
    if name in {"io.file.write", "io.file.writelines", "io.file.truncate"}:
        return "replace/delete" if name == "io.file.truncate" else "write"
    if name.startswith("sqlite3.") and name.rsplit(".", 1)[-1] in {"execute", "executemany", "executescript"}:
        database = recv.constant
        if isinstance(database, str) and (database == ":memory:" or
                database.startswith("file:") and ("mode=memory" in database or database.startswith("file::memory:"))):
            return None
        match = SQL_WRITE.match(args[0].constant) if args and isinstance(args[0].constant, str) else None
        if match:
            return "write" if match[1].upper() in {"INSERT", "CREATE"} else "replace/delete"
    if name in {"os.remove", "os.unlink", "os.rename", "os.replace", "os.rmdir", "shutil.rmtree",
                "shutil.move", "pathlib.Path.unlink", "pathlib.Path.rename", "pathlib.Path.replace",
                "pathlib.Path.rmdir", "pathlib.Path.write_text", "pathlib.Path.write_bytes"}:
        return "replace/delete"
    if name in {"os.mkdir", "os.makedirs", "pathlib.Path.mkdir", "pathlib.Path.touch", "shutil.copy",
                "shutil.copy2", "shutil.copyfile", "shutil.copytree"}:
        return "write"
    return None


def process(frame, node, name, args, kw):
    command = kw.get("args", kw.get("program", kw.get("cmd", args[0] if args else Value())))
    shell = name in SHELL or kw.get("shell", Value()).constant is True
    executable = kw.get("executable", Value())
    first = command.items[0] if command.items else command
    controlling = combine(command if shell and not command.items else first, executable)
    posix_shell = executable.constant in {"/bin/sh", "/bin/bash", "/bin/dash"}
    shell_argv = plain_shell_argv(command, posix_shell=posix_shell) if shell and not command.items else ()
    # A shell-quoted value still controls executable selection when it is the whole command.
    steps = (controlling.marks.get("input") or controlling.marks.get("quoted")
             or controlling.marks.get("shell_safe_arg"))
    if (shell_argv and not executable.marks and not controlling.marks.get("input")
            and (not controlling.marks.get("quoted") or posix_shell)):
        steps = None
    if steps:
        frame.emit(node, "command_injection", steps, symbol=name)
        return Value()

    worker_args = args if name.endswith("subprocess_exec") else command.items or shell_argv
    fixed_argv = [item.constant for item in worker_args]
    if not all(isinstance(item, str) for item in fixed_argv):
        fixed_argv = []
    command_text = command.constant if isinstance(command.constant, str) else None
    if shell and command.items and fixed_argv:
        command_text = fixed_argv[0]
    effect = None
    branch_step = ()
    default_executable = "executable" not in kw or any(
        option.arg == "executable" and isinstance(option.value, ast.Constant) and option.value.value is None
        for option in node.keywords
    )
    if default_executable or isinstance(executable.constant, str):
        effect = fixed_process_effect(command_text, fixed_argv, shell=shell, executable=executable.constant)
        if effect is None and shell and command.string_options:
            effects = [
                fixed_process_effect(text, (), shell=True, executable=executable.constant)
                for text in command.string_options
            ]
            effect = next((possible for possible in effects if possible is not None), None)
            if effect and any(possible != effect for possible in effects):
                step = frame.step(node, "transform", "alternative fixed command")
                branch_step = (replace(step, edge_kind="possible"),)
    if effect:
        behavior = "shell_sensitive_transfer" if effect == SENSITIVE_TRANSFER else "risky_fixed_execution"
        frame.emit(node, behavior, branch_step, symbol=name, detail=effect)
    elif frame.reg:
        partial_argv = [item.constant if isinstance(item.constant, str) else None for item in worker_args]
        mut_effect = destructive_or_mutating_process_effect(partial_argv)
        if mut_effect:
            if frame.reg.kind == "resource":
                frame.emit(node, "resource_destruction", symbol=name,
                           detail=f"External process in resource handler {mut_effect}.")
                return Value()
            if frame.reg.readonly is True or frame.reg.destructive is False:
                frame.emit(node, "contract_mutation", symbol=name,
                           detail=f"External process under restrictive contract {mut_effect}.")
                return Value()
            if is_readonly_tool_description(frame.reg):
                frame.emit(node, "undeclared_destructive_effect", symbol=name,
                           detail=f"External process in a tool described as read-only {mut_effect}.")
                return Value()
        frame.worker(node, name, worker_args)
    return Value()


def _mark_self_created(frame, path_node: ast.AST | None, path_val: Value) -> None:
    """Record flow-sensitive creation proof in frame.env for non-input paths inside a function."""
    if not frame.stack or "input" in path_val.marks:
        return
    if isinstance(path_node, ast.Name):
        frame.env[path_node.id] = replace(path_val, self_created=True)
    if isinstance(path_val.constant, str):
        frame.env[f"__created_const__:{path_val.constant}"] = Value(self_created=True)


def _is_self_created(frame, path_val: Value) -> bool:
    """Return True only when all reaching control-flow paths proved the target was self-created."""
    if "input" in path_val.marks:
        return False
    if path_val.self_created:
        return True
    if isinstance(path_val.constant, str):
        return frame.env.get(f"__created_const__:{path_val.constant}", Value()).self_created
    return False


def call(frame, node: ast.Call, name: str, recv: Value, args, kw) -> Value:
    first = args[0] if args else Value()
    values = combine(*args, *kw.values())
    method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
    if name in {"os.getenv", "os.environ.get", "os.environ.__getitem__"}:
        return env_value(frame, node, kw.get("key", first).constant)
    effect = mutation(name, recv, args, kw)
    if effect:
        target = recv if name.startswith(("pathlib.Path.", "io.file.")) else kw.get("path", first)
        frame.effect(
            node,
            name,
            effect,
            temporary=target.temporary_path,
            self_created=_is_self_created(frame, target),
        )
    if name in {"pathlib.Path.write_text", "pathlib.Path.write_bytes"}:
        path_node = node.func.value if isinstance(node.func, ast.Attribute) else None
        _mark_self_created(frame, path_node, recv)
    if is_ssh_access_file(recv.constant) and (
        name in {"pathlib.Path.write_text", "pathlib.Path.write_bytes"}
        or name in {"io.file.write", "io.file.writelines"}
        and recv.fields.get("writable", Value()).constant is True
    ):
        frame.emit(node, "ssh_access_file_write", symbol=name)
    if name == "tempfile.TemporaryDirectory":
        return Value(ref=name)
    if name in {"tempfile.mkdtemp", "tempfile.gettempdir"}:
        return Value(ref=name, temporary_path=True)
    if name == "tempfile.mkstemp":
        return Value(ref="tuple", items=(Value(), Value(temporary_path=True)))
    if name == "tempfile.NamedTemporaryFile":
        return Value(ref=name, fields={"name": Value(temporary_path=True)})
    if name in {"print", "logging.info", "logging.warning", "logging.error", "logging.debug"} and "secret" in values.marks:
        frame.emit(node, "local_disclosure", values.marks["secret"], symbol=name)
    if name in PROCESS:
        return process(frame, node, name, args, kw)
    if name == "shlex.quote":
        return first.guarded("quoted", frame.step(node, "guard", name))
    if name in {"json.load", "yaml.safe_load"} and first.ref == "io.file" and secret_path(first.constant):
        return Value().mark("secret", frame.step(node, "source", "credential document read"))
    if name == "urllib.request.Request.add_header" and len(args) >= 2:
        recv.fields["headers"] = combine(recv.fields.get("headers", Value()), args[1])
        return Value()
    if name in {"getattr", "builtins.getattr"} and len(args) >= 2:
        attr = args[1].constant
        index = frame.engine.index
        first_party = first.ref in index.classes or first.ref in index.modules
        if first_party and not isinstance(attr, str):
            candidates = []
            if first.ref in index.classes:
                names = args[1].string_options or index.method_names(first.ref)
                for method_name in names:
                    if len(candidates) == 8:
                        return Value(unresolved_callable=True)
                    fallback = Value(ref=f"{first.ref}.{method_name}", bound_to=first)
                    candidates.append(first.fields.get(method_name, fallback))
            return Value(choices=tuple(candidates), unresolved_callable=True)
        if first.ref in index.classes:
            return first.fields.get(attr, Value(ref=f"{first.ref}.{attr}", bound_to=first))
        if first.ref in index.modules:
            return Value(ref=f"{first.ref}.{attr}")
    if name in {"str", "builtins.str"}:
        constant = str(first.constant) if type(first.constant) in {str, int, float, bool} else None
        return replace(first, constant=constant, ref="str", text_kind="str").through(frame.step(node, "transform", "str"))
    if name == "os.path.dirname" and isinstance(first.constant, str):
        return Value(constant=posixpath.dirname(first.constant), marks=first.marks)
    if name in {"os.environ.copy", "os.environ.items", "os.environ.values"}:
        return env_value(frame, node, None)
    if name in DECODE:
        step = frame.step(node, "transform", name)
        return values.through(step) if "decoded" in values.marks else values.mark("decoded", step)
    if name == "getattr" and len(args) > 1 and first.ref in {"builtins", "__builtins__"}:
        attr = args[1].constant
        return Value(ref=f"builtins.{attr}" if attr in {"eval", "exec", "compile"} else "")
    if name in DYNAMIC:
        operand = kw.get("source", kw.get("name", first))
        if name.endswith("spec_from_file_location") and len(args) > 1:
            operand = args[1]
        steps = operand.marks.get("decoded") or operand.marks.get("input")
        if steps:
            frame.emit(node, "dynamic_code_execution", steps, symbol=name)
        return operand.through(frame.step(node, "transform", name)) if name.endswith("compile") else Value()
    if name in {"open", "builtins.open", "io.open", "pathlib.Path.open"}:
        path = recv if name == "pathlib.Path.open" else kw.get("file", first)
        mode_position = 0 if name == "pathlib.Path.open" else 1
        fallback_mode = args[mode_position] if len(args) > mode_position else Value(constant="r")
        mode = kw.get("mode", fallback_mode).constant
        writable = isinstance(mode, str) and any(flag in mode for flag in "wax+")
        if isinstance(mode, str) and any(flag in mode for flag in "wx"):
            path_node = (
                node.func.value
                if name == "pathlib.Path.open" and isinstance(node.func, ast.Attribute)
                else next((k.value for k in node.keywords if k.arg == "file"), node.args[0] if node.args else None)
            )
            _mark_self_created(frame, path_node, path)
        return Value(ref="io.file", constant=path.constant, temporary_path=path.temporary_path,
                     fields={"writable": Value(constant=writable)})
    if name in {"pathlib.Path.read_text", "pathlib.Path.read_bytes", "io.file.read", "io.file.readline", "io.file.readlines"}:
        if secret_path(recv.constant):
            return Value().mark("secret", frame.step(node, "source", "credential file read"))
        return Value()
    if name == "urllib.request.urlopen" and first.ref == "urllib.request.Request":
        fields = first.fields.copy()
        fields.update({k: v for k, v in network_fields(name, args, kw).items() if k != "url"})
    else:
        fields = network_fields(name, args, kw)
    if name == "urllib.request.Request":
        return Value(ref=name, fields=fields)
    secret_fields = sorted(k for k, v in fields.items() if "secret" in v.marks)
    if secret_fields:
        frame.emit(node, "sensitive_network_flow", fields[secret_fields[0]].marks["secret"],
                   symbol=name, detail="Observed network fields: " + ", ".join(secret_fields))
    if name in CONSTRUCTORS:
        ref = {"pathlib.PosixPath": "pathlib.Path", "pathlib.WindowsPath": "pathlib.Path",
               "http.client.HTTPConnection": "http.client.connection", "http.client.HTTPSConnection": "http.client.connection"}.get(name, name)
        const = first.constant
        if ref == "pathlib.Path" and args and all(isinstance(a.constant, str) for a in args):
            const = posixpath.join(*(a.constant for a in args))
        temporary = ref == "pathlib.Path" and within_temporary_path(first, args[1:])
        self_created = ref == "pathlib.Path" and len(args) == 1 and first.self_created and "input" not in values.marks
        return Value(ref=ref, constant=const, marks=values.marks, temporary_path=temporary, self_created=self_created)
    if name == "pathlib.Path.home":
        return Value(ref="pathlib.Path", constant="~")
    if name == "os.path.expanduser":
        return first
    if name in {"os.path.normpath", "os.path.abspath", "os.path.realpath"} and isinstance(first.constant, str):
        if name == "os.path.normpath" or posixpath.isabs(first.constant):
            # Keep lexical source evidence without touching the scanner filesystem.
            return replace(first, constant=posixpath.normpath(first.constant))
    if name == "os.path.join" and args:
        const = posixpath.join(*(a.constant for a in args)) if all(isinstance(a.constant, str) for a in args) else None
        return Value(constant=const, marks=values.marks, temporary_path=within_temporary_path(first, args[1:]))
    if name == "sqlite3.connect.cursor":
        return Value(ref="sqlite3.cursor", constant=recv.constant)
    if name.startswith("pathlib.Path.") and method in {"with_name", "with_stem", "with_suffix"}:
        path = None
        if isinstance(recv.constant, str) and isinstance(first.constant, str):
            try:
                path = str(getattr(PurePosixPath(recv.constant), method)(first.constant))
            except ValueError:
                pass
        return Value(ref="pathlib.Path", constant=path, marks=combine(recv, first).marks)
    if name.startswith("pathlib.Path.") and method in {"resolve", "absolute", "expanduser", "joinpath"}:
        path = recv.constant
        if method == "joinpath" and isinstance(path, str) and all(isinstance(a.constant, str) for a in args):
            path = posixpath.join(path, *(a.constant for a in args))
        temporary = method == "joinpath" and within_temporary_path(recv, args)
        self_created = method != "joinpath" and recv.self_created and "input" not in values.marks
        return Value(ref="pathlib.Path", constant=path, marks=combine(recv, values).marks,
                     temporary_path=temporary, self_created=self_created)
    text_receiver = not recv.ref or recv.ref in {"str", "bytes", "bytearray"}
    if name in PRESERVE or method in TEXT_TRANSFORMS and text_receiver:
        transformed = combine(values, recv)
        if name != "str":
            transformed = transformed.without_shell_guard()
        if method in TEXT_TRANSFORMS and text_receiver:
            if method == "encode":
                transformed.text_kind = "bytes"
            elif method == "decode":
                transformed.text_kind = "str"
            elif method not in {"split", "rsplit", "splitlines", "partition", "rpartition"}:
                transformed.text_kind = recv.text_type()
        return transformed.through(frame.step(node, "transform", name or method))
    if method == "get" and isinstance(first.constant, str) and recv.fields:
        return recv.fields.get(first.constant, Value())
    if method in SCALAR_METHODS and (text_receiver or recv.ref in GENERIC_CONTAINERS):
        return Value()
    if method and recv.marks and text_receiver:
        step = replace(frame.step(node, "transform", method), edge_kind="possible")
        return combine(recv, values).without_shell_guard().through(step)
    if method and recv.marks:
        frame.engine.boundary("external_lib", frame.mod.path, "Tainted receiver passed through an external method without a summary.")
    return Value()
