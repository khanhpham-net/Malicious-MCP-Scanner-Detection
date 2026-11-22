"""Behavior predicates for resolved Python APIs. All inputs are abstract values."""
from __future__ import annotations

import ast
import posixpath
from pathlib import PurePosixPath
import re

from .flow import Value, combine

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
PRESERVE = {"str", "bytes", "bytearray", "dict", "list", "tuple", "json.dumps", "json.loads",
            "urllib.parse.urlencode", "urllib.parse.quote", "os.path.expanduser", "os.path.join"}
SECRET_KEY = re.compile(r"(?:TOKEN|PASS(?:WORD|WD)?|SECRET|CREDENTIAL|API.?KEY|PRIVATE.?KEY|ACCESS.?KEY|AUTH|COOKIE|SESSION.?KEY)", re.I)
SECRET_PATH = re.compile(r"(?:^|/)(?:\.env(?:\.[^/]*)?|\.(?:ssh|aws|gnupg)(?:/|$)|\.npmrc$|\.netrc$|credentials(?:\.[^/]*)?$|(?:tokens?|wallet|keystore)(?:[./]|$))", re.I)
SQL_WRITE = re.compile(r"^\s*(INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER|TRUNCATE)\b", re.I)


def secret_path(value) -> bool:
    return isinstance(value, str) and bool(SECRET_PATH.search(value.replace("\\", "/")))


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
    # A shell-quoted value still controls executable selection when it is the whole command.
    steps = controlling.marks.get("input") or controlling.marks.get("quoted")
    if ("input" not in controlling.marks and command.posix_quoted_command and shell
            and executable.constant in {"/bin/sh", "/bin/bash", "/bin/dash"}):
        steps = None
    if steps:
        frame.emit(node, "command_injection", steps, symbol=name)
    elif frame.reg:
        worker_args = args if name.endswith("subprocess_exec") else command.items
        frame.worker(node, name, worker_args)
    return Value()


def call(frame, node: ast.Call, name: str, recv: Value, args, kw) -> Value:
    first = args[0] if args else Value()
    values = combine(*args, *kw.values())
    method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
    if name in {"os.getenv", "os.environ.get", "os.environ.__getitem__"}:
        return env_value(frame, node, kw.get("key", first).constant)
    effect = mutation(name, recv, args, kw)
    if effect:
        frame.effect(node, name, effect)
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
    if name == "getattr" and len(args) >= 2 and isinstance(args[1].constant, str):
        attr = args[1].constant
        if first.ref in frame.engine.index.classes:
            return first.fields.get(attr, Value(ref=f"{first.ref}.{attr}", bound_to=first))
        if first.ref in frame.engine.index.modules:
            return Value(ref=f"{first.ref}.{attr}")
    if name == "str" and isinstance(first.constant, str):
        return Value(constant=first.constant, marks=first.marks)
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
        return Value(ref="io.file", constant=path.constant)
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
        return Value(ref=ref, constant=const, marks=values.marks)
    if name == "pathlib.Path.home":
        return Value(ref="pathlib.Path", constant="~")
    if name == "os.path.expanduser":
        return first
    if name == "os.path.join" and args and all(isinstance(a.constant, str) for a in args):
        return Value(constant=posixpath.join(*(a.constant for a in args)), marks=values.marks)
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
        return Value(ref="pathlib.Path", constant=path, marks=combine(recv, values).marks)
    if name in PRESERVE or method in {"encode", "decode", "join", "format", "strip", "replace"}:
        return combine(values, recv).through(frame.step(node, "transform", name or method))
    if method == "get" and isinstance(first.constant, str) and recv.fields:
        return recv.fields.get(first.constant, Value())
    return Value()
