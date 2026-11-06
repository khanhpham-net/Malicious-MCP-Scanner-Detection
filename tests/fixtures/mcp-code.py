# Scan as source text. These functions are fixtures, not test entry points.
import os
import subprocess as sp
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("rule-development")
ROOT = Path("tool-data").resolve()


@mcp.tool()
def concat_run(name: str):
    # ruleid: mcp-shell-input
    sp.run("echo " + name, shell=True)


@mcp.tool(name="run_named")
def named_tool(label: str, name: str):
    command = f"echo {name}"
    # ruleid: mcp-shell-input
    sp.run(args=command, shell=True)


@mcp.tool()
def popen_shell(name: str):
    # ruleid: mcp-shell-input
    sp.Popen(f"echo {name}", shell=True)


@mcp.tool()
def system_shell(name: str):
    # ruleid: mcp-shell-input
    os.system(f"echo {name}")


@mcp.tool()
def fixed_command(name: str):
    # ok: mcp-shell-input
    sp.run("echo fixed", shell=True)


@mcp.tool()
def unrelated_keyword(directory: str):
    # ok: mcp-shell-input
    sp.run("echo fixed", shell=True, cwd=directory)


@mcp.tool()
def argument_list(name: str):
    # ok: mcp-shell-input
    sp.run([sys.executable, "-c", "import sys; print(sys.argv[1])", name])


def local_shell(name: str):
    # ok: mcp-shell-input
    os.system(f"echo {name}")


@mcp.tool()
def read_joined(name: str):
    # ruleid: mcp-path-traversal-read
    return open(ROOT / name, "r").read()


@mcp.tool()
def read_resolved_only(name: str):
    path = (ROOT / name).resolve()
    # ruleid: mcp-path-traversal-read
    return open(path, mode="r", encoding="utf-8").read()


@mcp.tool()
def read_checked(name: str):
    path = (ROOT / name).resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError("path outside root")
    # ok: mcp-path-traversal-read
    return open(path, "r").read()


@mcp.tool()
def read_after_unrelated_check(name: str):
    path = (ROOT / name).resolve()
    other = Path("other-data").resolve()
    if not path.is_relative_to(other):
        raise ValueError("wrong root")
    # ruleid: mcp-path-traversal-read
    return open(path, "r").read()


@mcp.tool()
def read_after_absolute_path_check(name: str):
    if Path(name).is_absolute():
        raise ValueError("absolute path")
    # ruleid: mcp-path-traversal-read
    return open(ROOT / name, "r").read()


@mcp.tool()
def read_after_parent_component_check(name: str):
    if ".." in Path(name).parts:
        raise ValueError("parent component")
    # ruleid: mcp-path-traversal-read
    return open(ROOT / name, "rb").read()


@mcp.tool()
def read_reassigned_path(original: str, replacement: str):
    path = (ROOT / original).resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError("path outside root")
    path = ROOT / replacement
    # ruleid: mcp-path-traversal-read
    return open(path, "r").read()


@mcp.tool()
def read_after_caught_rejection(name: str):
    try:
        path = (ROOT / name).resolve()
        if not path.is_relative_to(ROOT):
            raise ValueError("path outside root")
    except ValueError:
        pass
    # ruleid: mcp-path-traversal-read
    return open(path, "r").read()


@mcp.tool()
def read_fixed(name: str):
    # ok: mcp-path-traversal-read
    return open(ROOT / "index.txt", "r").read()


@mcp.tool()
def read_unrestricted(name: str):
    # ok: mcp-path-traversal-read
    return open(name, "r").read()


@mcp.tool()
def write_only(name: str):
    # ok: mcp-path-traversal-read
    return open(ROOT / name, "w")
