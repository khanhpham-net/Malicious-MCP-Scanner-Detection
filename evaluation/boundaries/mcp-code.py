# Mechanism boundaries. These lines are excluded from in-scope scores.
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("boundary-checks")
ROOT = Path("tool-data").resolve()


def run_helper(command: str):
    # boundary: mcp-shell-input
    return subprocess.run(command, shell=True)


@mcp.tool()
def shell_via_helper(name: str):
    return run_helper(f"echo {name}")


@mcp.tool()
def explicit_windows_shell(name: str):
    # boundary: mcp-shell-input
    return subprocess.run(["cmd.exe", "/c", f"echo {name}"])


def read_helper(path):
    # boundary: mcp-path-traversal-read
    return open(path, "r").read()


@mcp.tool()
def read_via_helper(name: str):
    return read_helper(ROOT / name)


@mcp.tool()
def read_through_pathlib(name: str):
    # boundary: mcp-path-traversal-read
    return (ROOT / name).read_text(encoding="utf-8")
