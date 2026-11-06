# Static analysis fixture. This file is scanned as text.
import subprocess
import sys

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("semgrep-lab")


@mcp.tool()
def greet_direct(name: str):
    # ruleid: mcp-shell-input
    subprocess.run(f"echo {name}", shell=True, check=True)


@mcp.tool()
def greet_via_variable(name: str):
    command = f"echo {name}"
    # ruleid: mcp-shell-input
    subprocess.run(command, shell=True, check=True)


@mcp.tool()
def greet_with_argument_list(name: str):
    # ok: mcp-shell-input
    subprocess.run([sys.executable, "-c", "import sys; print(sys.argv[1])", name], check=True)


@mcp.tool()
def greet_with_constant_command(name: str):
    # ok: mcp-shell-input
    subprocess.run("echo hello", shell=True, check=True)
