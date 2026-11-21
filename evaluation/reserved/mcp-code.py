# Reserved synthetic checks declared before the expanded rules were implemented.
# Only scan as source text.
import subprocess
from os import system as execute
from pathlib import Path as LocalPath

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("reserved-checks")
DOCUMENTS = LocalPath("demo-documents").resolve()


@mcp.tool()
def format_status(ticket: str):
    command = "echo Ticket: {}".format(ticket)
    # ruleid: mcp-shell-input
    subprocess.Popen(args=command, shell=True)


@mcp.tool(name="show_event")
def show_event(event: str):
    # ruleid: mcp-shell-input
    execute("echo " + event)


@mcp.tool()
def keep_output(location: str):
    # ok: mcp-shell-input
    subprocess.Popen("echo fixed", shell=True, cwd=location)


@mcp.tool()
def read_attachment(label: str, filename: str):
    path = DOCUMENTS / filename
    # ruleid: mcp-path-traversal-read
    return open(path, "rb").read()


@mcp.tool()
def read_resolved_attachment(filename: str):
    # ruleid: mcp-path-traversal-read
    return open((DOCUMENTS / filename).resolve()).read()


@mcp.tool()
def read_checked_attachment(filename: str):
    candidate = (DOCUMENTS / filename).resolve()
    if not candidate.is_relative_to(DOCUMENTS):
        raise PermissionError("path outside documents")
    # ok: mcp-path-traversal-read
    return open(candidate, "rb").read()


@mcp.tool()
def read_public_index(filename: str):
    # ok: mcp-path-traversal-read
    return open(DOCUMENTS / "public-index.txt").read()
