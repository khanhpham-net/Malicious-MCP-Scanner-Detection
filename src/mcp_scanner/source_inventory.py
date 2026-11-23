"""Resilient, safe static source inventory for MCP snapshots.

Walks a local directory or single source file without executing target code,
blocking symlink/junction escapes, surviving AV/permission read errors,
skipping noisy/binary/minified/oversized files, and enforcing a deterministic
file budget and monotonic deadline.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from .models import ReadErrorRecord, SkippedFile, stable_sha256_id

DEFAULT_MAX_FILE_BYTES = 1_048_576  # 1 MiB
DEFAULT_MAX_FILES = 500
DEFAULT_MINIFIED_AVG_LINE_LEN = 300
DEFAULT_MINIFIED_MIN_BYTES = 1000

IGNORED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "dist",
        "build",
        "out",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".eggs",
        "coverage",
        ".next",
        ".nuxt",
        ".cache",
        ".idea",
        ".vscode",
    }
)

BINARY_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".bmp",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
        ".7z",
        ".whl",
        ".pyc",
        ".pyo",
        ".pyd",
        ".so",
        ".dll",
        ".dylib",
        ".exe",
        ".bin",
        ".wasm",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
        ".mp3",
        ".mp4",
        ".wav",
        ".sqlite",
        ".db",
        ".parquet",
        ".pkl",
        ".pickle",
        ".class",
        ".jar",
    }
)

LANGUAGE_BY_EXT: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".json": "json",
    ".jsonc": "json",
    ".yaml": "text",
    ".yml": "text",
    ".toml": "text",
    ".md": "text",
    ".markdown": "text",
    ".txt": "text",
    ".cfg": "text",
    ".ini": "text",
    ".env": "text",
    ".gyp": "text",
    ".lock": "text",
}

ENTRYPOINT_NAMES: frozenset[str] = frozenset(
    {
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "binding.gyp",
        "pyproject.toml",
        "poetry.lock",
        "uv.lock",
        "pipfile.lock",
        "requirements.txt",
        "mcp.json",
        "server.py",
        "main.py",
        "app.py",
        "__init__.py",
        "index.ts",
        "index.js",
        "server.ts",
        "server.js",
        "main.ts",
        "main.js",
    }
)

# Build output directories that may contain the only runtime code in published npm packages
_BUILD_OUTPUT_DIRS: frozenset[str] = frozenset({"dist", "build", "out"})

# Windows error codes for access denied / sharing violation / Defender AV quarantine
_AV_OR_PERM_WINERRORS = frozenset({5, 32, 225, 226})


def _extract_manifest_path_strings(value: object) -> list[str]:
    """Collect relative entrypoint path strings from package.json main/bin/exports fields."""
    found: list[str] = []
    if isinstance(value, str):
        found.append(value)
    elif isinstance(value, dict):
        for sub in value.values():
            found.extend(_extract_manifest_path_strings(sub))
    elif isinstance(value, list):
        for item in value:
            found.extend(_extract_manifest_path_strings(item))
    return found


def _included_npm_build_dirs(
    current_dir: Path,
    entries: list[os.DirEntry[str]],
    *,
    max_file_bytes: int,
) -> set[str]:
    """Allow dist/build/out when package.json is present without a src/ tree and references them."""
    present_build_dirs = {
        e.name for e in entries if e.name in _BUILD_OUTPUT_DIRS
    }
    if not present_build_dirs:
        return set()

    has_pkg_json = False
    has_src_dir = False
    has_direct_code = False
    for entry in entries:
        low = entry.name.lower()
        try:
            if low == "package.json" and entry.is_file(follow_symlinks=False):
                has_pkg_json = True
            elif low == "src" and entry.is_dir(follow_symlinks=False):
                has_src_dir = True
            elif entry.is_file(follow_symlinks=False) and Path(entry.name).suffix.lower() in {
                ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"
            }:
                has_direct_code = True
        except OSError:
            continue

    # Require a sibling package.json to consider build output directories
    if not has_pkg_json:
        return set()

    pkg_path = current_dir / "package.json"
    if _is_link_or_junction(pkg_path):
        return set()

    referenced: set[str] = set()
    try:
        if pkg_path.stat().st_size <= max_file_bytes:
            payload = json.loads(pkg_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                for field_name in ("main", "module", "browser", "bin", "exports"):
                    for raw_target in _extract_manifest_path_strings(payload.get(field_name)):
                        norm = raw_target.strip().replace("\\", "/")
                        while norm.startswith("./"):
                            norm = norm[2:]
                        first_seg = norm.split("/", 1)[0]
                        if first_seg in present_build_dirs:
                            referenced.add(first_seg)
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        pass

    # Manifest-declared runtime entrypoints (e.g. main/bin/exports -> dist/...) are always inspected,
    # even when src/ is also present, because Node loads the declared runtime artifact.
    if referenced:
        return referenced
    # Fallback heuristic when manifest has no explicit build-dir entrypoint: only scan dist/build/out
    # if there is neither a src/ tree nor direct root JS/TS source files.
    if not has_src_dir and not has_direct_code:
        return present_build_dirs
    return set()


@dataclass(frozen=True)
class SourceFileRecord:
    """Single readable file safely verified inside the snapshot root."""

    rel_path: str
    abs_path: Path
    language: str
    size_bytes: int
    sha256: str
    text: str | None = None


@dataclass
class SourceInventory:
    """Normalized inventory passed to downstream analyzers (Python AST, Semgrep, package.json)."""

    root: Path
    input_kind: str
    snapshot_sha256: str
    files: list[SourceFileRecord] = field(default_factory=list)
    skipped_files: list[SkippedFile] = field(default_factory=list)
    read_errors: list[ReadErrorRecord] = field(default_factory=list)
    skipped_budget: list[SkippedFile] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)
    files_discovered: int = 0
    timed_out: bool = False

    def python_files(self) -> list[SourceFileRecord]:
        return [record for record in self.files if record.language == "python"]

    def js_ts_files(self) -> list[SourceFileRecord]:
        return [
            record for record in self.files if record.language in {"javascript", "typescript"}
        ]

    def code_files(self) -> list[SourceFileRecord]:
        return [
            record
            for record in self.files
            if record.language in {"python", "javascript", "typescript"}
        ]

    def package_json_files(self) -> list[SourceFileRecord]:
        return [
            record
            for record in self.files
            if Path(record.rel_path).name.lower() == "package.json"
        ]

    def binding_gyp_files(self) -> list[SourceFileRecord]:
        return [
            record
            for record in self.files
            if Path(record.rel_path).name.lower() == "binding.gyp"
        ]

    def dependency_files(self) -> list[SourceFileRecord]:
        dep_names = {
            "package.json",
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "pyproject.toml",
            "poetry.lock",
            "uv.lock",
            "pipfile.lock",
        }
        out: list[SourceFileRecord] = []
        for record in self.files:
            name = Path(record.rel_path).name.lower()
            if name in dep_names or (name.startswith("requirements") and name.endswith(".txt")):
                out.append(record)
        return out

    def by_rel_path(self) -> dict[str, SourceFileRecord]:
        return {record.rel_path: record for record in self.files}


def _is_link_or_junction(path: Path) -> bool:
    """Detect POSIX/Windows symlinks and Windows NTFS junctions safely."""
    try:
        if path.is_symlink():
            return True
    except OSError:
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction):
        try:
            if is_junction():
                return True
        except OSError:
            return True
    try:
        st = os.lstat(path)
        reparse_tag = getattr(st, "st_reparse_tag", 0)
        if reparse_tag:
            return True
    except OSError:
        return False
    return False


def _is_inside_root(candidate: Path, root_resolved: Path) -> bool:
    try:
        candidate.resolve(strict=False).relative_to(root_resolved)
        return True
    except ValueError:
        return False


def _classify_language(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in LANGUAGE_BY_EXT:
        return LANGUAGE_BY_EXT[ext]
    if path.name.lower() in {"dockerfile", "makefile"}:
        return "text"
    return "other"


def _classify_os_error(error: OSError) -> str:
    if isinstance(error, PermissionError):
        return "EACCES_OR_AV_QUARANTINE"
    winerror = getattr(error, "winerror", None)
    if winerror in _AV_OR_PERM_WINERRORS:
        return "EACCES_OR_AV_QUARANTINE"
    # On Windows, MSVC open() translates Win32 ERROR_VIRUS_INFECTED (225) into POSIX errno 22 (EINVAL)
    if os.name == "nt" and getattr(error, "errno", None) == 22:
        return "EACCES_OR_AV_QUARANTINE"
    return "IO_ERROR"


def _is_minified(text: str, language: str) -> bool:
    if language not in {"javascript", "typescript", "python"}:
        return False
    if len(text) < DEFAULT_MINIFIED_MIN_BYTES:
        return False
    line_count = text.count("\n") + 1
    avg_line_len = len(text) / max(1, line_count)
    return avg_line_len > DEFAULT_MINIFIED_AVG_LINE_LEN


def _priority_key(rel_path: str, language: str) -> tuple[int, int, str]:
    """Deterministic reachability-oriented ordering before applying max_files budget."""
    parts = rel_path.split("/")
    name = parts[-1].lower()
    depth = len(parts)
    if name in ENTRYPOINT_NAMES or name.endswith("mcp.json"):
        tier = 0
    elif language in {"python", "javascript", "typescript"}:
        tier = 1
    elif language in {"json", "text"}:
        tier = 2
    else:
        tier = 3
    return (tier, depth, rel_path)


def _compute_snapshot_sha256(
    files: list[SourceFileRecord],
    read_errors: list[ReadErrorRecord],
) -> str:
    manifest = {
        "files": sorted((r.rel_path, r.sha256) for r in files),
        "read_errors": sorted((e.path, e.error_code) for e in read_errors),
    }
    return stable_sha256_id(manifest)


def collect_source_inventory(
    target: Path,
    *,
    input_kind: str | None = None,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
    deadline: float | None = None,
) -> SourceInventory:
    """Collect a resilient static SourceInventory for a file or directory snapshot."""
    if max_file_bytes <= 0:
        raise ValueError("max_file_bytes must be positive.")
    if max_files <= 0:
        raise ValueError("max_files must be positive.")
    if deadline is not None and not math.isfinite(deadline):
        raise ValueError("deadline must be a finite monotonic timestamp.")

    raw_target = Path(target).expanduser()
    if _is_link_or_junction(raw_target):
        raise ValueError(f"Scan target cannot be a symlink or junction: {raw_target}")
    if not raw_target.exists():
        raise FileNotFoundError(f"Scan target does not exist: {raw_target}")

    timed_out_walk = False
    if raw_target.is_file():
        root_resolved = raw_target.parent.resolve()
        resolved_kind = input_kind or (
            "config_file" if raw_target.suffix.lower() == ".json" else "local_directory"
        )
        candidates: list[tuple[str, Path]] = [(raw_target.name, raw_target)]
        skipped_files: list[SkippedFile] = []
        read_errors: list[ReadErrorRecord] = []
        files_discovered = 1
    elif raw_target.is_dir():
        root_resolved = raw_target.resolve()
        resolved_kind = input_kind or "local_directory"
        candidates = []
        skipped_files = []
        read_errors = []
        files_discovered = 0

        # Manual BFS/stack walk with followlinks=False and strict root containment
        dir_stack: list[Path] = [root_resolved]

        while dir_stack:
            if deadline is not None and time.monotonic() >= deadline:
                timed_out_walk = True
                break
            current_dir = dir_stack.pop()
            try:
                with os.scandir(current_dir) as it:
                    entries = sorted(it, key=lambda e: e.name)
            except OSError as error:
                rel_dir = (
                    current_dir.relative_to(root_resolved).as_posix()
                    if current_dir != root_resolved
                    else "."
                )
                read_errors.append(
                    ReadErrorRecord(
                        path=rel_dir,
                        error_code=_classify_os_error(error),
                        message=f"{type(error).__name__}: {error}",
                    )
                )
                continue

            included_build_dirs = _included_npm_build_dirs(
                current_dir, entries, max_file_bytes=max_file_bytes
            )
            subdirs_to_visit: list[Path] = []
            for entry in entries:
                if deadline is not None and time.monotonic() >= deadline:
                    timed_out_walk = True
                    break
                entry_path = Path(entry.path)
                try:
                    rel_path = entry_path.relative_to(root_resolved).as_posix()
                except ValueError:
                    skipped_files.append(SkippedFile(path=entry.name, reason="symlink_escape"))
                    continue

                if _is_link_or_junction(entry_path):
                    reason = (
                        "symlink_not_followed"
                        if _is_inside_root(entry_path, root_resolved)
                        else "symlink_escape"
                    )
                    skipped_files.append(SkippedFile(path=rel_path, reason=reason))
                    continue

                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                    is_file = entry.is_file(follow_symlinks=False)
                except OSError as error:
                    read_errors.append(
                        ReadErrorRecord(
                            path=rel_path,
                            error_code=_classify_os_error(error),
                            message=f"{type(error).__name__}: {error}",
                        )
                    )
                    continue

                if is_dir:
                    if entry.name in IGNORED_DIRS and entry.name not in included_build_dirs:
                        skipped_files.append(SkippedFile(path=rel_path, reason="ignored_directory"))
                        continue
                    subdirs_to_visit.append(entry_path)
                elif is_file:
                    files_discovered += 1
                    candidates.append((rel_path, entry_path))
                else:
                    skipped_files.append(SkippedFile(path=rel_path, reason="special_file"))

            # Push in reverse sorted order for deterministic DFS
            for sub in reversed(subdirs_to_visit):
                dir_stack.append(sub)
    else:
        raise ValueError(f"Unsupported target type: {raw_target}")

    # Deterministic reachability prioritization before applying max_files budget
    prioritized = sorted(
        candidates,
        key=lambda item: _priority_key(item[0], _classify_language(item[1])),
    )

    records: list[SourceFileRecord] = []
    skipped_budget: list[SkippedFile] = []
    detected_languages: set[str] = set()
    timed_out = timed_out_walk

    for rel_path, entry_path in prioritized:
        if deadline is not None and time.monotonic() >= deadline:
            timed_out = True
            skipped_budget.append(SkippedFile(path=rel_path, reason="deadline_exceeded"))
            continue

        if len(records) >= max_files:
            skipped_budget.append(SkippedFile(path=rel_path, reason="max_files_budget_exceeded"))
            continue

        # Double-check target file symlink escape (especially for single-file mode)
        if _is_link_or_junction(entry_path):
            reason = (
                "symlink_not_followed"
                if _is_inside_root(entry_path, root_resolved)
                else "symlink_escape"
            )
            skipped_files.append(SkippedFile(path=rel_path, reason=reason))
            continue

        if not _is_inside_root(entry_path, root_resolved):
            skipped_files.append(SkippedFile(path=rel_path, reason="symlink_escape"))
            continue

        ext = entry_path.suffix.lower()
        if ext in BINARY_EXTENSIONS:
            skipped_files.append(SkippedFile(path=rel_path, reason="binary_file"))
            continue

        try:
            st = entry_path.stat()
            size_bytes = int(st.st_size)
        except OSError as error:
            read_errors.append(
                ReadErrorRecord(
                    path=rel_path,
                    error_code=_classify_os_error(error),
                    message=f"{type(error).__name__}: {error}",
                )
            )
            continue

        if size_bytes > max_file_bytes:
            skipped_files.append(SkippedFile(path=rel_path, reason="file_too_large"))
            continue

        try:
            raw_bytes = entry_path.read_bytes()
        except OSError as error:
            read_errors.append(
                ReadErrorRecord(
                    path=rel_path,
                    error_code=_classify_os_error(error),
                    message=f"{type(error).__name__}: {error}",
                )
            )
            continue

        # Binary content check via NUL byte in prefix
        if b"\x00" in raw_bytes[:8192]:
            skipped_files.append(SkippedFile(path=rel_path, reason="binary_file"))
            continue

        language = _classify_language(entry_path)
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            read_errors.append(
                ReadErrorRecord(
                    path=rel_path,
                    error_code="UNICODE_DECODE_ERROR",
                    message=f"UnicodeDecodeError: {error.reason} at byte {error.start}",
                )
            )
            continue

        if _is_minified(text, language):
            skipped_files.append(SkippedFile(path=rel_path, reason="minified_file"))
            continue

        file_sha = hashlib.sha256(raw_bytes).hexdigest()
        if language in {"python", "javascript", "typescript"}:
            detected_languages.add(language)

        records.append(
            SourceFileRecord(
                rel_path=rel_path,
                abs_path=entry_path.resolve(),
                language=language,
                size_bytes=len(raw_bytes),
                sha256=file_sha,
                text=text,
            )
        )

    records.sort(key=lambda r: r.rel_path)
    skipped_files.sort(key=lambda s: (s.path, s.reason))
    read_errors.sort(key=lambda e: (e.path, e.error_code))
    skipped_budget.sort(key=lambda s: (s.path, s.reason))

    return SourceInventory(
        root=root_resolved,
        input_kind=resolved_kind,
        snapshot_sha256=_compute_snapshot_sha256(records, read_errors),
        files=records,
        skipped_files=skipped_files,
        read_errors=read_errors,
        skipped_budget=skipped_budget,
        languages=sorted(detected_languages),
        files_discovered=files_discovered,
        timed_out=timed_out,
    )
