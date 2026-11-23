"""Offline Software Composition Analysis (SCA) adapter (K3.2).

Operates strictly offline against pinned local OSV vulnerability snapshots:
- Reads only lockfiles and dependency manifests approved by SourceInventory.
- Distinguishes manifest version ranges already resolved by a sibling lockfile
  from truly unresolved dependencies.
- Validates offline DB integrity (including optional manifest.json / explicit
  SHA-256 pin) before trusting results.
- Supports both `osv-scanner` (verified strictly offline via `--help`) and direct
  local OSV JSON lookup with ecosystem-accurate version matching (PEP 440 for
  PyPI, SemVer 2.0.0 for npm, exact `versions` lists).
- Never makes network requests and never reports "0 CVE" when dependencies or
  ranges could not be verified (`sca_status = "partial" | "unmeasured" | "failed"`).
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

from .models import (
    AnalysisBoundary,
    Finding,
    OwaspMapping,
    RedactedEvidence,
    SourceSpan,
    TraceStep,
    make_finding_id,
    make_root_cause_group_id,
)
from .source_inventory import SourceFileRecord, SourceInventory, _is_link_or_junction

try:
    from packaging.version import InvalidVersion as _InvalidPep440
    from packaging.version import Version as _Pep440Version
except Exception:  # pragma: no cover - optional fallback if packaging unavailable
    _Pep440Version = None  # type: ignore[assignment]
    _InvalidPep440 = ValueError  # type: ignore[assignment]


LOCKFILE_NAMES: frozenset[str] = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "uv.lock",
        "pipfile.lock",
    }
)

_SEMVER_RE = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_EXACT_NPM_VER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_REQ_EXACT_PIN_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*(?<!=)==(?!=)\s*([^\s;,\\]+)"
)
_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_PYPROJECT_PIN_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*(?<!=)==(?!=)\s*([^\s;,]+)"
)
_PEP503_RE = re.compile(r"[-_.]+")
_SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class PinnedDependency:
    ecosystem: str  # "PyPI" | "npm"
    name: str
    normalized_name: str
    version: str
    source_path: str
    line: int | None = None


@dataclass(frozen=True)
class UnresolvedDependency:
    ecosystem: str
    spec: str
    source_path: str
    reason: str
    line: int | None = None


@dataclass
class ScaAnalysisResult:
    status: str = "unmeasured"  # "complete" | "partial" | "unmeasured" | "unsupported" | "failed"
    findings: list[Finding] = field(default_factory=list)
    analysis_boundaries: list[AnalysisBoundary] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    pinned_dependencies: int = 0
    unresolved_dependencies: int = 0
    db_sha256: str | None = None
    db_snapshot_id: str | None = None
    engine_mode: str = "disabled"  # "disabled" | "local_osv_json" | "osv_scanner_offline"


def _normalize_pkg_name(ecosystem: str, name: str) -> str:
    eco = ecosystem.lower()
    if eco == "pypi":
        return _PEP503_RE.sub("-", name.strip()).lower()
    return name.strip().lower()


def _parse_semver(raw: str) -> tuple[int, int, int, tuple[tuple[int, int | str], ...]] | None:
    match = _SEMVER_RE.fullmatch(raw.strip())
    if not match:
        return None
    major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))
    pre_raw = match.group(4)
    if not pre_raw:
        return (major, minor, patch, ())
    pre_parts: list[tuple[int, int | str]] = []
    for ident in pre_raw.split("."):
        if ident.isdigit():
            # SemVer 2.0.0 forbids leading zeros in numeric pre-release identifiers
            if len(ident) > 1 and ident.startswith("0"):
                return None
            pre_parts.append((0, int(ident)))
        else:
            pre_parts.append((1, ident))
    return (major, minor, patch, tuple(pre_parts))


def _compare_semver(a: str, b: str) -> int | None:
    pa = _parse_semver(a)
    pb = _parse_semver(b)
    if pa is None or pb is None:
        return None
    core_a, pre_a = pa[:3], pa[3]
    core_b, pre_b = pb[:3], pb[3]
    if core_a != core_b:
        return -1 if core_a < core_b else 1
    if not pre_a and not pre_b:
        return 0
    if not pre_a:
        return 1  # release > pre-release
    if not pre_b:
        return -1
    for ia, ib in zip(pre_a, pre_b):
        if ia != ib:
            return -1 if ia < ib else 1
    if len(pre_a) != len(pre_b):
        return -1 if len(pre_a) < len(pre_b) else 1
    return 0


def _compare_ecosystem_version(ecosystem: str, range_type: str, a: str, b: str) -> int | None:
    """Compare version `a` vs `b` using strict ecosystem semantics; None if unsupported/unparseable."""
    rtype = range_type.upper()
    eco = ecosystem.lower()
    if rtype == "SEMVER":
        return _compare_semver(a, b)
    if rtype == "ECOSYSTEM":
        if eco == "pypi":
            if _Pep440Version is None:
                return None
            try:
                va = _Pep440Version(a.strip())
                vb = _Pep440Version(b.strip())
            except _InvalidPep440:
                return None
            return -1 if va < vb else (1 if va > vb else 0)
        if eco == "npm":
            return _compare_semver(a, b)
    return None


def _matches_osv_range(
    ecosystem: str,
    installed_version: str,
    range_obj: dict[str, Any],
) -> tuple[bool, str | None]:
    """Evaluate one OSV range object strictly.

    Returns (is_affected, unsupported_reason). Never guesses on unsupported
    range types, `limit` events, or unparseable version strings.
    """
    range_type = str(range_obj.get("type", "")).upper()
    if range_type not in {"SEMVER", "ECOSYSTEM"}:
        return False, f"unsupported_range_type:{range_type or 'unknown'}"
    if range_type == "ECOSYSTEM" and ecosystem.lower() not in {"pypi", "npm"}:
        return False, f"unsupported_ecosystem_range:{ecosystem}"

    events = range_obj.get("events")
    if not isinstance(events, list) or not events:
        return False, "empty_or_invalid_range_events"

    # Validate installed_version itself under strict ecosystem semantics first
    if _compare_ecosystem_version(ecosystem, range_type, installed_version, installed_version) is None:
        return False, f"unparseable_version:{ecosystem}"

    # Parse and sort all events in ascending ecosystem version order (per OSV spec, events may be unsorted)
    from functools import cmp_to_key

    parsed_events: list[tuple[str, str]] = []  # (kind, raw_bound)
    for ev in events:
        if not isinstance(ev, dict):
            return False, "invalid_range_event"
        if "limit" in ev:
            return False, "unsupported_range_event:limit"
        if "introduced" in ev:
            bound = str(ev["introduced"]).strip()
            if bound != "0" and _compare_ecosystem_version(ecosystem, range_type, bound, bound) is None:
                return False, f"unparseable_range_bound:{ecosystem}"
            parsed_events.append(("introduced", bound))
        elif "fixed" in ev:
            bound = str(ev["fixed"]).strip()
            if _compare_ecosystem_version(ecosystem, range_type, bound, bound) is None:
                return False, f"unparseable_range_bound:{ecosystem}"
            parsed_events.append(("fixed", bound))
        elif "last_affected" in ev:
            bound = str(ev["last_affected"]).strip()
            if _compare_ecosystem_version(ecosystem, range_type, bound, bound) is None:
                return False, f"unparseable_range_bound:{ecosystem}"
            parsed_events.append(("last_affected", bound))
        else:
            return False, "unknown_range_event_key"

    kind_rank = {"introduced": 0, "last_affected": 1, "fixed": 2}

    def _cmp_events(a: tuple[str, str], b: tuple[str, str]) -> int:
        ka, ba = a
        kb, bb = b
        a_zero = ka == "introduced" and ba == "0"
        b_zero = kb == "introduced" and bb == "0"
        if a_zero and b_zero:
            return 0
        if a_zero:
            return -1
        if b_zero:
            return 1
        c = _compare_ecosystem_version(ecosystem, range_type, ba, bb)
        if c is not None and c != 0:
            return c
        return kind_rank[ka] - kind_rank[kb]

    parsed_events.sort(key=cmp_to_key(_cmp_events))

    in_range = False
    for kind, bound in parsed_events:
        if kind == "introduced":
            if bound == "0":
                in_range = True
            else:
                cmp = _compare_ecosystem_version(ecosystem, range_type, installed_version, bound)
                if cmp is None:
                    return False, f"unparseable_range_bound:{ecosystem}"
                if cmp >= 0:
                    in_range = True
        elif kind == "fixed":
            cmp = _compare_ecosystem_version(ecosystem, range_type, installed_version, bound)
            if cmp is None:
                return False, f"unparseable_range_bound:{ecosystem}"
            if cmp >= 0:
                in_range = False
        elif kind == "last_affected":
            cmp = _compare_ecosystem_version(ecosystem, range_type, installed_version, bound)
            if cmp is None:
                return False, f"unparseable_range_bound:{ecosystem}"
            if cmp > 0:
                in_range = False

    return in_range, None


def _is_version_affected_by_entry(
    ecosystem: str,
    installed_version: str,
    affected_entry: dict[str, Any],
) -> tuple[bool, str | None]:
    """Check one `affected[]` block in an OSV record for exact version or range match."""
    versions = affected_entry.get("versions")
    if isinstance(versions, list):
        for candidate in versions:
            if not isinstance(candidate, str):
                continue
            if candidate.strip() == installed_version.strip():
                return True, None
            if ecosystem.lower() == "pypi" and _Pep440Version is not None:
                try:
                    if _Pep440Version(candidate.strip()) == _Pep440Version(installed_version.strip()):
                        return True, None
                except _InvalidPep440:
                    pass

    ranges = affected_entry.get("ranges")
    if not isinstance(ranges, list):
        return False, None

    unsupported_reason: str | None = None
    for rng in ranges:
        if not isinstance(rng, dict):
            unsupported_reason = "invalid_range_object"
            continue
        hit, err = _matches_osv_range(ecosystem, installed_version, rng)
        if hit:
            return True, None
        if err is not None and unsupported_reason is None:
            unsupported_reason = err
    return False, unsupported_reason


def _extract_npm_lock_deps(
    record: SourceFileRecord,
) -> tuple[list[PinnedDependency], list[dict[str, Any]]]:
    pinned: list[PinnedDependency] = []
    diags: list[dict[str, Any]] = []
    if record.text is None:
        return pinned, diags
    try:
        payload = json.loads(record.text)
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        diags.append(
            {
                "kind": "sca_lockfile_parse_error",
                "path": record.rel_path,
                "message": f"Failed to parse {record.rel_path} ({type(exc).__name__}).",
            }
        )
        return pinned, diags

    if not isinstance(payload, dict):
        diags.append(
            {
                "kind": "sca_lockfile_parse_error",
                "path": record.rel_path,
                "message": f"Top-level JSON in {record.rel_path} is not an object.",
            }
        )
        return pinned, diags

    seen: set[tuple[str, str]] = set()
    packages = payload.get("packages")
    if isinstance(packages, dict):
        for pkg_key, meta in packages.items():
            if not pkg_key or not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if not isinstance(version, str) or not version.strip():
                continue
            name = meta.get("name")
            if not isinstance(name, str) or not name.strip():
                marker = "node_modules/"
                if marker in pkg_key:
                    name = pkg_key.rsplit(marker, 1)[-1]
                else:
                    continue
            norm = _normalize_pkg_name("npm", name)
            ver = version.strip()
            if (norm, ver) not in seen:
                seen.add((norm, ver))
                pinned.append(PinnedDependency("npm", name.strip(), norm, ver, record.rel_path))

    # Fallback for lockfileVersion 1 `dependencies` tree
    if not pinned and isinstance(payload.get("dependencies"), dict):
        def _walk_v1(tree: dict[str, Any], depth: int = 0) -> None:
            if depth > 12:
                return
            for pkg_name, meta in tree.items():
                if not isinstance(meta, dict):
                    continue
                ver = meta.get("version")
                if isinstance(ver, str) and ver.strip():
                    norm = _normalize_pkg_name("npm", pkg_name)
                    if (norm, ver.strip()) not in seen:
                        seen.add((norm, ver.strip()))
                        pinned.append(PinnedDependency("npm", pkg_name, norm, ver.strip(), record.rel_path))
                nested = meta.get("dependencies")
                if isinstance(nested, dict):
                    _walk_v1(nested, depth + 1)

        _walk_v1(payload["dependencies"])

    return pinned, diags


def _extract_toml_lock_deps(
    record: SourceFileRecord,
) -> tuple[list[PinnedDependency], list[dict[str, Any]]]:
    """Parse poetry.lock or uv.lock via tomllib (or tomli on Python 3.10)."""
    pinned: list[PinnedDependency] = []
    diags: list[dict[str, Any]] = []
    if record.text is None:
        return pinned, diags
    if tomllib is None:
        diags.append(
            {
                "kind": "sca_toml_parser_unavailable",
                "path": record.rel_path,
                "message": f"TOML parser unavailable (install tomli on Python <3.11) to parse {record.rel_path}.",
            }
        )
        return pinned, diags
    try:
        payload = tomllib.loads(record.text)
    except Exception as exc:
        diags.append(
            {
                "kind": "sca_lockfile_parse_error",
                "path": record.rel_path,
                "message": f"Failed to parse TOML lockfile {record.rel_path} ({type(exc).__name__}).",
            }
        )
        return pinned, diags

    packages = payload.get("package")
    if not isinstance(packages, list):
        return pinned, diags

    seen: set[tuple[str, str]] = set()
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        name_s, ver_s = name.strip(), version.strip()
        if not name_s or not ver_s:
            continue
        norm = _normalize_pkg_name("PyPI", name_s)
        if (norm, ver_s) not in seen:
            seen.add((norm, ver_s))
            pinned.append(PinnedDependency("PyPI", name_s, norm, ver_s, record.rel_path))
    return pinned, diags


def _extract_requirements_deps(
    record: SourceFileRecord,
    *,
    resolved_pypi_names: set[str],
) -> tuple[list[PinnedDependency], list[UnresolvedDependency]]:
    pinned: list[PinnedDependency] = []
    unresolved: list[UnresolvedDependency] = []
    if record.text is None:
        return pinned, unresolved

    for idx, raw_line in enumerate(record.text.splitlines(), start=1):
        # Strip inline comments cleanly
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("-r ", "--requirement", "-c ", "--constraint")):
            unresolved.append(
                UnresolvedDependency("PyPI", line.split()[0], record.rel_path, "nested_requirements_directive", idx)
            )
            continue
        if line.startswith(("-e ", "--editable")):
            unresolved.append(
                UnresolvedDependency("PyPI", "editable_requirement", record.rel_path, "editable_or_vcs_requirement", idx)
            )
            continue
        if line.startswith("-"):
            # pip index/option lines (--extra-index-url, --hash, etc.)
            continue
        if "://" in line or line.startswith(("git+", "hg+", "svn+", "bzr+")) or " @ " in line:
            unresolved.append(
                UnresolvedDependency("PyPI", "url_or_vcs_requirement", record.rel_path, "direct_url_or_vcs_unpinned", idx)
            )
            continue
        m_pin = _REQ_EXACT_PIN_RE.match(line)
        if m_pin:
            name, ver = m_pin.group(1), m_pin.group(2).strip()
            if ver and "*" not in ver:
                norm = _normalize_pkg_name("PyPI", name)
                pinned.append(PinnedDependency("PyPI", name, norm, ver, record.rel_path, idx))
                continue
        m_name = _REQ_NAME_RE.match(line)
        pkg_label = m_name.group(1) if m_name else "unknown_requirement"
        norm_label = _normalize_pkg_name("PyPI", pkg_label)
        if norm_label in resolved_pypi_names:
            # Manifest range already resolved by a sibling poetry.lock / uv.lock
            continue
        unresolved.append(
            UnresolvedDependency("PyPI", pkg_label, record.rel_path, "unpinned_version_range", idx)
        )
    return pinned, unresolved


def _extract_dependencies_from_inventory(
    inventory: SourceInventory,
    *,
    using_osv_scanner_binary: bool,
) -> tuple[list[PinnedDependency], list[UnresolvedDependency], list[dict[str, Any]], list[SourceFileRecord]]:
    """Collect pinned vs unresolved dependencies grouped by directory (lockfile overrides manifest ranges)."""
    dep_files = inventory.dependency_files()
    by_dir: dict[str, list[SourceFileRecord]] = {}
    for rec in dep_files:
        by_dir.setdefault(posixpath.dirname(rec.rel_path), []).append(rec)

    all_pinned: list[PinnedDependency] = []
    all_unresolved: list[UnresolvedDependency] = []
    all_diags: list[dict[str, Any]] = []
    lockfiles_for_binary: list[SourceFileRecord] = []

    for dir_key in sorted(by_dir):
        records = by_dir[dir_key]
        by_name = {Path(r.rel_path).name.lower(): r for r in records}

        # --- npm ecosystem in this directory ---
        resolved_npm_names: set[str] = set()
        npm_lock = by_name.get("package-lock.json") or by_name.get("npm-shrinkwrap.json")
        if npm_lock is not None:
            lockfiles_for_binary.append(npm_lock)
            lock_pinned, lock_diags = _extract_npm_lock_deps(npm_lock)
            all_pinned.extend(lock_pinned)
            all_diags.extend(lock_diags)
            resolved_npm_names.update(d.normalized_name for d in lock_pinned)
        elif "yarn.lock" in by_name or "pnpm-lock.yaml" in by_name:
            other_lock = by_name.get("yarn.lock") or by_name["pnpm-lock.yaml"]
            lockfiles_for_binary.append(other_lock)
            if not using_osv_scanner_binary:
                all_diags.append(
                    {
                        "kind": "sca_unsupported_lockfile_format",
                        "path": other_lock.rel_path,
                        "message": f"Lockfile {other_lock.rel_path} requires osv-scanner offline binary for full resolution.",
                    }
                )
                all_unresolved.append(
                    UnresolvedDependency(
                        "npm",
                        Path(other_lock.rel_path).name,
                        other_lock.rel_path,
                        "unsupported_lockfile_without_osv_scanner",
                    )
                )

        pkg_json = by_name.get("package.json")
        if pkg_json is not None and pkg_json.text is not None:
            try:
                payload = json.loads(pkg_json.text)
            except (json.JSONDecodeError, ValueError, RecursionError):
                payload = None
            if isinstance(payload, dict):
                for section in ("dependencies", "optionalDependencies"):
                    deps = payload.get(section)
                    if not isinstance(deps, dict):
                        continue
                    for dep_name, dep_spec in deps.items():
                        if not isinstance(dep_name, str) or not isinstance(dep_spec, str):
                            continue
                        norm = _normalize_pkg_name("npm", dep_name)
                        if norm in resolved_npm_names:
                            # Already resolved by sibling package-lock.json / npm-shrinkwrap.json
                            continue
                        if ("yarn.lock" in by_name or "pnpm-lock.yaml" in by_name) and using_osv_scanner_binary:
                            continue
                        spec_s = dep_spec.strip()
                        if _EXACT_NPM_VER_RE.fullmatch(spec_s):
                            all_pinned.append(PinnedDependency("npm", dep_name, norm, spec_s, pkg_json.rel_path))
                        else:
                            all_unresolved.append(
                                UnresolvedDependency("npm", dep_name, pkg_json.rel_path, "unpinned_manifest_range")
                            )

        # --- PyPI ecosystem in this directory ---
        resolved_pypi_names: set[str] = set()
        for lock_name in ("poetry.lock", "uv.lock"):
            py_lock = by_name.get(lock_name)
            if py_lock is not None:
                lockfiles_for_binary.append(py_lock)
                lock_pinned, lock_diags = _extract_toml_lock_deps(py_lock)
                all_pinned.extend(lock_pinned)
                all_diags.extend(lock_diags)
                resolved_pypi_names.update(d.normalized_name for d in lock_pinned)
        if "pipfile.lock" in by_name:
            pf_lock = by_name["pipfile.lock"]
            lockfiles_for_binary.append(pf_lock)
            if pf_lock.text is not None:
                try:
                    pf_data = json.loads(pf_lock.text)
                    if isinstance(pf_data, dict):
                        for sec in ("default", "develop"):
                            sec_obj = pf_data.get(sec)
                            if isinstance(sec_obj, dict):
                                for dep_name, meta in sec_obj.items():
                                    if isinstance(meta, dict) and isinstance(meta.get("version"), str):
                                        v = meta["version"].strip()
                                        if v.startswith("=="):
                                            ver_s = v[2:].strip()
                                            norm = _normalize_pkg_name("PyPI", dep_name)
                                            all_pinned.append(PinnedDependency("PyPI", dep_name, norm, ver_s, pf_lock.rel_path))
                                            resolved_pypi_names.add(norm)
                except (json.JSONDecodeError, ValueError, RecursionError) as exc:
                    all_diags.append(
                        {
                            "kind": "sca_lockfile_parse_error",
                            "path": pf_lock.rel_path,
                            "message": f"Failed to parse {pf_lock.rel_path} ({type(exc).__name__}).",
                        }
                    )

        for rec in records:
            lname = Path(rec.rel_path).name.lower()
            if lname.startswith("requirements") and lname.endswith(".txt"):
                lockfiles_for_binary.append(rec)
                req_pinned, req_unresolved = _extract_requirements_deps(
                    rec, resolved_pypi_names=resolved_pypi_names
                )
                all_pinned.extend(req_pinned)
                all_unresolved.extend(req_unresolved)
                resolved_pypi_names.update(d.normalized_name for d in req_pinned)

        pyproject = by_name.get("pyproject.toml")
        if pyproject is not None and pyproject.text is not None:
            if tomllib is None:
                all_diags.append(
                    {
                        "kind": "sca_toml_parser_unavailable",
                        "path": pyproject.rel_path,
                        "message": f"TOML parser unavailable (install tomli on Python <3.11) to parse {pyproject.rel_path}.",
                    }
                )
                py_data = None
            else:
                try:
                    py_data = tomllib.loads(pyproject.text)
                except Exception as exc:
                    all_diags.append(
                        {
                            "kind": "sca_manifest_parse_error",
                            "path": pyproject.rel_path,
                            "message": f"Failed to parse {pyproject.rel_path} ({type(exc).__name__}).",
                        }
                    )
                    py_data = None
            if isinstance(py_data, dict):
                proj = py_data.get("project")
                if isinstance(proj, dict) and isinstance(proj.get("dependencies"), list):
                    for raw_dep in proj["dependencies"]:
                        if not isinstance(raw_dep, str) or not raw_dep.strip():
                            continue
                        m_pin = _PYPROJECT_PIN_RE.match(raw_dep)
                        if m_pin and "*" not in m_pin.group(2):
                            norm = _normalize_pkg_name("PyPI", m_pin.group(1))
                            if norm not in resolved_pypi_names:
                                all_pinned.append(
                                    PinnedDependency("PyPI", m_pin.group(1), norm, m_pin.group(2).strip(), pyproject.rel_path)
                                )
                                resolved_pypi_names.add(norm)
                            continue
                        m_name = _REQ_NAME_RE.match(raw_dep)
                        dep_name = m_name.group(1) if m_name else "unknown_dependency"
                        norm = _normalize_pkg_name("PyPI", dep_name)
                        if norm in resolved_pypi_names:
                            continue
                        all_unresolved.append(
                            UnresolvedDependency("PyPI", dep_name, pyproject.rel_path, "unpinned_manifest_range")
                        )

                poetry_deps = (
                    py_data.get("tool", {}).get("poetry", {}).get("dependencies")
                    if isinstance(py_data.get("tool"), dict)
                    and isinstance(py_data.get("tool", {}).get("poetry"), dict)
                    else None
                )
                if isinstance(poetry_deps, dict):
                    for dep_name, dep_spec in poetry_deps.items():
                        if dep_name.lower() == "python":
                            continue
                        norm = _normalize_pkg_name("PyPI", dep_name)
                        if norm in resolved_pypi_names:
                            continue
                        spec_str = dep_spec if isinstance(dep_spec, str) else (
                            dep_spec.get("version") if isinstance(dep_spec, dict) else None
                        )
                        if isinstance(spec_str, str) and re.fullmatch(r"\d+(?:\.\d+)+", spec_str.strip()):
                            all_pinned.append(PinnedDependency("PyPI", dep_name, norm, spec_str.strip(), pyproject.rel_path))
                            resolved_pypi_names.add(norm)
                        else:
                            all_unresolved.append(
                                UnresolvedDependency("PyPI", dep_name, pyproject.rel_path, "unpinned_manifest_range")
                            )

    return all_pinned, all_unresolved, all_diags, lockfiles_for_binary


def _verify_and_load_local_osv_db(
    db_dir: Path,
    *,
    expected_sha256: str | None = None,
    deadline: float | None = None,
) -> tuple[dict[tuple[str, str], list[dict[str, Any]]] | None, str | None, str | None, list[dict[str, Any]]]:
    """Verify pinned offline OSV JSON DB directory, check manifest/hash pin, and index advisories."""
    diags: list[dict[str, Any]] = []
    if not db_dir.exists() or not db_dir.is_dir() or _is_link_or_junction(db_dir):
        diags.append(
            {
                "kind": "osv_db_invalid",
                "message": "Configured offline OSV DB path does not exist or is not a safe directory.",
            }
        )
        return None, None, None, diags

    advisory_files: list[Path] = []
    manifest_path: Path | None = None
    for root_str, dirnames, filenames in os.walk(db_dir, followlinks=False):
        if deadline is not None and time.monotonic() >= deadline:
            diags.append({"kind": "sca_budget_exceeded", "message": "Deadline reached while scanning offline OSV DB."})
            return None, None, None, diags
        dirnames[:] = sorted(d for d in dirnames if not _is_link_or_junction(Path(root_str) / d))
        for fname in sorted(filenames):
            fpath = Path(root_str) / fname
            if _is_link_or_junction(fpath):
                continue
            low = fname.lower()
            if fpath.parent == db_dir and low in {"manifest.json", "db-pin.json"}:
                manifest_path = fpath
                continue
            if low.endswith(".json"):
                advisory_files.append(fpath)

    if not advisory_files:
        diags.append(
            {
                "kind": "osv_db_empty",
                "message": "Configured offline OSV DB directory contains no advisory JSON files.",
            }
        )
        return None, None, None, diags

    hasher = hashlib.sha256()
    index: dict[tuple[str, str], list[dict[str, Any]]] = {}
    parsed_count = 0

    for fpath in sorted(advisory_files, key=lambda p: p.relative_to(db_dir).as_posix()):
        if deadline is not None and time.monotonic() >= deadline:
            diags.append({"kind": "sca_budget_exceeded", "message": "Deadline reached while loading offline OSV DB."})
            return None, None, None, diags
        rel = fpath.relative_to(db_dir).as_posix()
        try:
            raw_bytes = fpath.read_bytes()
        except OSError as exc:
            diags.append({"kind": "osv_db_read_error", "path": rel, "message": f"Failed reading DB file ({type(exc).__name__})."})
            return None, None, None, diags

        hasher.update(rel.encode("utf-8"))
        hasher.update(b"\x00")
        hasher.update(hashlib.sha256(raw_bytes).digest())
        hasher.update(b"\n")

        try:
            data = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
            diags.append({"kind": "osv_db_corrupt_json", "path": rel, "message": f"Invalid OSV JSON in DB ({type(exc).__name__})."})
            return None, None, None, diags

        records: list[dict[str, Any]]
        if isinstance(data, dict) and isinstance(data.get("advisories"), list):
            records = [r for r in data["advisories"] if isinstance(r, dict)]
        elif isinstance(data, list):
            records = [r for r in data if isinstance(r, dict)]
        elif isinstance(data, dict) and isinstance(data.get("id"), str):
            records = [data]
        else:
            continue

        for adv in records:
            adv_id = adv.get("id")
            affected = adv.get("affected")
            if not isinstance(adv_id, str) or not isinstance(affected, list):
                continue
            parsed_count += 1
            for aff in affected:
                if not isinstance(aff, dict):
                    continue
                pkg = aff.get("package")
                if not isinstance(pkg, dict):
                    continue
                eco = pkg.get("ecosystem")
                pname = pkg.get("name")
                if not isinstance(eco, str) or not isinstance(pname, str):
                    continue
                key = (eco.lower(), _normalize_pkg_name(eco, pname))
                index.setdefault(key, []).append(adv)

    computed_sha256 = hasher.hexdigest()
    snapshot_id: str | None = None

    # Validate manifest.json / db-pin.json if present
    if manifest_path is not None:
        try:
            manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            diags.append({"kind": "osv_db_manifest_invalid", "message": f"Malformed DB pin manifest ({type(exc).__name__})."})
            return None, None, None, diags
        if not isinstance(manifest_data, dict):
            diags.append({"kind": "osv_db_manifest_invalid", "message": "DB pin manifest must be a JSON object."})
            return None, None, None, diags
        if isinstance(manifest_data.get("snapshot_id"), str):
            snapshot_id = manifest_data["snapshot_id"].strip()
        pinned_hash = manifest_data.get("sha256")
        if pinned_hash is not None:
            if not isinstance(pinned_hash, str) or not _SHA256_HEX_RE.fullmatch(pinned_hash.strip()):
                diags.append({"kind": "osv_db_hash_invalid", "message": "DB manifest sha256 pin is malformed."})
                return None, None, None, diags
            if pinned_hash.strip().lower() != computed_sha256:
                diags.append(
                    {
                        "kind": "osv_db_hash_mismatch",
                        "message": "Offline OSV DB digest does not match manifest.json sha256 pin.",
                    }
                )
                return None, None, None, diags

    if expected_sha256 is not None:
        clean_expected = expected_sha256.strip().removeprefix("sha256:")
        if not _SHA256_HEX_RE.fullmatch(clean_expected) or clean_expected.lower() != computed_sha256:
            diags.append(
                {
                    "kind": "osv_db_hash_mismatch",
                    "message": "Offline OSV DB digest does not match requested --osv-db-sha256 pin.",
                }
            )
            return None, None, None, diags

    if parsed_count == 0:
        diags.append({"kind": "osv_db_empty", "message": "No valid OSV advisory records loaded from offline DB."})
        return None, None, None, diags

    return index, f"sha256:{computed_sha256}", snapshot_id, diags


def _map_osv_severity(advisory: dict[str, Any]) -> str:
    db_spec = advisory.get("database_specific")
    if isinstance(db_spec, dict) and isinstance(db_spec.get("severity"), str):
        sev_raw = db_spec["severity"].strip().upper()
        if sev_raw == "CRITICAL":
            return "critical"
        if sev_raw == "HIGH":
            return "high"
        if sev_raw in {"MODERATE", "MEDIUM"}:
            return "medium"
        if sev_raw == "LOW":
            return "low"
    sev_list = advisory.get("severity")
    if isinstance(sev_list, list):
        for entry in sev_list:
            if isinstance(entry, dict) and isinstance(entry.get("score"), str):
                score_str = entry["score"].strip()
                try:
                    num = float(score_str)
                except ValueError:
                    continue
                if num >= 9.0:
                    return "critical"
                if num >= 7.0:
                    return "high"
                if num >= 4.0:
                    return "medium"
                return "low"
    return "high"


def _make_advisory_finding(
    *,
    server_id: str,
    dep: PinnedDependency,
    adv_id: str,
    aliases: list[str],
    severity: str,
    summary: str,
    db_sha256: str | None,
) -> Finding:
    span = SourceSpan(
        path=dep.source_path,
        start_line=dep.line or 1,
        end_line=dep.line or 1,
    )
    rule_id = "mcp-sca-vulnerable-dependency"
    fid = make_finding_id(server_id, f"{rule_id}:{adv_id}:{dep.normalized_name}:{dep.version}", span)
    rcg = make_root_cause_group_id(
        server_id=server_id,
        component="bootstrap",
        root_behavior=f"sca_{dep.ecosystem.lower()}_{dep.normalized_name}_{adv_id}",
        primary_span=span,
    )
    cves = [a for a in aliases if a.upper().startswith("CVE-")]
    alias_suffix = f" ({', '.join(cves[:3])})" if cves else ""
    safe_snippet = (
        f"{dep.source_path}:{dep.line or 1}: {dep.ecosystem}:{dep.name}=={dep.version} "
        f"matched offline advisory {adv_id}{alias_suffix}"
    )
    limits = [f"Offline OSV DB pin: {db_sha256}" if db_sha256 else "Offline OSV lookup."]
    return Finding(
        finding_id=fid,
        root_cause_group_id=rcg,
        server_id=server_id,
        component="bootstrap",
        rule_id=rule_id,
        rule_version="0.5",
        detector="sca_osv",
        kind="dependency_advisory",
        category="supply_chain",
        severity=severity,
        evidence_strength="verified",
        confidence=0.95,
        mcp_surface="A3",
        title=f"Vulnerable dependency {dep.name} {dep.version} ({adv_id})",
        reasoning=(
            f"Pinned {dep.ecosystem} dependency '{dep.name}' version '{dep.version}' in {dep.source_path} "
            f"matches offline OSV advisory {adv_id}{alias_suffix}: {summary or 'Known vulnerability'}."
        ),
        remediation=f"Upgrade '{dep.name}' to a fixed version per advisory {adv_id} and regenerate the lockfile.",
        owasp_mapping=OwaspMapping(
            status="mapped",
            primary_id="MCP04:2025",
            primary_name="Software Supply Chain Attacks and Dependency Tampering",
            llm_top10_ids=("LLM03:2025",),
            predicate_rationale=f"Pinned dependency matched offline OSV advisory {adv_id}.",
        ),
        cwe_ids=[],
        sink_span=span,
        trace=[
            TraceStep(
                role="artifact",
                span=span,
                symbol=f"{dep.ecosystem}:{dep.name}=={dep.version}",
                edge_kind="definite",
            )
        ],
        redacted_evidence=RedactedEvidence(snippet=safe_snippet, secrets_redacted=True),
        limitations=limits,
        evidence_sources=["sca_osv"],
        review_status="pending" if severity in {"critical", "high"} else "not_required",
    )


def _verify_osv_scanner_offline_flags(
    binary_path: str, timeout: float
) -> tuple[bool, list[str], list[str], bool, str | None]:
    """Inspect `osv-scanner scan source --help` (fallback `scan --help`) for strict offline flags.

    Returns (ok, subcommand_args, offline_flags, uses_local_db_flag, error_message).
    Requires both `--offline` and `--all-packages` so offline execution and full
    package-coverage verification are both guaranteed.
    """
    candidates = (["scan", "source"], ["scan"])
    last_err: str | None = None
    for subcmd in candidates:
        try:
            proc = subprocess.run(
                [binary_path, *subcmd, "--help"],
                capture_output=True,
                text=True,
                timeout=max(1.0, min(timeout, 10.0)),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, [], [], False, f"Failed invoking osv-scanner --help ({type(exc).__name__})."

        help_text = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if proc.returncode == 0 and "--offline" in help_text and "--all-packages" in help_text:
            flags = ["--offline"]
            if "--offline-vulnerabilities" in help_text:
                flags.append("--offline-vulnerabilities")
            flags.append("--all-packages")
            uses_local_db_flag = "--local-db-base-directory" in help_text
            return True, subcmd, flags, uses_local_db_flag, None
        last_err = (
            "Installed osv-scanner binary does not advertise required --offline and "
            "--all-packages flags."
        )

    return False, [], [], False, last_err


def _run_osv_scanner_offline(
    *,
    binary_path: str,
    db_dir: Path,
    lockfiles: list[SourceFileRecord],
    expected_pinned: list[PinnedDependency],
    server_id: str,
    deadline: float | None,
    db_sha256: str | None,
) -> tuple[list[Finding], list[dict[str, Any]], list[AnalysisBoundary], str, set[str], set[tuple[str, str, str]]]:
    """Run verified-offline osv-scanner on a temporary staging copy of approved lockfiles.

    Returns (findings, diagnostics, boundaries, status, observed_sources, observed_packages)
    where status is one of {"complete", "partial", "failed"}.
    """
    remaining = 30.0 if deadline is None else (deadline - time.monotonic())
    if remaining <= 0.5:
        return (
            [],
            [{"kind": "sca_budget_exceeded", "message": "Insufficient budget before osv-scanner execution."}],
            [AnalysisBoundary(kind="budget_exceeded", location=None, detail="Insufficient budget before osv-scanner execution.")],
            "partial",
            set(),
            set(),
        )

    ok, subcmd, offline_flags, uses_local_db_flag, err = _verify_osv_scanner_offline_flags(binary_path, remaining)
    if not ok:
        return (
            [],
            [{"kind": "osv_scanner_offline_flags_unsupported", "message": err or "Offline flags unsupported."}],
            [],
            "failed",
            set(),
            set(),
        )

    has_nonempty_lockfile = any(bool(rec.text and rec.text.strip()) for rec in lockfiles)
    resolved_db_str = str(db_dir.resolve())
    with TemporaryDirectory(prefix="mcpsca_") as stage_str:
        stage_root = Path(stage_str)
        for rec in lockfiles:
            if rec.text is None:
                continue
            dest = stage_root / Path(rec.rel_path)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(rec.text.encode("utf-8"))

        remaining = 30.0 if deadline is None else (deadline - time.monotonic())
        if remaining <= 0.5:
            return (
                [],
                [{"kind": "sca_budget_exceeded", "message": "Deadline reached before osv-scanner subprocess."}],
                [AnalysisBoundary(kind="budget_exceeded", location=None, detail="Deadline reached before osv-scanner execution.")],
                "partial",
                set(),
                set(),
            )

        cmd = [
            binary_path,
            *subcmd,
            *offline_flags,
        ]
        if uses_local_db_flag:
            cmd.extend(["--local-db-base-directory", resolved_db_str])
        cmd.extend(
            [
                "--format=json",
                "--recursive",
                str(stage_root),
            ]
        )
        child_env = {**os.environ, "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": resolved_db_str}
        try:
            proc = subprocess.run(
                cmd,
                env=child_env,
                capture_output=True,
                text=True,
                timeout=max(1.0, remaining),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return (
                [],
                [{"kind": "osv_scanner_error", "message": f"osv-scanner failed ({type(exc).__name__})."}],
                [],
                "failed",
                set(),
                set(),
            )

        # osv-scanner exit codes: 0 = no vulns, 1 = vulns found, 128 = no packages found, others = error
        if proc.returncode not in {0, 1, 128}:
            return (
                [],
                [{"kind": "osv_scanner_error", "message": f"osv-scanner exited with code {proc.returncode}."}],
                [],
                "failed",
                set(),
                set(),
            )

        if proc.returncode == 128:
            if expected_pinned or has_nonempty_lockfile:
                return (
                    [],
                    [
                        {
                            "kind": "osv_scanner_no_packages_detected",
                            "message": "osv-scanner exited with code 128 (no packages found) despite non-empty lockfiles/expected pinned dependencies.",
                        }
                    ],
                    [
                        AnalysisBoundary(
                            kind="external_lib",
                            location=lockfiles[0].rel_path if lockfiles else None,
                            detail="osv-scanner reported no packages for staged dependency lockfiles; SCA coverage incomplete.",
                        )
                    ],
                    "partial",
                    set(),
                    set(),
                )
            return [], [], [], "complete", set(), set()

        if not (proc.stdout or "").strip():
            return (
                [],
                [
                    {
                        "kind": "osv_scanner_empty_output",
                        "message": f"osv-scanner exited with code {proc.returncode} but produced empty stdout.",
                    }
                ],
                [],
                "failed",
                set(),
                set(),
            )

        try:
            out_data = json.loads(proc.stdout)
        except (json.JSONDecodeError, ValueError) as exc:
            return (
                [],
                [{"kind": "osv_scanner_invalid_json", "message": f"Invalid JSON from osv-scanner ({type(exc).__name__})."}],
                [],
                "failed",
                set(),
                set(),
            )

        if not isinstance(out_data, dict) or not isinstance(out_data.get("results"), list):
            return (
                [],
                [
                    {
                        "kind": "osv_scanner_invalid_output_shape",
                        "message": "osv-scanner JSON output must be an object containing a 'results' list.",
                    }
                ],
                [],
                "failed",
                set(),
                set(),
            )

        findings: list[Finding] = []
        diags: list[dict[str, Any]] = []
        boundaries: list[AnalysisBoundary] = []
        seen_keys: set[tuple[str, str, str, str]] = set()
        observed_sources: set[str] = set()
        observed_packages: set[tuple[str, str, str]] = set()
        malformed_entries = 0
        resolved_stage = stage_root.resolve()

        for res in out_data["results"]:
            if not isinstance(res, dict) or not isinstance(res.get("packages"), list):
                malformed_entries += 1
                continue
            src = res.get("source")
            raw_path = src.get("path", "") if isinstance(src, dict) and isinstance(src.get("path"), str) else ""
            rel_path = ""
            if raw_path:
                try:
                    rel_path = Path(raw_path).resolve().relative_to(resolved_stage).as_posix()
                except Exception:
                    rel_path = raw_path.replace("\\", "/").lstrip("./")
            if rel_path:
                observed_sources.add(rel_path)
            fallback_path = rel_path or "lockfile"

            for pkg_entry in res["packages"]:
                if not isinstance(pkg_entry, dict):
                    malformed_entries += 1
                    continue
                pkg_meta = pkg_entry.get("package")
                if not isinstance(pkg_meta, dict):
                    malformed_entries += 1
                    continue
                eco = str(pkg_meta.get("ecosystem", "")).strip()
                name = str(pkg_meta.get("name", "")).strip()
                ver = str(pkg_meta.get("version", "")).strip()
                if not eco or not name or not ver:
                    malformed_entries += 1
                    continue
                norm_name = _normalize_pkg_name(eco, name)
                observed_packages.add((eco.lower(), norm_name, ver))
                dep = PinnedDependency(eco, name, norm_name, ver, fallback_path)

                raw_vulns = pkg_entry.get("vulnerabilities", [])
                if raw_vulns is None:
                    raw_vulns = []
                if not isinstance(raw_vulns, list):
                    malformed_entries += 1
                    continue
                for vuln in raw_vulns:
                    if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str) or not vuln["id"].strip():
                        malformed_entries += 1
                        continue
                    adv_id = vuln["id"].strip()
                    key = (eco.lower(), dep.normalized_name, ver, adv_id)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    aliases = [a for a in vuln.get("aliases", []) if isinstance(a, str)]
                    findings.append(
                        _make_advisory_finding(
                            server_id=server_id,
                            dep=dep,
                            adv_id=adv_id,
                            aliases=aliases,
                            severity=_map_osv_severity(vuln),
                            summary=str(vuln.get("summary") or ""),
                            db_sha256=db_sha256,
                        )
                    )

        if malformed_entries > 0:
            diags.append(
                {
                    "kind": "osv_scanner_malformed_result_entry",
                    "count": malformed_entries,
                    "message": f"osv-scanner JSON output contained {malformed_entries} malformed result/package/vulnerability entry(ies).",
                }
            )
            if out_data["results"] and not observed_packages:
                return [], diags, boundaries, "failed", observed_sources, observed_packages

        if proc.returncode == 1 and not findings:
            diags.append(
                {
                    "kind": "osv_scanner_exit_mismatch",
                    "message": "osv-scanner exited with code 1 (vulnerabilities found) but output yielded no valid vulnerability findings.",
                }
            )
            return [], diags, boundaries, "failed", observed_sources, observed_packages

        outcome = "partial" if malformed_entries > 0 else "complete"
        return findings, diags, boundaries, outcome, observed_sources, observed_packages


def analyze_sca_offline(
    inventory: SourceInventory,
    *,
    server_id: str,
    osv_db: Path | None = None,
    osv_db_sha256: str | None = None,
    osv_scanner: str | None = None,
    enabled: bool = True,
    deadline: float | None = None,
) -> ScaAnalysisResult:
    """Run strictly offline SCA over inventory-approved lockfiles and manifests."""
    if not enabled:
        return ScaAnalysisResult(status="unmeasured", engine_mode="disabled")

    resolved_db = osv_db
    if resolved_db is None:
        env_db = os.environ.get("MCP_SCANNER_OSV_DB")
        if env_db:
            resolved_db = Path(env_db)
    resolved_pin = osv_db_sha256 or os.environ.get("MCP_SCANNER_OSV_DB_SHA256")
    resolved_bin = osv_scanner or os.environ.get("MCP_SCANNER_OSV_SCANNER")

    if resolved_db is None:
        # SCA not configured in this environment -> honestly report unmeasured (never 0 CVE)
        return ScaAnalysisResult(status="unmeasured", engine_mode="disabled")

    if deadline is not None and time.monotonic() >= deadline:
        return ScaAnalysisResult(
            status="partial",
            analysis_boundaries=[
                AnalysisBoundary(
                    kind="budget_exceeded",
                    location=None,
                    detail="Deadline reached before offline SCA analysis could run.",
                )
            ],
            diagnostics=[{"kind": "sca_budget_exceeded", "message": "Deadline reached before SCA."}],
            engine_mode="local_osv_json",
        )

    use_binary = False
    binary_resolved: str | None = None
    if resolved_bin:
        found = shutil.which(resolved_bin) if not Path(resolved_bin).exists() else str(Path(resolved_bin))
        if not found:
            return ScaAnalysisResult(
                status="failed",
                diagnostics=[
                    {
                        "kind": "osv_scanner_not_found",
                        "message": f"Configured osv-scanner executable '{resolved_bin}' was not found.",
                    }
                ],
                engine_mode="osv_scanner_offline",
            )
        use_binary = True
        binary_resolved = found

    # Check skipped/unreadable lockfiles in inventory (real SCA coverage gap when SCA is enabled)
    diags: list[dict[str, Any]] = []
    boundaries: list[AnalysisBoundary] = []
    has_partial_gap = False

    def _is_dep_file_name(rel: str) -> bool:
        lname = Path(rel).name.lower()
        return lname in LOCKFILE_NAMES or lname in {"package.json", "pyproject.toml"} or (
            lname.startswith("requirements") and lname.endswith(".txt")
        )

    for sk in [*inventory.skipped_files, *inventory.skipped_budget]:
        if _is_dep_file_name(sk.path):
            has_partial_gap = True
            diags.append(
                {
                    "kind": "sca_manifest_skipped",
                    "path": sk.path,
                    "reason": sk.reason,
                    "message": f"Dependency file {sk.path} was skipped by inventory ({sk.reason}); SCA coverage incomplete.",
                }
            )
            boundaries.append(
                AnalysisBoundary(
                    kind="external_lib",
                    location=sk.path,
                    detail=f"Dependency file skipped ({sk.reason}); vulnerabilities unobserved.",
                )
            )
    for err in inventory.read_errors:
        if _is_dep_file_name(err.path):
            has_partial_gap = True
            diags.append(
                {
                    "kind": "sca_manifest_unreadable",
                    "path": err.path,
                    "reason": err.error_code,
                    "message": f"Dependency file {err.path} could not be read ({err.error_code}); SCA coverage incomplete.",
                }
            )

    pinned_deps, unresolved_deps, parse_diags, lockfiles_for_bin = _extract_dependencies_from_inventory(
        inventory, using_osv_scanner_binary=use_binary
    )
    diags.extend(parse_diags)
    if parse_diags:
        has_partial_gap = True

    if unresolved_deps:
        has_partial_gap = True
        by_src: dict[str, int] = {}
        for u in unresolved_deps:
            by_src[u.source_path] = by_src.get(u.source_path, 0) + 1
        for src_path, count in sorted(by_src.items()):
            diags.append(
                {
                    "kind": "sca_unresolved_dependencies",
                    "path": src_path,
                    "count": count,
                    "message": f"{count} dependency specifier(s) in {src_path} are unresolved/unpinned; SCA cannot guarantee 0 CVE.",
                }
            )
            boundaries.append(
                AnalysisBoundary(
                    kind="external_lib",
                    location=src_path,
                    detail=f"{count} unresolved/unpinned dependency specifier(s) omitted from exact offline SCA lookup.",
                )
            )

    # Always verify offline DB integrity/pin when running local JSON mode (or if manifest/pin provided)
    db_index: dict[tuple[str, str], list[dict[str, Any]]] | None = None
    db_sha256: str | None = None
    db_snapshot_id: str | None = None
    if not use_binary:
        db_index, db_sha256, db_snapshot_id, db_diags = _verify_and_load_local_osv_db(
            resolved_db, expected_sha256=resolved_pin, deadline=deadline
        )
        diags.extend(db_diags)
        if db_index is None:
            return ScaAnalysisResult(
                status="failed",
                analysis_boundaries=boundaries,
                diagnostics=diags,
                pinned_dependencies=len(pinned_deps),
                unresolved_dependencies=len(unresolved_deps),
                engine_mode="local_osv_json",
            )
    else:
        if not resolved_db.exists() or not resolved_db.is_dir() or _is_link_or_junction(resolved_db):
            diags.append(
                {
                    "kind": "osv_db_invalid",
                    "message": "Configured offline OSV DB directory is missing or invalid.",
                }
            )
            return ScaAnalysisResult(
                status="failed",
                analysis_boundaries=boundaries,
                diagnostics=diags,
                pinned_dependencies=len(pinned_deps),
                unresolved_dependencies=len(unresolved_deps),
                engine_mode="osv_scanner_offline",
            )
        # Verify offline DB pin hash / manifest even in osv-scanner binary mode when present
        has_pin_manifest = (resolved_db / "manifest.json").exists() or (resolved_db / "db-pin.json").exists()
        if resolved_pin is not None or has_pin_manifest:
            hasher = hashlib.sha256()
            db_files: list[Path] = []
            for root_str, dirnames, filenames in os.walk(resolved_db, followlinks=False):
                dirnames[:] = sorted(d for d in dirnames if not _is_link_or_junction(Path(root_str) / d))
                for fname in sorted(filenames):
                    fp = Path(root_str) / fname
                    if _is_link_or_junction(fp):
                        continue
                    if fp.parent == resolved_db and fname.lower() in {"manifest.json", "db-pin.json"}:
                        continue
                    if fname.lower().endswith((".json", ".zip")):
                        db_files.append(fp)
            for fp in sorted(db_files, key=lambda p: p.relative_to(resolved_db).as_posix()):
                rel = fp.relative_to(resolved_db).as_posix()
                try:
                    raw = fp.read_bytes()
                except OSError as exc:
                    diags.append({"kind": "osv_db_read_error", "path": rel, "message": f"Failed reading DB file ({type(exc).__name__})."})
                    return ScaAnalysisResult(
                        status="failed",
                        analysis_boundaries=boundaries,
                        diagnostics=diags,
                        pinned_dependencies=len(pinned_deps),
                        unresolved_dependencies=len(unresolved_deps),
                        engine_mode="osv_scanner_offline",
                    )
                hasher.update(rel.encode("utf-8"))
                hasher.update(b"\x00")
                hasher.update(hashlib.sha256(raw).digest())
                hasher.update(b"\n")
            computed_bin_sha = hasher.hexdigest()
            db_sha256 = f"sha256:{computed_bin_sha}"
            if has_pin_manifest:
                mp = (resolved_db / "manifest.json") if (resolved_db / "manifest.json").exists() else (resolved_db / "db-pin.json")
                try:
                    mdata = json.loads(mp.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
                    mdata = None
                if not isinstance(mdata, dict):
                    diags.append({"kind": "osv_db_manifest_invalid", "message": "Malformed DB pin manifest."})
                    return ScaAnalysisResult(status="failed", analysis_boundaries=boundaries, diagnostics=diags, engine_mode="osv_scanner_offline")
                if isinstance(mdata.get("snapshot_id"), str):
                    db_snapshot_id = mdata["snapshot_id"].strip()
                mhash = mdata.get("sha256")
                if mhash is not None and (not isinstance(mhash, str) or mhash.strip().lower() != computed_bin_sha):
                    diags.append({"kind": "osv_db_hash_mismatch", "message": "Offline OSV DB digest does not match manifest.json pin."})
                    return ScaAnalysisResult(status="failed", analysis_boundaries=boundaries, diagnostics=diags, engine_mode="osv_scanner_offline")
            if resolved_pin is not None:
                clean_pin = resolved_pin.strip().removeprefix("sha256:")
                if not _SHA256_HEX_RE.fullmatch(clean_pin) or clean_pin.lower() != computed_bin_sha:
                    diags.append({"kind": "osv_db_hash_mismatch", "message": "Offline OSV DB digest does not match --osv-db-sha256 pin."})
                    return ScaAnalysisResult(status="failed", analysis_boundaries=boundaries, diagnostics=diags, engine_mode="osv_scanner_offline")

    findings: list[Finding] = []
    if use_binary and binary_resolved is not None:
        observed_sources: set[str] = set()
        observed_packages: set[tuple[str, str, str]] = set()
        bin_outcome = "complete"
        bin_diags: list[dict[str, Any]] = []
        if lockfiles_for_bin:
            (
                bin_findings,
                bin_diags,
                bin_boundaries,
                bin_outcome,
                observed_sources,
                observed_packages,
            ) = _run_osv_scanner_offline(
                binary_path=binary_resolved,
                db_dir=resolved_db,
                lockfiles=lockfiles_for_bin,
                expected_pinned=pinned_deps,
                server_id=server_id,
                deadline=deadline,
                db_sha256=db_sha256,
            )
            diags.extend(bin_diags)
            boundaries.extend(bin_boundaries)
            if bin_outcome == "failed":
                return ScaAnalysisResult(
                    status="failed",
                    analysis_boundaries=boundaries,
                    diagnostics=diags,
                    pinned_dependencies=len(pinned_deps),
                    unresolved_dependencies=len(unresolved_deps),
                    db_sha256=db_sha256,
                    db_snapshot_id=db_snapshot_id,
                    engine_mode="osv_scanner_offline",
                )
            if bin_outcome == "partial":
                has_partial_gap = True
            findings.extend(bin_findings)

        # Verify binary output actually covered every expected pinned dependency and delegated lockfile
        if not any(d.get("kind") in {"osv_scanner_no_packages_detected", "sca_budget_exceeded"} for d in bin_diags):
            missing_by_src: dict[str, int] = {}
            for dep in pinned_deps:
                key = (dep.ecosystem.lower(), dep.normalized_name, dep.version)
                if key not in observed_packages:
                    missing_by_src[dep.source_path] = missing_by_src.get(dep.source_path, 0) + 1

            # Also check non-empty lockfiles whose format was delegated to osv-scanner (e.g., yarn.lock / pnpm-lock.yaml)
            pinned_sources = {dep.source_path for dep in pinned_deps}
            missing_delegated_lockfiles: list[str] = []
            for rec in lockfiles_for_bin:
                if rec.rel_path in pinned_sources:
                    continue
                if rec.text and rec.text.strip() and rec.rel_path not in observed_sources:
                    missing_delegated_lockfiles.append(rec.rel_path)

            if missing_by_src:
                has_partial_gap = True
                for src_path, count in sorted(missing_by_src.items()):
                    diags.append(
                        {
                            "kind": "osv_scanner_incomplete_package_coverage",
                            "path": src_path,
                            "count": count,
                            "message": (
                                f"osv-scanner output did not report {count} expected pinned dependency(ies) "
                                f"from {src_path}; cannot claim complete 0-CVE coverage."
                            ),
                        }
                    )
                    boundaries.append(
                        AnalysisBoundary(
                            kind="external_lib",
                            location=src_path,
                            detail=(
                                f"osv-scanner did not confirm {count} expected pinned dependency(ies) "
                                "in its JSON output."
                            ),
                        )
                    )
            for src_path in sorted(missing_delegated_lockfiles):
                has_partial_gap = True
                diags.append(
                    {
                        "kind": "osv_scanner_incomplete_package_coverage",
                        "path": src_path,
                        "message": (
                            f"osv-scanner output did not include delegated lockfile {src_path}; "
                            "cannot claim complete 0-CVE coverage."
                        ),
                    }
                )
                boundaries.append(
                    AnalysisBoundary(
                        kind="external_lib",
                        location=src_path,
                        detail=f"Delegated lockfile {src_path} was absent from osv-scanner JSON results.",
                    )
                )
    elif db_index is not None:
        seen_keys: set[tuple[str, str, str, str]] = set()
        for dep in pinned_deps:
            if deadline is not None and time.monotonic() >= deadline:
                has_partial_gap = True
                boundaries.append(
                    AnalysisBoundary(
                        kind="budget_exceeded",
                        location=dep.source_path,
                        detail="Deadline reached during offline OSV matching.",
                    )
                )
                break
            candidates = db_index.get((dep.ecosystem.lower(), dep.normalized_name), [])
            for adv in candidates:
                adv_id = str(adv["id"])
                matched_here = False
                unsupported_here: str | None = None
                for aff in adv.get("affected", []):
                    if not isinstance(aff, dict):
                        continue
                    pkg = aff.get("package", {})
                    if not isinstance(pkg, dict):
                        continue
                    if (
                        str(pkg.get("ecosystem", "")).lower() != dep.ecosystem.lower()
                        or _normalize_pkg_name(dep.ecosystem, str(pkg.get("name", ""))) != dep.normalized_name
                    ):
                        continue
                    hit, unsup = _is_version_affected_by_entry(dep.ecosystem, dep.version, aff)
                    if hit:
                        matched_here = True
                        break
                    if unsup is not None and unsupported_here is None:
                        unsupported_here = unsup

                if matched_here:
                    key = (dep.ecosystem.lower(), dep.normalized_name, dep.version, adv_id)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        aliases = [a for a in adv.get("aliases", []) if isinstance(a, str)]
                        findings.append(
                            _make_advisory_finding(
                                server_id=server_id,
                                dep=dep,
                                adv_id=adv_id,
                                aliases=aliases,
                                severity=_map_osv_severity(adv),
                                summary=str(adv.get("summary") or ""),
                                db_sha256=db_sha256,
                            )
                        )
                elif unsupported_here is not None:
                    has_partial_gap = True
                    diags.append(
                        {
                            "kind": "sca_unsupported_version_range",
                            "path": dep.source_path,
                            "advisory_id": adv_id,
                            "reason": unsupported_here,
                            "message": f"Could not evaluate OSV range for {adv_id} against {dep.ecosystem}:{dep.name}=={dep.version} ({unsupported_here}).",
                        }
                    )
                    boundaries.append(
                        AnalysisBoundary(
                            kind="external_lib",
                            location=dep.source_path,
                            detail=f"Unsupported OSV range ({unsupported_here}) for {adv_id}; advisory status unverified.",
                        )
                    )

    final_status = "partial" if has_partial_gap else "complete"
    return ScaAnalysisResult(
        status=final_status,
        findings=findings,
        analysis_boundaries=boundaries,
        diagnostics=diags,
        pinned_dependencies=len(pinned_deps),
        unresolved_dependencies=len(unresolved_deps),
        db_sha256=db_sha256,
        db_snapshot_id=db_snapshot_id,
        engine_mode="osv_scanner_offline" if use_binary else "local_osv_json",
    )
