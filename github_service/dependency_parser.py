"""Parsers for Python dependency manifests using packaging and tomllib.

Strictly avoids inventing installed versions from version ranges.
"""

from __future__ import annotations

import re
import tomllib

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from .schemas import DependencyRecord

POETRY_EXACT_VERSION_RE = re.compile(r"^(?:==|===)?\s*([A-Za-z0-9][A-Za-z0-9._+-]*)$")


def _extract_exact_version_from_specifiers(spec_str: str) -> str | None:
    """Return exact version string only when pinned by a single == or === specifier."""
    if not spec_str:
        return None
    parts = [part.strip() for part in spec_str.split(",") if part.strip()]
    if len(parts) != 1:
        return None
    part = parts[0]
    if part.startswith("==="):
        candidate = part[3:].strip()
        return candidate if candidate and "*" not in candidate else None
    if part.startswith("=="):
        candidate = part[2:].strip()
        return candidate if candidate and "*" not in candidate else None
    return None


def parse_pep508_requirement(
    raw_line: str,
    manifest_path: str,
    manifest_type: str,
    source_url: str,
) -> DependencyRecord | None:
    """Parse a single PEP 508 dependency string into a DependencyRecord."""
    cleaned = raw_line.strip()
    if not cleaned or cleaned.startswith("#"):
        return None

    # Strip inline comments outside URLs/markers conservatively
    if " #" in cleaned:
        cleaned = cleaned.split(" #", 1)[0].strip()

    # Handle requirements.txt options or editable/VCS installs
    if cleaned.startswith(("-", "--")):
        return None
    if "://" in cleaned and "@" not in cleaned:
        return DependencyRecord(
            package_name=cleaned,
            normalized_name=cleaned.lower(),
            ecosystem="PyPI",
            installed_version=None,
            version_specifier=cleaned,
            is_resolved=False,
            resolution_status="unresolved",
            manifest_path=manifest_path,
            manifest_type=manifest_type,
            raw_requirement=raw_line.strip(),
            source_url=source_url,
        )

    # Strip pip hashes like --hash=sha256:...
    cleaned_no_hash = re.split(r"\s+--hash=\S+", cleaned)[0].strip()
    # Strip trailing line continuation
    cleaned_no_hash = cleaned_no_hash.rstrip("\\").strip()
    if not cleaned_no_hash:
        return None

    try:
        req = Requirement(cleaned_no_hash)
    except InvalidRequirement:
        # Fallback for malformed or VCS line without inventing a version
        token = re.split(r"[<>=!~;\s\[]", cleaned_no_hash, maxsplit=1)[0].strip()
        if not token:
            return None
        return DependencyRecord(
            package_name=token,
            normalized_name=canonicalize_name(token),
            ecosystem="PyPI",
            installed_version=None,
            version_specifier=cleaned_no_hash,
            is_resolved=False,
            resolution_status="unresolved",
            manifest_path=manifest_path,
            manifest_type=manifest_type,
            raw_requirement=raw_line.strip(),
            source_url=source_url,
        )

    spec_text = str(req.specifier) if req.specifier else None
    exact_version = _extract_exact_version_from_specifiers(spec_text or "")
    is_resolved = exact_version is not None and req.url is None

    return DependencyRecord(
        package_name=req.name,
        normalized_name=canonicalize_name(req.name),
        ecosystem="PyPI",
        installed_version=exact_version if is_resolved else None,
        version_specifier=spec_text or (req.url if req.url else None),
        is_resolved=is_resolved,
        resolution_status="pinned" if is_resolved else "unresolved",
        manifest_path=manifest_path,
        manifest_type=manifest_type,
        raw_requirement=raw_line.strip(),
        source_url=source_url,
    )


def parse_requirements_txt(
    content: str,
    manifest_path: str,
    source_url: str,
) -> list[DependencyRecord]:
    """Parse a requirements.txt file joining backslash-continued lines."""
    joined_lines: list[str] = []
    buffer = ""
    for line in content.splitlines():
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buffer += stripped[:-1].strip() + " "
        else:
            joined_lines.append((buffer + stripped).strip())
            buffer = ""
    if buffer.strip():
        joined_lines.append(buffer.strip())

    records: list[DependencyRecord] = []
    for line in joined_lines:
        parsed = parse_pep508_requirement(
            line, manifest_path, "requirements.txt", source_url
        )
        if parsed is not None:
            records.append(parsed)
    return records


def _parse_poetry_spec(
    package_name: str,
    spec_value: object,
    manifest_path: str,
    source_url: str,
) -> DependencyRecord | None:
    """Parse a Poetry dependency entry without inventing versions from caret/tilde ranges."""
    if package_name.lower() == "python":
        return None

    raw_spec: str
    if isinstance(spec_value, str):
        raw_spec = spec_value.strip()
    elif isinstance(spec_value, dict):
        if "version" in spec_value and isinstance(spec_value["version"], str):
            raw_spec = spec_value["version"].strip()
        else:
            raw_spec = str(spec_value)
            return DependencyRecord(
                package_name=package_name,
                normalized_name=canonicalize_name(package_name),
                ecosystem="PyPI",
                installed_version=None,
                version_specifier=raw_spec,
                is_resolved=False,
                resolution_status="unresolved",
                manifest_path=manifest_path,
                manifest_type="pyproject.toml",
                raw_requirement=f"{package_name} = {spec_value}",
                source_url=source_url,
            )
    else:
        return None

    # Poetry caret (^), tilde (~), wildcard (*), inequality (<, >, !=), or comma ranges are NOT exact pins.
    if any(op in raw_spec for op in ("^", "~", "*", "<", ">", "!=", ",")):
        exact_version = None
    else:
        match = POETRY_EXACT_VERSION_RE.match(raw_spec)
        exact_version = match.group(1) if match else None

    is_resolved = exact_version is not None
    return DependencyRecord(
        package_name=package_name,
        normalized_name=canonicalize_name(package_name),
        ecosystem="PyPI",
        installed_version=exact_version,
        version_specifier=raw_spec or None,
        is_resolved=is_resolved,
        resolution_status="pinned" if is_resolved else "unresolved",
        manifest_path=manifest_path,
        manifest_type="pyproject.toml",
        raw_requirement=f"{package_name} = {raw_spec}",
        source_url=source_url,
    )


def parse_pyproject_toml(
    content: str,
    manifest_path: str,
    source_url: str,
) -> list[DependencyRecord]:
    """Parse PEP 621, dependency-groups, and Poetry dependencies from pyproject.toml."""
    data = tomllib.loads(content)
    records: list[DependencyRecord] = []

    project = data.get("project", {})
    if isinstance(project, dict):
        deps = project.get("dependencies", [])
        if isinstance(deps, list):
            for item in deps:
                if isinstance(item, str):
                    parsed = parse_pep508_requirement(
                        item, manifest_path, "pyproject.toml", source_url
                    )
                    if parsed is not None:
                        records.append(parsed)

        opt_deps = project.get("optional-dependencies", {})
        if isinstance(opt_deps, dict):
            for group_items in opt_deps.values():
                if isinstance(group_items, list):
                    for item in group_items:
                        if isinstance(item, str):
                            parsed = parse_pep508_requirement(
                                item, manifest_path, "pyproject.toml", source_url
                            )
                            if parsed is not None:
                                records.append(parsed)

    dep_groups = data.get("dependency-groups", {})
    if isinstance(dep_groups, dict):
        for group_items in dep_groups.values():
            if isinstance(group_items, list):
                for item in group_items:
                    if isinstance(item, str):
                        parsed = parse_pep508_requirement(
                            item, manifest_path, "pyproject.toml", source_url
                        )
                        if parsed is not None:
                            records.append(parsed)

    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if isinstance(poetry_deps, dict):
        for pkg_name, spec_val in poetry_deps.items():
            parsed = _parse_poetry_spec(pkg_name, spec_val, manifest_path, source_url)
            if parsed is not None:
                records.append(parsed)

    poetry_groups = data.get("tool", {}).get("poetry", {}).get("group", {})
    if isinstance(poetry_groups, dict):
        for group_data in poetry_groups.values():
            if isinstance(group_data, dict):
                g_deps = group_data.get("dependencies", {})
                if isinstance(g_deps, dict):
                    for pkg_name, spec_val in g_deps.items():
                        parsed = _parse_poetry_spec(
                            pkg_name, spec_val, manifest_path, source_url
                        )
                        if parsed is not None:
                            records.append(parsed)

    return records


def parse_lockfile_toml(
    content: str,
    manifest_path: str,
    manifest_type: str,
    source_url: str,
    root_project_name: str | None = None,
) -> list[DependencyRecord]:
    """Parse poetry.lock or uv.lock [[package]] tables with exact locked versions."""
    data = tomllib.loads(content)
    packages = data.get("package", [])
    records: list[DependencyRecord] = []
    if not isinstance(packages, list):
        return records

    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if not isinstance(name, str) or not name.strip():
            continue
        # uv.lock often includes the root workspace package itself without a registry source
        source = pkg.get("source")
        if isinstance(source, dict) and source.get("virtual") is not None:
            continue
        if (
            isinstance(source, dict)
            and source.get("editable") is not None
            and not version
        ):
            continue
        if (
            root_project_name
            and canonicalize_name(name) == canonicalize_name(root_project_name)
            and isinstance(source, dict)
            and "editable" in source
        ):
            continue

        exact_version = (
            str(version).strip()
            if isinstance(version, str) and version.strip()
            else None
        )
        is_resolved = exact_version is not None
        records.append(
            DependencyRecord(
                package_name=name.strip(),
                normalized_name=canonicalize_name(name.strip()),
                ecosystem="PyPI",
                installed_version=exact_version,
                version_specifier=f"=={exact_version}" if exact_version else None,
                is_resolved=is_resolved,
                resolution_status="pinned" if is_resolved else "unresolved",
                manifest_path=manifest_path,
                manifest_type=manifest_type,
                raw_requirement=f"{name}=={exact_version}" if exact_version else name,
                source_url=source_url,
            )
        )
    return records


def merge_dependency_records(records: list[DependencyRecord]) -> list[DependencyRecord]:
    """Deduplicate dependencies by normalized name, preferring pinned lockfile/exact entries."""
    priority = {
        "uv.lock": 4,
        "poetry.lock": 3,
        "requirements.txt": 2,
        "pyproject.toml": 1,
    }
    best_by_name: dict[str, DependencyRecord] = {}

    for rec in records:
        key = rec.normalized_name
        existing = best_by_name.get(key)
        if existing is None:
            best_by_name[key] = rec
            continue
        # Prefer resolved exact pins over unresolved ranges; break ties by lockfile specificity.
        if (
            rec.is_resolved
            and not existing.is_resolved
            or rec.is_resolved == existing.is_resolved
            and priority.get(rec.manifest_type, 0)
            > priority.get(existing.manifest_type, 0)
        ):
            best_by_name[key] = rec

    return list(best_by_name.values())
