#!/usr/bin/env python3
"""Check that the Inspect integration's declared version is pinned consistently."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "integrations" / "inspect_autocage"


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def main() -> int:
    source = (PACKAGE / "pyproject.toml").read_text(encoding="utf-8")
    build_match = re.search(r"(?ms)^\[build-system\]\s*(.*?)(?=^\[|\Z)", source)
    project_match = re.search(r"(?ms)^\[project\]\s*(.*?)(?=^\[|\Z)", source)
    if build_match is None or project_match is None:
        raise ValueError("pyproject.toml must have [build-system] and [project] sections")
    build_requires = re.findall(r'"setuptools==([^" ]+)"', build_match.group(1))
    if len(build_requires) != 1:
        raise ValueError("build-system must pin exactly one setuptools version")
    if tuple(int(part) for part in build_requires[0].split(".")) < (77, 0, 3):
        raise ValueError("setuptools 77.0.3 or newer is required for PEP 639 license metadata")
    project = project_match.group(1)
    version_match = re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', project)
    dependency_match = re.search(r"(?ms)^dependencies\s*=\s*\[(.*?)\]", project)
    if version_match is None or dependency_match is None:
        raise ValueError("pyproject [project] section is missing version or dependencies")
    dependencies = re.findall(r'"([^"]+)"', dependency_match.group(1))
    inspect_deps = [dep for dep in dependencies if normalize(dep.split("==", 1)[0]) == "inspect-ai"]
    if len(inspect_deps) != 1 or "==" not in inspect_deps[0]:
        raise ValueError("pyproject must declare exactly one exact inspect-ai dependency")
    inspect_version = inspect_deps[0].split("==", 1)[1]

    pins: dict[str, str] = {}
    for line in (PACKAGE / "requirements.lock").read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9.!+_-]+)", value)
        if match is None:
            raise ValueError(f"dependency lock entry is not an exact version pin: {value}")
        key = normalize(match.group(1))
        if key in pins:
            raise ValueError(f"duplicate normalized dependency in lock: {match.group(1)}")
        pins[key] = match.group(2)

    if pins.get("inspect-ai") != inspect_version:
        raise ValueError("requirements.lock and pyproject.toml disagree on inspect-ai")
    if version_match.group(1) != "0.1.0rc1":
        raise ValueError("Python package version must match the 0.1.0 release candidate")
    if 'license = "Apache-2.0"' not in project or 'license-files = ["LICENSE"]' not in project:
        raise ValueError("Python project must declare Apache-2.0 and package its LICENSE file")
    if (ROOT / "LICENSE").read_bytes() != (PACKAGE / "LICENSE").read_bytes():
        raise ValueError("root and Python package LICENSE files must be identical")
    rust_manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    rust_version_match = re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', rust_manifest)
    if rust_version_match is None or rust_version_match.group(1) != "0.1.0-rc.1":
        raise ValueError("Cargo package version must match 0.1.0-rc.1")
    if not re.search(r'(?m)^license\s*=\s*"Apache-2\.0"\s*$', rust_manifest):
        raise ValueError("Cargo package must declare the Apache-2.0 license")
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    for required in ("Apache License", "Version 2.0, January 2004", "END OF TERMS AND CONDITIONS"):
        if required not in license_text:
            raise ValueError(f"root LICENSE is missing canonical Apache-2.0 text: {required}")
    init_source = (PACKAGE / "autocage_inspect" / "__init__.py").read_text(encoding="utf-8")
    if '__version__ = "0.1.0rc1"' not in init_source:
        raise ValueError("Python package __version__ does not match pyproject metadata")
    print(
        "Python/package metadata: PASS "
        f"(inspect-ai=={inspect_version}, {len(pins)} exact runtime pins, "
        f"setuptools=={build_requires[0]}, Apache-2.0)"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError) as error:
        print(f"Python lock consistency: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
