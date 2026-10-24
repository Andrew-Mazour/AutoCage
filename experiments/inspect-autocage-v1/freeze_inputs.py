#!/usr/bin/env python3
"""Fingerprint the frozen M5 implementation, inputs, and Linux runtime."""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FILES = [
    "integrations/inspect_autocage/pyproject.toml",
    "integrations/inspect_autocage/requirements.lock",
    "integrations/inspect_autocage/eval.py",
    "integrations/inspect_autocage/autocage_inspect/__init__.py",
    "integrations/inspect_autocage/autocage_inspect/evidence.py",
    "integrations/inspect_autocage/autocage_inspect/execution.py",
    "integrations/inspect_autocage/autocage_inspect/task.py",
    "integrations/inspect_autocage/tests/test_evidence.py",
    "integrations/inspect_autocage/README.md",
    "integrations/inspect_autocage/scenarios/local-aider.json",
    "integrations/inspect_autocage/scenarios/local-aider-injection.txt",
    "experiments/agent-containment-v1/suite.json",
    "experiments/agent-containment-v1/PROTOCOL.json",
    "experiments/agent-containment-v1/configs/baseline.json",
    "experiments/agent-containment-v1/configs/candidate.json",
    "experiments/agent-containment-v1/configs/read-only.json",
    "experiments/agent-containment-v1/real_agent/launch_local_aider.py",
    "experiments/inspect-autocage-v1/PROTOCOL.json",
    "experiments/inspect-autocage-v1/freeze_inputs.py",
    "experiments/inspect-autocage-v1/summarize.py",
]
TREE_ROOTS = [
    "experiments/agent-containment-v1/fixtures/base",
    "experiments/agent-containment-v1/fixtures/overlays",
    "experiments/agent-containment-v1/fixtures/real-agent",
]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_digest(root: Path) -> str:
    files = sorted(path for path in root.rglob("*") if path.is_file())
    entries = [(str(path.relative_to(root)), digest(path)) for path in files]
    return hashlib.sha256(json.dumps(entries, separators=(",", ":")).encode()).hexdigest()


def output(command: list[str]) -> str:
    return subprocess.run(command, check=True, text=True, capture_output=True).stdout.strip()


def main() -> int:
    autocage = Path(sys.argv[1]).resolve()
    files = {name: digest(ROOT / name) for name in FILES}
    trees = {name: tree_digest(ROOT / name) for name in TREE_ROOTS}
    release = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            release[key] = value.strip('"')
    record = {
        "schema_version": 1,
        "created_utc": output(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"]),
        "environment": {
            "distribution": release.get("PRETTY_NAME", "unknown"),
            "architecture": platform.machine(),
            "kernel": platform.release(),
            "python": platform.python_version(),
            "inspect_ai": output([sys.executable, "-c", "import inspect_ai; print(inspect_ai.__version__)"]),
            "bubblewrap": output(["bwrap", "--version"]),
            "strace": output(["strace", "--version"]).splitlines()[0],
            "autocage_sha256": digest(autocage),
        },
        "files": files,
        "trees": trees,
    }
    print(json.dumps(record, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
