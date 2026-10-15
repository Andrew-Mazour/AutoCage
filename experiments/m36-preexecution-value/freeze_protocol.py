#!/usr/bin/env python3
"""Record exact inputs/runtime before the M3.6 held-out evaluation.

Run once in the supported Ubuntu guest after all code, fixtures, and the locked
release binary are final. It refuses to overwrite an already frozen protocol.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
from pathlib import Path


HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[1]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def output(argv: list[str]) -> str:
    result = subprocess.run(argv, check=True, capture_output=True, text=True)
    return (result.stdout + result.stderr).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--autocage", type=Path, required=True)
    parser.add_argument(
        "--repair-controller-pin",
        action="store_true",
        help="repair the pre-run controller hash only after every other frozen input has been verified unchanged",
    )
    args = parser.parse_args()
    binary = args.autocage.resolve()
    protocol_path = HERE / "PROTOCOL.json"
    protocol = json.loads(protocol_path.read_text())
    plan = json.loads((HERE / "workflow-plan.json").read_text())
    if plan.get("state") != "frozen-before-final-evaluation":
        raise SystemExit("workflow plan is not in the predeclared frozen state")
    keys = (
        "workflow_plan_sha256",
        "controller_sha256",
        "workflow_task_manifest_sha256",
        "m3_prepare_sha256",
        "m3_runtime_lock_sha256",
        "m36_prepare_sha256",
        "m36_build_lock_sha256",
        "m36_download_setup_sha256",
        "m36_install_setup_sha256",
        "profile_source_sha256",
        "policy_source_sha256",
        "bubblewrap_source_sha256",
        "linux_test_source_sha256",
        "m2_frozen_manifest_sha256",
        "m2_report_sha256",
        "m3_protocol_sha256",
        "m35_protocol_sha256",
        "m35_report_sha256",
        "autocage_release_binary_sha256",
        "cargo_manifest_sha256",
        "cargo_lock_sha256",
    )
    source_paths = {
        "workflow_plan_sha256": HERE / "workflow-plan.json",
        "controller_sha256": HERE / "run_m36.py",
        "workflow_task_manifest_sha256": HERE.parent / "real-repository-v1/tasks.json",
        "m3_prepare_sha256": HERE.parent / "real-repository-v1/prepare.py",
        "m3_runtime_lock_sha256": HERE.parent / "real-repository-v1/setup/python-requirements.lock",
        "m36_prepare_sha256": HERE / "prepare_workflows.py",
        "m36_build_lock_sha256": HERE / "setup/python-build-requirements.lock",
        "m36_download_setup_sha256": HERE / "setup/download-build-deps.sh",
        "m36_install_setup_sha256": HERE / "setup/install-build-deps.sh",
        "profile_source_sha256": PROJECT / "src/profile.rs",
        "policy_source_sha256": PROJECT / "src/policy.rs",
        "bubblewrap_source_sha256": PROJECT / "src/backend/bubblewrap.rs",
        "linux_test_source_sha256": PROJECT / "tests/linux_runner.rs",
        "m2_frozen_manifest_sha256": HERE.parent / "write-policy-v1/results/frozen-manifest.json",
        "m2_report_sha256": HERE.parent / "write-policy-v1/REPORT.md",
        "m3_protocol_sha256": HERE.parent / "real-repository-v1/protocol.json",
        "m35_protocol_sha256": HERE.parent / "m35-product-value/PROTOCOL.json",
        "m35_report_sha256": HERE.parent / "m35-product-value/REPORT.md",
        "autocage_release_binary_sha256": binary,
        "cargo_manifest_sha256": PROJECT / "Cargo.toml",
        "cargo_lock_sha256": PROJECT / "Cargo.lock",
    }

    already_frozen = any(protocol.get(key) for key in keys) or bool(protocol.get("runtime"))
    if already_frozen:
        if not args.repair_controller_pin:
            raise SystemExit("refusing to rewrite an already frozen protocol")
        final_output = Path("/tmp/autocage-m36/results/final")
        if final_output.exists() and any(final_output.iterdir()):
            raise SystemExit("cannot repair the pre-run controller pin after final evaluation has started")
        for key, path in source_paths.items():
            if key == "controller_sha256":
                continue
            if protocol.get(key) != digest(path):
                raise SystemExit(f"repair refused because another frozen input changed: {key}")
        protocol.setdefault("freeze_audit", []).append(
            "Before any held-out execution, protocol validation found controller_sha256 pointed to the freeze helper. Corrected it to run_m36.py after verifying every other frozen input unchanged. Workflow set, costs, thresholds, and runtime were unchanged."
        )

    for key, path in source_paths.items():
        if not path.is_file():
            raise SystemExit(f"required frozen input missing: {path}")
        protocol[key] = digest(path)

    protocol["runtime"] = {
        "platform": {
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "python": output(["/usr/bin/python3", "--version"]),
            "bubblewrap": output(["/usr/bin/bwrap", "--version"]),
            "rustc": output(["rustc", "--version"]),
            "cargo": output(["cargo", "--version"]),
        },
        "python_build_backend": "flit_core 3.12.0 at /usr/local/lib/autocage-m36-build-site",
        "test_runtime": "M3 python-requirements.lock installed at /usr/local/lib/autocage-m3-site-v2",
        "network": "No task-time egress; dependency preparation is separate and hash-pinned",
    }
    protocol_path.write_text(json.dumps(protocol, indent=2) + "\n")
    print(json.dumps({"protocol": str(protocol_path), "frozen_hashes": protocol[keys[0]], "runtime": protocol["runtime"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
