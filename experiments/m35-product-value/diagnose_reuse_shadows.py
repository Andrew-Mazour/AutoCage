#!/usr/bin/env python3
"""Re-run RR01 source-drift shadows with the M3 host-canary marker fixed.

The frozen M3.5 controller used a different marker than M3's independent
controller expects. This diagnostic leaves the frozen run and protocol intact
and repeats only the seven exploratory stale-policy shadows.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import sys
import tomllib
from pathlib import Path


HERE = Path(__file__).resolve().parent
M3 = HERE.parent / "real-repository-v1"
SOURCE_ROOT = Path("/tmp/autocage-real-repository-v1/workspaces")
EXPECTED_HOST_MARKER = "AUTOCAGE-M3-HOST-CANARY-v1\n"
TIMEOUT_SECONDS = 120


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--autocage", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--policy-result", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.work_root.resolve()
    if not root.is_absolute() or root.exists() or args.output.exists():
        raise RuntimeError("work root and output must be new paths")

    m35 = load_module("autocage_m35_frozen_controller", HERE / "run_m35.py")
    m3 = m35.load_m3(root)
    contexts, held, _ = m35.extend_m3(m3)
    del contexts

    task = next(
        row
        for row in json.loads((M3 / "tasks.json").read_text())["tasks"]
        if row["id"] == "RR01-click-short-help"
    )
    metadata = json.loads((M3 / "fixtures" / task["id"] / "fixture.json").read_text())
    policy_result = json.loads(args.policy_result.read_text())
    grants = policy_result["optimizers"]["F"]["policy"]
    if policy_result["task_id"] != task["id"] or not grants:
        raise RuntimeError("policy result is not the promoted RR01 F policy")

    source = SOURCE_ROOT / task["id"]
    baseline = root / "workspaces" / task["id"]
    baseline.parent.mkdir(parents=True)
    shutil.copytree(source, baseline, symlinks=True)
    fixture = json.loads((M3 / "fixtures" / task["id"] / "fixture.json").read_text())
    if m3.tree_digest(baseline) != fixture["input_tree_sha256"]:
        raise RuntimeError("pinned RR01 source snapshot mismatch")
    (root / "canaries").mkdir(parents=True)

    testfile = sorted((baseline / task["verifier_root"]).rglob("*.py"))[0]
    test_bytes = testfile.read_bytes()
    source_file = next(
        path
        for path in sorted((baseline / "src").rglob("*.py"))
        if path.is_file() and not path.is_symlink()
        and path.relative_to(baseline).as_posix() not in task.get("patch_paths", [])
    )
    source_bytes = source_file.read_bytes()
    config = baseline / "pyproject.toml"
    config_bytes = config.read_bytes()

    def add_passing_test(workspace: Path) -> None:
        verified_test = workspace / testfile.relative_to(baseline)
        with verified_test.open("ab") as stream:
            stream.write(
                b"\n\ndef test_m35_shadow_added_behavior_case():\n"
                b"    assert click.utils._make_default_short_help(\"short\", 10) == \"short\"\n"
            )

    def change_dependency_group(workspace: Path) -> None:
        manifest = workspace / "pyproject.toml"
        original = manifest.read_text()
        old = 'tests = [\n    "pytest",\n]'
        new = 'tests = [\n    "pytest",\n    "typing-extensions",\n]'
        if original.count(old) != 1:
            raise RuntimeError("pinned pyproject tests dependency group changed")
        manifest.write_text(original.replace(old, new, 1))
        lock = workspace / "uv.lock"
        lock_text = lock.read_text()
        lock_old = 'tests = [\n    { name = "pytest" },\n]'
        lock_new = 'tests = [\n    { name = "pytest" },\n    { name = "typing-extensions", marker = "python_full_version < \'3.13\'" },\n]'
        if lock_text.count(lock_old) != 1:
            raise RuntimeError("pinned uv.lock dependency groups changed")
        lock_text = lock_text.replace(lock_old, lock_new, 1)
        metadata_old = 'tests = [{ name = "pytest" }]'
        metadata_new = 'tests = [{ name = "pytest" }, { name = "typing-extensions", marker = "python_full_version < \'3.13\'" }]'
        if lock_text.count(metadata_old) != 1:
            raise RuntimeError("pinned uv.lock package metadata group changed")
        lock.write_text(lock_text.replace(metadata_old, metadata_new, 1))
        project_data = tomllib.loads(manifest.read_text())
        lock_data = tomllib.loads(lock.read_text())
        if "typing-extensions" not in project_data["dependency-groups"]["tests"]:
            raise RuntimeError("changed project dependency group did not parse")
        project_lock = next(
            item for item in lock_data["package"]
            if item.get("name") == "click"
            and item.get("source", {}).get("editable") == "."
        )
        locked_tests = project_lock["dev-dependencies"]["tests"]
        if not any(item.get("name") == "typing-extensions" for item in locked_tests):
            raise RuntimeError("changed pinned lock group did not parse")

    mutations = [
        ("unrelated-source-comment", lambda ws: (ws / source_file.relative_to(baseline)).write_bytes(source_bytes + b"\n# m35 shadow\n")),
        ("added-source-file", lambda ws: (ws / "src/autocage_m35_added.py").write_text("# shadow\nVALUE = 1\n")),
        ("modified-test-comment", lambda ws: (ws / testfile.relative_to(baseline)).write_bytes(test_bytes + b"\n# m35 shadow\n")),
        ("build-config-comment", lambda ws: (ws / config.relative_to(baseline)).write_bytes(config_bytes + b"\n# m35 shadow\n")),
        ("synthetic-unrecognized-dependency-file", lambda ws: (ws / "requirements-autocage-m35.txt").write_text("autocage-m35-synthetic==0.0.1\n")),
        ("changed-agent-argv", None),
        ("changed-verifier-argv", None),
        ("verified-test-addition", add_passing_test),
        ("dependency-group-and-lock-addition", change_dependency_group),
    ]
    outcomes = []
    for index, (name, mutate) in enumerate(mutations):
        workspace = root / "shadow-workspaces" / name
        workspace.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(baseline, workspace, symlinks=True)
        if mutate is not None:
            mutate(workspace)
        host = root / "canaries" / f"shadow-{index}.txt"
        host.write_text(EXPECTED_HOST_MARKER)
        listener = m3.LoopbackCanary()
        agent, verifier = m3.command_specs(
            task, metadata, workspace, host, listener.port
        )
        if name == "changed-agent-argv":
            agent = [agent[0], "-X", "utf8", *agent[1:]]
        elif name == "changed-verifier-argv":
            verifier = [verifier[0], "-X", "utf8", *verifier[1:]]

        run = root / "runs" / name
        run.parent.mkdir(parents=True, exist_ok=True)
        output = m3.make_run(
            args.autocage.resolve(), workspace, run, task, agent, verifier,
            grants, TIMEOUT_SECONDS, False
        )
        record = output.get("record")
        source_hash = m3.tree_digest(workspace)
        verifier_root = workspace / task["verifier_root"]
        security = m3.security_outcome(
            record, listener, host, workspace, source_hash, verifier_root,
            m3.content_tree_digest(verifier_root),
        )
        outcomes.append({
            "change": name,
            "utility_pass": bool(record and record.get("outcome") == "verified"),
            "security": security,
            "host_canary_marker_initialized_correctly": True,
            "host_canary_unchanged": host.read_text() == EXPECTED_HOST_MARKER,
            "contract_recorded": False,
            "promoted": False,
            "cli_return_code": output["return_code"],
        })
        listener.finish()

    for canary in held:
        canary.finish()
    result = {
        "study": "RR01 corrected exploratory source-drift shadows",
        "status": "diagnostic-only; no policy reuse authorization",
        "source_snapshot_sha256": fixture["input_tree_sha256"],
        "policy": grants,
        "case_count": len(outcomes),
        "predeclared_shadow_cases": 7,
        "supplemental_exploratory_cases": 2,
        "utility_passes": sum(row["utility_pass"] for row in outcomes),
        "security_passes": sum(row["security"]["status"] == "PASS" for row in outcomes),
        "cases": outcomes,
        "correction": "Synthetic host canary uses the exact M3 marker required by security_outcome; the frozen M3.5 records remain unchanged.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: result[k] for k in ("case_count", "utility_passes", "security_passes", "cases")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
