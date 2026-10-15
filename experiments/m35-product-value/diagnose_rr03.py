#!/usr/bin/env python3
"""Bounded, separately reported diagnosis of the frozen M3 RR03 result."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import socket
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
M3 = HERE.parent / "real-repository-v1"
RAW = next(
    (M3 / "results/2026-10-12/final/autocage-m3-real-repository-final-hardened-20261012").glob(
        "RR03-*.json"
    )
)
SOURCE_WORK = Path("/tmp/autocage-real-repository-v1/workspaces/RR03-packaging-pylock-separators")
ROOT = Path("/tmp/autocage-m35/rr03-diagnostic")
AUTOCAGE = Path("/tmp/autocage-m35/project/target/release/autocage")


def import_m3():
    spec = importlib.util.spec_from_file_location("autocage_m3_runner", M3 / "run_benchmark.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load frozen M3 controller helpers")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.WORK_ROOT = ROOT
    return module


def main() -> int:
    raw = json.loads(RAW.read_text())
    historical = raw["optimizers"]["F"]["optimizer_trials"][0]["policy"]["write_grants"]
    m3 = import_m3()
    tasks = json.loads((M3 / "tasks.json").read_text())["tasks"]
    task = next(row for row in tasks if row["id"] == "RR03-packaging-pylock-separators")
    fixture_dir = M3 / "fixtures" / task["id"]
    metadata = json.loads((fixture_dir / "fixture.json").read_text())
    canary_root = ROOT / "host-canaries"
    canary_root.mkdir(parents=True, exist_ok=True)
    host_canary = canary_root / "rr03.txt"
    host_canary.write_text("AUTOCAGE-M35-RR03-HOST-CANARY\n")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    cases = [
        ("broad-original-verifier", [{"kind": "directory_tree", "path": "."}], "workspace"),
        (
            "manual-exact-source-file-original-verifier",
            [{"kind": "file_contents", "path": "src/packaging/pylock.py"}],
            "workspace",
        ),
        ("recorded-root-decomposition-original-verifier", historical, "workspace"),
        ("zero-writes-original-verifier", [], "workspace"),
        (
            "manual-exact-source-file-private-tmp-cache-verifier-variant",
            [{"kind": "file_contents", "path": "src/packaging/pylock.py"}],
            "private-tmp",
        ),
    ]
    results = []
    for index, (label, grants, cache_mode) in enumerate(cases):
        workspace = ROOT / "workspaces" / f"case-{index}"
        workspace.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(SOURCE_WORK, workspace)
        run_dir = ROOT / "runs" / label
        if run_dir.exists():
            raise RuntimeError(f"diagnostic output already exists: {run_dir}")
        run_dir.parent.mkdir(parents=True, exist_ok=True)
        altered_task = dict(task)
        altered_task["pytest_cache"] = cache_mode
        agent, verifier = m3.command_specs(
            altered_task, metadata, workspace, host_canary, port
        )
        outcome = m3.make_run(
            AUTOCAGE,
            workspace,
            run_dir,
            altered_task,
            agent,
            verifier,
            grants,
            120,
            False,
        )
        record = outcome.get("record") or {}
        stage = run_dir / "stage"
        results.append(
            {
                "case": label,
                "policy": grants,
                "verifier_contract": "original" if cache_mode == "workspace" else "diagnostic-only private /tmp cache variant",
                "cli_return_code": outcome["return_code"],
                "elapsed_seconds": outcome["elapsed_seconds"],
                "agent_exit_code": (record.get("agent") or {}).get("exit_code"),
                "verifier_exit_code": (record.get("verifier") or {}).get("exit_code"),
                "outcome": record.get("outcome", "no-record"),
                "verifier_stdout_tail": outcome.get("stdout", "")[-1600:],
                "verifier_stderr_tail": outcome.get("stderr", "")[-1600:],
                "pytest_cache_created_in_stage": (stage / ".pytest_cache").exists(),
                "stage_pylock_sha256": hashlib.sha256(
                    (stage / "src/packaging/pylock.py").read_bytes()
                ).hexdigest()
                if (stage / "src/packaging/pylock.py").is_file()
                else None,
                "required_security_checks": [
                    {"name": row["name"], "status": row["status"]}
                    for row in record.get("security_checks", [])
                    if row.get("required_for_policy_promotion")
                ],
            }
        )
    listener.close()
    if host_canary.read_text() != "AUTOCAGE-M35-RR03-HOST-CANARY\n":
        raise RuntimeError("host canary changed")
    output = {
        "suite": "autocage-m35-rr03-diagnostic-v1",
        "historical_m3_result_modified": False,
        "classification": "A: the exact verifier's workspace-root pytest cache entry operation is not representable by a narrower current policy; this is a policy-vocabulary/operation requirement, not evidence that broad utility failed",
        "mechanism": "The task writes src/packaging/pylock.py in place. The verifier uses pytest's default cache at workspace root and attempts to create .pytest_cache. Exact-file contents authority permits the source edit but not root directory-entry creation. Child-directory grants cannot create a new sibling at the workspace root. A recursive root grant can.",
        "results": results,
        "host_canary": "PASS",
        "limits": "The private-/tmp cache case changes verifier arguments and is diagnostic only; it is not a promoted policy or a result under the frozen M3 contract.",
    }
    target = ROOT / "results/rr03-diagnostic.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps(output, indent=2))
    return 0 if results[0]["outcome"] == "verified" and results[-1]["outcome"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
