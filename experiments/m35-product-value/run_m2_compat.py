#!/usr/bin/env python3
"""Compatibility adapter for rerunning frozen M2 tasks with the current tune CLI.

The historical M2 controller predates required command/workspace arguments on
tune. This wrapper supplies those exact values from the pinned task and fresh
source path; it does not change tasks, policies, or the optimizer.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--controller", type=Path, required=True)
    parser.add_argument("--autocage", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()
    controller = args.controller.resolve()
    binary = args.autocage.resolve()
    results = args.results.resolve()
    sys.path.insert(0, str(controller.parent))
    spec = importlib.util.spec_from_file_location("frozen_m2_controller", controller)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load frozen M2 controller")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    def launch_tune_compat(binary_path: Path, run_dir: Path, strategy: str, max_replays: int):
        task_id = run_dir.parent.name
        task = module.TASKS_BY_ID[task_id]
        workspace = run_dir.parent / "source"
        host_canary = Path.home() / ".autocage-m2-synthetic-host-canary"
        agent = module.build_agent(task, workspace, host_canary)
        verifier = module.build_verifier(task)
        command = [
            str(binary_path), "tune", str(run_dir),
            "--workspace", str(workspace),
            "--agent-command", "/usr/bin/python3",
            "--agent-arg", "-c", "--agent-arg", agent,
            "--verify-command", "/usr/bin/python3",
            "--verify-arg", "-c", "--verify-arg", verifier,
            "--max-replays", str(max_replays), "--strategy", strategy,
        ]
        started = time.monotonic()
        completed = subprocess.run(command, text=True, capture_output=True, timeout=600)
        result_path = run_dir / "optimizer.json"
        result = json.loads(result_path.read_text()) if result_path.is_file() else None
        return {
            "exit": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "elapsed_seconds": time.monotonic() - started,
            "result": result,
            "argv": command,
        }

    module.launch_tune = launch_tune_compat
    sys.argv = [str(controller), "--autocage", str(binary), "--results", str(results)]
    return int(module.main())

if __name__ == "__main__":
    raise SystemExit(main())
