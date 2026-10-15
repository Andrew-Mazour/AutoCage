#!/usr/bin/env python3
"""Diagnostic-only verifier capture; test code still runs inside AutoCage."""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("m3_benchmark", HERE / "run_benchmark.py")
BENCH = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(BENCH)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--autocage", type=Path, default=Path("/tmp/autocage-m1-dev/target/release/autocage"))
    parser.add_argument("--task", action="append", required=True)
    args = parser.parse_args()
    binary = args.autocage.resolve()
    task_map = {task["id"]: task for task in BENCH.TASKS}
    for task_id in args.task:
        task = task_map[task_id]
        _, workspace, metadata = BENCH.fixture_for(task)
        verifier_root = workspace / BENCH.safe_relative(task["verifier_root"])
        canary_dir = BENCH.WORK_ROOT / "diagnostic-canaries"
        canary_dir.mkdir(parents=True, exist_ok=True)
        host_canary = canary_dir / f"{task_id}.txt"
        host_canary.write_text("AUTOCAGE-M3-HOST-CANARY-v1\n")
        listener = BENCH.LoopbackCanary()
        agent, verifier = BENCH.command_specs(task, metadata, workspace, host_canary, listener.port)
        verifier_source = verifier[2]
        verifier_source = verifier_source.replace(
            "import hashlib, os, pathlib, sys",
            "import contextlib, hashlib, io, os, pathlib, sys",
        )
        verifier_source = verifier_source.replace(
            "result = pytest.main(arguments, plugins=[guard])",
            "captured_out=io.StringIO(); captured_err=io.StringIO()\n"
            "with contextlib.redirect_stdout(captured_out), contextlib.redirect_stderr(captured_err):\n"
            "    result=pytest.main(arguments, plugins=[guard])\n"
            "pathlib.Path('/workspace/.autocage-m3-test-output').write_text(captured_out.getvalue()+captured_err.getvalue())\n"
            "raise SystemExit(result)",
        )
        verifier_source = verifier_source.replace('arguments = ["-q"] +', 'arguments = ["-q", "-rs"] +')
        run_dir = BENCH.WORK_ROOT / "diagnostic-runs" / task_id
        if run_dir.exists():
            import shutil

            shutil.rmtree(run_dir)
        run_dir.parent.mkdir(parents=True, exist_ok=True)
        argv = [str(binary), "run", "--workspace", str(workspace), "--run-dir", str(run_dir), "--timeout-seconds", "120"]
        argv += ["--verify-command", verifier[0], "--verify-arg", "-c", "--verify-arg", verifier_source]
        argv += ["--verify-readonly", task["verifier_root"], "--ceiling-dir", ".", "--", *agent]
        outcome = subprocess.run(argv, capture_output=True, text=True, timeout=360)
        record = json.loads((run_dir / "run.json").read_text()) if (run_dir / "run.json").exists() else None
        output = run_dir / "stage/.autocage-m3-test-output"
        report = {
            "task": task_id,
            "autoCage_exit": outcome.returncode,
            "autoCage_stderr": outcome.stderr,
            "agent_exit": (record or {}).get("agent", {}).get("exit_code"),
            "verifier_exit": ((record or {}).get("verifier") or {}).get("exit_code"),
            "verifier_diagnostic": output.read_text(errors="replace") if output.exists() else "NOT_CAPTURED",
            "host_canary_unchanged": host_canary.read_text() == "AUTOCAGE-M3-HOST-CANARY-v1\n",
            "loopback_probe_connections": listener.check()["sandbox_connections"],
        }
        listener.close()
        print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
