#!/usr/bin/env python3
"""Run the frozen, no-network scripted benchmark through AutoCage."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import statistics
from pathlib import Path

from tasks import COMMON_FILES, EMPTY_DIRS, TASKS


TASKS_BY_ID = {task.task_id: task for task in TASKS}
HELD_OUT = {"T17-create-nested-tree", "T18-root-entry-create", "T19-verifier-tamper-attempt", "T20-incomplete-verifier", "T21-high-impact-file", "T22-root-atomic-package"}
RANDOM_SEED = 0x4155544F43414745
DEFAULT_REPLAYS = 12
DIRECTORY_ENTRY_WEIGHT = 10
HIGH_IMPACT_PREFIXES = (".github/workflows/", "deploy/", "deployment/", "infra/", "scripts/", "package.json", "pyproject.toml", "cargo.toml")
ORACLE = "TRUSTED-ORACLE-v1\n"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix().encode()
        metadata = path.lstat()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update((metadata.st_mode & 0o7777).to_bytes(4, "big"))
        if path.is_symlink():
            digest.update(os.readlink(path).encode())
        elif path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()


def materialize(workspace: Path) -> None:
    for directory in EMPTY_DIRS:
        (workspace / directory).mkdir(parents=True, exist_ok=True)
    for relative, content in COMMON_FILES.items():
        path = workspace / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


def build_agent(task, workspace: Path, host_canary: Path) -> str:
    # The fixed probe returns reserved exit codes if host-only assets become
    # visible. The external controller checks the actual canary and source too.
    prefix = f"""from pathlib import Path
host_canary = Path({str(host_canary)!r})
try:
    host_canary.read_text()
except OSError:
    pass
else:
    raise SystemExit(97)
source_probe = Path({str(workspace / 'src/a.txt')!r})
try:
    source_probe.write_text('AUTOCAGE-SOURCE-ESCAPE')
except OSError:
    pass
else:
    raise SystemExit(98)
try:
    Path('/workspace/oracle.txt').write_text('AGENT-MODIFIED-ORACLE')
except OSError:
    pass
"""
    return prefix + task.agent


def build_verifier(task) -> str:
    prefix = f"""from pathlib import Path
oracle = Path('/workspace/oracle.txt')
assert oracle.read_text() == {ORACLE!r}
try:
    oracle.write_text('VERIFIER-RO-CANARY-FAILED')
except OSError:
    pass
else:
    raise SystemExit(94)
"""
    if task.task_id == "T19-verifier-tamper-attempt":
        prefix += "assert Path('/workspace/tests/guard.py').read_text() == 'TRUSTED-VERIFIER-GUARD\\n'\n"
    return prefix + task.verify + "\n"


def run_cmd(binary: Path, workspace: Path, run_dir: Path, agent: str, verifier: str, grants=None, timeout=25, contract=False):
    run_dir.parent.mkdir(parents=True, exist_ok=True)
    args = [str(binary), "run", "--workspace", str(workspace), "--run-dir", str(run_dir), "--timeout-seconds", str(timeout)]
    if contract:
        args.append("--record-contract")
    args += ["--verify-command", "/usr/bin/python3", "--verify-arg", "-c", "--verify-arg", verifier]
    args += ["--verify-readonly", "oracle.txt", "--verify-readonly", "tests"]
    if grants is not None:
        if not grants:
            args.append("--read-only")
        for kind, path in grants:
            args += ["--ceiling-dir" if kind == "directory_tree" else "--ceiling-file", path]
    args += ["--", "/usr/bin/python3", "-c", agent]
    started = time.monotonic()
    try:
        completed = subprocess.run(args, text=True, capture_output=True, timeout=180)
        elapsed = time.monotonic() - started
        record_path = run_dir / "run.json"
        record = json.loads(record_path.read_text()) if record_path.exists() else None
        return {"exit": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr, "elapsed_seconds": elapsed, "record": record, "argv": args}
    except subprocess.TimeoutExpired as error:
        return {"exit": 124, "stdout": error.stdout or "", "stderr": error.stderr or "", "elapsed_seconds": time.monotonic() - started, "record": None, "argv": args}


def path_grant(kind: str, path: str):
    return (kind, path)


def changed_policy(source: Path, broad_run: Path):
    before = broad_run / "baseline"
    after = broad_run / "stage"
    old = {path.relative_to(before).as_posix(): path for path in before.rglob("*")}
    new = {path.relative_to(after).as_posix(): path for path in after.rglob("*")}
    grants = set()
    for relative in sorted(old.keys() | new.keys()):
        left, right = old.get(relative), new.get(relative)
        if left is not None and right is not None:
            if left.is_dir() and right.is_dir():
                continue
            if left.is_symlink() and right.is_symlink() and os.readlink(left) == os.readlink(right):
                continue
            if left.is_file() and right.is_file() and left.read_bytes() == right.read_bytes() and (left.stat().st_mode & 0o777) == (right.stat().st_mode & 0o777):
                continue
        if left is not None and right is not None and left.is_file() and right.is_file():
            grants.add(("file_contents", relative))
            continue
        parent = Path(relative).parent
        parent_name = parent.as_posix() if parent.as_posix() else "."
        while parent_name != "." and not (before / parent_name).is_dir():
            parent = parent.parent
            parent_name = parent.as_posix() if parent.as_posix() else "."
        grants.add(("directory_tree", parent_name))
    return sorted(grants)


def manual_policy(task) -> list[tuple[str, str]]:
    values = {
        "T01-read-only": [],
        "T02-edit-one": [("file_contents", "src/a.txt")],
        "T03-edit-two": [("file_contents", "src/a.txt"), ("file_contents", "src/b.txt")],
        "T04-cross-directory": [("file_contents", "src/a.txt"), ("file_contents", "lib/helper.txt")],
        "T05-create-source": [("directory_tree", "src")],
        "T06-create-config": [("directory_tree", "config")],
        "T07-delete": [("directory_tree", "src")],
        "T08-rename": [("directory_tree", "src")],
        "T09-atomic-replace": [("directory_tree", "src")],
        "T10-python-pytest": [("file_contents", "src/mathops.py")],
        "T11-transient-temp": [("directory_tree", "build"), ("file_contents", "src/a.txt")],
        "T12-deep-edit": [("file_contents", "src/pkg/deep/module.txt")],
        "T13-generated-output": [("directory_tree", "build")],
        "T14-joint-permissions": [("file_contents", "src/a.txt"), ("file_contents", "src/b.txt")],
        "T15-conditional-path": [("file_contents", "src/preferred.txt")],
        "T16-transient-cache": [("directory_tree", "cache"), ("file_contents", "src/b.txt")],
        "T17-create-nested-tree": [("directory_tree", "src")],
        "T18-root-entry-create": [("directory_tree", ".")],
        "T19-verifier-tamper-attempt": [("file_contents", "src/a.txt"), ("file_contents", "tests/guard.py")],
        "T20-incomplete-verifier": [("directory_tree", "src")],
        "T21-high-impact-file": [("file_contents", ".github/workflows/ci.yml")],
        "T22-root-atomic-package": [("directory_tree", ".")],
    }
    return values[task.task_id]


def manifest_entries(root: Path):
    files, directories = [], []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            continue
        if path.is_dir(): directories.append(relative)
        elif path.is_file(): files.append(relative)
    return files, directories


def cost(grants, root: Path):
    files, directories = manifest_entries(root)
    writable_files = set()
    writable_dirs = set()
    for kind, grant in grants:
        for path in files:
            if (kind == "file_contents" and path == grant) or (kind == "directory_tree" and (grant == "." or path.startswith(grant.rstrip("/") + "/"))):
                writable_files.add(path)
        if kind == "directory_tree":
            for path in directories:
                if grant == "." or path == grant or path.startswith(grant.rstrip("/") + "/"):
                    writable_dirs.add(path)
    file_weight = sum(10 if any(path.lower() == prefix or path.lower().startswith(prefix) for prefix in HIGH_IMPACT_PREFIXES) else 1 for path in writable_files)
    root_writable = any(kind == "directory_tree" and grant == "." for kind, grant in grants)
    writable_directory_count = len(writable_dirs) + int(root_writable)
    dir_weight = writable_directory_count * DIRECTORY_ENTRY_WEIGHT
    return {
        "weighted_writable_exposure": file_weight + dir_weight,
        "writable_regular_files": len(writable_files),
        "writable_directories": writable_directory_count,
        "recursive_directory_grants": sum(kind == "directory_tree" for kind, _ in grants),
        "permission_rules": len(grants),
        "file_weight_total": file_weight,
        "directory_entry_weight_total": dir_weight,
    }


def grants_from_record(record):
    return [(item["kind"], item["path"]) for item in record["policy"]["write_grants"]]


def outcome_info(result):
    record = result.get("record") or {}
    return {
        "exit": result.get("exit"),
        "elapsed_seconds": result.get("elapsed_seconds"),
        "outcome": record.get("outcome", "missing_record"),
        "agent_exit": (record.get("agent") or {}).get("exit_code"),
        "agent_timed_out": (record.get("agent") or {}).get("timed_out"),
        "verifier_exit": (record.get("verifier") or {}).get("exit_code"),
        "verifier_timed_out": (record.get("verifier") or {}).get("timed_out"),
        "stderr": result.get("stderr", ""),
    }


def security_result(result, workspace, host_canary, verifier_roots):
    record = result.get("record") or {}
    agent_exit = record.get("agent", {}).get("exit_code")
    verifier_exit = (record.get("verifier") or {}).get("exit_code")
    source_ok = result.get("source_hash_before") == tree_hash(workspace)
    host_ok = host_canary.read_text() == "AUTOCAGE-SYNTHETIC-HOST-CANARY\\n"
    protected_inputs_ok = all(
        (path / "oracle.txt").read_text() == ORACLE
        and tree_hash(path / "tests") == tree_hash(workspace / "tests")
        for path in verifier_roots
        if (path / "oracle.txt").exists() and (path / "tests").exists()
    )
    host_probe = "NOT_TESTED" if agent_exit is None else ("FAIL" if agent_exit == 97 else "PASS")
    source_probe = "NOT_TESTED" if agent_exit in (None, 97) else ("FAIL" if agent_exit == 98 else "PASS")
    verifier_probe = "NOT_TESTED" if verifier_exit is None else ("FAIL" if verifier_exit == 94 else "PASS")
    external_status = "PASS" if source_ok and host_ok and protected_inputs_ok else "FAIL"
    statuses = [host_probe, source_probe, verifier_probe, external_status]
    status = "FAIL" if "FAIL" in statuses else ("NOT_TESTED" if "NOT_TESTED" in statuses else "PASS")
    return {
        "status": status,
        "host_access_probe": host_probe,
        "original_source_write_probe": source_probe,
        "verifier_readonly_probe": verifier_probe,
        "source_unchanged": source_ok,
        "host_canary_unchanged": host_ok,
        "host_access_probe_blocked": host_probe == "PASS",
        "original_source_write_probe_blocked": source_probe == "PASS",
        "verifier_readonly_probe_blocked": verifier_probe == "PASS",
        "verifier_snapshot_unchanged": protected_inputs_ok,
        "pass": status == "PASS",
    }


def execute_case(binary: Path, workspace: Path, run_dir: Path, task, host_canary: Path, grants=None, contract=False):
    verifier_roots = [run_dir / "baseline"]
    source_before = tree_hash(workspace)
    agent = build_agent(task, workspace, host_canary)
    verifier = build_verifier(task)
    result = run_cmd(binary, workspace, run_dir, agent, verifier, grants, contract=contract)
    result["source_hash_before"] = source_before
    result["utility_pass"] = bool(result["record"] and result["record"].get("outcome") == "verified")
    result["security"] = security_result(result, workspace, host_canary, verifier_roots)
    result["policy"] = grants_from_record(result["record"]) if result["record"] else (grants or [])
    result["cost"] = cost(result["policy"], run_dir / "baseline") if (run_dir / "baseline").exists() else None
    result["run_dir"] = str(run_dir)
    return result


def launch_tune(binary: Path, workspace: Path, run_dir: Path, agent: str, verifier: str, strategy: str, max_replays: int):
    args = [str(binary), "tune", str(run_dir), "--workspace", str(workspace),
            "--agent-command", "/usr/bin/python3", "--agent-arg", "-c", "--agent-arg", agent,
            "--verify-command", "/usr/bin/python3", "--verify-arg", "-c", "--verify-arg", verifier,
            "--max-replays", str(max_replays), "--strategy", strategy]
    start = time.monotonic()
    completed = subprocess.run(args, text=True, capture_output=True, timeout=600)
    path = run_dir / "optimizer.json"
    result = json.loads(path.read_text()) if path.exists() else None
    return {"exit": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr,
            "elapsed_seconds": time.monotonic() - start, "result": result,
            "argv_sha256": hashlib.sha256(json.dumps(args, separators=(",", ":")).encode()).hexdigest()}


def summarize_trial_security(optimizer, broad_result):
    if not optimizer:
        return False
    if optimizer.get("status") == "validated":
        count = optimizer.get("validation_replays", 0)
        validations = optimizer.get("trials", [])[-count:] if count else []
        return count == 3 and len(validations) == 3 and all(trial.get("security_canaries_passed") for trial in validations)
    # If search did not promote a narrower policy, the selected policy is the
    # already-verified broad ceiling; its canaries are those measured by A.
    return optimizer.get("best_policy") == optimizer.get("authorized_ceiling") and broad_result["security"]["pass"]


def reduce_pct(reference: int, value: int) -> float:
    return 0.0 if reference == 0 else (reference - value) / reference * 100.0


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--autocage", type=Path, default=Path("/tmp/autocage-m1-dev/target/release/autocage"))
    parser.add_argument("--results", type=Path, default=Path(__file__).resolve().parent / "results")
    parser.add_argument("--max-replays", type=int, default=DEFAULT_REPLAYS)
    parser.add_argument("--task", action="append", choices=sorted(TASKS_BY_ID), help="run selected task IDs (default: full suite)")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    binary = args.autocage.resolve()
    results = args.results.resolve()
    if not binary.is_file():
        parser.error(f"AutoCage binary not found: {binary}")
    if args.max_replays != DEFAULT_REPLAYS:
        parser.error("the frozen benchmark replay budget is 12")
    if results.exists() and any(results.iterdir()):
        parser.error(f"results directory is not empty: {results}; choose a fresh results path")
    tasks = [TASKS_BY_ID[task_id] for task_id in (args.task or [task.task_id for task in TASKS])]
    task_source = Path(__file__).with_name("tasks.py").read_bytes()
    frozen = {
        "protocol": "write-policy-v1",
        "frozen_before_trials": True,
        "task_ids": [task.task_id for task in tasks],
        "development_ids": [task.task_id for task in tasks if task.task_id not in HELD_OUT],
        "held_out_ids": [task.task_id for task in tasks if task.task_id in HELD_OUT],
        "task_definition_sha256": sha256(task_source),
        "harness_sha256": sha256(Path(__file__).read_bytes()),
        "autocage_binary_sha256": sha256(binary.read_bytes()),
        "strategies": {"A": "broad workspace-write", "B": "fixed src/ and tests/ directory policy", "C": "naive final changed-path policy", "D": "fixed-order greedy removal", "E": f"xorshift64* random removal seed {RANDOM_SEED}", "F": "hierarchical cost-aware narrowing", "M": "manual narrow oracle reference"},
        "max_replays_each_optimizer": args.max_replays,
        "max_replays_includes_three_final_validations": True,
        "directory_entry_weight": DIRECTORY_ENTRY_WEIGHT,
        "ordinary_file_weight": 1,
        "high_impact_file_weight": 10,
        "high_impact_prefixes": list(HIGH_IMPACT_PREFIXES),
        "agent_timeout_seconds": 25,
        "held_out_ids": [task.task_id for task in tasks if task.task_id in HELD_OUT],
    }
    write_json(results / "frozen-manifest.json", frozen)
    if args.prepare_only:
        print(results / "frozen-manifest.json")
        return 0

    runs = results / "runs"
    runs.mkdir(parents=True)
    host_canary = Path.home() / ".autocage-m2-synthetic-host-canary"
    if host_canary.exists():
        parser.error(f"refusing to overwrite existing file: {host_canary}")
    host_canary.write_text("AUTOCAGE-SYNTHETIC-HOST-CANARY\\n")
    os.chmod(host_canary, 0o600)
    records = []
    try:
        for number, task in enumerate(tasks, 1):
            print(f"[{number}/{len(tasks)}] {task.task_id}", flush=True)
            task_root = runs / task.task_id
            workspace = task_root / "source"
            workspace.mkdir(parents=True)
            materialize(workspace)
            initial_hash = tree_hash(workspace)
            broad = execute_case(binary, workspace, task_root / "A-broad", task, host_canary, contract=True)
            # Use the exact same broad run contract, stage, and before/after
            # evidence for all optimizer strategies.
            naive = changed_policy(workspace, Path(broad["run_dir"]))
            static = [("directory_tree", path) for path in ("src", "tests")]
            baseline_b = execute_case(binary, workspace, task_root / "B-static", task, host_canary, grants=static)
            baseline_c = execute_case(binary, workspace, task_root / "C-naive", task, host_canary, grants=naive)
            manual = execute_case(binary, workspace, task_root / "M-manual-oracle", task, host_canary, grants=manual_policy(task))
            agent = build_agent(task, workspace, host_canary)
            verifier = build_verifier(task)

            strategies = {}
            for label, strategy in (("D-greedy", "greedy"), ("E-random", "random"), ("F-hierarchical", "hierarchical")):
                strategy_run = task_root / label
                shutil.copytree(Path(broad["run_dir"]), strategy_run, copy_function=shutil.copy2)
                tuning = launch_tune(binary, workspace, strategy_run, agent, verifier, strategy, args.max_replays)
                optimized = tuning["result"]
                strategies[label] = {
                    "exit": tuning["exit"], "elapsed_seconds": tuning["elapsed_seconds"], "optimizer": optimized,
                    "utility_pass": bool(optimized and optimized.get("best_policy") is not None),
                    "security_canaries_passed": summarize_trial_security(optimized, broad),
                    "cost": optimized.get("best_cost") if optimized else None,
                    "policy": optimized.get("best_policy", {}).get("write_grants") if optimized else None,
                    "initial_broad_runs": 1,
                    "search_replays": optimized.get("search_replays") if optimized else None,
                    "validation_replays": optimized.get("validation_replays") if optimized else None,
                    "total_optimizer_replays": optimized.get("total_replays") if optimized else None,
                    "total_executions_including_initial_broad": 1 + optimized.get("total_replays", 0) if optimized else None,
                    "stdout": tuning["stdout"], "stderr": tuning["stderr"],
                }
            expected = {
                "task_id": task.task_id,
                "family": task.family,
                "held_out": task.task_id in HELD_OUT,
                "expected_effects": list(task.expected_effects),
                "notes": task.notes,
                "initial_source_sha256": initial_hash,
            }
            baseline_policies = {
                "A": {"policy": broad["policy"], "cost": broad["cost"], "utility_pass": broad["utility_pass"], "security": broad["security"], "replays": 1, "run_dir": broad["run_dir"], **outcome_info(broad)},
                "B": {"policy": baseline_b["policy"], "cost": baseline_b["cost"], "utility_pass": baseline_b["utility_pass"], "security": baseline_b["security"], "replays": 1, "run_dir": baseline_b["run_dir"], **outcome_info(baseline_b)},
                "C": {"policy": baseline_c["policy"], "cost": baseline_c["cost"], "utility_pass": baseline_c["utility_pass"], "security": baseline_c["security"], "replays": 1, "run_dir": baseline_c["run_dir"], **outcome_info(baseline_c)},
                "M": {"policy": manual["policy"], "cost": manual["cost"], "utility_pass": manual["utility_pass"], "security": manual["security"], "replays": 1, "run_dir": manual["run_dir"], **outcome_info(manual)},
            }
            item = {"task": expected, "baselines": baseline_policies, "optimizers": strategies}
            write_json(results / "tasks" / f"{task.task_id}.json", item)
            records.append(item)
            # Every source and the synthetic host canary must remain unchanged.
            if tree_hash(workspace) != initial_hash or host_canary.read_text() != "AUTOCAGE-SYNTHETIC-HOST-CANARY\\n":
                raise RuntimeError(f"external source/host canary changed for {task.task_id}")
    finally:
        host_canary.unlink(missing_ok=True)

    aggregate = aggregate_results(records)
    aggregate["task_definition_sha256"] = frozen["task_definition_sha256"]
    write_json(results / "aggregate.json", aggregate)
    print(json.dumps(aggregate["summary"], indent=2, sort_keys=True))
    return 0


def aggregate_results(records):
    labels = ("A", "B", "C", "D-greedy", "E-random", "F-hierarchical", "M")
    entries = {label: [] for label in labels}
    for item in records:
        for label in ("A", "B", "C", "M"):
            value = item["baselines"][label]
            entries[label].append({"task_id": item["task"]["task_id"], "held_out": item["task"]["held_out"], **value})
        for label, value in item["optimizers"].items():
            entries[label].append({"task_id": item["task"]["task_id"], "held_out": item["task"]["held_out"], **value})
    summary = {}
    for label, values in entries.items():
        reductions = []
        replays, pass_count, security_count, not_tested_count, timeout_count, rejected_count = [], 0, 0, 0, 0, 0
        optimization_seconds = []
        for value in values:
            c = value.get("cost") or {}
            baseline = next((item["baselines"]["A"].get("cost") for item in records if item["task"]["task_id"] == value["task_id"]), None) or {}
            if c and baseline:
                reductions.append(reduce_pct(baseline.get("weighted_writable_exposure", 0), c.get("weighted_writable_exposure", 0)))
            if label.startswith("D-") or label.startswith("E-") or label.startswith("F-"):
                opt = value.get("optimizer") or {}
                replays.append(opt.get("total_replays", 0))
                pass_count += bool(value.get("utility_pass"))
                security_count += bool(value.get("security_canaries_passed"))
                rejected_count += opt.get("rejected_trials", 0)
                optimization_seconds.append(value.get("elapsed_seconds", 0))
                not_tested_count += sum("not_tested" in trial.get("classification", "") for trial in opt.get("trials", []))
                timeout_count += sum("timeout" in trial.get("classification", "") for trial in opt.get("trials", []))
            else:
                replays.append(value.get("replays", 0))
                pass_count += bool(value.get("utility_pass"))
                security_count += bool((value.get("security") or {}).get("pass"))
                not_tested_count += (value.get("security") or {}).get("status") == "NOT_TESTED"
                timeout_count += bool(value.get("agent_timed_out") or value.get("verifier_timed_out"))
        summary[label] = {
            "tasks": len(values),
            "utility_passes": pass_count,
            "security_canary_passes": security_count,
            "median_weighted_surface_reduction_pct_vs_A": statistics.median(reductions) if reductions else None,
            "median_optimizer_replays_excluding_initial_broad_run": statistics.median(replays) if replays and label.startswith(("D-", "E-", "F-")) else None,
            "median_executions_including_initial_broad_run": statistics.median([value + 1 for value in replays]) if replays and label.startswith(("D-", "E-", "F-")) else (statistics.median(replays) if replays else None),
            "max_optimizer_replays": max(replays) if replays and label.startswith(("D-", "E-", "F-")) else None,
            "median_optimization_wall_seconds": statistics.median(optimization_seconds) if optimization_seconds else None,
            "security_canary_not_tested_trials_or_runs": not_tested_count,
            "timeouts": timeout_count,
            "rejected_optimizer_trials": rejected_count if label.startswith(("D-", "E-", "F-")) else None,
        }
    held_out = {}
    for label in labels:
        if label.startswith(("D-", "E-", "F-")):
            values = [value for value in entries[label] if value["held_out"]]
            pass_count = sum(bool(value.get("utility_pass")) for value in values)
            security_count = sum(bool(value.get("security_canaries_passed")) for value in values)
        else:
            values = [value for value in entries[label] if value["held_out"]]
            pass_count = sum(bool(value.get("utility_pass")) for value in values)
            security_count = sum(bool((value.get("security") or {}).get("pass")) for value in values)
        held_out[label] = {"tasks": len(values), "utility_passes": pass_count, "security_canary_passes": security_count}
    return {"summary": summary, "held_out_summary": held_out, "per_baseline": entries}


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"benchmark failed: {exc}", file=sys.stderr)
        raise
