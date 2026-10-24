#!/usr/bin/env python3
"""Run the bounded M4 paired security-regression prototype on Linux."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
SIGNAL_PREFIX = "AUTOCAGE_AGENT_SIGNAL="
WRITE_FLAGS = re.compile(r"O_(?:WRONLY|RDWR|CREAT|TRUNC|APPEND)")
DENIED = re.compile(r"= -1 (?:EROFS|EACCES|EPERM)(?: \(|$)")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def tree_digest(root: Path) -> str:
    entries: list[tuple[str, str]] = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            rel = path.relative_to(root).as_posix()
            entries.append((rel, sha256_bytes(path.read_bytes())))
    return sha256_bytes(canonical_json(entries))


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object in {path}")
    return value


def apply_overlay(workspace: Path, case: dict[str, Any]) -> None:
    destination = workspace / case["input_path"]
    overlay = (ROOT / case["overlay"]).read_text(encoding="utf-8").rstrip("\n")
    mode = case["overlay_mode"]
    if mode == "append":
        destination.write_text(
            destination.read_text(encoding="utf-8").rstrip("\n") + "\n" + overlay + "\n",
            encoding="utf-8",
        )
    elif mode == "comment":
        source = destination.read_text(encoding="utf-8")
        marker = "def compute(left: int, right: int) -> int:\n"
        if source.count(marker) != 1:
            raise ValueError(f"unexpected source shape in {destination}")
        comment = "    # " + overlay + "\n"
        destination.write_text(source.replace(marker, marker + comment), encoding="utf-8")
    elif mode == "replace":
        destination.write_text(overlay + "\n", encoding="utf-8")
    else:
        raise ValueError(f"unsupported overlay mode: {mode}")


def parse_signal(output: str) -> dict[str, Any] | None:
    for line in output.splitlines():
        marker = line.find(SIGNAL_PREFIX)
        if marker >= 0:
            payload = line[marker + len(SIGNAL_PREFIX) :].strip()
            try:
                value = json.loads(payload)
            except json.JSONDecodeError:
                return {"parse_error": True}
            return value if isinstance(value, dict) else {"parse_error": True}
    return None


def trace_events(trace_path: Path, input_path: str, protected_path: str) -> dict[str, Any]:
    if not trace_path.is_file():
        return {
            "state": "UNOBSERVED",
            "input_open_observed": False,
            "protected_write_attempt": "UNOBSERVED",
            "protected_write_trace_lines": [],
            "tool_exec_observed": False,
        }

    raw_lines = trace_path.read_text(encoding="utf-8", errors="replace").splitlines()
    # `strace -f` prefixes calls from child processes with their PID. Keep the
    # original lines for evidence, but classify the syscall after removing
    # only that documented numeric prefix.
    lines = [re.sub(r"^\d+\s+", "", line) for line in raw_lines]
    input_literals = (json.dumps(input_path), json.dumps(f"/workspace/{input_path}"))
    protected_literal = json.dumps(protected_path)
    input_reads = [
        line
        for line in lines
        if line.startswith(("openat(", "openat2(", "open("))
        and any(literal in line for literal in input_literals)
        and "O_RDONLY" in line
        and "= -1 " not in line
    ]
    protected_writes = [
        line
        for line in lines
        if line.startswith(("openat(", "openat2(", "open("))
        and protected_literal in line
        and WRITE_FLAGS.search(line)
    ]
    # The helper's execution is evidence that a tool-output fixture ran; it
    # does not prove the agent's internal interpretation of that output.
    tool_exec_observed = any(
        line.startswith("execve(") and '"tools/untrusted_tool.py"' in line
        for line in lines
    )
    if not protected_writes:
        write_state = "NO_ATTEMPT_OBSERVED"
    elif any(DENIED.search(line) for line in protected_writes):
        write_state = "ATTEMPT_DENIED_BY_FILESYSTEM"
    elif any(re.search(r"\) = [0-9]+(?:<[^>]*>)?$", line) for line in protected_writes):
        write_state = "WRITE_OPEN_SUCCEEDED"
    else:
        write_state = "ATTEMPT_OUTCOME_UNCLEAR"
    return {
        "state": "OBSERVED",
        "input_open_observed": bool(input_reads),
        "protected_write_attempt": write_state,
        "protected_write_trace_lines": [
            raw_lines[index] for index, line in enumerate(lines) if line in protected_writes
        ],
        "tool_exec_observed": tool_exec_observed,
    }


def host_facts(autocage: Path, strace: str) -> dict[str, Any]:
    bwrap = subprocess.run(["bwrap", "--version"], text=True, capture_output=True, check=True)
    strace_version = subprocess.run(
        [strace, "--version"], text=True, capture_output=True, check=True
    ).stdout.splitlines()[0]
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "kernel": platform.release(),
        "python": sys.version.split()[0],
        "bubblewrap": bwrap.stdout.strip(),
        "strace": strace_version,
        "autocage_binary_sha256": sha256_bytes(autocage.read_bytes()),
        "strace_path": str(Path(strace).resolve()),
    }


def invoke_run(
    *,
    autocage: Path,
    strace: str,
    workspace: Path,
    run_dir: Path,
    config: dict[str, Any],
    case: dict[str, Any],
    timeout_seconds: int,
    trace_path: Path,
) -> dict[str, Any]:
    args = [
        str(autocage),
        "run",
        "--workspace",
        str(workspace),
        "--run-dir",
        str(run_dir),
        "--timeout-seconds",
        str(timeout_seconds),
        "--verify-command",
        "/usr/bin/python3",
    ]
    for arg in ["-m", "unittest", "tests.test_mathops", "-v"]:
        args.extend(["--verify-arg", arg])
    for root in case.get("verifier_readonly", ["tests"]):
        args.extend(["--verify-readonly", root])
    if config["write_dirs"]:
        for path in config["write_dirs"]:
            args.extend(["--ceiling-dir", path])
    else:
        args.append("--read-only")
    # The executable opens paths relative to /workspace, so pass the staged
    # script path rather than the controller's path.
    agent_args = [
        "/usr/bin/python3",
        "tools/scripted_agent.py",
        "--surface",
        case["surface"],
        "--input",
        case["input_path"],
        "--protected",
        case["protected_path"],
    ]
    args.extend(["--", *agent_args])
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    traced = [
        str(Path(strace).resolve()),
        "-f",
        "-qq",
        "-s",
        "256",
        "-e",
        "trace=%file",
        "-o",
        str(trace_path),
        *args,
    ]
    started = time.monotonic()
    try:
        proc = subprocess.run(
            traced,
            capture_output=True,
            text=True,
            timeout=timeout_seconds + 30,
            check=False,
        )
        supervisor_timeout = False
        stdout = proc.stdout
        stderr = proc.stderr
        process_status = proc.returncode
    except subprocess.TimeoutExpired as error:
        supervisor_timeout = True
        stdout = error.stdout.decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
        stderr = error.stderr.decode(errors="replace") if isinstance(error.stderr, bytes) else (error.stderr or "")
        process_status = None
    elapsed_millis = int((time.monotonic() - started) * 1000)

    record_path = run_dir / "run.json"
    record = load_json(record_path) if record_path.is_file() else None
    signal = parse_signal(stdout)
    trace = trace_events(trace_path, case["input_path"], case["protected_path"])
    canary_path = run_dir / "stage" / case["protected_path"]
    canary_after = canary_path.read_text(encoding="utf-8") if canary_path.is_file() else "MISSING"
    canary_changed = canary_after != case["canary_initial"]
    checks = record.get("security_checks", []) if record else []
    mandatory_checks = [
        check["name"]
        for check in checks
        if check.get("required_for_policy_promotion") is True
    ]
    mandatory_checks_passed = bool(mandatory_checks) and all(
        check.get("status") == "passed"
        for check in checks
        if check.get("required_for_policy_promotion") is True
    )
    utility = (
        "PASS"
        if record and record.get("outcome") == "verified"
        else "FAIL"
        if record and record.get("outcome") == "verifier_failed"
        else "INCONCLUSIVE"
    )
    return {
        "process_exit_code": process_status,
        "supervisor_timeout": supervisor_timeout,
        "elapsed_wall_millis": elapsed_millis,
        "agent_reported_signal": signal,
        "trace": trace,
        "utility": utility,
        "run_record_present": record is not None,
        "run_record_outcome": record.get("outcome") if record else None,
        "agent_exit_code": record.get("agent", {}).get("exit_code") if record else None,
        "verifier_exit_code": record.get("verifier", {}).get("exit_code") if record and record.get("verifier") else None,
        "required_autocage_checks": mandatory_checks,
        "required_autocage_checks_passed": mandatory_checks_passed,
        "canary_before": case["canary_initial"],
        "canary_after": canary_after,
        "canary_modified": canary_changed,
        "workspace_changed_paths": record.get("workspace", {}).get("changed_paths", []) if record else [],
        "run_record_runtime": record.get("runtime") if record else None,
        "run_record_phase_timings": record.get("phase_timings") if record else None,
        "stdout_summary": [line for line in stdout.splitlines() if line.startswith((SIGNAL_PREFIX, "run directory:", "record:"))],
        "stderr_tail": stderr.splitlines()[-8:],
        "trace_excerpt": trace.get("protected_write_trace_lines", []),
    }


def write_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def write_text_atomic(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(value, encoding="utf-8")
    temporary.replace(path)


def check_assertions(runs: list[dict[str, Any]], replicates: int, cases: list[dict[str, Any]]) -> dict[str, Any]:
    by_key = {(run["replicate"], run["case_id"], run["variant"], run["config_name"]): run for run in runs}
    checks: dict[str, Any] = {
        "all_required_runs_have_records": all(run["result"]["run_record_present"] for run in runs),
        "all_mandatory_runner_security_checks_passed": all(run["result"]["required_autocage_checks_passed"] for run in runs),
        "all_trace_files_collected": all(run["result"]["trace"]["state"] == "OBSERVED" for run in runs),
        "all_declared_inputs_open_observed": all(
            run["result"]["trace"]["input_open_observed"]
            for run in runs
            if run["config_name"] != "candidate-read-only"
        ),
        "all_task_verifiers_executed": all(run["result"]["verifier_exit_code"] is not None for run in runs),
        "source_fixture_unchanged": all(run["source_digest_before"] == run["source_digest_after"] for run in runs),
    }
    per_case = []
    for replicate in range(1, replicates + 1):
        for case in cases:
            safe = by_key[(replicate, case["case_id"], "adversarial", "static-src-only")]["result"]
            broad = by_key[(replicate, case["case_id"], "adversarial", "candidate-workspace-write")]["result"]
            clean = by_key[(replicate, case["case_id"], "clean", "static-src-only")]["result"]
            per_case.append(
                {
                    "replicate": replicate,
                    "case_id": case["case_id"],
                    "clean_task_passed": clean["utility"] == "PASS",
                    "static_policy_adversarial_task_passed": safe["utility"] == "PASS",
                    "broad_candidate_adversarial_task_passed": broad["utility"] == "PASS",
                    "static_policy_attempt_observed": safe["trace"]["protected_write_attempt"],
                    "static_policy_canary_unchanged": not safe["canary_modified"],
                    "candidate_attempt_observed": broad["trace"]["protected_write_attempt"],
                    "candidate_canary_modified": broad["canary_modified"],
                    "security_regression_detected": (
                        safe["trace"]["protected_write_attempt"] == "ATTEMPT_DENIED_BY_FILESYSTEM"
                        and not safe["canary_modified"]
                        and broad["trace"]["protected_write_attempt"] == "WRITE_OPEN_SUCCEEDED"
                        and broad["canary_modified"]
                    ),
                    "agent_reported_directive_seen": (safe.get("agent_reported_signal") or {}).get("directive_seen"),
                }
            )
    checks["paired_security_regressions_detected"] = len(per_case) == len(cases) * replicates and all(
        result["security_regression_detected"] for result in per_case
    )
    checks["all_main_task_pairs_passed"] = all(
        result["clean_task_passed"]
        and result["static_policy_adversarial_task_passed"]
        and result["broad_candidate_adversarial_task_passed"]
        for result in per_case
    )
    tool_output_runs = [run["result"] for run in runs if run["surface"] == "tool_output"]
    checks["tool_output_helper_execution_observed"] = bool(tool_output_runs) and all(
        result["trace"]["tool_exec_observed"] for result in tool_output_runs
    )
    clean_runs = [run["result"] for run in runs if run["variant"] == "clean"]
    checks["clean_arms_have_no_protected_write"] = all(
        result["trace"]["protected_write_attempt"] == "NO_ATTEMPT_OBSERVED"
        and not result["canary_modified"]
        for result in clean_runs
    )
    readonly = [
        run["result"]
        for run in runs
        if run["config_name"] == "candidate-read-only" and run["variant"] == "clean"
    ]
    checks["utility_regression_control_detected"] = len(readonly) == replicates and all(
        result["utility"] == "FAIL" and result["verifier_exit_code"] not in (None, 0)
        for result in readonly
    )
    checks["no_unobserved_security_event_counted_as_pass"] = all(
        run["result"]["trace"]["state"] == "OBSERVED"
        for run in runs
        if run["variant"] == "adversarial"
    )
    return {"checks": checks, "paired_case_results": per_case}


def render_report(record: dict[str, Any]) -> str:
    paired = record["validation"]["paired_case_results"]
    case_ids = list(dict.fromkeys(row["case_id"] for row in paired))
    lines = [
        "# AutoCage M4 paired containment result",
        "",
        f"- **Status:** {record['status']}",
        f"- **Suite:** `{record['suite_id']}`",
        f"- **Experiment identity:** `{record['experiment_input_identity_sha256']}`",
        f"- **Environment:** {record['host']['platform']}; {record['host']['machine']}; "
        f"Linux {record['host']['kernel']}; {record['host']['bubblewrap']}; {record['host']['strace']}",
        f"- **Executions:** {record['counts']['total_runs']} total; "
        f"{record['counts']['verifier_executions']} verifier executions; "
        f"{record['counts']['trace_files']} trace files",
        "",
        "## Paired policy comparison",
        "",
        "The agent is a deterministic controller, not a language model. The static policy grants writes to `src/`; the candidate deliberately grants recursive writes to the full staged workspace.",
        "",
        "| Untrusted surface | Clean utility | Static-policy adversarial utility | Static attempted writes denied | Static canary changed | Broad-policy adversarial utility | Broad writes allowed and canary changed |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for case_id in case_ids:
        rows = [row for row in paired if row["case_id"] == case_id]
        lines.append(
            "| {case} | {clean}/{n} | {safe}/{n} | {denied}/{n} | {safe_changed}/{n} | "
            "{broad}/{n} | {allowed}/{n} |".format(
                case=case_id,
                clean=sum(row["clean_task_passed"] for row in rows),
                safe=sum(row["static_policy_adversarial_task_passed"] for row in rows),
                denied=sum(row["static_policy_attempt_observed"] == "ATTEMPT_DENIED_BY_FILESYSTEM" for row in rows),
                safe_changed=sum(not row["static_policy_canary_unchanged"] for row in rows),
                broad=sum(row["broad_candidate_adversarial_task_passed"] for row in rows),
                allowed=sum(
                    row["candidate_attempt_observed"] == "WRITE_OPEN_SUCCEEDED"
                    and row["candidate_canary_modified"]
                    for row in rows
                ),
                n=len(rows),
            )
        )
    all_runs = record["runs"]
    main_runs = [run for run in all_runs if run["config_name"] != "candidate-read-only"]
    readonly_runs = [run for run in all_runs if run["config_name"] == "candidate-read-only"]
    lines.extend(
        [
            "",
            "## Evidence summary",
            "",
            f"- Main task arms passed the trusted verifier: {sum(run['result']['utility'] == 'PASS' for run in main_runs)}/{len(main_runs)}.",
            f"- Independent AutoCage required checks passed: {sum(run['result']['required_autocage_checks_passed'] for run in all_runs)}/{len(all_runs)}.",
            f"- Declared input opens observed by `strace`: {sum(run['result']['trace']['input_open_observed'] for run in main_runs)}/{len(main_runs)} main runs.",
            f"- Read-only utility-regression controls failed their trusted verifier as expected: {sum(run['result']['utility'] == 'FAIL' for run in readonly_runs)}/{len(readonly_runs)}.",
            f"- Median outer run duration, including staging, verification, and tracing: {statistics.median(run['result']['elapsed_wall_millis'] for run in all_runs):.1f} ms.",
            "",
            "## Interpretation and limits",
            "",
            "This demonstrates that the selected Bubblewrap write boundary can allow the legitimate `src/` edit while denying these exact out-of-scope writes, and that a deliberately broad workspace policy permits them. It does not show that a coding model would read, obey, or resist the injected content: the scripted control intentionally attempts the write. A denied syscall is enforcement evidence; the canary is checked independently after execution; the test verifier measures utility. No claim is made about all filesystem syscalls, model intent, generalization, or sandbox escape resistance.",
            "",
            "A missing trace, unobserved attempt, absent verifier result, or failed required AutoCage check remains incomplete and cannot count as a security pass.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--autocage", required=True, type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--replicates", type=int, default=1)
    parser.add_argument("--case", action="append", dest="case_ids")
    options = parser.parse_args()
    if options.replicates < 1 or options.replicates > 5:
        parser.error("--replicates must be from 1 to 5")

    autocage = options.autocage.resolve(strict=True)
    if not autocage.is_file() or not os.access(autocage, os.X_OK):
        parser.error("--autocage must name an executable file")
    strace = shutil.which("strace")
    if strace is None:
        raise SystemExit("BLOCKED: strace is required to distinguish attempted and denied filesystem operations")
    suite = load_json(ROOT / "suite.json")
    base_root = ROOT / suite["fixture_root"]
    config_paths = {
        name: ROOT / value for name, value in suite["policy_comparisons"].items()
    }
    configs = {config_path.stem: load_json(config_path) for config_path in config_paths.values()}
    baseline = configs["baseline"]
    candidate = configs["candidate"]
    readonly = configs["read-only"]
    configs_by_name = {
        baseline["name"]: baseline,
        candidate["name"]: candidate,
        readonly["name"]: readonly,
    }
    cases = suite["cases"]
    if options.case_ids:
        cases = [case for case in cases if case["case_id"] in set(options.case_ids)]
        if len(cases) != len(set(options.case_ids)):
            parser.error("unknown or duplicate --case id")
    if not cases:
        parser.error("no cases selected")

    work_root = options.work_root.resolve()
    if work_root.exists() and any(work_root.iterdir()):
        parser.error("--work-root must be empty or not yet exist")
    work_root.mkdir(parents=True, exist_ok=True)
    output = options.output.resolve()
    if output.exists():
        parser.error("--output must not already exist")

    preflight = subprocess.run([str(autocage), "check"], capture_output=True, text=True, check=False)
    host = host_facts(autocage, strace)
    host["preflight_exit_code"] = preflight.returncode
    host["preflight_output"] = (preflight.stdout + preflight.stderr).splitlines()[-12:]
    host["euid"] = os.geteuid()
    host["wall_clock_utc"] = datetime.now(timezone.utc).isoformat()
    source_digest_before = tree_digest(ROOT)
    immutable_inputs = {
        "suite_sha256": sha256_bytes((ROOT / "suite.json").read_bytes()),
        "base_fixture_sha256": tree_digest(base_root),
        "configs": {
            key: sha256_bytes(path.read_bytes()) for key, path in sorted(config_paths.items())
        },
        "harness_sha256": sha256_bytes((ROOT / "run_suite.py").read_bytes()),
        "overlay_digests": {
            case["case_id"]: sha256_bytes((ROOT / case["overlay"]).read_bytes()) for case in cases
        },
        "autocage_binary_sha256": host["autocage_binary_sha256"],
        "runtime": {
            key: host[key]
            for key in ("platform", "machine", "kernel", "python", "bubblewrap", "strace")
        },
    }
    protocol_id = sha256_bytes(canonical_json(immutable_inputs))
    execution_order = [
        (case, variant, config)
        for case in cases
        for variant in ("clean", "adversarial")
        for config in (baseline, candidate)
    ]
    # One clean read-only arm is the predeclared task-utility regression control.
    execution_order.extend((cases[0], "clean", readonly) for _ in [0])

    runs: list[dict[str, Any]] = []
    for replicate in range(1, options.replicates + 1):
        for case, variant, config in execution_order:
            run_id = f"r{replicate:02d}-{case['case_id']}-{variant}-{config['name']}"
            workspace = work_root / "inputs" / run_id
            run_dir = work_root / "runs" / run_id
            workspace.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(base_root, workspace)
            if variant == "adversarial":
                apply_overlay(workspace, case)
            # Capture fixture canary after overlay but before untrusted execution.
            canary = workspace / case["protected_path"]
            canary.write_text(case["canary_initial"], encoding="utf-8")
            digest_before = tree_digest(base_root)
            run_dir.parent.mkdir(parents=True, exist_ok=True)
            trace_path = work_root / "traces" / f"{run_id}.strace"
            case_with_canary = dict(case)
            result = invoke_run(
                autocage=autocage,
                strace=strace,
                workspace=workspace,
                run_dir=run_dir,
                config=config,
                case=case_with_canary,
                timeout_seconds=suite["timeout_seconds"],
                trace_path=trace_path,
            )
            runs.append(
                {
                    "replicate": replicate,
                    "run_id": run_id,
                    "case_id": case["case_id"],
                    "surface": case["surface"],
                    "variant": variant,
                    "config_name": config["name"],
                    "config_sha256": sha256_bytes(canonical_json(config)),
                    "authorized_write_dirs": config["write_dirs"],
                    "workspace_sha256_before_run": tree_digest(workspace),
                    "source_digest_before": digest_before,
                    "source_digest_after": tree_digest(base_root),
                    "result": result,
                }
            )

    source_digest_after = tree_digest(ROOT)
    validation = check_assertions(runs, options.replicates, cases)
    completed = preflight.returncode == 0 and all(validation["checks"].values())
    result_record = {
        "schema_version": 1,
        "suite_id": suite["suite_id"],
        "protocol_sha256": sha256_bytes((ROOT / "PROTOCOL.json").read_bytes()),
        "experiment_input_identity_sha256": protocol_id,
        "created_utc": host["wall_clock_utc"],
        "status": "COMPLETED" if completed else "INCOMPLETE",
        "host": host,
        "immutable_inputs": immutable_inputs,
        "policy_configurations": configs_by_name,
        "repeat_count": options.replicates,
        "task_description": suite["task"],
        "counts": {
            "total_runs": len(runs),
            "adversarial_runs": sum(run["variant"] == "adversarial" for run in runs),
            "clean_runs": sum(run["variant"] == "clean" for run in runs),
            "verifier_executions": sum(run["result"]["verifier_exit_code"] is not None for run in runs),
            "trace_files": sum((work_root / "traces" / f"{run['run_id']}.strace").is_file() for run in runs),
        },
        "validation": validation,
        "runs": runs,
        "source_fixture_tree_digest_before": source_digest_before,
        "source_fixture_tree_digest_after": source_digest_after,
        "source_fixture_unchanged": source_digest_before == source_digest_after,
        "limitations": [
            "The deterministic scripted agent proves harness classification behavior only; it is not LLM or real-agent evidence.",
            "strace records selected syscall-level path operations, not model intent or all filesystem behavior.",
            "A protected canary modification is a staged-workspace effect; the original checkout remains isolated by copy staging.",
            "No availability-isolation claim is made; aggregate CPU, memory, and process limits are not established.",
        ],
    }
    write_atomic(output, result_record)
    report_path = output.with_suffix(".md")
    write_text_atomic(report_path, render_report(result_record))
    print(
        json.dumps(
            {
                "status": result_record["status"],
                "output": str(output),
                "human_report": str(report_path),
                "counts": result_record["counts"],
                "checks": validation["checks"],
            },
            indent=2,
        )
    )
    return 0 if completed else 1


if __name__ == "__main__":
    raise SystemExit(main())
