#!/usr/bin/env python3
"""Frozen M3.6 first-run policy comparison; task code runs only in AutoCage."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
import zipfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[1]
M3 = HERE.parent / "real-repository-v1"
M2 = HERE.parent / "write-policy-v1"
M35 = HERE.parent / "m35-product-value"
PROTOCOL_PATH = HERE / "PROTOCOL.json"
CANARIES = {
    "unrelated_source": "src/autocage_m36_unrelated.py",
    "unrelated_test": "tests/autocage_m36_unrelated_test.py",
    "build_configuration": "autocage-m36-build-config.toml",
    "repository_automation": ".github/workflows/autocage-m36.yml",
    "deployment_configuration": "deploy/autocage-m36.yml",
    "sensitive_configuration": "config/.autocage-m36-sensitive-canary",
}
CANARY_CONTENT = "AUTOCAGE-M36-UNCHANGED-CANARY\n"
CANARY_REPLACEMENT = "AUTOCAGE-M36-COMPROMISED\n"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha(path: Path) -> str:
    return sha(path.read_bytes())


def tree_sha(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
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


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def call(argv: list[str], timeout: int = 240) -> dict:
    started = time.monotonic()
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "returncode": result.returncode,
            "elapsed_millis": round((time.monotonic() - started) * 1000),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as error:
        return {
            "returncode": None,
            "elapsed_millis": round((time.monotonic() - started) * 1000),
            "stdout": error.stdout.decode(errors="replace") if isinstance(error.stdout, bytes) else error.stdout or "",
            "stderr": error.stderr.decode(errors="replace") if isinstance(error.stderr, bytes) else error.stderr or "",
            "timed_out": True,
        }


def validate_protocol(binary: Path, work_root: Path) -> tuple[dict, dict, dict]:
    if not PROTOCOL_PATH.is_file():
        raise RuntimeError("PROTOCOL.json is missing; do not run held-out tasks before freeze")
    protocol = json.loads(PROTOCOL_PATH.read_text())
    plan_path = HERE / "workflow-plan.json"
    plan = json.loads(plan_path.read_text())
    manifest_path = work_root / "prepared-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    expected = {
        "workflow_plan_sha256": file_sha(plan_path),
        "controller_sha256": file_sha(Path(__file__)),
        "workflow_task_manifest_sha256": file_sha(M3 / "tasks.json"),
        "m3_prepare_sha256": file_sha(M3 / "prepare.py"),
        "m3_runtime_lock_sha256": file_sha(M3 / "setup/python-requirements.lock"),
        "m36_prepare_sha256": file_sha(HERE / "prepare_workflows.py"),
        "m36_build_lock_sha256": file_sha(HERE / "setup/python-build-requirements.lock"),
        "m36_download_setup_sha256": file_sha(HERE / "setup/download-build-deps.sh"),
        "m36_install_setup_sha256": file_sha(HERE / "setup/install-build-deps.sh"),
        "profile_source_sha256": file_sha(PROJECT / "src/profile.rs"),
        "policy_source_sha256": file_sha(PROJECT / "src/policy.rs"),
        "bubblewrap_source_sha256": file_sha(PROJECT / "src/backend/bubblewrap.rs"),
        "linux_test_source_sha256": file_sha(PROJECT / "tests/linux_runner.rs"),
        "m2_frozen_manifest_sha256": file_sha(M2 / "results/frozen-manifest.json"),
        "m2_report_sha256": file_sha(M2 / "REPORT.md"),
        "m3_protocol_sha256": file_sha(M3 / "protocol.json"),
        "m35_protocol_sha256": file_sha(M35 / "PROTOCOL.json"),
        "m35_report_sha256": file_sha(M35 / "REPORT.md"),
        "autocage_release_binary_sha256": file_sha(binary),
        "cargo_manifest_sha256": file_sha(PROJECT / "Cargo.toml"),
        "cargo_lock_sha256": file_sha(PROJECT / "Cargo.lock"),
    }
    for key, actual in expected.items():
        if protocol.get(key) != actual:
            raise RuntimeError(f"frozen input changed: {key}")
    if manifest.get("workflow_plan_sha256") != expected["workflow_plan_sha256"]:
        raise RuntimeError("prepared snapshots do not match the frozen workflow plan")
    if manifest.get("source_task_manifest_sha256") != expected["workflow_task_manifest_sha256"]:
        raise RuntimeError("prepared snapshots do not match the pinned M3 task manifest")
    if plan.get("state") != "frozen-before-final-evaluation":
        raise RuntimeError("workflow plan is not frozen")
    validate_workflow_layout(plan, manifest)
    runtime = protocol["runtime"]
    python_version = call(["/usr/bin/python3", "--version"])
    actual_runtime = {
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "python": (python_version["stdout"] + python_version["stderr"]).strip(),
        "bubblewrap": call(["/usr/bin/bwrap", "--version"])["stdout"].strip(),
        "rustc": call(["rustc", "--version"])["stdout"].strip(),
        "cargo": call(["cargo", "--version"])["stdout"].strip(),
    }
    if runtime.get("platform") != actual_runtime:
        raise RuntimeError(f"frozen platform runtime differs: {actual_runtime}")
    old_m3 = json.loads((M3 / "protocol.json").read_text())
    for package, expected_version in old_m3["apt_packages"].items():
        actual_version = call(["dpkg-query", "-W", f"-f=${{Version}}", package])["stdout"].strip()
        if actual_version != expected_version:
            raise RuntimeError(f"Ubuntu package version drift: {package}={actual_version}, expected {expected_version}")
    import importlib.metadata
    installed = {
        item.metadata.get("Name", "").lower().replace("_", "-"): item.version
        for item in importlib.metadata.distributions(path=["/usr/local/lib/autocage-m3-site-v2"])
        if item.metadata.get("Name")
    }
    for package, expected_version in old_m3["python_packages"].items():
        if installed.get(package.lower().replace("_", "-")) != expected_version:
            raise RuntimeError(f"M3 pinned Python package drift: {package}")
    build_site = {
        item.metadata.get("Name", "").lower().replace("_", "-"): item.version
        for item in importlib.metadata.distributions(path=["/usr/local/lib/autocage-m36-build-site"])
        if item.metadata.get("Name")
    }
    if build_site.get("flit-core") != "3.12.0":
        raise RuntimeError("pinned flit_core build dependency is missing or changed")
    return protocol, plan, manifest


def validate_workflow_layout(plan: dict, manifest: dict) -> None:
    """Validate declared task and verifier inputs before any workload executes."""
    snapshots = {
        (entry["workflow_id"], entry["revision"]): Path(entry["snapshot_path"])
        for entry in manifest["snapshots"]
    }

    def require_path(root: Path, relative: str, want_directory: bool, label: str) -> None:
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise RuntimeError(f"invalid {label} path in frozen workflow: {relative}")
        path = root / candidate
        if path.is_symlink() or not path.exists():
            raise RuntimeError(f"missing or symlinked {label} path in frozen workflow: {relative}")
        if want_directory:
            if not path.is_dir():
                raise RuntimeError(f"{label} path is not a directory: {relative}")
        elif not path.is_file():
            raise RuntimeError(f"{label} path is not a regular file: {relative}")

    for workflow in plan["workflows"]:
        workflow_id = workflow["id"]
        kind = workflow["kind"]
        for revision in ("parent", "target"):
            root = snapshots.get((workflow_id, revision))
            if root is None or not root.is_dir():
                raise RuntimeError(f"missing prepared {revision} snapshot for {workflow_id}")
            if kind == "python-test":
                require_path(root, workflow["test_path"], False, "test input")
            elif kind == "python-compileall":
                require_path(root, workflow["target"], True, "compileall target")
            elif kind == "python-wheel":
                require_path(root, workflow.get("project", "."), True, "wheel project")
                require_path(root, "dist", True, "declared wheel output")
            else:
                raise RuntimeError(f"unsupported frozen workflow kind for {workflow_id}: {kind}")
            _, readonly_roots = verifier_command(workflow)
            for readonly_root in readonly_roots:
                require_path(root, readonly_root, True, "verifier read-only root")


def workflow_command(workflow: dict) -> list[str]:
    kind = workflow["kind"]
    python_path = "/workspace/src:/usr/local/lib/autocage-m3-site-v2:/usr/local/lib/autocage-m36-build-site:/usr/lib/python3/dist-packages"
    env = ["/usr/bin/env", f"PYTHONPATH={python_path}"]
    if kind == "python-test":
        command = [
            *env,
            "/usr/bin/python3",
            "-m",
            "pytest",
            workflow["test_path"],
            "-q",
            "-o",
            "cache_dir=/tmp/autocage-m36-pytest-cache",
        ]
        command.extend(workflow.get("pytest_extra_args", []))
        return command
    if kind == "python-compileall":
        return [
            "/usr/bin/env",
            "PYTHONPYCACHEPREFIX=/tmp/autocage-m36-pycache",
            f"PYTHONPATH={python_path}",
            "/usr/bin/python3",
            "-m",
            "compileall",
            "-q",
            workflow["target"],
        ]
    if kind == "python-wheel":
        return [
            *env,
            "/usr/bin/python3",
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            "dist",
            ".",
        ]
    raise ValueError(f"unsupported frozen workflow kind: {kind}")


def verifier_command(workflow: dict) -> tuple[list[str], list[str]]:
    if workflow["kind"] == "python-wheel":
        return ["/usr/bin/python3", "/workspace/tests/autocage_m36_verify_wheel.py"], ["tests"]
    if workflow["kind"] == "python-test":
        return workflow_command(workflow), [Path(workflow["test_path"]).parts[0]]
    return workflow_command(workflow), [workflow["target"]]


def explicit_policy(workflow: dict) -> list[tuple[str, str]]:
    if workflow["kind"] == "python-wheel":
        return [("dir", "dist")]
    return []


def run_argv(
    binary: Path,
    source: Path,
    run_dir: Path,
    command: list[str],
    verifier: tuple[list[str], list[str]] | None,
    method: str,
    proposal: Path | None = None,
    record_contract: bool = True,
    policy_override: list[tuple[str, str]] | None = None,
) -> list[str]:
    argv = [str(binary), "run", "--workspace", str(source), "--run-dir", str(run_dir), "--timeout-seconds", "120"]
    if record_contract and verifier is not None:
        argv.append("--record-contract")
    if verifier is not None:
        verifier_command_, readonly = verifier
        argv.extend(["--verify-command", verifier_command_[0]])
        for argument in verifier_command_[1:]:
            argv.extend(["--verify-arg", argument])
        for path in readonly:
            argv.extend(["--verify-readonly", path])
    if method == "A":
        argv.extend(["--ceiling-dir", "."])
    elif method in ("B", "C"):
        grants = explicit_policy_from_override(source, policy_override)
        if grants:
            for kind, path in grants:
                argv.extend(["--ceiling-dir" if kind == "dir" else "--ceiling-file", path])
        else:
            argv.append("--read-only")
    elif method == "D":
        if proposal is None:
            raise ValueError("suggested profile run has no proposal")
        argv.extend(["--accept-proposal", str(proposal), "--ceiling-dir", "."])
    elif method == "E":
        grants = policy_override or []
        if grants:
            for kind, path in grants:
                argv.extend(["--ceiling-dir" if kind == "dir" else "--ceiling-file", path])
        else:
            argv.append("--read-only")
    elif method == "canary":
        grants = policy_override or []
        if grants:
            for kind, path in grants:
                argv.extend(["--ceiling-dir" if kind == "dir" else "--ceiling-file", path])
        else:
            argv.append("--read-only")
    else:
        raise ValueError(f"unknown method: {method}")
    argv.extend(["--", *command])
    return argv


def explicit_policy_from_override(
    source: Path, override: list[tuple[str, str]] | None
) -> list[tuple[str, str]]:
    del source
    return list(override or [])


def propose(binary: Path, workflow: dict, source: Path, command: list[str], output: Path) -> dict:
    started = time.monotonic()
    result = call(
        [str(binary), "propose", "--workspace", str(source), "--workflow", workflow["kind"], "--", *command]
    )
    elapsed = round((time.monotonic() - started) * 1000)
    if result["returncode"] != 0 or result["timed_out"]:
        raise RuntimeError(f"proposal generation failed for {workflow['id']}: {result['stderr'][-1000:]}")
    value = json.loads(result["stdout"])
    write_json(output, value)
    return {"proposal": value, "elapsed_millis": elapsed, "path": str(output)}


def execute(
    binary: Path,
    source: Path,
    run_dir: Path,
    command: list[str],
    verifier: tuple[list[str], list[str]] | None,
    method: str,
    proposal: Path | None = None,
    policy_override: list[tuple[str, str]] | None = None,
) -> dict:
    if run_dir.exists():
        raise RuntimeError(f"refusing to overwrite run directory {run_dir}")
    run_dir.parent.mkdir(parents=True, exist_ok=True)
    wrapper_started = time.monotonic()
    source_before = tree_sha(source)
    argv = run_argv(binary, source, run_dir, command, verifier, method, proposal, policy_override=policy_override)
    result = call(argv)
    source_after = tree_sha(source)
    run_record_path = run_dir / "run.json"
    record_error = None
    record = None
    if run_record_path.is_file():
        try:
            record = json.loads(run_record_path.read_text())
            if not isinstance(record, dict):
                record_error = "run record is not a JSON object"
                record = None
        except (OSError, json.JSONDecodeError) as error:
            record_error = f"run record could not be read: {type(error).__name__}"
    if method == "canary":
        canary_control_passed = bool(
            record
            and (record.get("agent") or {}).get("exit_code") == 0
            and any(
                check.get("name") == "readonly_mount_write_denial" and check.get("status") == "passed"
                for check in record.get("security_checks", [])
            )
            and any(
                check.get("name") == "source_checkout_unchanged" and check.get("status") == "passed"
                for check in record.get("security_checks", [])
            )
        )
        status = "PASS" if result["returncode"] == 0 and canary_control_passed else "FAIL"
    else:
        status = "PASS" if result["returncode"] == 0 and record and record.get("outcome") == "verified" else "FAIL"
    return {
        "status": status,
        "returncode": result["returncode"],
        "timed_out": result["timed_out"],
        "cli_wall_millis": result["elapsed_millis"],
        "controller_total_wall_millis": round((time.monotonic() - wrapper_started) * 1000),
        "source_tree_sha256_before": source_before,
        "source_tree_sha256_after": source_after,
        "source_tree_unchanged_by_controller": source_before == source_after,
        "stdout_tail": result["stdout"][-1000:] if result["returncode"] not in (0, None) or record is None else "",
        "stderr_tail": result["stderr"][-1500:] if result["returncode"] not in (0, None) or record is None else "",
        "record": record,
        "record_error": record_error,
        "run_dir": str(run_dir),
        "argv": argv,
    }


def policy_from_run(result: dict) -> list[tuple[str, str]]:
    if not result.get("record"):
        return []
    return [
        ("dir" if grant["kind"] == "directory_tree" else "file", grant["path"])
        for grant in result["record"]["policy"]["write_grants"]
    ]


def grants_json(record_or_policy: dict | None) -> list[dict]:
    if not record_or_policy:
        return []
    policy = record_or_policy.get("policy", record_or_policy)
    return policy.get("write_grants", [])


def optimizer_child_counts(trials: list[dict]) -> tuple[int, int]:
    """Count child executions from persisted trial classifications."""
    agents = 0
    verifiers = 0
    for trial in trials:
        classification = trial.get("classification", "")
        if classification.startswith("invalid_policy:"):
            continue
        agents += 1
        if ":agent_failed_" not in classification and ":agent_timeout:" not in classification:
            verifiers += 1
    return agents, verifiers


def policy_cost(grants: list[dict], source: Path) -> dict:
    files: list[str] = []
    directories: list[str] = []
    for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()):
        relative = path.relative_to(source).as_posix()
        if path.is_symlink():
            continue
        if path.is_dir():
            directories.append(relative)
        elif path.is_file():
            files.append(relative)

    def covered(path: str, grant: dict) -> bool:
        base = Path(grant["path"])
        target = Path(path)
        if grant["kind"] == "file_contents":
            return target == base
        return base == Path(".") or target == base or target.is_relative_to(base)

    writable_files = {path for path in files if any(covered(path, grant) for grant in grants)}
    writable_dirs = {path for path in directories if any(grant["kind"] == "directory_tree" and covered(path, grant) for grant in grants)}
    prefixes = (".github/workflows/", "deploy/", "deployment/", "scripts/", "package.json", "pyproject.toml", "cargo.toml")
    file_weight = sum(10 if any(path.lower() == prefix or path.lower().startswith(prefix) for prefix in prefixes) else 1 for path in writable_files)
    root_grant = any(grant["kind"] == "directory_tree" and grant["path"] == "." for grant in grants)
    directory_entries = len(writable_dirs) + int(root_grant)
    recursive = sorted(grant["path"] for grant in grants if grant["kind"] == "directory_tree")
    exact = sorted(grant["path"] for grant in grants if grant["kind"] == "file_contents")
    high_impact = sorted(path for path in writable_files if any(path.lower() == prefix or path.lower().startswith(prefix) for prefix in prefixes))
    return {
        "schema": "weighted-write-surface-v1",
        "weighted_writable_exposure": file_weight + directory_entries * 10,
        "writable_regular_files": len(writable_files),
        "writable_directory_entries": directory_entries,
        "exact_file_grants": exact,
        "recursive_directory_grants": recursive,
        "recursive_grant_count": len(recursive),
        "grant_depths": {path: 0 if path == "." else len(Path(path).parts) for path in recursive},
        "grant_breadth": {path: sum(1 for child in ((source if path == "." else source / path).iterdir())) for path in recursive},
        "high_impact_paths_covered": high_impact,
        "future_child_creation_allowed": bool(recursive),
        "future_child_scope": "unbounded below recursive grants" if recursive else "none",
    }


def canary_command() -> list[str]:
    script = (
        "import pathlib,sys\n"
        "for p in sys.argv[1:]:\n"
        "    try:\n"
        "        (pathlib.Path('/workspace')/p).write_text('AUTOCAGE-M36-COMPROMISED\\n')\n"
        "    except OSError:\n"
        "        pass\n"
    )
    return ["/usr/bin/python3", "-c", script, *CANARIES.values()]


def create_canary_workspace(source: Path, destination: Path) -> None:
    if destination.exists():
        raise RuntimeError(f"refusing to overwrite canary source {destination}")
    shutil.copytree(source, destination, symlinks=True)
    for relative in CANARIES.values():
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(CANARY_CONTENT)


def inspect_canary_result(run: dict) -> dict:
    record = run.get("record")
    stage = Path(run["run_dir"]) / "stage"
    observations = {}
    for name, relative in CANARIES.items():
        observed = stage / relative
        if not observed.is_file():
            observations[name] = {"path": relative, "blocked": False, "modified": False, "missing": True}
            continue
        content = observed.read_text()
        observations[name] = {
            "path": relative,
            "blocked": content == CANARY_CONTENT,
            "modified": content == CANARY_REPLACEMENT,
            "missing": False,
        }
    source_unchanged = bool(record and any(
        check["name"] == "source_checkout_unchanged" and check["status"] == "passed"
        for check in record.get("security_checks", [])
    ))
    return {
        "status": "PASS" if run["returncode"] == 0 and source_unchanged and all(not item["missing"] for item in observations.values()) else "FAIL",
        "paths": observations,
        "blocked_count": sum(item["blocked"] for item in observations.values()),
        "modified_count": sum(item["modified"] for item in observations.values()),
        "source_checkout_unchanged_check": source_unchanged,
        "controller_source_unchanged": run.get("source_tree_unchanged_by_controller") is True,
    }


def expected_canary_behavior(grants: list[tuple[str, str]]) -> dict:
    allowed = set()
    for name, relative in CANARIES.items():
        target = Path(relative)
        for kind, raw_path in grants:
            grant = Path(raw_path)
            if kind == "file" and target == grant:
                allowed.add(name)
            elif kind == "dir" and (grant == Path(".") or target == grant or target.is_relative_to(grant)):
                allowed.add(name)
    return {
        "allowed_by_compiled_policy": sorted(allowed),
        "expected_blocked_count": len(CANARIES) - len(allowed),
        "expected_modified_count": len(allowed),
    }


def attach_canary_evidence(result: dict, grants: list[tuple[str, str]]) -> None:
    observed = inspect_canary_result(result)
    expected = expected_canary_behavior(grants)
    observed.update(expected)
    observed["policy_expectation_met"] = (
        observed["blocked_count"] == expected["expected_blocked_count"]
        and observed["modified_count"] == expected["expected_modified_count"]
    )
    result["independent_canary"] = observed


def summarize(results: list[dict]) -> dict:
    okay = [result for result in results if result.get("status") == "PASS"]
    costs = [result["cost"]["weighted_writable_exposure"] for result in okay if result.get("cost")]
    reductions = [result["reduction_percent"] for result in okay if result.get("reduction_percent") is not None]
    return {
        "successful": len(okay),
        "total": len(results),
        "utility_success_rate": len(okay) / len(results) if results else None,
        "conditional_median_weighted_exposure": statistics.median(costs) if costs else None,
        "conditional_median_reduction_percent": statistics.median(reductions) if reductions else None,
        "full_corpus_median_reduction_percent_zero_for_failures": statistics.median(
            [result.get("reduction_percent", 0.0) if result.get("status") == "PASS" else 0.0 for result in results]
        ) if results else None,
        "total_cli_wall_millis": sum(result.get("cli_wall_millis", 0) for result in results),
        "total_controller_wall_millis_including_source_fingerprints": sum(result.get("controller_total_wall_millis", 0) for result in results),
        "agent_child_elapsed_millis": sum(
            ((result.get("record") or {}).get("agent") or {}).get("elapsed_millis", 0) for result in results
        ),
        "verifier_child_elapsed_millis": sum(
            ((result.get("record") or {}).get("verifier") or {}).get("elapsed_millis", 0)
            for result in results if result.get("record")
        ),
        "workspace_staging_millis": sum(
            ((result.get("record") or {}).get("phase_timings") or {}).get("workspace_stage_elapsed_millis", 0)
            for result in results if result.get("record")
        ),
        "bubblewrap_argument_compilation_millis": sum(
            ((result.get("record") or {}).get("phase_timings") or {}).get("agent_backend_compile_elapsed_millis", 0)
            for result in results if result.get("record")
        ),
    }


def prepare_canaries(workflow: dict, revision: str, source: Path, out_root: Path, binary: Path) -> list[dict]:
    rows = []
    policies = {
        "A": [("dir", ".")],
        "B": explicit_policy(workflow),
        "C": explicit_policy(workflow),
    }
    # The proposed policy is recompiled from its grant list through the same
    # production compiler. This is an enforcement check, not proposal reuse.
    # E is populated from the target-revision optimizer separately.
    methods = [(method, policy) for method, policy in policies.items()]
    for method, grants in methods:
        canary_source = out_root / "canary-sources" / workflow["id"] / revision / method
        create_canary_workspace(source, canary_source)
        run_dir = out_root / "canary-runs" / workflow["id"] / revision / method
        result = execute(
            binary, canary_source, run_dir, canary_command(), None, "canary", policy_override=grants
        )
        result.update({"workflow_id": workflow["id"], "revision": revision, "method": method})
        attach_canary_evidence(result, grants)
        rows.append(result)
    return rows


def environment_record() -> dict:
    result = call(["/usr/bin/python3", "--version"])
    return {
        "system": platform.platform(),
        "architecture": platform.machine(),
        "python": (result["stdout"] + result["stderr"]).strip(),
        "kernel": platform.release(),
        "bubblewrap": call(["/usr/bin/bwrap", "--version"])["stdout"].strip(),
        "rustc": call(["rustc", "--version"])["stdout"].strip(),
        "cargo": call(["cargo", "--version"])["stdout"].strip(),
        "network_policy": "AutoCage child uses a private network namespace; no network grants are passed",
    }


def additional_drift_study(
    binary: Path, workflow: dict, source: Path, out_root: Path
) -> list[dict]:
    """Research-only profile invalidation plus explicit-ceiling shadow executions."""
    command = workflow_command(workflow)
    verifier = verifier_command(workflow)
    proposal_path = out_root / "drift-study" / "original-proposal.json"
    proposal_result = propose(binary, workflow, source, command, proposal_path)
    variants = [
        ("unrelated-source-edit", lambda root: append_comment(next((root / "src").rglob("*.py")))),
        ("added-source-file", lambda root: write_new(root / "src/autocage_m36_added.py", "VALUE = 1\n")),
        ("modified-test", lambda root: append_comment(root / "tests/test_pylock.py")),
        ("build-configuration-edit", lambda root: append_comment(root / "pyproject.toml")),
        ("dependency-declaration-edit", lambda root: replace_once(root / "pyproject.toml", "dependencies = []", 'dependencies = ["typing-extensions>=4.0"]')),
    ]
    rows = []
    old_grants = [
        ("dir" if grant["kind"] == "directory_tree" else "file", grant["path"])
        for grant in proposal_result["proposal"]["policy"]["write_grants"]
    ]
    for name, mutate in variants:
        changed = out_root / "drift-study" / "sources" / name
        if changed.exists():
            raise RuntimeError(f"refusing to overwrite drift source {changed}")
        shutil.copytree(source, changed, symlinks=True)
        mutate(changed)
        stale = execute(
            binary, changed, out_root / "drift-study" / "stale" / name,
            command, verifier, "D", proposal_path,
        )
        rejected = stale["returncode"] not in (0, None) and stale.get("record") is None and "stale, modified" in stale["stderr_tail"]
        shadow = execute(
            binary, changed, out_root / "drift-study" / "shadow" / name,
            command, verifier, "E", policy_override=old_grants,
        )
        rows.append({
            "change": name,
            "stale_profile_rejected_before_execution": rejected,
            "stale_profile_returncode": stale["returncode"],
            "research_only_old_explicit_policy_shadow_utility": shadow["status"],
            "shadow_cli_wall_millis": shadow["cli_wall_millis"],
            "shadow_run_record_present": shadow.get("record") is not None,
            "shadow_agent_process_recorded": bool((shadow.get("record") or {}).get("agent")),
            "shadow_verifier_process_recorded": bool((shadow.get("record") or {}).get("verifier")),
            "old_policy_grants": grants_json(shadow.get("record")),
            "old_policy_child_write_authority_reauthorized_for_shadow_only": True,
            "stale_profile_stderr": stale["stderr_tail"][-400:],
        })
    changed_command = [*command]
    if changed_command[0] == "/usr/bin/env":
        changed_command.insert(1, "AUTOCAGE_M36_COMMAND_DRIFT=1")
    else:
        raise RuntimeError("frozen drift case expected an /usr/bin/env command wrapper")
    command_drift = execute(
        binary, source, out_root / "drift-study" / "stale" / "command-argument",
        changed_command, verifier, "D", proposal_path,
    )
    command_rejected = command_drift["returncode"] not in (0, None) and command_drift.get("record") is None and "stale, modified" in command_drift["stderr_tail"]
    rows.append({
        "change": "command-environment-argument",
        "stale_profile_rejected_before_execution": command_rejected,
        "stale_profile_returncode": command_drift["returncode"],
        "research_only_old_explicit_policy_shadow_utility": "NOT TESTED",
        "old_policy_grants": old_grants,
        "stale_profile_stderr": command_drift["stderr_tail"][-400:],
    })
    return rows


def append_comment(path: Path) -> None:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f"drift fixture target is not a regular file: {path}")
    path.write_bytes(path.read_bytes() + b"\n# AutoCage M3.6 controlled source revision\n")


def write_new(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise RuntimeError(f"drift fixture already exists: {path}")
    path.write_text(contents)


def replace_once(path: Path, old: str, new: str) -> None:
    data = path.read_text()
    if data.count(old) != 1:
        raise RuntimeError(f"dependency declaration anchor is not unique in {path}")
    path.write_text(data.replace(old, new, 1))


def run_final(binary: Path, work_root: Path, output: Path) -> dict:
    protocol, plan, manifest = validate_protocol(binary, work_root)
    task_manifest = json.loads((M3 / "tasks.json").read_text())
    task_by_id = {task["id"]: task for task in task_manifest["tasks"]}
    snapshots = {
        (entry["workflow_id"], entry["revision"]): Path(entry["snapshot_path"])
        for entry in manifest["snapshots"]
    }
    held_out = [item for item in plan["workflows"] if item["split"] == "held-out"]
    dev_only = [item for item in plan["workflows"] if item["split"] == "development"]
    if len(held_out) < 8:
        raise RuntimeError("frozen study must include at least eight held-out workflows")
    if output.exists() and any(output.iterdir()):
        raise RuntimeError(f"refusing to overwrite result directory {output}")
    output.mkdir(parents=True, exist_ok=True)
    task_rows: list[dict] = []
    canary_rows: list[dict] = []
    repeat_rows: list[dict] = []
    drift_rows: list[dict] = []
    tuning_rows: list[dict] = []
    proposal_timings: list[dict] = []
    tuned_policies: dict[str, list[tuple[str, str]]] = {}
    drift_shadow_rows: list[dict] = []

    def save_progress(phase: str) -> None:
        write_json(output / "progress.json", {
            "suite_id": protocol["suite_id"],
            "status": "INCOMPLETE",
            "last_completed_phase": phase,
            "task_runs_completed": len(task_rows),
            "repeat_runs_completed": len(repeat_rows),
            "canary_runs_completed": len(canary_rows),
            "drift_checks_completed": len(drift_rows),
            "tuning_workflows_completed": len(tuning_rows),
            "warning": "Partial records are exploratory only. Missing checks are NOT TESTED, never PASS.",
        })

    for workflow in held_out:
        task = task_by_id[workflow["task_id"]]
        command = workflow_command(workflow)
        verifier = verifier_command(workflow)
        for revision in ("parent", "target"):
            source = snapshots[(workflow["id"], revision)]
            baseline_dir = output / "runs" / workflow["id"] / revision
            proposal_path = output / "proposals" / workflow["id"] / f"{revision}.json"
            proposal_result = propose(binary, workflow, source, command, proposal_path)
            proposal = proposal_result["proposal"]
            proposal_timings.append({
                "workflow_id": workflow["id"], "revision": revision,
                "elapsed_millis": proposal_result["elapsed_millis"],
                "grant_count": len(proposal["policy"]["write_grants"]),
                "read_only_area_count": len(proposal["read_only_areas"]),
                "unresolved_requirement_count": len(proposal["unresolved_requirements"]),
                "rules": proposal["rules"],
            })
            executions: dict[str, dict] = {}
            policies = {
                "A": [("dir", ".")],
                "B": explicit_policy(workflow),
                "C": explicit_policy(workflow),
                "D": None,
            }
            for method, grants in policies.items():
                result = execute(
                    binary,
                    source,
                    baseline_dir / method,
                    command,
                    verifier,
                    method,
                    proposal_path if method == "D" else None,
                    policy_override=grants,
                )
                record = result.get("record")
                measured_grants = grants_json(record)
                cost = policy_cost(measured_grants, source)
                broad_cost = policy_cost([{"kind": "directory_tree", "path": "."}], source)
                result.update({
                    "workflow_id": workflow["id"],
                    "task_id": task["id"],
                    "repository": task["repository"],
                    "repository_license": task["license"],
                    "commit": task[revision],
                    "revision": revision,
                    "method": method,
                    "command": command,
                    "verifier": verifier[0],
                    "verifier_readonly_roots": verifier[1],
                    "cost": cost,
                    "broad_cost": broad_cost,
                    "reduction_percent": (100.0 * (broad_cost["weighted_writable_exposure"] - cost["weighted_writable_exposure"]) / broad_cost["weighted_writable_exposure"])
                    if broad_cost["weighted_writable_exposure"] else 0.0,
                    "proposal_generation_millis": proposal_result["elapsed_millis"] if method == "D" else None,
                    "manual_policy_rule_count": len(grants or []),
                    "interactive_approval_prompts": 0,
                    "manual_policy_corrections": 0,
                    "explicit_proposal_acceptance_required": method == "D",
                    "separate_developer_ceiling_required": method == "D",
                })
                executions[method] = result
                task_rows.append(result)
                save_progress(f"{workflow['id']}/{revision}/{method}")

            # Three fresh exact-source repetitions of the proposed first-run policy.
            for repeat in range(1, 4):
                result = execute(
                    binary, source, baseline_dir / f"D-repeat-{repeat}", command, verifier,
                    "D", proposal_path,
                )
                repeat_rows.append({
                    "workflow_id": workflow["id"], "revision": revision,
                    "repeat": repeat, "status": result["status"],
                    "cli_wall_millis": result["cli_wall_millis"],
                    "agent_elapsed_millis": ((result.get("record") or {}).get("agent") or {}).get("elapsed_millis"),
                    "verifier_elapsed_millis": ((result.get("record") or {}).get("verifier") or {}).get("elapsed_millis"),
                    "agent_process_recorded": bool((result.get("record") or {}).get("agent")),
                    "verifier_process_recorded": bool((result.get("record") or {}).get("verifier")),
                    "run_record_present": result.get("record") is not None,
                    "policy": grants_json(result.get("record")),
                })
                save_progress(f"{workflow['id']}/{revision}/D-repeat-{repeat}")

            # Independently exercise identical canaries under the policy variants.
            canary_rows.extend(prepare_canaries(workflow, revision, source, output, binary))
            save_progress(f"{workflow['id']}/{revision}/A-B-C-canaries")
            # `prepare_canaries` executes all three arms; retain D's actual suggested grant by
            # applying that exact normalized grant through the common compiler.
            suggested_grants = [
                ("dir" if grant["kind"] == "directory_tree" else "file", grant["path"])
                for grant in proposal["policy"]["write_grants"]
            ]
            canary_source = output / "canary-sources" / workflow["id"] / revision / "D"
            create_canary_workspace(source, canary_source)
            canary_result = execute(
                binary, canary_source, output / "canary-runs" / workflow["id"] / revision / "D",
                canary_command(), None, "canary", policy_override=suggested_grants,
            )
            canary_result.update({"workflow_id": workflow["id"], "revision": revision, "method": "D"})
            attach_canary_evidence(canary_result, suggested_grants)
            canary_rows.append(canary_result)
            save_progress(f"{workflow['id']}/{revision}/D-canary")

            # The same parent profile must reject on target source; the regenerated target
            # profile is evaluated independently above.
            if revision == "parent":
                target_source = snapshots[(workflow["id"], "target")]
                stale_run = output / "stale-proposals" / workflow["id"]
                stale = execute(
                    binary, target_source, stale_run, command, verifier, "D", proposal_path
                )
                stale_rejected = (
                    stale["returncode"] != 0
                    and stale.get("record") is None
                    and "stale, modified" in stale.get("stderr_tail", "")
                )
                drift_rows.append({
                    "workflow_id": workflow["id"], "change": "parent-to-target-pinned-source-revision",
                    "status": "PASS" if stale_rejected else "FAIL",
                    "rejected_before_task_execution": stale_rejected,
                    "returncode": stale["returncode"],
                    "stderr": stale.get("stderr_tail", "")[-400:],
                })
                save_progress(f"{workflow['id']}/parent-target-stale-profile")

            # One broad run per target workflow is the agreed post-run optimizer starting point.
            if revision == "target":
                broad_run = executions["A"]
                if broad_run["status"] == "PASS":
                    tune_started = time.monotonic()
                    tune_argv = [
                        str(binary), "tune", broad_run["run_dir"], "--workspace", str(source),
                        "--agent-command", command[0],
                    ]
                    for argument in command[1:]:
                        tune_argv.extend(["--agent-arg", argument])
                    tune_argv.extend(["--verify-command", verifier[0][0]])
                    for argument in verifier[0][1:]:
                        tune_argv.extend(["--verify-arg", argument])
                    tune_argv.extend(["--max-replays", "4", "--strategy", "greedy"])
                    tuned = call(tune_argv, timeout=900)
                    tune_elapsed = round((time.monotonic() - tune_started) * 1000)
                    optimizer_path = Path(broad_run["run_dir"]) / "optimizer.json"
                    optimized = json.loads(optimizer_path.read_text()) if optimizer_path.is_file() else None
                    grants = optimized.get("best_policy", {}).get("write_grants", []) if optimized else []
                    tuned_policies[workflow["id"]] = [
                        ("dir" if grant["kind"] == "directory_tree" else "file", grant["path"])
                        for grant in grants
                    ]
                    tuning_rows.append({
                        "workflow_id": workflow["id"], "revision": revision,
                        "status": "PASS" if tuned["returncode"] == 0 and optimized else "FAIL",
                        "strategy": optimized.get("strategy") if optimized else "greedy",
                        "optimizer_status": optimized.get("status") if optimized else None,
                        "search_replays": optimized.get("search_replays") if optimized else None,
                        "validation_replays": optimized.get("validation_replays") if optimized else None,
                        "total_replays": optimized.get("total_replays") if optimized else None,
                        "search_rejected_trials": optimized.get("rejected_trials") if optimized else None,
                        "cli_wall_millis": tune_elapsed,
                        "optimizer_trial_run_elapsed_millis": sum(trial.get("elapsed_millis", 0) for trial in optimized.get("trials", [])) if optimized else None,
                        "optimizer_child_execution_counts": {
                            "agent_processes": optimizer_child_counts(optimized.get("trials", []))[0],
                            "verifier_processes": optimizer_child_counts(optimized.get("trials", []))[1],
                        } if optimized else None,
                        "policy": grants,
                        "authorized_ceiling": optimized.get("authorized_ceiling", {}).get("write_grants", []) if optimized else [],
                        "baseline_cost": policy_cost([{"kind": "directory_tree", "path": "."}], source),
                        "best_cost": policy_cost(grants, source),
                        "stderr_tail": tuned["stderr"][-1000:] if tuned["returncode"] != 0 else "",
                    })
                    # E canary arm runs the policy actually produced by the optimizer.
                    e_source = output / "canary-sources" / workflow["id"] / revision / "E"
                    create_canary_workspace(source, e_source)
                    e_result = execute(
                        binary, e_source, output / "canary-runs" / workflow["id"] / revision / "E",
                        canary_command(), None, "canary", policy_override=tuned_policies[workflow["id"]],
                    )
                    e_result.update({"workflow_id": workflow["id"], "revision": revision, "method": "E"})
                    attach_canary_evidence(e_result, tuned_policies[workflow["id"]])
                    canary_rows.append(e_result)
                    save_progress(f"{workflow['id']}/target/greedy-tune-and-E-canary")

    dev_wheel = next(item for item in plan["workflows"] if item["id"] == "W09-packaging-wheel-pilot")
    drift_shadow_rows = additional_drift_study(
        binary, dev_wheel, snapshots[(dev_wheel["id"], "target")], output
    )
    save_progress("controlled-source-drift")

    tuning_agent_children = sum(
        (row.get("optimizer_child_execution_counts") or {}).get("agent_processes", 0)
        for row in tuning_rows
    )
    tuning_verifier_children = sum(
        (row.get("optimizer_child_execution_counts") or {}).get("verifier_processes", 0)
        for row in tuning_rows
    )
    recorded_agent_children = (
        sum(bool((row.get("record") or {}).get("agent")) for row in task_rows)
        + sum(bool(row.get("agent_process_recorded")) for row in repeat_rows)
        + sum(bool((row.get("record") or {}).get("agent")) for row in canary_rows)
        + tuning_agent_children
        + sum(bool(row.get("shadow_agent_process_recorded")) for row in drift_shadow_rows)
    )
    recorded_verifier_children = (
        sum(bool((row.get("record") or {}).get("verifier")) for row in task_rows)
        + sum(bool(row.get("verifier_process_recorded")) for row in repeat_rows)
        + tuning_verifier_children
        + sum(bool(row.get("shadow_verifier_process_recorded")) for row in drift_shadow_rows)
    )
    sessions_without_record = (
        sum(row.get("record") is None for row in task_rows)
        + sum(not row.get("run_record_present", True) for row in repeat_rows)
        + sum(row.get("record") is None for row in canary_rows)
        + sum(not row.get("shadow_run_record_present", True) for row in drift_shadow_rows if row.get("research_only_old_explicit_policy_shadow_utility") != "NOT TESTED")
    )

    # Full run and host-side security evidence are saved after all controlled arms finish.
    result = {
        "schema_version": 1,
        "suite_id": protocol["suite_id"],
        "protocol_sha256": file_sha(PROTOCOL_PATH),
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": environment_record(),
        "held_out_workflow_count": len(held_out),
        "development_workflows_excluded": [item["id"] for item in dev_only],
        "task_runs": task_rows,
        "proposal_generation": proposal_timings,
        "exact_source_repeats": repeat_rows,
        "stale_profile_rejections": drift_rows,
        "controlled_source_drift": drift_shadow_rows,
        "postrun_greedy": tuning_rows,
        "independent_canaries": canary_rows,
        "summary_by_method": {
            method: summarize([row for row in task_rows if row["method"] == method])
            for method in ("A", "B", "C", "D")
        },
        "exact_repeat_summary": {
            "successful": sum(row["status"] == "PASS" for row in repeat_rows),
            "total": len(repeat_rows),
            "median_cli_wall_millis": statistics.median([row["cli_wall_millis"] for row in repeat_rows]) if repeat_rows else None,
            "false_denials": sum(row["status"] != "PASS" for row in repeat_rows),
        },
        "profile_contract_summary": {
            "source_revision_rejections": sum(row["rejected_before_task_execution"] for row in drift_rows),
            "source_revision_attempts": len(drift_rows),
            "controlled_source_or_command_rejections": sum(row["stale_profile_rejected_before_execution"] for row in drift_shadow_rows),
            "controlled_source_or_command_attempts": len(drift_shadow_rows),
            "research_only_policy_shadow_successes": sum(row.get("research_only_old_explicit_policy_shadow_utility") == "PASS" for row in drift_shadow_rows),
            "research_only_policy_shadow_total": sum(row.get("research_only_old_explicit_policy_shadow_utility") != "NOT TESTED" for row in drift_shadow_rows),
        },
        "execution_accounting": {
            "first_run_policy_comparison_sessions": len(task_rows),
            "exact_profile_repeat_sessions": len(repeat_rows),
            "independent_canary_sessions": len(canary_rows),
            "postrun_optimizer_replay_sessions": sum(row.get("total_replays") or 0 for row in tuning_rows),
            "research_only_shadow_task_sessions": sum(row.get("research_only_old_explicit_policy_shadow_utility") != "NOT TESTED" for row in drift_shadow_rows),
            "stale_policy_rejection_attempts_expected_before_agent": len(drift_rows) + len(drift_shadow_rows),
            "agent_process_executions_recorded": recorded_agent_children,
            "verifier_process_executions_recorded": recorded_verifier_children,
            "sessions_without_run_record": sessions_without_record,
            "optimizer_replay_child_counts_source": "trial classifications: invalid_policy means no task child; agent_failed/agent_timeout means verifier was not run; other persisted task trials ran agent and verifier",
            "note": "Counts distinguish attempted AutoCage sessions from child processes recorded by the runtime. An absent run record is counted separately and is never treated as a successful execution. Canary sessions have an agent-like bounded canary process and no verifier. Each sandboxed run also performs its readonly-mount probe. Stale profile checks stop before task execution.",
        },
        "canary_summary_by_method": {
            method: {
                "attempts": sum(len(row["independent_canary"]["paths"]) for row in canary_rows if row["method"] == method),
                "blocked": sum(row["independent_canary"]["blocked_count"] for row in canary_rows if row["method"] == method),
                "modified": sum(row["independent_canary"]["modified_count"] for row in canary_rows if row["method"] == method),
                "all_controls_executed_and_classified": bool([row for row in canary_rows if row["method"] == method]) and all(
                    row["independent_canary"]["status"] == "PASS"
                    and row["independent_canary"]["policy_expectation_met"]
                    and row["independent_canary"]["controller_source_unchanged"]
                    for row in canary_rows if row["method"] == method
                ),
            }
            for method in ("A", "B", "C", "D", "E")
        },
        "postrun_summary": {
            "tasks_tuned": len(tuning_rows),
            "tune_commands_completed": sum(row["status"] == "PASS" for row in tuning_rows),
            "validated_narrow_policies": sum(row["optimizer_status"] == "validated" and row["policy"] != row["authorized_ceiling"] for row in tuning_rows),
            "no_narrower_candidate": sum(row["optimizer_status"] == "no_narrower_candidate" for row in tuning_rows),
            "inconclusive_optimizations": sum(row["optimizer_status"] == "inconclusive" for row in tuning_rows),
            "failed_tuning_commands": sum(row["status"] != "PASS" for row in tuning_rows),
            "median_total_replays": statistics.median([row["total_replays"] for row in tuning_rows if row["total_replays"] is not None]) if tuning_rows else None,
            "total_optimizer_trial_run_elapsed_millis": sum(row["optimizer_trial_run_elapsed_millis"] or 0 for row in tuning_rows),
            "agent_process_executions_recorded": tuning_agent_children,
            "verifier_process_executions_recorded": tuning_verifier_children,
            "total_tuning_wall_millis": sum(row["cli_wall_millis"] for row in tuning_rows),
        },
        "security_evidence": {
            "agent_environment_clear_and_child_namespace": "per-run records; see task_runs records",
            "independent_workspace_write_canary": "all named operations were verified by the trusted controller inspecting the staged filesystem after execution",
            "host_canary": "the integration runner independently verifies the original workspace did not change; each run record records source_checkout_unchanged",
            "network": "M0/M1 integration regressions and per-run preflight; task commands have no external network needs",
        },
        "limitations": [
            "The eight-workflow sample is small and scripted; it measures repeatable command behavior, not model coding ability or agent prompt-injection behavior.",
            "Human profile-authoring and review seconds were not measured. Rule counts and CLI inputs are recorded as proxies only.",
            "The proposal rules recognize only explicit Python workflows and do not analyze arbitrary plugins, build backends, or user code.",
            "The existing weighted score counts present filesystem entries; recursive grants also permit future child creation, reported separately.",
        ],
    }
    write_json(output / "results.json", result)
    write_json(output / "progress.json", {
        "suite_id": protocol["suite_id"],
        "status": "COMPLETED",
        "task_runs_completed": len(task_rows),
        "repeat_runs_completed": len(repeat_rows),
        "canary_runs_completed": len(canary_rows),
        "drift_checks_completed": len(drift_rows),
        "tuning_workflows_completed": len(tuning_rows),
    })
    return result


def run_development_pilot(binary: Path, work_root: Path, output: Path) -> dict:
    """Exercise only declared development cases; this output is never held-out evidence."""
    plan = json.loads((HERE / "workflow-plan.json").read_text())
    manifest = json.loads((work_root / "prepared-manifest.json").read_text())
    snapshots = {
        (entry["workflow_id"], entry["revision"]): Path(entry["snapshot_path"])
        for entry in manifest["snapshots"]
    }
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    canary_rows = []
    for workflow in plan["workflows"]:
        if workflow["split"] != "development":
            continue
        command = workflow_command(workflow)
        verifier = verifier_command(workflow)
        for revision in ("parent", "target"):
            source = snapshots[(workflow["id"], revision)]
            proposal_path = output / "proposals" / workflow["id"] / f"{revision}.json"
            proposal_result = propose(binary, workflow, source, command, proposal_path)
            run = execute(
                binary, source, output / "runs" / workflow["id"] / revision,
                command, verifier, "D", proposal_path,
            )
            rows.append({
                "workflow_id": workflow["id"], "revision": revision,
                "status": run["status"], "returncode": run["returncode"],
                "proposal_generation_millis": proposal_result["elapsed_millis"],
                "suggested_policy": grants_json(run.get("record")),
                "agent_elapsed_millis": ((run.get("record") or {}).get("agent") or {}).get("elapsed_millis"),
                "verifier_elapsed_millis": ((run.get("record") or {}).get("verifier") or {}).get("elapsed_millis"),
                "stderr_tail": run["stderr_tail"],
            })
            write_json(output / "pilot.json", {
                "classification": "development-only; excluded from held-out metrics",
                "workflow_results": rows,
                "canary_results": canary_rows,
            })
        source = snapshots[(workflow["id"], "parent")]
        canary_rows.extend(prepare_canaries(workflow, "parent", source, output, binary))
        proposal = json.loads((output / "proposals" / workflow["id"] / "parent.json").read_text())
        suggested_grants = [
            ("dir" if grant["kind"] == "directory_tree" else "file", grant["path"])
            for grant in proposal["policy"]["write_grants"]
        ]
        canary_source = output / "canary-sources" / workflow["id"] / "parent" / "D"
        create_canary_workspace(source, canary_source)
        canary_result = execute(
            binary,
            canary_source,
            output / "canary-runs" / workflow["id"] / "parent" / "D",
            canary_command(),
            None,
            "canary",
            policy_override=suggested_grants,
        )
        canary_result.update({"workflow_id": workflow["id"], "revision": "parent", "method": "D"})
        attach_canary_evidence(canary_result, suggested_grants)
        canary_rows.append(canary_result)
    dev_wheel = next(item for item in plan["workflows"] if item["id"] == "W09-packaging-wheel-pilot")
    drift_rows = additional_drift_study(
        binary, dev_wheel, snapshots[(dev_wheel["id"], "target")], output
    )
    write_json(output / "pilot.json", {
        "classification": "development-only; excluded from held-out metrics",
        "workflow_results": rows,
        "canary_results": canary_rows,
        "controlled_drift": drift_rows,
    })
    return {"workflow_results": rows, "canary_results": canary_rows, "controlled_drift": drift_rows, "path": str(output / "pilot.json")}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--autocage", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--development-pilot", action="store_true")
    args = parser.parse_args()
    if args.development_pilot:
        result = run_development_pilot(args.autocage.resolve(), args.work_root.resolve(), args.output.resolve())
        print(json.dumps(result, indent=2, sort_keys=True))
        pilot_passed = (
            all(row["status"] == "PASS" for row in result["workflow_results"])
            and all(row["independent_canary"]["status"] == "PASS" and row["independent_canary"]["policy_expectation_met"] for row in result["canary_results"])
            and all(row["stale_profile_rejected_before_execution"] for row in result["controlled_drift"])
        )
        return 0 if pilot_passed else 1
    result = run_final(args.autocage.resolve(), args.work_root.resolve(), args.output.resolve())
    print(json.dumps({
        "suite_id": result["suite_id"],
        "task_runs": len(result["task_runs"]),
        "exact_source_repeats": len(result["exact_source_repeats"]),
        "canary_runs": len(result["independent_canaries"]),
        "postrun_tasks": len(result["postrun_greedy"]),
        "summary_by_method": result["summary_by_method"],
        "canary_summary_by_method": result["canary_summary_by_method"],
        "results_path": str(args.output.resolve() / "results.json"),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
