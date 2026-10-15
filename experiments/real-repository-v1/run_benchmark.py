#!/usr/bin/env python3
"""Run fixed-budget write-policy comparisons on pinned Python projects."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import shutil
import socket
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
WORK_ROOT = Path("/tmp/autocage-real-repository-v1")
TASKS = json.loads((HERE / "tasks.json").read_text())["tasks"]
BUDGET = 12
RANDOM_SEED = 0x4155544F43414745
DIRECTORY_WEIGHT = 10
HIGH_IMPACT = (".github/workflows/", "deploy/", "deployment/", "scripts/", "package.json", "pyproject.toml", "cargo.toml")
PYTHON_SITE = "/usr/local/lib/autocage-m3-site-v2"
PYTHON_PACKAGES = {
    "iniconfig": "2.3.1",
    "packaging": "26.3",
    "pluggy": "1.6.0",
    "Pygments": "2.21.0",
    "pytest": "9.1.1",
    "pytest-asyncio": "1.3.0",
    "pytest-mock": "3.15.1",
    "pytest-timeout": "2.4.0",
    "typing-extensions": "4.16.0",
}
APT_PACKAGES = {
    "bubblewrap": "0.9.0-1ubuntu0.3",
    "python3-hypothesis": "6.98.15-1",
    "python3-minimal": "3.12.3-0ubuntu2.1",
    "python3-pip": "24.0+dfsg-1ubuntu1.3",
    "python3-pretend": "1.0.9-2.1",
    "python3-sortedcontainers": "2.4.0-2",
    "python3-tomli-w": "1.0.0-2",
}
TASK_TIMEOUT_SECONDS = 120
STARTUP_CONTROL_RUNS = 5


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        rel = path.relative_to(root).as_posix().encode()
        stat = path.lstat()
        digest.update(len(rel).to_bytes(4, "big"))
        digest.update(rel)
        digest.update((stat.st_mode & 0o7777).to_bytes(4, "big"))
        if path.is_symlink():
            digest.update(os.readlink(path).encode())
        elif path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()


def content_tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        rel = path.relative_to(root).as_posix().encode()
        digest.update(len(rel).to_bytes(4, "big"))
        digest.update(rel)
        if path.is_symlink():
            digest.update(b"L")
            digest.update(os.readlink(path).encode())
        elif path.is_dir():
            digest.update(b"D")
        elif path.is_file():
            digest.update(b"F")
            digest.update(path.read_bytes())
    return digest.hexdigest()


def safe_relative(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or not path.parts or any(part in (".", "..") for part in path.parts):
        raise ValueError(f"unsafe fixture path: {value!r}")
    return path


def fixture_for(task: dict) -> tuple[Path, Path, dict]:
    directory = HERE / "fixtures" / task["id"]
    metadata = json.loads((directory / "fixture.json").read_text())
    patch = directory / "task.patch"
    if sha(patch.read_bytes()) != metadata["patch_sha256"]:
        raise ValueError(f"task patch hash mismatch: {task['id']}")
    workspace = WORK_ROOT / "workspaces" / task["id"]
    if tree_digest(workspace) != metadata["input_tree_sha256"]:
        raise ValueError(f"source snapshot changed after preparation: {task['id']}")
    return directory, workspace, metadata


class LoopbackCanary:
    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.connections = 0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()
        with socket.create_connection(("127.0.0.1", self.port), timeout=1):
            pass
        deadline = time.monotonic() + 2
        while self.connections < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        if self.connections != 1:
            raise RuntimeError("positive control could not reach synthetic loopback listener")

    def _accept(self) -> None:
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
                self.connections += 1
                connection.close()
            except TimeoutError:
                continue
            except OSError:
                return

    def check(self) -> dict:
        # Let a delayed, unexpected connection become observable before sampling.
        time.sleep(0.05)
        return {"status": "PASS" if self.connections == 1 else "FAIL", "host_positive_controls": 1, "sandbox_connections": self.connections - 1}

    def close(self) -> None:
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=1)


AGENT_SCRIPT = r'''import base64, json, os, socket, sys, tempfile
from pathlib import Path
actions = json.loads(base64.b64decode("".join(sys.argv[1:-4])))
source_path = Path(sys.argv[-4])
host_canary = Path(sys.argv[-3])
port = int(sys.argv[-2])
operations = json.loads(sys.argv[-1])
try:
    host_canary.write_text("AUTOCAGE-CANARY-COMPROMISED\\n")
except OSError:
    pass
else:
    raise SystemExit(97)
try:
    source_path.write_text("AUTOCAGE-SOURCE-COMPROMISED\\n")
except OSError:
    pass
else:
    raise SystemExit(98)
probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
probe.settimeout(0.5)
try:
    probe.connect(("127.0.0.1", port))
except OSError:
    pass
else:
    raise SystemExit(96)
finally:
    probe.close()
for action in actions:
    path = Path("/workspace") / action["path"]
    operation = action["operation"]
    if operation == "write_existing":
        if not path.is_file() or path.is_symlink(): raise SystemExit(31)
        with path.open("wb") as output: output.write(base64.b64decode(action["content_base64"]))
        os.chmod(path, action["mode"])
    elif operation == "create":
        if path.exists() or path.is_symlink(): raise SystemExit(32)
        path.parent.mkdir(parents=False, exist_ok=True)
        with path.open("xb") as output: output.write(base64.b64decode(action["content_base64"]))
        os.chmod(path, action["mode"])
    elif operation == "delete":
        path.unlink()
    else:
        raise SystemExit("unknown pinned file action")
for operation in operations:
    kind = operation["kind"]
    directory = Path("/workspace") / operation.get("directory", str(Path(operation.get("path", ".")).parent))
    if kind == "transient-create-delete":
        path = directory / ".autocage-m3-transient"
        path.write_text("transient\\n")
        path.unlink()
    elif kind == "transient-create-rename-delete":
        first = directory / ".autocage-m3-staging"
        second = directory / ".autocage-m3-renamed"
        first.write_text("staging\\n")
        first.rename(second)
        second.unlink()
    elif kind == "atomic-replace":
        path = Path("/workspace") / operation["path"]
        contents = path.read_bytes()
        fd, temporary = tempfile.mkstemp(prefix=".autocage-save-", dir=path.parent)
        with os.fdopen(fd, "wb") as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    else:
        raise SystemExit("unknown fixture operation")
'''


def verifier_script(task: dict, metadata: dict, workspace: Path) -> str:
    root = workspace / safe_relative(task["verifier_root"])
    expected = content_tree_digest(root)
    tests = json.dumps(task["verifier_tests"])
    cache_mode = task["pytest_cache"]
    if cache_mode == "private-tmp":
        cache_args = '["-o", "cache_dir=/tmp/autocage-pytest-cache"]'
    elif cache_mode == "workspace":
        cache_args = "[]"
    else:
        raise ValueError(f"unknown pytest cache mode: {cache_mode}")
    config_overrides = task.get("pytest_config_overrides", [])
    override_args = json.dumps([argument for override in config_overrides for argument in ("-o", override)])
    plugins = json.dumps([argument for plugin in task.get("pytest_plugins", []) for argument in ("-p", plugin)])
    selection = json.dumps(["-k", task["pytest_k_filter"]]) if task.get("pytest_k_filter") else "[]"
    expected_packages = json.dumps(PYTHON_PACKAGES, sort_keys=True)
    verifier_path_prefix = task.get("verifier_path_prefix")
    path_setup = (
        f'os.environ["PATH"] = "/workspace/{safe_relative(verifier_path_prefix).as_posix()}:" + os.environ.get("PATH", "/usr/bin:/bin")'
        if verifier_path_prefix
        else ""
    )
    return f'''import hashlib, os, pathlib, sys
sys.path.insert(0, {PYTHON_SITE!r})
project_root = "/workspace/src" if pathlib.Path("/workspace/src").is_dir() else "/workspace"
sys.path.insert(0, project_root)
os.environ["PYTHONPATH"] = project_root
{path_setup}
import importlib.metadata
installed_packages = {{
    distribution.metadata["Name"].lower().replace("_", "-"): distribution.version
    for distribution in importlib.metadata.distributions(path=[{PYTHON_SITE!r}])
    if distribution.metadata.get("Name")
}}
for name, expected_version in {expected_packages}.items():
    if installed_packages.get(name.lower().replace("_", "-")) != expected_version:
        raise SystemExit(95)
import pytest
os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
root = pathlib.Path("/workspace") / {task["verifier_root"]!r}
digest = hashlib.sha256()
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    rel = path.relative_to(root).as_posix().encode()
    digest.update(len(rel).to_bytes(4, "big")); digest.update(rel)
    if path.is_symlink(): digest.update(b"L"); digest.update(os.readlink(path).encode())
    elif path.is_dir(): digest.update(b"D")
    elif path.is_file(): digest.update(b"F"); digest.update(path.read_bytes())
if digest.hexdigest() != {expected!r}:
    raise SystemExit(95)
arguments = ["-q"] + {plugins} + {override_args} + {tests} + {cache_args} + {selection}
class OutcomeGuard:
    def __init__(self): self.skipped = set()
    def pytest_runtest_logreport(self, report):
        if report.skipped: self.skipped.add(report.nodeid)
guard = OutcomeGuard()
result = pytest.main(arguments, plugins=[guard])
expected_skips = sorted({json.dumps(task.get("pytest_expected_skips", []))})
if sorted(guard.skipped) != expected_skips: raise SystemExit(97)
raise SystemExit(result)
'''


def command_specs(task: dict, metadata: dict, workspace: Path, canary: Path, port: int) -> tuple[list[str], list[str]]:
    actions_bytes = (HERE / "fixtures" / task["id"] / "agent-actions.json").read_bytes()
    if sha(actions_bytes) != metadata["agent_actions_sha256"]:
        raise ValueError(f"agent action hash mismatch: {task['id']}")
    actions_b64 = base64.b64encode(actions_bytes).decode("ascii")
    action_chunks = [actions_b64[index:index + 60_000] for index in range(0, len(actions_b64), 60_000)]
    operations = json.dumps(task["operations"], separators=(",", ":"))
    changed = [path for path in task["patch_paths"] if path.startswith("src/") and (workspace / path).is_file()]
    source_probe = str(workspace / (changed[0] if changed else "README"))
    agent = ["/usr/bin/python3", "-c", AGENT_SCRIPT, *action_chunks, source_probe, str(canary), str(port), operations]
    verifier = ["/usr/bin/python3", "-c", verifier_script(task, metadata, workspace)]
    return agent, verifier


def cost(grants: list[dict], root: Path) -> dict:
    files: list[str] = []
    directories: list[str] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            continue
        if path.is_dir():
            directories.append(relative)
        elif path.is_file():
            files.append(relative)
    writable_files: set[str] = set()
    writable_directories: set[str] = set()
    for grant in grants:
        target = grant["path"]
        kind = grant["kind"]
        for path in files:
            if (kind == "file_contents" and path == target) or (kind == "directory_tree" and (target == "." or path.startswith(target.rstrip("/") + "/"))):
                writable_files.add(path)
        if kind == "directory_tree":
            for path in directories:
                if target == "." or path == target or path.startswith(target.rstrip("/") + "/"):
                    writable_directories.add(path)
    file_weight = sum(10 if any(path.lower() == prefix or path.lower().startswith(prefix) for prefix in HIGH_IMPACT) else 1 for path in writable_files)
    root_grant = any(grant["kind"] == "directory_tree" and grant["path"] == "." for grant in grants)
    directory_count = len(writable_directories) + int(root_grant)
    return {
        "schema": "weighted-write-surface-v1",
        "weighted_writable_exposure": file_weight + directory_count * DIRECTORY_WEIGHT,
        "writable_regular_files": len(writable_files),
        "writable_directories": directory_count,
        "recursive_directory_grants": sum(grant["kind"] == "directory_tree" for grant in grants),
        "permission_rules": len(grants),
        "file_weight_total": file_weight,
        "directory_entry_weight_total": directory_count * DIRECTORY_WEIGHT,
    }


def grants_from_record(policy: dict) -> list[dict]:
    return [{"kind": grant["kind"], "path": Path(grant["path"]).as_posix()} for grant in policy["write_grants"]]


def normalize(grants: list[dict]) -> list[dict]:
    unique = {(item["kind"], item["path"]): item for item in grants}
    values = [unique[key] for key in sorted(unique)]
    result = []
    for item in values:
        path = item["path"]
        subsumed = any(
            other["kind"] == "directory_tree"
            and other != item
            and (other["path"] == "." or path.startswith(other["path"].rstrip("/") + "/"))
            for other in values
        )
        if not subsumed:
            result.append(item)
    return result


def changed_grants(before: Path, after: Path) -> list[dict]:
    def entries(root: Path) -> dict[str, tuple[str, str]]:
        output = {}
        for path in root.rglob("*"):
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                output[rel] = ("symlink", os.readlink(path))
            elif path.is_dir():
                output[rel] = ("directory", "")
            elif path.is_file():
                output[rel] = ("file", sha(path.read_bytes()))
        return output
    old, new = entries(before), entries(after)
    grants = []
    for path in sorted(old.keys() | new.keys()):
        if old.get(path) == new.get(path):
            continue
        if old.get(path, (None,))[0] == new.get(path, (None,))[0] == "file":
            grants.append({"kind": "file_contents", "path": path})
        else:
            parent = Path(path).parent
            name = parent.as_posix() if parent.as_posix() else "."
            while name != "." and not (before / name).is_dir():
                parent = parent.parent
                name = parent.as_posix() if parent.as_posix() else "."
            grants.append({"kind": "directory_tree", "path": name})
    return normalize(grants)


def static_policy(workspace: Path) -> list[dict]:
    # Frozen repo-agnostic code/test/doc policy, based only on conventional
    # repository structure and not on any task patch or candidate result.
    dirs = ("src", "lib", "docs", "testing", "tests", "changelog", "changelog.d")
    files = ("pyproject.toml", "setup.py", "setup.cfg", "tox.ini", "MANIFEST.in", "CHANGES.md", "CHANGELOG.md", "README.md", "README.rst")
    grants = [{"kind": "directory_tree", "path": name} for name in dirs if (workspace / name).is_dir()]
    grants += [{"kind": "file_contents", "path": name} for name in files if (workspace / name).is_file()]
    return normalize(grants)


def read_record(run_dir: Path) -> dict | None:
    path = run_dir / "run.json"
    if not path.exists():
        return None
    return json.loads(path.read_text())


def run_cli(binary: Path, argv: list[str], timeout: int) -> dict:
    started = time.monotonic()
    try:
        output = subprocess.run([str(binary), *argv], capture_output=True, text=True, timeout=timeout)
        return {"return_code": output.returncode, "elapsed_seconds": time.monotonic() - started, "stdout": output.stdout, "stderr": output.stderr}
    except subprocess.TimeoutExpired as error:
        return {"return_code": 124, "elapsed_seconds": time.monotonic() - started, "stdout": "", "stderr": str(error)}


def add_run_policy_args(argv: list[str], grants: list[dict]) -> None:
    if not grants:
        argv.append("--read-only")
    for grant in grants:
        option = "--ceiling-dir" if grant["kind"] == "directory_tree" else "--ceiling-file"
        argv.extend([option, grant["path"]])


def add_agent_args(argv: list[str], agent: list[str]) -> None:
    argv.extend(["--", *agent])


def make_run(binary: Path, workspace: Path, run_dir: Path, task: dict, agent: list[str], verifier: list[str], grants: list[dict], timeout: int, record_contract: bool) -> dict:
    argv = ["run", "--workspace", str(workspace), "--run-dir", str(run_dir), "--timeout-seconds", str(timeout)]
    if record_contract:
        argv.append("--record-contract")
    argv.extend(["--verify-command", verifier[0]])
    for arg in verifier[1:]:
        argv.extend(["--verify-arg", arg])
    argv.extend(["--verify-readonly", task["verifier_root"]])
    add_run_policy_args(argv, grants)
    add_agent_args(argv, agent)
    outcome = run_cli(binary, argv, timeout * 2 + 60)
    outcome["record"] = read_record(run_dir)
    return outcome


def tune(binary: Path, run_dir: Path, workspace: Path, agent: list[str], verifier: list[str], strategy: str, timeout: int) -> dict:
    argv = ["tune", str(run_dir), "--workspace", str(workspace), "--agent-command", agent[0]]
    for arg in agent[1:]:
        argv.extend(["--agent-arg", arg])
    argv.extend(["--verify-command", verifier[0]])
    for arg in verifier[1:]:
        argv.extend(["--verify-arg", arg])
    argv.extend(["--max-replays", str(BUDGET), "--strategy", strategy])
    outcome = run_cli(binary, argv, BUDGET * (timeout * 2 + 45) + 120)
    result_path = run_dir / "optimizer.json"
    outcome["optimization"] = json.loads(result_path.read_text()) if result_path.exists() else None
    outcome["record"] = read_record(run_dir)
    return outcome


def security_outcome(record: dict | None, canary: LoopbackCanary, host_canary: Path, source: Path, original_source_hash: str, verifier_root: Path, verifier_hash: str) -> dict:
    if record is None:
        return {"status": "NOT_TESTED", "reason": "run record missing"}
    agent_exit = record.get("agent", {}).get("exit_code")
    verifier = record.get("verifier")
    check_status = {check["name"]: check["status"] for check in record.get("security_checks", [])}
    host_control = canary.check()
    host_file_ok = host_canary.read_text() == "AUTOCAGE-M3-HOST-CANARY-v1\n"
    source_ok = tree_digest(source) == original_source_hash
    verifier_ok = content_tree_digest(verifier_root) == verifier_hash
    escape_exit = agent_exit in (96, 97, 98)
    required_runner = check_status.get("readonly_mount_write_denial") == "passed"
    if not host_control["status"] == "PASS" or not host_file_ok or not source_ok or not verifier_ok or escape_exit:
        status = "FAIL"
    elif not required_runner or verifier is None:
        status = "NOT_TESTED"
    else:
        status = "PASS"
    return {
        "status": status,
        "network_positive_control": "PASS",
        "network_sandbox_connections": host_control["sandbox_connections"],
        "host_canary_controller": "PASS" if host_file_ok else "FAIL",
        "original_source_controller": "PASS" if source_ok else "FAIL",
        "verifier_fixture_controller": "PASS" if verifier_ok else "FAIL",
        "readonly_mount_runtime_probe": check_status.get("readonly_mount_write_denial", "NOT_TESTED").upper(),
        "agent_canary_exit": agent_exit,
        "agent_escape_probe": "FAIL" if escape_exit else ("PASS" if agent_exit is not None else "NOT_TESTED"),
        "verifier_executed": verifier is not None,
    }


def record_metrics(record: dict | None) -> dict:
    if not record:
        return {"agent_executions": 1, "verifier_executions": 0, "agent_seconds": None, "verifier_seconds": None, "timeouts": 0, "outcome": "missing_record"}
    agent = record.get("agent") or {}
    verifier = record.get("verifier")
    return {
        "agent_executions": 1,
        "verifier_executions": int(verifier is not None),
        "agent_seconds": agent.get("elapsed_millis", 0) / 1000,
        "verifier_seconds": (verifier or {}).get("elapsed_millis", 0) / 1000 if verifier else 0.0,
        "timeouts": int(bool(agent.get("timed_out"))) + int(bool(verifier and verifier.get("timed_out"))),
        "outcome": record.get("outcome", "unknown"),
    }


def summarize_method(name: str, cli: dict, record: dict | None, baseline_cost: dict, manifest_root: Path, canary: LoopbackCanary, host_canary: Path, workspace: Path, source_hash: str, verifier_root: Path, verifier_hash: str, *, optimization: dict | None = None, replay_records: list[dict | None] | None = None, replay_security: list[dict] | None = None, shared_setup: dict | None = None) -> dict:
    is_optimizer = name in ("D", "E", "F")
    utility = (optimization or {}).get("status") == "validated" if is_optimizer else bool(record and record.get("outcome") == "verified")
    policy = (optimization or {}).get("best_policy")
    if policy is None and record:
        policy = record.get("policy", {})
    grants = grants_from_record(policy) if policy else []
    method_cost = cost(grants, manifest_root)
    status = (optimization or {}).get("status", "not_run" if is_optimizer else ("verified" if utility else (record or {}).get("outcome", "missing_record")))
    validated = status == "validated" if is_optimizer else utility
    full_reduction = reduction(baseline_cost, method_cost) if utility and validated else 0.0
    security = security_outcome(record, canary, host_canary, workspace, source_hash, verifier_root, verifier_hash) if not is_optimizer else {"status": "NOT_TESTED", "reason": "optimizer trial evidence evaluated separately"}
    execution = record_metrics(record) if not is_optimizer else {"agent_executions": 0, "verifier_executions": 0, "agent_seconds": 0.0, "verifier_seconds": 0.0, "timeouts": 0, "outcome": "optimizer_trials"}
    trials = (optimization or {}).get("trials", [])
    trial_records = replay_records or []
    extra_agent = len(trial_records) if is_optimizer else 0
    extra_verifier = sum(1 for value in trial_records if value and value.get("verifier") is not None)
    elapsed = cli.get("elapsed_seconds", 0.0) + (shared_setup or {}).get("elapsed_seconds", 0.0)
    agent_seconds = execution["agent_seconds"]
    verifier_seconds = execution["verifier_seconds"]
    if is_optimizer:
        agent_seconds = sum((value or {}).get("agent", {}).get("elapsed_millis", 0) for value in trial_records) / 1000 + (shared_setup or {}).get("agent_seconds", 0.0)
        verifier_seconds = sum(((value or {}).get("verifier") or {}).get("elapsed_millis", 0) for value in trial_records) / 1000 + (shared_setup or {}).get("verifier_seconds", 0.0)
    all_agent = extra_agent + (shared_setup or {}).get("agent_executions", 0) + execution["agent_executions"]
    all_verifier = extra_verifier + (shared_setup or {}).get("verifier_executions", 0) + execution["verifier_executions"]
    return {
        "strategy": name,
        "status": status,
        "utility_pass": utility,
        "promotable": validated and utility and security["status"] == "PASS",
        "security": security,
        "policy": grants,
        "cost": method_cost,
        "successful_task_reduction_percent": reduction(baseline_cost, method_cost) if utility else None,
        "full_corpus_reduction_percent": full_reduction,
        "agent_executions_including_shared_setup": all_agent,
        "verifier_executions_including_shared_setup": all_verifier,
        "search_replays": (optimization or {}).get("search_replays", 0),
        "fresh_validation_replays": (optimization or {}).get("validation_replays", 0),
        "optimizer_total_replays": (optimization or {}).get("total_replays", 0),
        "rejected_trials": (optimization or {}).get("rejected_trials", 0),
        "optimizer_trials": trials,
        "timeouts": execution["timeouts"] + sum(record_metrics(value)["timeouts"] for value in trial_records),
        "trial_failures": sum(not trial.get("passed", False) for trial in trials),
        "wall_seconds_attributed": elapsed,
        "task_process_seconds": agent_seconds,
        "verifier_process_seconds": verifier_seconds,
        "controller_overhead_seconds_estimate": max(0.0, elapsed - (agent_seconds or 0) - (verifier_seconds or 0)),
        "stderr_sha256": sha(cli.get("stderr", "").encode()),
        "cli_return_code": cli.get("return_code"),
        "outcome": execution["outcome"],
        "agent_exit_code": (record or {}).get("agent", {}).get("exit_code") if not is_optimizer else None,
        "verifier_exit_code": ((record or {}).get("verifier") or {}).get("exit_code") if not is_optimizer else None,
        "agent_timed_out": (record or {}).get("agent", {}).get("timed_out") if not is_optimizer else None,
        "verifier_timed_out": ((record or {}).get("verifier") or {}).get("timed_out") if not is_optimizer else None,
        "replay_security_passes": sum(value.get("status") == "PASS" for value in (replay_security or [])),
        "replay_security_not_tested": sum(value.get("status") == "NOT_TESTED" for value in (replay_security or [])),
    }


def reduction(before: dict, after: dict) -> float:
    value = before["weighted_writable_exposure"]
    return ((value - after["weighted_writable_exposure"]) / value * 100.0) if value else 0.0


def validate_protocol(binary: Path) -> tuple[dict, str]:
    protocol_path = HERE / "protocol.json"
    protocol_bytes = protocol_path.read_bytes()
    protocol = json.loads(protocol_bytes)
    if protocol.get("status") != "frozen-before-final-comparison":
        raise ValueError("real-repository protocol is not frozen")
    inputs = {
        "tasks.json": "tasks_sha256",
        "prepare.py": "prepare_sha256",
        "run_benchmark.py": "runner_sha256",
        "setup/python-requirements.lock": "python_lock_sha256",
        "setup/install-python-runtime.sh": "runtime_setup_sha256",
        "fixtures/prepared-manifest.json": "prepared_manifest_sha256",
    }
    for relative, key in inputs.items():
        if sha((HERE / relative).read_bytes()) != protocol.get(key):
            raise ValueError(f"frozen protocol input changed: {relative}")
    parameters = protocol.get("parameters", {})
    expected_parameters = {
        "strategy_budget_including_validations": BUDGET,
        "random_seed": hex(RANDOM_SEED),
        "validation_replays": 3,
        "task_timeout_seconds": TASK_TIMEOUT_SECONDS,
        "startup_control_runs": STARTUP_CONTROL_RUNS,
        "directory_weight": DIRECTORY_WEIGHT,
        "high_impact_prefixes": list(HIGH_IMPACT),
        "cost_schema": "weighted-write-surface-v1",
    }
    if parameters != expected_parameters:
        raise ValueError("benchmark parameters differ from the frozen protocol")
    if protocol.get("python_packages") != PYTHON_PACKAGES:
        raise ValueError("Python runtime packages differ from the frozen protocol")
    if protocol.get("apt_packages") != APT_PACKAGES:
        raise ValueError("Ubuntu runtime packages differ from the frozen protocol")
    expected_tasks = protocol.get("tasks", [])
    actual_tasks = [{"id": task["id"], "split": task["split"], "repository": task["repository"]} for task in TASKS]
    if expected_tasks != actual_tasks:
        raise ValueError("task IDs or development/held-out assignments differ from the frozen protocol")
    if sha(binary.read_bytes()) != protocol.get("autocage_binary_sha256"):
        raise ValueError("AutoCage release binary differs from the frozen protocol")
    prepared = json.loads((HERE / "fixtures/prepared-manifest.json").read_text())
    if prepared.get("tasks_sha256") != protocol.get("tasks_sha256"):
        raise ValueError("prepared fixtures do not match the frozen task manifest")
    import importlib.metadata

    discovered = {
        distribution.metadata["Name"].lower().replace("_", "-"): distribution.version
        for distribution in importlib.metadata.distributions(path=[PYTHON_SITE])
        if distribution.metadata.get("Name")
    }
    actual_packages = {name: discovered.get(name.lower().replace("_", "-")) for name in PYTHON_PACKAGES}
    if actual_packages != PYTHON_PACKAGES:
        raise ValueError(f"installed Python benchmark runtime differs from the frozen protocol: {actual_packages}")
    actual_apt_packages = {}
    for package in APT_PACKAGES:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", package],
            capture_output=True,
            text=True,
            check=True,
        )
        actual_apt_packages[package] = result.stdout.strip()
    if actual_apt_packages != APT_PACKAGES:
        raise ValueError(f"installed Ubuntu benchmark packages differ from the frozen protocol: {actual_apt_packages}")
    return protocol, sha(protocol_bytes)


def measure_startup(binary: Path) -> dict:
    elapsed = []
    for _ in range(STARTUP_CONTROL_RUNS):
        result = run_cli(binary, ["check"], 60)
        if result["return_code"] != 0:
            raise RuntimeError(f"autocage check startup control failed: {result['stderr']}")
        elapsed.append(result["elapsed_seconds"])
    return {
        "runs": STARTUP_CONTROL_RUNS,
        "samples_seconds": elapsed,
        "median_seconds": statistics.median(elapsed),
        "mean_seconds": statistics.mean(elapsed),
        "meaning": "AutoCage process launch plus fail-closed host preflight; excluded from task replay wall time",
    }


def environment_info() -> dict:
    os_release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            os_release[key] = value.strip('"')
    bwrap = subprocess.run(["/usr/bin/bwrap", "--version"], capture_output=True, text=True, check=True)
    return {
        "distribution": os_release.get("PRETTY_NAME"),
        "architecture": platform.machine(),
        "kernel": platform.release(),
        "python": platform.python_version(),
        "bubblewrap": bwrap.stdout.strip(),
    }


def optimizer_replay_security(run_dir: Path, canary: LoopbackCanary, host_canary: Path, workspace: Path, source_hash: str, verifier_root: Path, verifier_hash: str) -> list[dict]:
    output = []
    replay_root = run_dir / "tuning" / "replays"
    if not replay_root.exists():
        return output
    for path in sorted(replay_root.glob("trial-*")):
        record = read_record(path)
        output.append({
            "trial": path.name,
            "run_outcome": (record or {}).get("outcome", "missing_record"),
            "agent_exit_code": (record or {}).get("agent", {}).get("exit_code"),
            "verifier_exit_code": ((record or {}).get("verifier") or {}).get("exit_code"),
            **security_outcome(record, canary, host_canary, workspace, source_hash, verifier_root, verifier_hash),
        })
    return output


def optimizer_replay_records(run_dir: Path) -> list[dict | None]:
    replay_root = run_dir / "tuning" / "replays"
    if not replay_root.exists():
        return []
    return [read_record(path) for path in sorted(replay_root.glob("trial-*"))]


def blocked_method(name: str, grants: list[dict] | None, cost_value: dict | None, *, wall: float = 0.0, rc: int | None = None, error_hash: str = "") -> dict:
    return {
        "strategy": name,
        "status": "BLOCKED",
        "utility_pass": False,
        "promotable": False,
        "security": {"status": "NOT_TESTED", "reason": "sandboxed task process was not launched"},
        "policy": grants,
        "cost": cost_value,
        "successful_task_reduction_percent": None,
        "full_corpus_reduction_percent": 0.0,
        "agent_executions_including_shared_setup": 0,
        "verifier_executions_including_shared_setup": 0,
        "search_replays": 0,
        "fresh_validation_replays": 0,
        "optimizer_total_replays": 0,
        "rejected_trials": 0,
        "optimizer_trials": [],
        "timeouts": 0,
        "trial_failures": 0,
        "wall_seconds_attributed": wall,
        "task_process_seconds": 0.0,
        "verifier_process_seconds": 0.0,
        "controller_overhead_seconds_estimate": wall,
        "stderr_sha256": error_hash,
        "cli_return_code": rc,
        "outcome": "unsupported_staging_or_preflight",
        "agent_exit_code": None,
        "verifier_exit_code": None,
        "agent_timed_out": None,
        "verifier_timed_out": None,
        "replay_security_passes": 0,
        "replay_security_not_tested": 0,
    }


def task_run(binary: Path, task: dict, index: int) -> dict:
    fixture_dir, workspace, fixture = fixture_for(task)
    verifier_root = workspace / safe_relative(task["verifier_root"])
    verifier_hash = content_tree_digest(verifier_root)
    source_hash = tree_digest(workspace)
    if verifier_hash != fixture["verifier_content_sha256"]:
        raise ValueError(f"verifier fixture hash mismatch for {task['id']}")
    canary_dir = WORK_ROOT / "canaries"
    canary_dir.mkdir(parents=True, exist_ok=True)
    host_canary = canary_dir / f"{task['id']}.txt"
    host_canary.write_text("AUTOCAGE-M3-HOST-CANARY-v1\n")
    canary = LoopbackCanary()
    agent, verifier = command_specs(task, fixture, workspace, host_canary, canary.port)
    run_root = WORK_ROOT / "runs" / task["id"]
    if run_root.exists():
        shutil.rmtree(run_root)
    run_root.mkdir(parents=True)

    broad_dir = run_root / "A-broad"
    broad = make_run(binary, workspace, broad_dir, task, agent, verifier, [{"kind": "directory_tree", "path": "."}], TASK_TIMEOUT_SECONDS, True)
    broad_record = broad.get("record")
    if broad_record is None:
        broad_policy = [{"kind": "directory_tree", "path": "."}]
        source_cost = cost(broad_policy, workspace)
        static_grants = static_policy(workspace)
        oracle_grants = normalize(task["oracle_grants"])
        rc = broad.get("return_code")
        error_hash = sha(broad.get("stderr", "").encode())
        reason = "unsupported_staging_symlink" if "symlink" in broad.get("stderr", "").lower() else "no_run_record_before_agent_launch"
        controller_ok = (
            host_canary.read_text() == "AUTOCAGE-M3-HOST-CANARY-v1\n"
            and tree_digest(workspace) == source_hash
            and content_tree_digest(verifier_root) == verifier_hash
        )
        network = canary.check()
        canary.close()
        if not controller_ok or network["status"] != "PASS":
            raise RuntimeError(f"independent canary changed after blocked task {task['id']}")
        return {
            "task_id": task["id"],
            "split": task["split"],
            "execution_status": "BLOCKED" if reason == "unsupported_staging_symlink" else "FAIL",
            "blocker": reason,
            "repository": task["repository"],
            "license": task["license"],
            "parent_commit": task["parent"],
            "target_commit": task["target"],
            "patch_sha256": fixture["patch_sha256"],
            "input_tree_sha256": fixture["input_tree_sha256"],
            "source_tree_stats": fixture["source_tree_stats"],
            "verifier_tree_sha256": verifier_hash,
            "task_operations": task["operations"],
            "verifier_tests": task["verifier_tests"],
            "pytest_cache": task["pytest_cache"],
            "authorized_ceiling": broad_policy,
            "baseline_cost": source_cost,
            "baseline_A": blocked_method("A", broad_policy, source_cost, wall=broad.get("elapsed_seconds", 0), rc=rc, error_hash=error_hash),
            "baselines": {
                "A": blocked_method("A", broad_policy, source_cost, wall=broad.get("elapsed_seconds", 0), rc=rc, error_hash=error_hash),
                "B": blocked_method("B", static_grants, cost(static_grants, workspace)),
                "C": blocked_method("C", None, None),
                "M": blocked_method("M", oracle_grants, cost(oracle_grants, workspace)),
            },
            "optimizers": {label: blocked_method(label, None, None) for label in ("D", "E", "F")},
            "naive_changed_policy": None,
            "static_policy": static_grants,
            "manual_policy": oracle_grants,
            "host_loopback_positive_control": "PASS",
            "independent_controller_checks": {"host_canary_unchanged": "PASS", "source_unchanged": "PASS", "verifier_fixture_unchanged": "PASS"},
        }
    baseline_grants = grants_from_record(broad_record["policy"])
    baseline_cost = cost(baseline_grants, broad_dir / "baseline")
    baseline_shared = record_metrics(broad_record)
    baseline_shared["elapsed_seconds"] = broad.get("elapsed_seconds", 0.0)
    broad_summary = summarize_method("A", broad, broad_record, baseline_cost, broad_dir / "baseline", canary, host_canary, workspace, source_hash, verifier_root, verifier_hash)

    static_grants = static_policy(workspace)
    static = make_run(binary, workspace, run_root / "B-static", task, agent, verifier, static_grants, TASK_TIMEOUT_SECONDS, False)
    static_record = static.get("record")
    static_summary = summarize_method("B", static, static_record, baseline_cost, broad_dir / "baseline", canary, host_canary, workspace, source_hash, verifier_root, verifier_hash)

    inferred = changed_grants(broad_dir / "baseline", broad_dir / "stage")
    changed = make_run(binary, workspace, run_root / "C-changed", task, agent, verifier, inferred, TASK_TIMEOUT_SECONDS, False)
    changed_record = changed.get("record")
    changed_summary = summarize_method("C", changed, changed_record, baseline_cost, broad_dir / "baseline", canary, host_canary, workspace, source_hash, verifier_root, verifier_hash, shared_setup=baseline_shared)

    oracle_grants = normalize(task["oracle_grants"])
    oracle = make_run(binary, workspace, run_root / "M-manual-oracle", task, agent, verifier, oracle_grants, TASK_TIMEOUT_SECONDS, False)
    oracle_record = oracle.get("record")
    oracle_summary = summarize_method("M", oracle, oracle_record, baseline_cost, broad_dir / "baseline", canary, host_canary, workspace, source_hash, verifier_root, verifier_hash)

    optimizers = {}
    for label, strategy in (("D", "greedy"), ("E", "random"), ("F", "hierarchical")):
        tuning_dir = run_root / f"{label}-{strategy}"
        shutil.copytree(broad_dir, tuning_dir, symlinks=True, copy_function=shutil.copy2)
        tuned = tune(binary, tuning_dir, workspace, agent, verifier, strategy, TASK_TIMEOUT_SECONDS)
        optimization = tuned.get("optimization")
        replay_records = optimizer_replay_records(tuning_dir)
        replay_security = optimizer_replay_security(tuning_dir, canary, host_canary, workspace, source_hash, verifier_root, verifier_hash)
        summary = summarize_method(label, tuned, broad_record, baseline_cost, broad_dir / "baseline", canary, host_canary, workspace, source_hash, verifier_root, verifier_hash, optimization=optimization, replay_records=replay_records, replay_security=replay_security, shared_setup=baseline_shared)
        summary["replay_security"] = replay_security
        validation_count = (optimization or {}).get("validation_replays", 0)
        validation_evidence = replay_security[-validation_count:] if validation_count else []
        if validation_count == 3 and len(validation_evidence) == 3 and all(item["status"] == "PASS" for item in validation_evidence):
            summary["security"] = {"status": "PASS", "fresh_validation_canaries": 3, "evidence": validation_evidence}
        elif any(item["status"] == "FAIL" for item in replay_security):
            summary["security"] = {"status": "FAIL", "evidence": replay_security}
        else:
            summary["security"] = {"status": "NOT_TESTED", "fresh_validation_canaries": len(validation_evidence), "evidence": validation_evidence}
        summary["promotable"] = bool(optimization and optimization.get("status") == "validated" and summary["utility_pass"] and summary["security"]["status"] == "PASS")
        optimizers[label] = summary

    final_network = canary.check()
    if final_network["status"] != "PASS" or host_canary.read_text() != "AUTOCAGE-M3-HOST-CANARY-v1\n" or tree_digest(workspace) != source_hash or content_tree_digest(verifier_root) != verifier_hash:
        raise RuntimeError(f"independent host-side canary changed during task {task['id']}")
    canary.close()
    return {
        "task_id": task["id"],
        "split": task["split"],
        "execution_status": "COMPLETED",
        "repository": task["repository"],
        "license": task["license"],
        "parent_commit": task["parent"],
        "target_commit": task["target"],
        "patch_sha256": fixture["patch_sha256"],
        "input_tree_sha256": fixture["input_tree_sha256"],
        "source_tree_stats": fixture["source_tree_stats"],
        "verifier_tree_sha256": verifier_hash,
        "task_operations": task["operations"],
        "verifier_tests": task["verifier_tests"],
        "pytest_cache": task["pytest_cache"],
        "authorized_ceiling": [{"kind": "directory_tree", "path": "."}],
        "baseline_cost": baseline_cost,
        "baseline_A": broad_summary,
        "baselines": {"A": broad_summary, "B": static_summary, "C": changed_summary, "M": oracle_summary},
        "optimizers": optimizers,
        "naive_changed_policy": inferred,
        "static_policy": static_grants,
        "manual_policy": oracle_grants,
        "host_loopback_positive_control": "PASS",
        "independent_controller_checks": {"host_canary_unchanged": "PASS", "source_unchanged": "PASS", "verifier_fixture_unchanged": "PASS"},
    }


def summarize_rows(results: list[dict], label: str) -> dict:
    rows = [item["baselines"][label] if label in item["baselines"] else item["optimizers"][label] for item in results]
    successful = [row for row in rows if row["utility_pass"]]
    conditional = [row["successful_task_reduction_percent"] for row in successful if row["successful_task_reduction_percent"] is not None]
    full = [row["full_corpus_reduction_percent"] for row in rows]
    return {
        "task_count": len(rows),
        "utility_passes": len(successful),
        "utility_failures_or_inconclusive": len(rows) - len(successful),
        "utility_rate": len(successful) / len(rows) if rows else 0.0,
        "conditional_median_reduction_percent": statistics.median(conditional) if conditional else None,
        "conditional_mean_reduction_percent": statistics.mean(conditional) if conditional else None,
        "full_corpus_mean_reduction_percent": statistics.mean(full) if full else 0.0,
        "full_corpus_median_reduction_percent": statistics.median(full) if full else 0.0,
        "full_corpus_success_and_reduction": sum(row["utility_pass"] and row["full_corpus_reduction_percent"] > 0 for row in rows),
        "total_agent_executions_attributed": sum(row["agent_executions_including_shared_setup"] for row in rows),
        "total_verifier_executions_attributed": sum(row["verifier_executions_including_shared_setup"] for row in rows),
        "total_search_replays": sum(row["search_replays"] for row in rows),
        "total_fresh_validation_replays": sum(row["fresh_validation_replays"] for row in rows),
        "total_optimizer_replays": sum(row["optimizer_total_replays"] for row in rows),
        "median_optimizer_replays": statistics.median(row["optimizer_total_replays"] for row in rows) if rows else 0.0,
        "total_rejected_trials": sum(row["rejected_trials"] for row in rows),
        "timeouts": sum(row["timeouts"] for row in rows),
        "wall_seconds_attributed": sum(row["wall_seconds_attributed"] for row in rows),
        "median_wall_seconds_per_task": statistics.median(row["wall_seconds_attributed"] for row in rows) if rows else 0.0,
        "mean_agent_seconds_per_task": statistics.mean(row["task_process_seconds"] or 0 for row in rows) if rows else 0.0,
        "mean_verifier_seconds_per_task": statistics.mean(row["verifier_process_seconds"] or 0 for row in rows) if rows else 0.0,
        "controller_overhead_seconds_attributed": sum(row["controller_overhead_seconds_estimate"] for row in rows),
        "security_failures": sum(row["security"]["status"] == "FAIL" for row in rows),
        "security_not_tested": sum(row["security"]["status"] == "NOT_TESTED" for row in rows),
    }


def aggregate(results: list[dict]) -> dict:
    labels = ("A", "B", "C", "D", "E", "F", "M")
    summary = {label: summarize_rows(results, label) for label in labels}
    split_summaries = {}
    for split in ("development", "held-out"):
        subset = [item for item in results if item["split"] == split]
        split_summaries[split] = {
            "task_count": len(subset),
            "repository_count": len({item["repository"] for item in subset}),
            "methods": {label: summarize_rows(subset, label) for label in labels},
        }
    physical_unique = sum(row["baselines"]["A"]["agent_executions_including_shared_setup"] for row in results)
    physical_unique += sum(row["baselines"]["B"]["agent_executions_including_shared_setup"] for row in results)
    physical_unique += sum(max(0, row["baselines"]["C"]["agent_executions_including_shared_setup"] - 1) for row in results)
    physical_unique += sum(row["baselines"]["M"]["agent_executions_including_shared_setup"] for row in results)
    physical_unique += sum(sum(row["optimizers"][label]["optimizer_total_replays"] for label in ("D", "E", "F")) for row in results)
    return {"methods": summary, "split_aggregates": split_summaries, "unique_physical_agent_executions": physical_unique}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--autocage", type=Path, default=Path("/tmp/autocage-m1-dev/target/release/autocage"))
    parser.add_argument("--output", type=Path, default=HERE / "results")
    parser.add_argument("--task", action="append", help="run only the listed task ID (exploratory unless all IDs are used)")
    parser.add_argument("--keep-runs", action="store_true")
    args = parser.parse_args()
    binary = args.autocage.resolve()
    if not binary.is_file():
        raise SystemExit(f"AutoCage binary not found: {binary}")
    protocol, protocol_sha256 = validate_protocol(binary)
    startup_control = measure_startup(binary)
    environment = environment_info()
    environment["autocage_binary_sha256"] = sha(binary.read_bytes())
    tasks = [task for task in TASKS if not args.task or task["id"] in args.task]
    if args.task and {task["id"] for task in tasks} != set(args.task):
        raise SystemExit("unknown task ID supplied")
    output_dir = args.output.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    run_dir = WORK_ROOT / "runs"
    run_dir.mkdir(parents=True, exist_ok=True)
    results = []
    try:
        for index, task in enumerate(tasks, 1):
            print(f"[{index}/{len(tasks)}] {task['id']} starting", flush=True)
            item = task_run(binary, task, index)
            results.append(item)
            target = output_dir / f"{task['id']}.json"
            target.write_text(json.dumps(item, indent=2, sort_keys=True) + "\n")
            print(f"[{index}/{len(tasks)}] {task['id']} A={item['baselines']['A']['utility_pass']} F={item['optimizers']['F']['status']}", flush=True)
        report = aggregate(results)
        report.update({
            "schema_version": 1,
            "suite_id": json.loads((HERE / "tasks.json").read_text())["suite_id"],
            "evaluation_status": "exploratory" if args.task else "frozen_final",
            "protocol_sha256": protocol_sha256,
            "startup_control": startup_control,
            "environment": environment,
            "python_runtime_packages": PYTHON_PACKAGES,
            "apt_runtime_packages": APT_PACKAGES,
            "tasks_manifest_sha256": sha((HERE / "tasks.json").read_bytes()),
            "optimizer_budget_per_strategy_per_task": BUDGET,
            "random_seed": hex(RANDOM_SEED),
            "cost_schema": "weighted-write-surface-v1",
            "comparison_note": "D/E/F share a byte-identical broad verified source-snapshot record per task; that one physical setup run is charged once in unique physical totals and charged once per optimizer in per-method amortized costs.",
            "results": [item["task_id"] for item in results],
        })
        (output_dir / "aggregate.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps(report, indent=2), flush=True)
    finally:
        if not args.keep_runs:
            shutil.rmtree(run_dir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
