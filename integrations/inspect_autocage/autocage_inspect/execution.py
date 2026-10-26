"""One complete AutoCage or Inspect-local execution for one Inspect sample."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from inspect_ai.util import sandbox

from .evidence import (
    classify_unauthorized_write,
    required_checks,
    sha256_bytes,
    sha256_file,
    trace_events,
    tree_digest,
    validate_autocage_record,
    verifier_execution_status,
)
from .diagnostics import DiagnosticFrameError, parse_diagnostic_frame, persist_diagnostic_frame


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
M4_ROOT = REPOSITORY_ROOT / "experiments" / "agent-containment-v1"
BASE_FIXTURE = M4_ROOT / "fixtures" / "base"
TRACE_SYSCALLS = "open,openat,openat2,connect"
SAFE_ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/tmp",
    "TMPDIR": "/tmp",
    "LANG": "C.UTF-8",
    "PYTHONDONTWRITEBYTECODE": "1",
}
VERIFIER_ARGS = ["-m", "unittest", "tests.test_mathops", "-v"]
def _digest_text(data: str) -> str:
    return sha256_bytes(data.encode("utf-8"))


def _overlay_bytes(case: dict[str, Any], variant: str, scenario_root: Path, fixture_root: Path) -> bytes | None:
    if variant == "clean":
        return None
    if variant != "adversarial":
        raise ValueError(f"unsupported fixture variant {variant!r}")
    overlay = (scenario_root / case["overlay"]).read_text(encoding="utf-8").rstrip("\n")
    destination = case["input_path"]
    if case["overlay_mode"] == "append":
        original = (fixture_root / destination).read_text(encoding="utf-8").rstrip("\n")
        value = f"{original}\n{overlay}\n"
    elif case["overlay_mode"] == "comment":
        original = (fixture_root / destination).read_text(encoding="utf-8")
        marker = "def compute(left: int, right: int) -> int:\n"
        if original.count(marker) != 1:
            raise ValueError("code-comment fixture no longer matches the frozen source shape")
        value = original.replace(marker, marker + f"    # {overlay}\n")
    elif case["overlay_mode"] == "replace":
        value = overlay + "\n"
    else:
        raise ValueError(f"unsupported overlay mode {case['overlay_mode']!r}")
    return value.encode("utf-8")


def _prepare_workspace(
    destination: Path,
    case: dict[str, Any],
    variant: str,
    agent_config: dict[str, Any],
    agent_helper_source: str | None,
    agent_helper_destination: str | None,
    fixture_root: Path,
    scenario_root: Path,
) -> str:
    if destination.exists():
        raise FileExistsError("sample workspace already exists")
    before = tree_digest(fixture_root)
    shutil.copytree(fixture_root, destination, symlinks=False)
    for source in fixture_root.rglob("*"):
        if source.is_symlink() or (not source.is_file() and not source.is_dir()):
            raise ValueError(f"fixture contains unsupported filesystem entry: {source.relative_to(fixture_root)}")
    overlay = _overlay_bytes(case, variant, scenario_root, fixture_root)
    if overlay is not None:
        target = destination / case["input_path"]
        target.write_bytes(overlay)
    if agent_helper_source is not None:
        if agent_helper_destination is None:
            raise ValueError("agent helper destination is missing")
        helper = destination / agent_helper_destination
        helper.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(agent_helper_source, helper)
    return before


def _new_sample_root(work_root: str | None, sample_id: str) -> Path:
    base = Path(work_root or os.environ.get("AUTOCAGE_INSPECT_WORK_ROOT", "/tmp/autocage-inspect-results"))
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    safe_id = "".join(char if char.isalnum() or char in "-_" else "_" for char in sample_id)[:80]
    return Path(tempfile.mkdtemp(prefix=f"{safe_id}-{uuid.uuid4().hex[:8]}-", dir=base))


def _trace_binary() -> str | None:
    return shutil.which("strace")


def _tool_report(path: Path, timeout: int) -> dict[str, Any]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            [str(path), "check"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=min(timeout, 30),
            env=SAFE_ENV,
            check=False,
        )
        return {
            "available": completed.returncode == 0,
            "exit_code": completed.returncode,
            "elapsed_millis": int((time.monotonic() - started) * 1000),
            "stdout_sha256": _digest_text(completed.stdout),
            "stderr_sha256": _digest_text(completed.stderr),
        }
    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "available": False,
            "exit_code": None,
            "elapsed_millis": int((time.monotonic() - started) * 1000),
            "error": type(error).__name__,
        }


def _read_canary(path: Path, expected: str | dict[str, str]) -> dict[str, Any]:
    try:
        data = path.read_bytes()
    except OSError as error:
        return {"status": "NOT_TESTED", "error": type(error).__name__}
    digest = sha256_bytes(data)
    if isinstance(expected, dict) and set(expected) == {"sha256"}:
        unchanged = expected["sha256"] == digest
    else:
        value = data.decode("utf-8", errors="replace")
        unchanged = value == expected
    return {
        "status": "UNCHANGED" if unchanged else "CHANGED",
        "sha256": digest,
    }


def _parse_agent_signal(stdout: str, marker: str) -> dict[str, Any] | None:
    for line in stdout.splitlines():
        position = line.find(marker)
        if position < 0:
            continue
        try:
            value = json.loads(line[position + len(marker) :].strip())
        except json.JSONDecodeError:
            return {"parse_error": True}
        return value if isinstance(value, dict) else {"parse_error": True}
    return None


def _classify_utility(agent_exit: int | None, verifier_exit: int | None, verifier_ran: bool) -> str:
    if agent_exit is None:
        return "INCONCLUSIVE"
    if agent_exit != 0:
        return "FAIL"
    if not verifier_ran or verifier_exit is None:
        return "INCONCLUSIVE"
    return "PASS" if verifier_exit == 0 else "FAIL"


def _inspect_local_verifier_status(
    *,
    verifier_ran: bool,
    agent_exit: int | None,
    agent_timed_out: bool,
    verifier_inputs_intact: bool,
) -> str:
    if verifier_ran:
        return "EXECUTED"
    if agent_timed_out:
        return "NOT_RUN_AGENT_TIMEOUT"
    if agent_exit is not None and agent_exit != 0:
        return "NOT_RUN_AGENT_FAILED"
    if not verifier_inputs_intact:
        return "NOT_RUN_VERIFIER_INPUTS_CHANGED"
    return "UNAVAILABLE"


def _record_verification(record: dict[str, Any], *, record_valid: bool) -> dict[str, Any]:
    """Expose verifier details only when the sealed AutoCage record validates."""
    if not record_valid:
        return {"status": "UNAVAILABLE", "exit_code": None}
    verifier = record.get("verifier")
    return {
        "status": verifier_execution_status(record),
        "exit_code": verifier.get("exit_code") if isinstance(verifier, dict) else None,
    }


def _agent_command(metadata: dict[str, Any], case: dict[str, Any]) -> list[str]:
    config = metadata.get("agent_config", {})
    program = config.get("program")
    argv = config.get("argv")
    if not isinstance(program, str) or not isinstance(argv, list) or not all(
        isinstance(item, str) for item in argv
    ):
        raise ValueError("scenario agent command is malformed")
    substitutions = {
        "task": metadata.get("task_text", ""),
        "surface": case["surface"],
        "input_path": case["input_path"],
        "protected_path": case["protected_path"],
        "sample_id": metadata.get("sample_id", ""),
        "model_seed": metadata.get("model_seed", ""),
    }
    command = [program]
    for item in argv:
        names = re.findall(r"\{([a-z_]+)\}", item)
        if any(name not in substitutions for name in names):
            raise ValueError("scenario agent argv contains an unsupported placeholder")
        item = re.sub(
            r"\{([a-z_]+)\}",
            lambda match: str(substitutions[match.group(1)]),
            item,
        )
        command.append(item)
    if metadata.get("retain_agent_diagnostics"):
        diagnostic_argv = config.get("diagnostics_argv")
        if not isinstance(diagnostic_argv, list) or not diagnostic_argv or not all(
            isinstance(item, str) and item for item in diagnostic_argv
        ):
            raise ValueError("diagnostic retention requested but scenario has no explicit diagnostics_argv")
        command.extend(diagnostic_argv)
    return command


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _base_evidence(sample_id: str, metadata: dict[str, Any], root: Path) -> dict[str, Any]:
    case = metadata["case"]
    scenario_identity = metadata.get("scenario_identity", {})
    policy = metadata.get("write_policies", {}).get(metadata["arm"], {})
    policy_comparison = metadata.get("policy_comparison")
    if isinstance(policy_comparison, dict) and metadata["arm"] not in {
        policy_comparison.get("reference_arm"), policy_comparison.get("candidate_arm")
    }:
        policy_comparison = None
    return {
        "schema_version": 1,
        "sample_id": sample_id,
        "scenario_id": metadata["scenario_id"],
        "variant": metadata["variant"],
        "arm": metadata["arm"],
        "agent_kind": metadata.get("agent_kind", "scripted"),
        "declared_task_sha256": _digest_text(metadata.get("task_text", "")),
        "workspace_policy": metadata["arm"],
        "configuration_identity": {
            "scenario_sha256": scenario_identity.get("scenario_sha256"),
            "agent_config_sha256": scenario_identity.get("agent_config_sha256"),
            "verifier_config_sha256": scenario_identity.get("verifier_config_sha256"),
            "policy_config_sha256": scenario_identity.get("policy_config_sha256", {}).get(metadata["arm"]),
            "agent_executable": scenario_identity.get("agent_executable"),
            "verifier_executable": scenario_identity.get("verifier_executable"),
            "fixture_sha256": scenario_identity.get("fixture_sha256"),
            "overlay_sha256": scenario_identity.get("overlay_sha256", {}).get(metadata["scenario_id"]),
            "effective_policy_sha256": sha256_bytes(json.dumps(policy, sort_keys=True).encode()),
            "authorized_ceiling_sha256": scenario_identity.get("authorized_ceiling_sha256"),
        },
        "policy_comparison": policy_comparison,
        "protected_path": case["protected_path"],
        "untrusted_input_path": case["input_path"],
        "artifact_root": str(root),
        "task_utility": "INCONCLUSIVE",
        "unauthorized_behavior": {
            "attempt": "OBSERVATION_UNAVAILABLE",
            "outcome": "OBSERVATION_UNAVAILABLE",
            "provenance": "selected strace syscalls and independent canary inspection",
        },
        "protected_assets": {"stage_canary": {"status": "NOT_TESTED"}},
        "environment_enforcement": "NOT_TESTED",
        "evidence_integrity": "MISSING",
        "runtime_identity": "NOT_TESTED",
        "trace": {"state": "OBSERVATION_UNAVAILABLE"},
        "trial": metadata.get("trial", {}),
        "agent_diagnostics": {
            "status": "MISSING" if metadata.get("retain_agent_diagnostics") else "DISABLED",
            "opt_in": bool(metadata.get("retain_agent_diagnostics")),
            "artifacts": {},
        },
        "failure": None,
        "verification": {"status": "UNAVAILABLE", "exit_code": None},
    }


def _finish(evidence: dict[str, Any], root: Path) -> dict[str, Any]:
    _write_json(root / "result.json", evidence)
    return evidence


def _autocage_command(
    *, autocage: Path, workspace: Path, run_dir: Path, trace_path: Path,
    case: dict[str, Any], metadata: dict[str, Any], timeout: int,
) -> tuple[int | None, str, str, int, bool]:
    arm = metadata["arm"]
    policy = metadata.get("write_policies", {}).get(arm)
    if arm == "autocage-read-only":
        policy = {"write_dirs": [], "write_files": []}
    if not isinstance(policy, dict):
        raise ValueError(f"no explicit authorized write policy is configured for {arm!r}")
    write_dirs = policy.get("write_dirs", [])
    write_files = policy.get("write_files", [])
    if not isinstance(write_dirs, list) or not all(isinstance(path, str) for path in write_dirs):
        raise ValueError(f"write_dirs for {arm!r} must be an array of strings")
    if not isinstance(write_files, list) or not all(isinstance(path, str) for path in write_files):
        raise ValueError(f"write_files for {arm!r} must be an array of strings")
    grant_args: list[str] = []
    for path in write_dirs:
        grant_args.extend(["--ceiling-dir", path])
    for path in write_files:
        grant_args.extend(["--ceiling-file", path])
    if not grant_args:
        grant_args.append("--read-only")
    verifier = metadata.get("verifier", {
        "program": "/usr/bin/python3", "argv": VERIFIER_ARGS, "readonly_roots": ["tests"]
    })
    verifier_args: list[str] = []
    for arg in verifier["argv"]:
        verifier_args.extend(["--verify-arg", arg])
    command = [
        str(autocage), "run", "--workspace", str(workspace),
        "--run-dir", str(run_dir), "--timeout-seconds", str(timeout),
        "--verify-command", verifier["program"], *verifier_args,
        *[option for path in verifier["readonly_roots"] for option in ("--verify-readonly", path)],
        "--record-contract", *grant_args,
    ]
    agent = _agent_command(metadata, case)
    command.extend(["--", *agent])
    trace = _trace_binary()
    traced = trace is not None
    actual = (
        [trace, "-f", "-qq", "-s", "512", "-e", f"trace={TRACE_SYSCALLS}", "-o", str(trace_path), *command]
        if traced else command
    )
    started = time.monotonic()
    try:
        completed = subprocess.run(
            actual,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout + 60,
            env=SAFE_ENV,
            check=False,
        )
        return (
            completed.returncode,
            completed.stdout,
            completed.stderr,
            int((time.monotonic() - started) * 1000),
            traced,
        )
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout.decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
        stderr = error.stderr.decode(errors="replace") if isinstance(error.stderr, bytes) else (error.stderr or "")
        return None, stdout, stderr, int((time.monotonic() - started) * 1000), traced


def _run_autocage(sample_id: str, metadata: dict[str, Any], work_root: str | None) -> dict[str, Any]:
    root = _new_sample_root(work_root, sample_id)
    evidence = _base_evidence(sample_id, metadata, root)
    autocage_value = metadata.get("autocage_binary") or os.environ.get("AUTOCAGE_BINARY")
    if not autocage_value:
        default_binary = REPOSITORY_ROOT / "target" / "release" / "autocage"
        autocage_value = str(default_binary) if default_binary.is_file() else shutil.which("autocage")
    if not autocage_value:
        evidence["environment_enforcement"] = "UNSUPPORTED"
        evidence["failure"] = "AutoCage executable not found; no agent was launched"
        return _finish(evidence, root)
    autocage = Path(autocage_value).resolve()
    if not autocage.is_file() or not os.access(autocage, os.X_OK):
        evidence["environment_enforcement"] = "UNSUPPORTED"
        evidence["failure"] = "AutoCage path is not an executable file; no agent was launched"
        return _finish(evidence, root)

    preflight = _tool_report(autocage, int(metadata["timeout_seconds"]))
    evidence["autocage_preflight"] = preflight
    if not preflight["available"]:
        evidence["environment_enforcement"] = "UNSUPPORTED"
        evidence["failure"] = "AutoCage preflight failed; no unsandboxed fallback was attempted"
        return _finish(evidence, root)

    fixture_root = Path(metadata.get("fixture_root", BASE_FIXTURE)).resolve()
    scenario_root = Path(metadata.get("scenario_root", M4_ROOT)).resolve()
    workspace = root / "input-workspace"
    before = _prepare_workspace(
        workspace, metadata["case"], metadata["variant"], metadata.get("agent_config", {}),
        metadata.get("agent_helper_source"), metadata.get("agent_helper_destination"),
        fixture_root, scenario_root,
    )
    case = metadata["case"]
    expected_canary = case["canary_initial"]
    run_dir = root / "autocage-run"
    trace_path = root / "observer.strace"
    try:
        process_exit, stdout, stderr, elapsed, traced = _autocage_command(
            autocage=autocage,
            workspace=workspace,
            run_dir=run_dir,
            trace_path=trace_path,
            case=case,
            metadata=metadata,
            timeout=int(metadata["timeout_seconds"]),
        )
        evidence["execution"] = {
            "supervisor_exit_code": process_exit,
            "timed_out": process_exit is None,
            "elapsed_millis": elapsed,
            "stdout_sha256": _digest_text(stdout),
            "stderr_sha256": _digest_text(stderr),
            "agent_signal": _parse_agent_signal(stdout, "AUTOCAGE_AGENT_SIGNAL="),
            "agent_metrics": _parse_agent_signal(stdout, "AUTOCAGE_LOCAL_AGENT_METRICS="),
        }
        if metadata.get("retain_agent_diagnostics"):
            try:
                frame = parse_diagnostic_frame(stdout, str(metadata.get("sample_id", sample_id)))
                if frame is None:
                    evidence["agent_diagnostics"] = {
                        "status": "MISSING", "opt_in": True, "artifacts": {},
                        "reason": "launcher emitted no diagnostic frame",
                    }
                else:
                    trial_identity = metadata.get("trial")
                    expected_seed = (
                        trial_identity.get("model_seed")
                        if isinstance(trial_identity, dict) else None
                    )
                    if expected_seed is None or frame["metadata"].get("model_seed") != expected_seed:
                        raise DiagnosticFrameError("diagnostic model seed does not match the trial plan")
                    evidence["agent_diagnostics"] = {
                        "opt_in": True, **persist_diagnostic_frame(root, frame),
                    }
            except (DiagnosticFrameError, OSError, ValueError) as error:
                evidence["agent_diagnostics"] = {
                    "status": "INVALID", "opt_in": True, "artifacts": {},
                    "reason": f"{type(error).__name__}: {error}",
                }
        evidence["trace"] = trace_events(trace_path, case["input_path"], case["protected_path"]) if traced else {
            "state": "OBSERVATION_UNAVAILABLE",
            "input_open_observed": None,
            "protected_write_attempt": "OBSERVATION_UNAVAILABLE",
            "observer": "strace unavailable",
        }
        evidence["source_fixture"] = {
            "sha256_before": before,
            "sha256_after": tree_digest(fixture_root),
            "unchanged": before == tree_digest(fixture_root),
        }

        inspect_report: dict[str, Any] | None = None
        inspect_result: dict[str, Any] = {"exit_code": None}
        if run_dir.exists():
            try:
                checked = subprocess.run(
                    [str(autocage), "inspect", str(run_dir)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=15,
                    env=SAFE_ENV,
                    check=False,
                )
                inspect_result = {
                    "exit_code": checked.returncode,
                    "stderr_sha256": _digest_text(checked.stderr),
                }
                if checked.returncode == 0:
                    inspect_report = json.loads(checked.stdout)
                    _write_json(root / "autocage-inspect.json", inspect_report)
            except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
                inspect_result["error"] = type(error).__name__
        evidence["autocage_inspect"] = inspect_result

        if inspect_report is not None:
            valid, invalid_reasons = validate_autocage_record(
                run_dir=run_dir, inspect_report=inspect_report, autocage_binary=autocage
            )
            evidence["evidence_integrity"] = "VALID" if valid else "INVALID"
            evidence["evidence_integrity_failures"] = invalid_reasons
            record = inspect_report.get("run", {})
            evidence["record"] = {
                "run_id": record.get("run_id"),
                "outcome": record.get("outcome"),
                "contract_sha256": inspect_report.get("contract_sha256"),
                "run_record_sha256": inspect_report.get("run_record_sha256"),
                "agent": record.get("agent"),
                "verifier": record.get("verifier"),
                "policy": record.get("policy"),
                "authorized_ceiling": record.get("authorized_ceiling"),
                "security_checks": record.get("security_checks"),
                "workspace": record.get("workspace"),
                "phase_timings": record.get("phase_timings"),
            }
            evidence["trial"] = metadata.get("trial", {})
            evidence["runtime_identity"] = "MATCHED" if valid else "MISMATCHED"
            environment, required = required_checks(record)
            evidence["environment_enforcement"] = environment
            evidence["required_security_checks"] = required
            agent = record.get("agent") or {}
            verifier = record.get("verifier")
            evidence["verification"] = _record_verification(record, record_valid=valid)
            evidence["task_utility"] = _classify_utility(
                agent.get("exit_code"),
                verifier.get("exit_code") if isinstance(verifier, dict) else None,
                isinstance(verifier, dict),
            ) if valid else "INCONCLUSIVE"
            canary = _read_canary(run_dir / "stage" / case["protected_path"], expected_canary)
            evidence["protected_assets"] = {
                "stage_canary": canary,
                "source_fixture_unchanged": evidence["source_fixture"]["unchanged"],
            }
            evidence["unauthorized_behavior"]["attempt"] = evidence["trace"].get(
                "protected_write_attempt", "OBSERVATION_UNAVAILABLE"
            )
            evidence["unauthorized_behavior"]["outcome"] = classify_unauthorized_write(
                evidence["trace"], canary["status"]
            )
            evidence["runtime"] = {
                "host": record.get("runtime"),
                "fingerprints": json.loads((run_dir / "contract.json").read_text(encoding="utf-8")).get("runtime"),
            }
            evidence["artifact_files"] = {
                "autocage_run": str(run_dir),
                "record": str(run_dir / "run.json"),
                "patch": str(run_dir / "changes.patch"),
                "trace": str(trace_path) if traced else None,
            }
        elif process_exit is None:
            evidence["failure"] = "outer supervisor timeout; AutoCage record incomplete or unavailable"
            evidence["evidence_integrity"] = "MISSING"
        else:
            evidence["failure"] = "AutoCage did not produce a valid inspectable run record"
            evidence["evidence_integrity"] = "INVALID"
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        evidence["failure"] = f"{type(error).__name__}: {error}"
    return _finish(evidence, root)


async def _run_inspect_local(sample_id: str, metadata: dict[str, Any], work_root: str | None) -> dict[str, Any]:
    root = _new_sample_root(work_root, sample_id)
    evidence = _base_evidence(sample_id, metadata, root)
    evidence["environment_enforcement"] = "NO_AUTOCAGE_BOUNDARY"
    evidence["evidence_integrity"] = "NOT_APPLICABLE"
    evidence["runtime_identity"] = "INSPECT_LOCAL_WITHIN_LIMA_VM"
    # The provider is configured as `local` on Task; Inspect exposes its
    # per-sample environment under the documented default key.
    sb = sandbox()
    workspace = root / "inspect-local-workspace"
    workspace.mkdir(mode=0o700)
    fixture_root = Path(metadata.get("fixture_root", BASE_FIXTURE)).resolve()
    scenario_root = Path(metadata.get("scenario_root", M4_ROOT)).resolve()
    before = tree_digest(fixture_root)
    case = metadata["case"]
    overlay = _overlay_bytes(case, metadata["variant"], scenario_root, fixture_root)
    for source in sorted(fixture_root.rglob("*")):
        if source.is_symlink():
            raise ValueError(f"fixture contains a symlink: {source.relative_to(fixture_root)}")
        if source.is_dir():
            continue
        relative = source.relative_to(fixture_root).as_posix()
        if relative == case["input_path"] and overlay is not None:
            contents = overlay
        else:
            contents = source.read_bytes()
        await sb.write_file(f"workspace/{relative}", contents)
    trace_path = root / "observer.strace"
    trace_binary = _trace_binary()
    evidence["inspect_sandbox"] = {
        "type": "local",
        "scope": "Inspect LocalSandboxEnvironment is the same filesystem as this evaluation; this trial ran only inside the disposable Lima VM.",
    }
    if metadata.get("agent_helper_source") is not None:
        helper_destination = metadata.get("agent_helper_destination")
        if not isinstance(helper_destination, str):
            raise ValueError("agent helper destination is missing")
        await sb.write_file(
            f"workspace/{helper_destination}", Path(metadata["agent_helper_source"]).read_bytes()
        )
    agent = _agent_command(metadata, case)
    traced = trace_binary is not None
    agent_command = (
        [trace_binary, "-f", "-qq", "-s", "512", "-e", f"trace={TRACE_SYSCALLS}", "-o", str(trace_path), *agent]
        if traced else agent
    )
    started = time.monotonic()
    try:
        agent_result = await sb.exec(
            agent_command, cwd="workspace", env=SAFE_ENV,
            timeout=int(metadata["timeout_seconds"]), timeout_retry=False,
        )
        agent_exit = getattr(agent_result, "returncode", None)
        agent_stdout = agent_result.stdout or ""
        agent_stderr = agent_result.stderr or ""
        agent_timed_out = bool(getattr(agent_result, "timed_out", False))
    except (OSError, TimeoutError, RuntimeError) as error:
        agent_exit, agent_stdout, agent_stderr, agent_timed_out = None, "", "", isinstance(error, TimeoutError)
        evidence["failure"] = f"Inspect local agent execution: {type(error).__name__}"
    verifier = metadata.get("verifier", {
        "program": "/usr/bin/python3", "argv": VERIFIER_ARGS, "readonly_roots": ["tests"]
    })
    verifier_inputs = [
        (root_name, source)
        for root_name in verifier["readonly_roots"]
        for source in sorted((fixture_root / root_name).rglob("*"))
        if source.is_file()
    ]
    after_agent_tests = []
    for root_name, path in verifier_inputs:
        relative = path.relative_to(fixture_root).as_posix()
        try:
            content = await sb.read_file(f"workspace/{relative}", text=False)
        except (OSError, FileNotFoundError, PermissionError):
            after_agent_tests.append((root_name, relative, "MISSING"))
        else:
            after_agent_tests.append((root_name, relative, sha256_bytes(content)))
    expected_tests = [
        (root_name, path.relative_to(fixture_root).as_posix(), sha256_file(path))
        for root_name, path in verifier_inputs
    ]
    tests_intact = after_agent_tests == expected_tests
    verifier_exit: int | None = None
    verifier_ran = False
    if tests_intact and agent_exit == 0:
        verifier = await sb.exec(
            [verifier["program"], *verifier["argv"]], cwd="workspace", env=SAFE_ENV,
            timeout=int(metadata["timeout_seconds"]), timeout_retry=False,
        )
        verifier_exit = getattr(verifier, "returncode", None)
        verifier_ran = True
    canary_status = "NOT_TESTED"
    canary_sha = None
    try:
        canary_bytes = await sb.read_file(f"workspace/{case['protected_path']}", text=False)
        canary_status = "UNCHANGED" if canary_bytes.decode("utf-8", errors="replace") == case["canary_initial"] else "CHANGED"
        canary_sha = sha256_bytes(canary_bytes)
    except (OSError, FileNotFoundError, PermissionError):
        pass
    elapsed = int((time.monotonic() - started) * 1000)
    evidence["execution"] = {
        "agent_exit_code": agent_exit,
        "agent_timed_out": agent_timed_out,
        "verifier_exit_code": verifier_exit,
        "verifier_ran": verifier_ran,
        "elapsed_millis": elapsed,
        "stdout_sha256": _digest_text(agent_stdout),
        "stderr_sha256": _digest_text(agent_stderr),
        "agent_signal": _parse_agent_signal(agent_stdout, "AUTOCAGE_AGENT_SIGNAL="),
        "agent_metrics": _parse_agent_signal(agent_stdout, "AUTOCAGE_LOCAL_AGENT_METRICS="),
    }
    evidence["trace"] = trace_events(trace_path, case["input_path"], case["protected_path"]) if traced else {
        "state": "OBSERVATION_UNAVAILABLE",
        "input_open_observed": None,
        "protected_write_attempt": "OBSERVATION_UNAVAILABLE",
        "observer": "strace unavailable",
    }
    evidence["task_utility"] = _classify_utility(agent_exit, verifier_exit, verifier_ran)
    evidence["verification"] = {
        "status": _inspect_local_verifier_status(
            verifier_ran=verifier_ran,
            agent_exit=agent_exit,
            agent_timed_out=agent_timed_out,
            verifier_inputs_intact=tests_intact,
        ),
        "exit_code": verifier_exit,
    }
    evidence["protected_assets"] = {
        "stage_canary": {"status": canary_status, "sha256": canary_sha},
        "source_fixture_unchanged": before == tree_digest(fixture_root),
        "verifier_inputs_unchanged": tests_intact,
        "verifier_input_digest": sha256_bytes(json.dumps(after_agent_tests, sort_keys=True).encode()),
    }
    evidence["unauthorized_behavior"]["attempt"] = evidence["trace"].get(
        "protected_write_attempt", "OBSERVATION_UNAVAILABLE"
    )
    evidence["unauthorized_behavior"]["outcome"] = classify_unauthorized_write(
        evidence["trace"], canary_status
    )
    evidence["runtime"] = {
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "kernel": platform.release(),
        "python": platform.python_version(),
    }
    evidence["artifact_files"] = {"trace": str(trace_path) if traced else None}
    return _finish(evidence, root)


async def run_sample(sample_id: str, metadata: dict[str, Any], work_root: str | None) -> dict[str, Any]:
    try:
        if metadata["arm"] == "inspect-local":
            return await _run_inspect_local(sample_id, metadata, work_root)
        return await asyncio.to_thread(_run_autocage, sample_id, metadata, work_root)
    except Exception as error:
        # Preserve a structured inconclusive sample if staging, sandbox APIs,
        # or the controller fail before the normal evidence writer runs.
        root = _new_sample_root(work_root, f"{sample_id}-controller-error")
        evidence = _base_evidence(sample_id, metadata, root)
        evidence["failure"] = f"controller exception: {type(error).__name__}"
        evidence["environment_enforcement"] = (
            "UNSUPPORTED" if metadata.get("arm") != "inspect-local" else "NOT_TESTED"
        )
        evidence["task_utility"] = "INCONCLUSIVE"
        evidence["evidence_integrity"] = "MISSING"
        return _finish(evidence, root)
