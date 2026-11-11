#!/usr/bin/env python3
"""Run Aider with an already-installed Ollama model inside AutoCage.

Ollama binds only to sandbox loopback. This helper never pulls models and never
retains prompt, chat-history, or model-response files.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

DEFAULT_AIDER = Path("/usr/local/venvs/aider/bin/aider")
DEFAULT_OLLAMA = Path("/usr/bin/ollama")
MODEL_STORE = Path("/usr/local/share/ollama/models")
MODEL_TAG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}")
EDIT_FORMATS = ("whole", "diff", "udiff")
METRICS_MARKER = "AUTOCAGE_LOCAL_AGENT_METRICS="


def _program(value: str, label: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        raise ValueError(f"{label} must be an absolute executable path")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"{label} is unavailable at {value}") from error
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError(f"{label} is not an executable regular file: {value}")
    return resolved


def _workspace_file(value: str, *, allow_new: bool) -> str:
    relative = PurePosixPath(value)
    if not value or relative.is_absolute() or any(
        part in ("", ".", "..") for part in value.split("/")
    ):
        raise ValueError("agent file paths must be normalized workspace-relative paths")
    try:
        root = Path.cwd().resolve(strict=True)
    except OSError as error:
        raise ValueError("workspace root cannot be resolved") from error
    candidate = root.joinpath(*relative.parts)
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"agent file path contains a symlink: {value}")
    if candidate.exists():
        resolved = candidate.resolve(strict=True)
        try:
            resolved.relative_to(root)
        except ValueError as error:
            raise ValueError(f"agent file path escapes the workspace: {value}") from error
        if not resolved.is_file():
            raise ValueError(f"agent file path must name a regular file: {value}")
    elif allow_new:
        try:
            parent = candidate.parent.resolve(strict=True)
        except OSError as error:
            raise ValueError(f"agent file parent does not exist: {value}") from error
        try:
            parent.relative_to(root)
        except ValueError as error:
            raise ValueError(f"agent file parent escapes the workspace: {value}") from error
        if not parent.is_dir():
            raise ValueError(f"agent file parent is not a directory: {value}")
    else:
        raise ValueError(f"read-only agent input does not exist: {value}")
    return relative.as_posix()


def _validate_model_tag(value: str) -> str:
    if not MODEL_TAG_RE.fullmatch(value):
        raise ValueError("model tag contains unsupported characters")
    return value


def _clean_environment(home: Path, model_dir: Path, context_length: int) -> dict[str, str]:
    return {
        "HOME": str(home),
        "TMPDIR": "/tmp",
        "PATH": "/usr/local/venvs/aider/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "TERM": "dumb",
        "NO_COLOR": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "OLLAMA_HOST": "127.0.0.1:11434",
        "OLLAMA_MODELS": str(model_dir),
        "OLLAMA_CONTEXT_LENGTH": str(context_length),
        "OLLAMA_KEEP_ALIVE": "5m",
        "OLLAMA_API_BASE": "http://127.0.0.1:11434",
    }


def _settings(model: str, edit_format: str, temperature: float, context_length: int, seed: int) -> str:
    return (
        f"- name: {model}\n"
        f"  edit_format: {edit_format}\n"
        f"  use_temperature: {temperature:g}\n"
        "  extra_params:\n"
        f"    num_ctx: {context_length}\n"
        f"    seed: {seed}\n"
    )


def _aider_command(
    aider: Path, model: str, settings: Path, empty_config: Path, task: str,
    read_files: list[str], editable_files: list[str], edit_format: str,
) -> list[str]:
    command = [
        str(aider), "--model", model, "--model-settings-file", str(settings),
        "--config", str(empty_config), "--env-file", "/dev/null",
        "--edit-format", edit_format, "--no-git", "--no-analytics",
        "--no-auto-commits", "--yes-always", "--map-tokens", "0", "--no-pretty",
        "--input-history-file", "/dev/null", "--chat-history-file", "/dev/null",
    ]
    for path in read_files:
        command.extend(["--read", path])
    command.extend(["--message", task, *editable_files])
    return command


def _version(binary: Path, env: dict[str, str], label: str) -> str:
    try:
        result = subprocess.run(
            [str(binary), "--version"], env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"could not identify {label} version ({type(error).__name__})") from error
    if result.returncode != 0:
        raise RuntimeError(f"{label} version command failed with exit code {result.returncode}")
    output = (result.stdout or "") + "\n" + (result.stderr or "")
    versions = re.findall(r"\bversion(?:\s+is)?\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", output, re.IGNORECASE)
    if versions:
        return versions[-1]
    lines = output.strip().splitlines()
    value = lines[-1].strip() if lines else ""
    if not value or len(value) > 100 or not re.fullmatch(r"[A-Za-z0-9 .:/_-]+", value):
        raise RuntimeError(f"{label} returned an invalid version string")
    return value


def _model_is_installed(tag: str, timeout: float = 1.0) -> bool | None:
    try:
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=timeout) as response:
            if response.status != 200:
                raise RuntimeError(f"Ollama model-list endpoint returned HTTP {response.status}")
            payload = json.loads(response.read(1024 * 1024 + 1))
    except (OSError, urllib.error.URLError, TimeoutError):
        return None
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise RuntimeError("Ollama returned malformed model-list JSON") from error
    if not isinstance(payload, dict) or not isinstance(payload.get("models"), list):
        raise RuntimeError("Ollama model-list response has an unsupported schema")
    names = []
    for entry in payload["models"]:
        if not isinstance(entry, dict):
            raise RuntimeError("Ollama model-list response contains an invalid entry")
        if isinstance(entry.get("name"), str):
            names.append(entry["name"])
    return tag in names


def _wait_for_model(server: subprocess.Popen[bytes], tag: str, timeout_seconds: int) -> int:
    started = time.monotonic()
    deadline = started + timeout_seconds
    while time.monotonic() < deadline:
        status = server.poll()
        if status is not None:
            raise RuntimeError(f"Ollama server exited before readiness (exit code {status})")
        present = _model_is_installed(tag)
        if present is True:
            return int((time.monotonic() - started) * 1000)
        if present is False:
            raise RuntimeError(
                f"local Ollama model {tag!r} is not installed in {MODEL_STORE}; "
                "install it in the guest before evaluation; AutoCage will not pull it"
            )
        time.sleep(0.25)
    raise TimeoutError("Ollama did not become ready on sandbox loopback before the startup deadline")


def _stop_server(server: subprocess.Popen[bytes]) -> None:
    if server.poll() is not None:
        return
    server.terminate()
    try:
        server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=5)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", required=True)
    parser.add_argument("--model-tag", required=True, help="exact, already-installed Ollama tag")
    parser.add_argument("--editable-file", action="append", required=True)
    parser.add_argument("--read-file", action="append", default=[])
    parser.add_argument("--edit-format", choices=EDIT_FORMATS, default="whole")
    parser.add_argument("--context-length", type=int, default=8192)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--startup-timeout", type=int, default=60)
    parser.add_argument("--aider-bin", default=str(DEFAULT_AIDER))
    parser.add_argument("--ollama-bin", default=str(DEFAULT_OLLAMA))
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if not args.task.strip():
            raise ValueError("task must not be empty")
        tag = _validate_model_tag(args.model_tag)
        if not 1024 <= args.context_length <= 131072:
            raise ValueError("context length must be between 1024 and 131072")
        if not math.isfinite(args.temperature) or not 0.0 <= args.temperature <= 2.0:
            raise ValueError("temperature must be finite and between 0 and 2")
        if not 0 <= args.seed <= 0x7FFFFFFF:
            raise ValueError("seed must be between 0 and 2147483647")
        if not 1 <= args.startup_timeout <= 300:
            raise ValueError("startup timeout must be between 1 and 300 seconds")
        editable_files = [_workspace_file(item, allow_new=True) for item in args.editable_file]
        read_files = [_workspace_file(item, allow_new=False) for item in args.read_file]
        if len(set(editable_files)) != len(editable_files) or len(set(read_files)) != len(read_files):
            raise ValueError("agent file paths must be unique within each permission list")
        if set(editable_files) & set(read_files):
            raise ValueError("a file cannot be both read-only and editable")
        aider = _program(args.aider_bin, "Aider")
        ollama = _program(args.ollama_bin, "Ollama")
        if not MODEL_STORE.is_dir():
            raise RuntimeError(f"local Ollama model store is missing at {MODEL_STORE}")
    except ValueError as error:
        parser.error(str(error))
    except RuntimeError as error:
        print(f"AutoCage local Aider preflight failed: {error}", file=sys.stderr)
        return 2

    os.umask(0o077)
    server: subprocess.Popen[bytes] | None = None
    model_name = f"ollama_chat/{tag}"
    try:
        with tempfile.TemporaryDirectory(prefix="autocage-local-aider-", dir="/tmp") as directory:
            private = Path(directory)
            private.chmod(0o700)
            home = private / "home"
            home.mkdir(mode=0o700)
            env = _clean_environment(home, MODEL_STORE, args.context_length)
            aider_version = _version(aider, env, "Aider")
            ollama_version = _version(ollama, env, "Ollama")
            settings = private / "model-settings.yml"
            settings.write_text(
                _settings(model_name, args.edit_format, args.temperature, args.context_length, args.seed),
                encoding="utf-8",
            )
            settings.chmod(0o600)
            empty_config = private / "aider-empty.yml"
            empty_config.write_text("{}\n", encoding="utf-8")
            empty_config.chmod(0o600)

            server = subprocess.Popen(
                [str(ollama), "serve"], env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            ready_millis = _wait_for_model(server, tag, args.startup_timeout)
            print(
                f"AutoCage local agent ready: Aider={aider_version}; Ollama={ollama_version}; "
                f"model={tag}; loopback-only; no model download.",
                file=sys.stderr, flush=True,
            )
            command = _aider_command(
                aider, model_name, settings, empty_config, args.task,
                read_files, editable_files, args.edit_format,
            )
            process_started = time.monotonic()
            try:
                result = subprocess.run(command, env=env, check=False)
                aider_exit = result.returncode
            except OSError as error:
                print(f"AutoCage could not launch Aider ({type(error).__name__}).", file=sys.stderr)
                aider_exit = 127
            elapsed = int((time.monotonic() - process_started) * 1000)
            metrics = {
                "agent": "Aider", "aider_version": aider_version,
                "ollama_version": ollama_version, "model": tag,
                "server_ready_millis": ready_millis,
                "agent_elapsed_millis": elapsed,
            }
            print(METRICS_MARKER + json.dumps(metrics, sort_keys=True), flush=True)
            return aider_exit
    except (OSError, RuntimeError, TimeoutError) as error:
        print(f"AutoCage local Aider execution failed: {error}", file=sys.stderr)
        return 2
    finally:
        if server is not None:
            try:
                _stop_server(server)
            except (OSError, subprocess.TimeoutExpired):
                print("AutoCage could not cleanly stop the sandbox Ollama process.", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
