#!/usr/bin/env python3
"""Synthetic-playground Aider/Ollama launcher with explicit bounded diagnostics."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request


OLLAMA = Path("/usr/bin/ollama")
AIDER = Path("/usr/local/venvs/aider/bin/aider")
AIDER_PYTHON = Path("/usr/local/venvs/aider/bin/python")
MODEL = "ollama_chat/qwen2.5-coder:3b"
MODEL_ID = "qwen2.5-coder:3b"
MODEL_DIR = Path("/usr/local/share/ollama/models")
MANIFEST = MODEL_DIR / "manifests/registry.ollama.ai/library/qwen2.5-coder/3b"
MODEL_BLOB = MODEL_DIR / "blobs/sha256-4a188102020e9c9530b687fd6400f775c45e90a0d7baafe65bd0a36963fbb7ba"
MODEL_SIZE = 1_929_903_072
EDITABLE_FILES = ("src/calculator.py", "config/settings.json")
EXPECTED_AIDER_VERSION = "0.86.2"
EXPECTED_OLLAMA_VERSION = "0.40.4"
EXPECTED_MANIFEST_SHA256 = "ce40a49b0aa2b3b607d26a603e0f2db06a256cecbc9cca7adf893ae11a80275a"
CONTEXT_LENGTH = 8192
TEMPERATURE = 0.0
CAPTURE_LIMITS = {
    "aider-chat-history.md": 512 * 1024,
    "aider-llm-history.log": 512 * 1024,
    "aider-stdout.bin": 256 * 1024,
    "aider-stderr.bin": 256 * 1024,
    "ollama-server.log": 256 * 1024,
    "ollama-model-info.json": 64 * 1024,
    "effective-settings.json": 16 * 1024,
}
FRAME_MARKER = "AUTOCAGE_AGENT_DIAGNOSTICS_V1="


def workspace_input(value: str) -> str:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("input must be workspace-relative")
    root = Path.cwd().resolve(strict=True)
    result = (root / path).resolve(strict=True)
    result.relative_to(root)
    if not result.is_file():
        raise ValueError("input must name a regular file")
    return result.relative_to(root).as_posix()


def verify_local_install() -> tuple[str, str, str, str]:
    if not OLLAMA.is_file() or not os.access(OLLAMA, os.X_OK):
        raise RuntimeError("Ollama missing at /usr/bin/ollama; no network fallback is used")
    if not AIDER.is_file() or not os.access(AIDER, os.X_OK):
        raise RuntimeError("Aider missing at /usr/local/venvs/aider/bin/aider")
    version_env = {"HOME": "/tmp", "PATH": "/usr/local/venvs/aider/bin:/usr/bin:/bin"}
    aider = subprocess.run([str(AIDER), "--version"], env=version_env,
                           capture_output=True, text=True, timeout=10, check=False)
    ollama = subprocess.run([str(OLLAMA), "--version"], env=version_env,
                            capture_output=True, text=True, timeout=10, check=False)
    if aider.returncode != 0 or EXPECTED_AIDER_VERSION not in aider.stdout + aider.stderr:
        raise RuntimeError("Aider version does not match the validated 0.86.2 setup")
    if ollama.returncode != 0 or EXPECTED_OLLAMA_VERSION not in ollama.stdout + ollama.stderr:
        raise RuntimeError("Ollama version does not match the validated 0.40.4 setup")
    litellm = subprocess.run(
        [str(AIDER_PYTHON), "-c", "import importlib.metadata as m; print(m.version('litellm'))"],
        env=version_env, capture_output=True, text=True, timeout=10, check=False,
    )
    if litellm.returncode != 0 or not litellm.stdout.strip():
        raise RuntimeError("could not identify the installed LiteLLM version")
    if not MANIFEST.is_file():
        raise RuntimeError("local Qwen2.5-Coder model manifest missing; no model will be downloaded")
    raw = MANIFEST.read_bytes()
    manifest_hash = hashlib.sha256(raw).hexdigest()
    if manifest_hash != EXPECTED_MANIFEST_SHA256:
        raise RuntimeError("local Qwen2.5-Coder manifest does not match the pinned identity")
    manifest = json.loads(raw)
    for item in [manifest.get("config"), *manifest.get("layers", [])]:
        if not isinstance(item, dict) or not isinstance(item.get("digest"), str):
            raise RuntimeError("local model manifest contains an invalid layer identity")
        blob = MODEL_DIR / "blobs" / item["digest"].replace(":", "-")
        if not blob.is_file() or blob.stat().st_size != item.get("size"):
            raise RuntimeError("a pinned local Ollama model blob is missing or has the wrong size")
    if not MODEL_BLOB.is_file() or MODEL_BLOB.stat().st_size != MODEL_SIZE:
        raise RuntimeError("pinned Qwen2.5-Coder model blob is missing or has the wrong size")
    return manifest_hash, aider.stdout.strip(), ollama.stdout.strip(), litellm.stdout.strip()


def _drain_bounded(stream, limit: int, result: dict[str, object]) -> None:
    captured = bytearray()
    total = 0
    try:
        while True:
            read_chunk = getattr(stream, "read1", stream.read)
            chunk = read_chunk(16 * 1024)
            if not chunk:
                break
            total += len(chunk)
            remaining = max(0, limit - len(captured))
            if remaining:
                captured.extend(chunk[:remaining])
    finally:
        stream.close()
    result["data"] = bytes(captured)
    result["source_bytes"] = total
    result["truncated"] = total > len(captured)


def run_bounded(argv: list[str], env: dict[str, str], limit: int) -> tuple[int, bytes, bytes, dict[str, int | bool]]:
    process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out: dict[str, object] = {}
    err: dict[str, object] = {}
    threads = [
        threading.Thread(target=_drain_bounded, args=(process.stdout, limit, out), daemon=True),
        threading.Thread(target=_drain_bounded, args=(process.stderr, limit, err), daemon=True),
    ]
    for thread in threads:
        thread.start()
    exit_code = process.wait()
    for thread in threads:
        thread.join()
    return exit_code, out["data"], err["data"], {
        "stdout_source_bytes": int(out["source_bytes"]),
        "stderr_source_bytes": int(err["source_bytes"]),
        "stdout_truncated": bool(out["truncated"]),
        "stderr_truncated": bool(err["truncated"]),
    }


def read_bounded(path: Path, limit: int) -> tuple[bytes, int, bool]:
    try:
        size = path.stat().st_size
        with path.open("rb") as source:
            data = source.read(limit + 1)
    except OSError:
        return b"", 0, False
    truncated = len(data) > limit or size > limit
    return data[:limit], max(size, len(data)), truncated


def _request_options(stderr: bytes) -> list[dict[str, object]]:
    """Extract only safe generation fields from Aider's verbose kwargs dump."""
    text = stderr.decode("utf-8", errors="replace")
    decoder = json.JSONDecoder()
    found: list[dict[str, object]] = []
    cursor = 0
    while True:
        marker = text.find("kwargs:", cursor)
        if marker < 0:
            break
        start = text.find("{", marker)
        if start < 0:
            break
        try:
            value, end = decoder.raw_decode(text[start:])
        except json.JSONDecodeError:
            cursor = start + 1
            continue
        allowed = (
            "model", "temperature", "seed", "num_ctx", "num_predict", "top_p", "top_k",
            "repeat_penalty", "repeat_last_n", "stop", "mirostat", "mirostat_eta",
            "mirostat_tau", "num_gpu", "num_thread",
        )
        if isinstance(value, dict) and any(key in value for key in ("temperature", "seed", "num_ctx")):
            found.append({key: value[key] for key in allowed if key in value})
        cursor = start + max(end, 1)
    return found


def model_settings_content(model_seed: int) -> str:
    return (
        "- name: " + MODEL + "\n"
        "  edit_format: whole\n"
        "  use_temperature: 0.0\n"
        "  extra_params:\n"
        f"    num_ctx: {CONTEXT_LENGTH}\n"
        f"    seed: {model_seed}\n"
    )


def _artifact(data: bytes, source_bytes: int, truncated: bool) -> dict[str, object]:
    return {
        "data_base64": base64.b64encode(data).decode("ascii"),
        "sha256": hashlib.sha256(data).hexdigest(),
        "captured_bytes": len(data),
        "source_bytes": source_bytes,
        "truncated": truncated,
    }


def _emit_diagnostics(sample_id: str, metadata: dict[str, object], artifacts: dict[str, tuple[bytes, int, bool]]) -> None:
    frame = {
        "schema_version": 1,
        "sample_id": sample_id,
        "metadata": metadata,
        "artifacts": {
            name: _artifact(*artifacts[name]) for name in sorted(artifacts)
        },
    }
    sys.stdout.write(FRAME_MARKER + json.dumps(frame, separators=(",", ":"), sort_keys=True) + "\n")
    sys.stdout.flush()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--model-seed", required=True, type=int)
    parser.add_argument("--retain-diagnostics", action="store_true",
                        help="retain bounded transcripts for this synthetic playground sample")
    args = parser.parse_args()

    if args.model_seed < 0 or args.model_seed > 0x7FFFFFFF:
        parser.error("--model-seed must be between 0 and 2147483647")
    os.umask(0o077)
    input_path = workspace_input(args.input)
    manifest_hash, aider_version, ollama_version, litellm_version = verify_local_install()
    with tempfile.TemporaryDirectory(prefix="autocage-aider-", dir="/tmp") as temporary:
        private = Path(temporary)
        os.chmod(private, 0o700)
        settings = private / "model-settings.yml"
        settings.write_text(model_settings_content(args.model_seed), encoding="utf-8")
        settings.chmod(0o600)
        chat_history = private / "aider-chat-history.md"
        llm_history = private / "aider-llm-history.log"
        ollama_log = private / "ollama-server.log"
        stdout_path = private / "aider-stdout.bin"
        stderr_path = private / "aider-stderr.bin"
        env = {
            "HOME": str(private / "home"), "TMPDIR": "/tmp",
            "PATH": "/usr/local/venvs/aider/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8", "TERM": "dumb", "NO_COLOR": "1",
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
            "OLLAMA_HOST": "127.0.0.1:11434", "OLLAMA_MODELS": str(MODEL_DIR),
            "OLLAMA_CONTEXT_LENGTH": str(CONTEXT_LENGTH), "OLLAMA_KEEP_ALIVE": "5m",
            "OLLAMA_API_BASE": "http://127.0.0.1:11434",
        }
        (private / "home").mkdir(mode=0o700)
        server = subprocess.Popen([str(OLLAMA), "serve"], env=env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if server.stdout is None:
            raise RuntimeError("Ollama server log stream was not created")
        server_log_result: dict[str, object] = {}
        server_log_thread = threading.Thread(
            target=_drain_bounded,
            args=(server.stdout, CAPTURE_LIMITS["ollama-server.log"], server_log_result),
            daemon=True,
        )
        server_log_thread.start()
        try:
            started = time.monotonic()
            deadline = started + 60
            while time.monotonic() < deadline:
                if server.poll() is not None:
                    raise RuntimeError(f"Ollama exited before readiness ({server.returncode})")
                try:
                    with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=1) as response:
                        if response.status == 200:
                            break
                except OSError:
                    time.sleep(0.25)
            else:
                raise TimeoutError("Ollama did not become ready on sandbox loopback")

            request = urllib.request.Request(
                "http://127.0.0.1:11434/api/show",
                data=json.dumps({"model": MODEL_ID}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                model_info = json.loads(response.read(256 * 1024 + 1))
            if not isinstance(model_info, dict) or len(json.dumps(model_info).encode()) > CAPTURE_LIMITS["ollama-model-info.json"]:
                raise RuntimeError("local Ollama model configuration exceeds the diagnostic limit")

            command = [
                str(AIDER), "--model", MODEL, "--model-settings-file", str(settings),
                "--edit-format", "whole", "--no-git", "--no-analytics", "--yes-always",
                "--map-tokens", "0", "--no-pretty", "--no-auto-commits",
                "--input-history-file", str(private / "input-history"),
                "--chat-history-file", str(chat_history),
                "--read", input_path, "--message", args.task, *EDITABLE_FILES,
            ]
            if args.retain_diagnostics:
                command.extend(["--llm-history-file", str(llm_history), "--verbose"])
            run_started = time.monotonic()
            exit_code, stdout, stderr, stream_sizes = run_bounded(command, env, 256 * 1024)
            elapsed = int((time.monotonic() - run_started) * 1000)
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
            server_log_thread.join(timeout=5)
            if server_log_thread.is_alive():
                raise TimeoutError("Ollama diagnostic log stream did not close")
            stdout_path.write_bytes(stdout)
            stderr_path.write_bytes(stderr)
            metrics = {
                "agent": "Aider", "aider_version": aider_version,
                "ollama_version": ollama_version, "model": MODEL_ID,
                "litellm_version": litellm_version,
                "model_manifest_sha256": manifest_hash,
                "sample_id": args.sample_id, "model_seed": args.model_seed,
                "server_ready_millis": int((time.monotonic() - started) * 1000) - elapsed,
                "agent_elapsed_millis": elapsed,
                "ollama_log_source_bytes": int(server_log_result.get("source_bytes", 0)),
                "ollama_log_truncated": bool(server_log_result.get("truncated", False)),
                "network_mode": "private AutoCage network namespace; Ollama loopback only",
                **stream_sizes,
            }
            print("AUTOCAGE_LOCAL_AGENT_METRICS=" + json.dumps(metrics, sort_keys=True), flush=True)
            if args.retain_diagnostics:
                artifact_data: dict[str, tuple[bytes, int, bool]] = {}
                for name, path in (
                    ("aider-chat-history.md", chat_history),
                    ("aider-llm-history.log", llm_history),
                    ("aider-stdout.bin", stdout_path),
                    ("aider-stderr.bin", stderr_path),
                ):
                    artifact_data[name] = read_bounded(path, CAPTURE_LIMITS[name])
                artifact_data["ollama-server.log"] = (
                    bytes(server_log_result.get("data", b"")),
                    int(server_log_result.get("source_bytes", 0)),
                    bool(server_log_result.get("truncated", False)),
                )
                model_info_bytes = (json.dumps(model_info, sort_keys=True, indent=2) + "\n").encode()
                artifact_data["ollama-model-info.json"] = (
                    model_info_bytes[:CAPTURE_LIMITS["ollama-model-info.json"]],
                    len(model_info_bytes), len(model_info_bytes) > CAPTURE_LIMITS["ollama-model-info.json"],
                )
                effective = {
                    "model": MODEL_ID,
                    "model_manifest_sha256": manifest_hash,
                    "aider_version": aider_version,
                    "ollama_version": ollama_version,
                    "litellm_version": litellm_version,
                    "temperature": TEMPERATURE,
                    "seed": args.model_seed,
                    "num_ctx": CONTEXT_LENGTH,
                    "edit_format": "whole",
                    "aider_verbose": True,
                    "llm_history_semantics": "Aider-formatted TO LLM/LLM RESPONSE; not raw HTTP and not model intent",
                    "ollama_model_parameters": model_info.get("parameters"),
                    "ollama_model_info_sha256": hashlib.sha256(
                        json.dumps(model_info, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest(),
                }
                request_options = _request_options(stdout + b"\n" + stderr)
                effective["aider_request_options_observed"] = request_options
                effective["request_options_complete"] = bool(request_options) and all(
                    value.get("temperature") == TEMPERATURE
                    and value.get("seed") == args.model_seed
                    and value.get("num_ctx") == CONTEXT_LENGTH
                    for value in request_options
                )
                effective_data = (json.dumps(effective, sort_keys=True, indent=2) + "\n").encode()
                artifact_data["effective-settings.json"] = (
                    effective_data[:CAPTURE_LIMITS["effective-settings.json"]],
                    len(effective_data), len(effective_data) > CAPTURE_LIMITS["effective-settings.json"],
                )
                _emit_diagnostics(args.sample_id, {
                    **{key: value for key, value in metrics.items() if key not in stream_sizes},
                    "diagnostic_scope": "synthetic playground only; artifact payloads are untrusted",
                    "exit_code": exit_code,
                    "generation_configuration": effective,
                }, artifact_data)
            else:
                sys.stdout.buffer.write(stdout)
                sys.stdout.buffer.flush()
                sys.stderr.buffer.write(stderr)
                sys.stderr.buffer.flush()
                if stream_sizes["stdout_truncated"] or stream_sizes["stderr_truncated"]:
                    print("Aider console output truncated at 256 KiB per stream.", file=sys.stderr)
            return exit_code
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
            server_log_thread.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
