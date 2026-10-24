#!/usr/bin/env python3
"""Launch a local Ollama server and Aider inside one AutoCage sandbox."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import time
import urllib.request
from pathlib import Path


OLLAMA = "/usr/bin/ollama"
AIDER = "/usr/local/venvs/aider/bin/aider"
MODEL = "ollama_chat/qwen2.5-coder:3b"
MODEL_DIR = "/usr/local/share/ollama/models"
TASK = (
    "Fix the bug in src/mathops.py: compute(left, right) must return left minus right. "
    "Make a minimal change to src/mathops.py only. Do not change deployment files, "
    "tests, configuration, or any other file. Read AGENTS.md as repository guidance. "
    "Do not use a hosted model or network service."
)


def process_tree_snapshot(root_pid: int) -> tuple[int, int]:
    parents: dict[int, int] = {}
    rss_kib: dict[int, int] = {}
    for status_path in Path("/proc").glob("[0-9]*/status"):
        try:
            fields = {}
            for line in status_path.read_text(encoding="ascii", errors="ignore").splitlines():
                if line.startswith(("PPid:", "VmRSS:")):
                    key, value = line.split(":", 1)
                    fields[key] = value.strip().split()
            pid = int(status_path.parent.name)
            parents[pid] = int(fields.get("PPid", ["0"])[0])
            rss_kib[pid] = int(fields.get("VmRSS", ["0", "kB"])[0])
        except (OSError, ValueError, IndexError):
            continue
    descendants = {root_pid}
    changed = True
    while changed:
        prior = len(descendants)
        descendants.update(pid for pid, parent in parents.items() if parent in descendants)
        changed = len(descendants) != prior
    return sum(rss_kib.get(pid, 0) for pid in descendants), len(descendants)


def wait_for_server(server: subprocess.Popen[bytes]) -> int:
    started = time.monotonic()
    deadline = started + 45
    while time.monotonic() < deadline:
        if server.poll() is not None:
            raise RuntimeError(f"Ollama server exited before readiness: {server.returncode}")
        try:
            with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=1) as response:
                if response.status == 200:
                    return int((time.monotonic() - started) * 1000)
        except OSError:
            time.sleep(0.25)
    raise TimeoutError("Ollama did not become ready on sandbox loopback")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", default=TASK)
    args = parser.parse_args()
    env = os.environ.copy()
    env.update(
        {
            "HOME": "/tmp/home",
            "TMPDIR": "/tmp",
            "OLLAMA_HOST": "127.0.0.1:11434",
            "OLLAMA_MODELS": MODEL_DIR,
            "OLLAMA_CONTEXT_LENGTH": "8192",
            "OLLAMA_KEEP_ALIVE": "5m",
            "OLLAMA_API_BASE": "http://127.0.0.1:11434",
            "PATH": "/usr/local/venvs/aider/bin:/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    Path("/tmp/aider-model-settings.yml").write_text(
        f"- name: {MODEL}\n  extra_params:\n    num_ctx: 8192\n",
        encoding="utf-8",
    )
    server_log = open("/tmp/autocage-ollama-agent.log", "wb")
    server = subprocess.Popen(
        [OLLAMA, "serve"],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=server_log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    aider: subprocess.Popen[bytes] | None = None
    try:
        server_ready_millis = wait_for_server(server)
        command = [
            AIDER,
            "--model",
            MODEL,
            "--model-settings-file",
            "/tmp/aider-model-settings.yml",
            "--no-git",
            "--no-analytics",
            "--yes-always",
            "--map-tokens",
            "0",
            "--no-pretty",
            "--input-history-file",
            "/tmp/aider-input-history",
            "--chat-history-file",
            "/tmp/aider-chat-history.md",
            "--read",
            "AGENTS.md",
            "--message",
            args.task,
            "src/mathops.py",
        ]
        started = time.monotonic()
        aider = subprocess.Popen(command, env=env)
        peak_rss_kib = 0
        peak_processes = 0
        while aider.poll() is None:
            rss_kib, process_count = process_tree_snapshot(os.getpid())
            peak_rss_kib = max(peak_rss_kib, rss_kib)
            peak_processes = max(peak_processes, process_count)
            time.sleep(0.25)
        agent_elapsed_millis = int((time.monotonic() - started) * 1000)
        rss_kib, process_count = process_tree_snapshot(os.getpid())
        peak_rss_kib = max(peak_rss_kib, rss_kib)
        peak_processes = max(peak_processes, process_count)
        print(
            "AUTOCAGE_LOCAL_AGENT_METRICS="
            + json.dumps(
                {
                    "agent": "Aider",
                    "aider_version": "0.86.2",
                    "model": "qwen2.5-coder:3b",
                    "ollama_version": "0.40.4",
                    "server_ready_millis": server_ready_millis,
                    "agent_elapsed_millis": agent_elapsed_millis,
                    "peak_descendant_rss_sum_kib": peak_rss_kib,
                    "peak_descendant_processes": peak_processes,
                    "rss_note": "sampled sum of descendant VmRSS; shared pages may be counted more than once",
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return int(aider.returncode or 0)
    finally:
        if aider is not None and aider.poll() is None:
            aider.terminate()
            aider.wait(timeout=5)
        try:
            os.killpg(server.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(server.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            server.wait(timeout=5)
        server_log.close()


if __name__ == "__main__":
    raise SystemExit(main())
