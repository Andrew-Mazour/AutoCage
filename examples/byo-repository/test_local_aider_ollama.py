from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("local_aider_ollama.py")
SPEC = importlib.util.spec_from_file_location("local_aider_ollama", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class _Response:
    status = 200

    def __init__(self, value: object):
        self.value = json.dumps(value).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit: int) -> bytes:
        return self.value[:limit]


class _Server:
    pid = 98765

    def __init__(self):
        self.running = True
        self.terminated = False

    def poll(self):
        return None if self.running else 0

    def terminate(self):
        self.terminated = True
        self.running = False

    def wait(self, timeout: int):
        return 0

    def kill(self):
        self.running = False


class LocalAiderOllamaTests(unittest.TestCase):
    def test_agent_command_is_shell_free_and_never_retains_transcripts(self) -> None:
        command = runner._aider_command(
            Path("/usr/bin/aider"), "ollama_chat/model:tag",
            Path("/tmp/settings.yml"), Path("/tmp/empty.yml"),
            "fix one function", ["README.md"], ["src/module.py"], "whole",
        )
        self.assertIn("--no-git", command)
        self.assertIn("--no-analytics", command)
        self.assertIn("--no-auto-commits", command)
        self.assertNotIn("--llm-history-file", command)
        self.assertEqual(command[command.index("--chat-history-file") + 1], "/dev/null")
        self.assertEqual(command[command.index("--input-history-file") + 1], "/dev/null")
        self.assertEqual(command[command.index("--env-file") + 1], "/dev/null")
        self.assertEqual(command[command.index("--config") + 1], "/tmp/empty.yml")
        self.assertEqual(command[-1], "src/module.py")

    def test_generation_settings_are_explicit_and_model_agnostic(self) -> None:
        content = runner._settings("ollama_chat/example:tag", "diff", 0.25, 4096, 123)
        self.assertIn("- name: ollama_chat/example:tag", content)
        self.assertIn("edit_format: diff", content)
        self.assertIn("use_temperature: 0.25", content)
        self.assertIn("num_ctx: 4096", content)
        self.assertIn("seed: 123", content)

    def test_model_tag_rejects_yaml_or_argument_injection(self) -> None:
        for value in ("model\nextra: yes", "../model", "model;pull", ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                runner._validate_model_tag(value)

    def test_local_model_must_be_listed_by_the_loopback_ollama_server(self) -> None:
        with patch.object(runner.urllib.request, "urlopen", return_value=_Response({
            "models": [{"name": "already-installed:latest"}],
        })):
            self.assertTrue(runner._model_is_installed("already-installed:latest"))
            self.assertFalse(runner._model_is_installed("missing:latest"))

    def test_version_output_extracts_installed_tool_versions(self) -> None:
        with patch.object(runner.subprocess, "run", return_value=subprocess.CompletedProcess(
            ["ollama", "--version"], 0,
            "Warning: could not connect to a running Ollama instance\\nWarning: client version is 0.40.4\\n",
            "",
        )):
            self.assertEqual(
                runner._version(Path("/usr/bin/ollama"), {}, "Ollama"),
                "0.40.4",
            )

    def test_model_response_schema_is_fail_closed(self) -> None:
        with patch.object(runner.urllib.request, "urlopen", return_value=_Response({"items": []})):
            with self.assertRaisesRegex(RuntimeError, "unsupported schema"):
                runner._model_is_installed("model")

    def test_paths_reject_traversal_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src" / "file.py").write_text("x")
            (root / "link.py").symlink_to(root / "src" / "file.py")
            prior = Path.cwd()
            os.chdir(root)
            try:
                self.assertEqual(runner._workspace_file("src/file.py", allow_new=False), "src/file.py")
                with self.assertRaisesRegex(ValueError, "normalized"):
                    runner._workspace_file("../outside.py", allow_new=False)
                with self.assertRaisesRegex(ValueError, "symlink"):
                    runner._workspace_file("link.py", allow_new=False)
                with self.assertRaisesRegex(ValueError, "parent does not exist"):
                    runner._workspace_file("missing/new.py", allow_new=True)
                self.assertEqual(runner._workspace_file("src/new.py", allow_new=True), "src/new.py")
            finally:
                os.chdir(prior)

    def test_environment_is_allowlisted_and_has_loopback_only_ollama(self) -> None:
        env = runner._clean_environment(Path("/tmp/private-home"), Path("/models"), 8192)
        self.assertEqual(env["OLLAMA_HOST"], "127.0.0.1:11434")
        self.assertEqual(env["OLLAMA_API_BASE"], "http://127.0.0.1:11434")
        self.assertEqual(set(env), {
            "HOME", "TMPDIR", "PATH", "LANG", "TERM", "NO_COLOR",
            "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "OLLAMA_HOST",
            "OLLAMA_MODELS", "OLLAMA_CONTEXT_LENGTH", "OLLAMA_KEEP_ALIVE",
            "OLLAMA_API_BASE",
        })
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn("HTTP_PROXY", env)
        self.assertEqual(env["HOME"], "/tmp/private-home")

    def test_fake_local_runtime_executes_aider_and_emits_only_operational_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src" / "module.py").write_text("def value(): return 1\n")
            model_store = root / "models"
            model_store.mkdir()
            prior = Path.cwd()
            os.chdir(root)
            server = _Server()
            calls: list[list[str]] = []

            def run(command, **kwargs):
                calls.append(command)
                if command[-1] == "--version":
                    value = "aider 0.86.2" if "aider" in command[0] else "ollama version is 0.40.4"
                    return subprocess.CompletedProcess(command, 0, value, "")
                return subprocess.CompletedProcess(command, 0, "", "")

            try:
                with patch.object(runner, "MODEL_STORE", model_store), \
                     patch.object(runner, "_program", side_effect=lambda value, _label: Path(value)), \
                     patch.object(runner.subprocess, "Popen", return_value=server) as popen, \
                     patch.object(runner.subprocess, "run", side_effect=run), \
                     patch.object(runner.urllib.request, "urlopen", return_value=_Response({
                         "models": [{"name": "test:local"}],
                     })), \
                     contextlib.redirect_stdout(io.StringIO()) as stdout, \
                     contextlib.redirect_stderr(io.StringIO()):
                    status = runner.main([
                        "--task", "fix src/module.py", "--model-tag", "test:local",
                        "--editable-file", "src/module.py", "--aider-bin", "/usr/bin/aider",
                        "--ollama-bin", "/usr/bin/ollama",
                    ])
                self.assertEqual(status, 0)
                self.assertTrue(server.terminated)
                self.assertFalse(popen.call_args.kwargs.get("start_new_session", False))
                self.assertEqual(len(calls), 3)
                agent_command = calls[2]
                self.assertEqual(agent_command[agent_command.index("--model") + 1], "ollama_chat/test:local")
                self.assertEqual(agent_command[agent_command.index("--edit-format") + 1], "whole")
                self.assertEqual(agent_command[-1], "src/module.py")
                marker = next(line for line in stdout.getvalue().splitlines()
                              if line.startswith(runner.METRICS_MARKER))
                metrics = json.loads(marker[len(runner.METRICS_MARKER):])
                self.assertEqual(metrics["model"], "test:local")
                self.assertEqual(metrics["aider_version"], "aider 0.86.2")
                self.assertNotIn("response", metrics)
            finally:
                os.chdir(prior)

    def test_missing_model_aborts_before_aider_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src" / "module.py").write_text("x")
            model_store = root / "models"
            model_store.mkdir()
            prior = Path.cwd()
            os.chdir(root)
            server = _Server()
            run_calls: list[list[str]] = []

            def run(command, **kwargs):
                run_calls.append(command)
                value = "aider 0.86.2" if "aider" in command[0] else "ollama 0.40.4"
                return subprocess.CompletedProcess(command, 0, value, "")

            try:
                with patch.object(runner, "MODEL_STORE", model_store), \
                     patch.object(runner, "_program", side_effect=lambda value, _label: Path(value)), \
                     patch.object(runner.subprocess, "Popen", return_value=server), \
                     patch.object(runner.subprocess, "run", side_effect=run), \
                     patch.object(runner.urllib.request, "urlopen", return_value=_Response({"models": []})), \
                     contextlib.redirect_stderr(io.StringIO()):
                    status = runner.main([
                        "--task", "fix", "--model-tag", "missing:tag",
                        "--editable-file", "src/module.py", "--aider-bin", "/usr/bin/aider",
                        "--ollama-bin", "/usr/bin/ollama",
                    ])
                self.assertEqual(status, 2)
                self.assertTrue(server.terminated)
                self.assertEqual(len(run_calls), 2)
                self.assertTrue(all(call[-1] == "--version" for call in run_calls))
            finally:
                os.chdir(prior)


if __name__ == "__main__":
    unittest.main()
