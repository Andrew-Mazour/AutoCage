from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


RUNNER_PATH = Path(__file__).with_name("local_aider_runner.py")
spec = importlib.util.spec_from_file_location("local_aider_runner", RUNNER_PATH)
assert spec is not None and spec.loader is not None
runner = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runner
spec.loader.exec_module(runner)


class LocalRunnerTests(unittest.TestCase):
    def test_output_capture_is_bounded_while_fully_draining(self) -> None:
        command = [sys.executable, "-c", "import sys; sys.stdout.write('x' * 10000); sys.stderr.write('e' * 9000)"]
        exit_code, stdout, stderr, sizes = runner.run_bounded(command, dict(__import__("os").environ), 256)
        self.assertEqual(exit_code, 0)
        self.assertEqual(len(stdout), 256)
        self.assertEqual(len(stderr), 256)
        self.assertTrue(sizes["stdout_truncated"])
        self.assertTrue(sizes["stderr_truncated"])
        self.assertEqual(sizes["stdout_source_bytes"], 10000)
        self.assertEqual(sizes["stderr_source_bytes"], 9000)

    def test_aider_verbose_generation_kwargs_are_parsed_without_other_fields(self) -> None:
        raw = b"kwargs: {\"model\": \"ollama_chat/qwen2.5-coder:3b\", \"temperature\": 0.0, \"seed\": 42, \"num_ctx\": 8192, \"api_base\": \"local\"}"
        self.assertEqual(runner._request_options(raw), [{
            "model": "ollama_chat/qwen2.5-coder:3b", "temperature": 0.0,
            "seed": 42, "num_ctx": 8192,
        }])

    def test_effective_model_settings_are_explicit_and_seeded(self) -> None:
        content = runner.model_settings_content(42)
        self.assertIn("edit_format: whole", content)
        self.assertIn("use_temperature: 0.0", content)
        self.assertIn("num_ctx: 8192", content)
        self.assertIn("seed: 42", content)

    def test_pinned_qwen7b_profile_and_manifest_are_explicit(self) -> None:
        profile = runner.MODEL_PROFILES["qwen2.5-coder-7b-q4_k_m"]
        self.assertEqual(profile["model_id"], "qwen2.5-coder:7b-instruct-q4_K_M")
        self.assertEqual(
            profile["manifest_sha256"],
            "4aaba1ee422af93aad53ecbdfc8a159770cf254a9950b7a4304cf9ee3555ef31",
        )
        self.assertEqual(profile["primary_blob_size"], 4_683_074_048)
        settings = runner.model_settings_content(42, str(profile["model"]))
        self.assertIn("ollama_chat/qwen2.5-coder:7b-instruct-q4_K_M", settings)
        self.assertIn("seed: 42", settings)
        self.assertIn("num_ctx: 8192", settings)

    def test_aider_command_receives_declared_context_and_editable_target(self) -> None:
        from pathlib import Path

        command = runner.build_aider_command(
            model="ollama_chat/qwen2.5-coder:7b-instruct-q4_K_M",
            settings=Path("/tmp/model-settings.yml"),
            task="Implement the synthetic validator.",
            read_files=["README.md", "src/data/prices.json", "scripts/fetch_prices.py"],
            editable_files=["scripts/validate_prices.py"],
            chat_history=Path("/tmp/chat.md"),
            input_history=Path("/tmp/input-history"),
            llm_history=Path("/tmp/llm.log"),
        )
        self.assertEqual(command[command.index("--model") + 1],
                         "ollama_chat/qwen2.5-coder:7b-instruct-q4_K_M")
        self.assertEqual(command[command.index("--edit-format") + 1], "whole")
        self.assertEqual(command[command.index("--message") + 1],
                         "Implement the synthetic validator.")
        self.assertIn("scripts/validate_prices.py", command)
        self.assertGreater(command.index("scripts/validate_prices.py"), command.index("--message"))
        self.assertEqual(
            [command[index + 1] for index, value in enumerate(command[:-1]) if value == "--read"],
            ["README.md", "src/data/prices.json", "scripts/fetch_prices.py"],
        )
        self.assertIn("--llm-history-file", command)
        self.assertIn("--verbose", command)

    def test_diagnostic_runner_path_arguments_reject_escape(self) -> None:
        with self.assertRaises(ValueError):
            runner._workspace_relative_file("../outside.py")
        with self.assertRaises(ValueError):
            runner._workspace_relative_file("/etc/passwd")

    def test_each_output_frame_binds_artifacts_to_sample_identity(self) -> None:
        import contextlib
        import io
        import json

        target = io.StringIO()
        with contextlib.redirect_stdout(target):
            runner._emit_diagnostics("sample-x", {"sample_id": "sample-x"}, {
                "aider-stdout.bin": (b"synthetic", 9, False),
            })
        line = target.getvalue().strip()
        self.assertTrue(line.startswith(runner.FRAME_MARKER))
        frame = json.loads(line[len(runner.FRAME_MARKER):])
        self.assertEqual(frame["sample_id"], "sample-x")
        self.assertEqual(frame["artifacts"]["aider-stdout.bin"]["captured_bytes"], 9)


if __name__ == "__main__":
    unittest.main()
