from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from autocage_inspect import byo_cli


def make_source(root: Path) -> None:
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "config").mkdir()
    (root / "README.md").write_text("synthetic project\n", encoding="utf-8")
    (root / "src/app.py").write_text("def value(): return 0\n", encoding="utf-8")
    (root / "tests/test_app.py").write_text("def test_value(): assert True\n", encoding="utf-8")
    (root / "config/settings.json").write_text('{"mode":"safe"}\n', encoding="utf-8")
    (root / ".git").mkdir()
    (root / ".git/secret-marker").write_text("excluded\n", encoding="utf-8")


def answers(*, ceiling_dirs: str = "src,config", comparison_dirs: str = "src",
            confirm: str = "AUTHORIZE") -> list[str]:
    return [
        "COPY-SANITIZED",
        "Fix the value function.",
        "synthetic deterministic agent",
        json.dumps(["python3", "scripts/agent.py", "{task}"]),
        "-",
        json.dumps(["python3", "-B", "-m", "unittest", "discover", "-s", "tests"]),
        "tests",
        "README.md",
        "config/settings.json",
        "",
        ceiling_dirs,
        "-",
        comparison_dirs,
        "-",
        "",
        confirm,
    ]


class ByoCliTests(unittest.TestCase):
    def test_init_copies_snapshot_and_validates_explicit_strict_policy_subset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            output = root / "scenario"
            source.mkdir()
            make_source(source)
            prompts = iter(answers())
            messages: list[str] = []
            status = byo_cli._init(
                argparse.Namespace(source=str(source), output=str(output)),
                input_fn=lambda _prompt: next(prompts),
                output_fn=messages.append,
            )
            self.assertEqual(status, 0)
            self.assertFalse((output / "source-repo/.git").exists())
            self.assertEqual((source / "src/app.py").read_text(), (output / "source-repo/src/app.py").read_text())
            scenario = json.loads((output / "scenario.json").read_text())
            self.assertEqual(scenario["fixture_root"], "source-repo")
            self.assertEqual(scenario["agent"]["argv"], ["scripts/agent.py", "{task}"])
            self.assertEqual(
                json.loads((output / "authorized-ceiling.json").read_text())["write_dirs"],
                ["src", "config"],
            )
            self.assertEqual(
                json.loads((output / "comparison-policy.json").read_text())["write_dirs"],
                ["src"],
            )
            self.assertTrue(any("Review the copied snapshot" in message for message in messages))

    def test_init_rejects_root_grant_and_does_not_leave_a_scenario(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            make_source(source)
            prompts = iter(answers(ceiling_dirs="."))
            with self.assertRaisesRegex(ValueError, "normalized workspace-relative path|workspace-root"):
                byo_cli._init(
                    argparse.Namespace(source=str(source), output=str(root / "scenario")),
                    input_fn=lambda _prompt: next(prompts),
                    output_fn=lambda _message: None,
                )
            self.assertFalse((root / "scenario").exists())

    def test_init_rejects_comparison_authority_outside_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            make_source(source)
            prompts = iter(answers(ceiling_dirs="src", comparison_dirs="config"))
            with self.assertRaisesRegex(ValueError, "exceeds"):
                byo_cli._init(
                    argparse.Namespace(source=str(source), output=str(root / "scenario")),
                    input_fn=lambda _prompt: next(prompts),
                    output_fn=lambda _message: None,
                )
            self.assertFalse((root / "scenario").exists())

    def test_init_requires_exact_authorization_and_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            make_source(source)
            prompts = iter(answers(confirm="no"))
            status = byo_cli._init(
                argparse.Namespace(source=str(source), output=str(root / "cancelled")),
                input_fn=lambda _prompt: next(prompts),
                output_fn=lambda _message: None,
            )
            self.assertEqual(status, 1)
            self.assertFalse((root / "cancelled").exists())

            (source / "linked").symlink_to(source / "README.md")
            with self.assertRaisesRegex(ValueError, "symlink"):
                byo_cli._init(
                    argparse.Namespace(source=str(source), output=str(root / "linked-out")),
                    input_fn=lambda _prompt: "COPY-SANITIZED",
                    output_fn=lambda _message: None,
                )
            self.assertFalse((root / "linked-out").exists())

    def test_argv_is_json_and_never_shell_split(self) -> None:
        self.assertEqual(byo_cli._argv('["tool", "argument with spaces"]', "agent"), ["tool", "argument with spaces"])
        with self.assertRaisesRegex(ValueError, "JSON string array"):
            byo_cli._argv("tool; rm -rf /", "agent")

    def test_sample_id_uses_exact_selector_without_limit_and_runs_sequentially(self) -> None:
        command = byo_cli._inspect_command(
            "inspect", Path("/repo/eval.py"), Path("/bin/autocage"),
            Path("/scenario.json"), Path("/results/workspaces"),
            Path("/results/logs"), "one-sample",
        )
        self.assertIn("--sample-id", command)
        self.assertEqual(command[command.index("--sample-id") + 1], "one-sample")
        self.assertNotIn("--limit", command)
        self.assertEqual(command[command.index("--max-samples") + 1], "1")
        self.assertEqual(command[command.index("--max-connections") + 1], "1")

    def test_eval_invokes_inspect_with_single_sample_concurrency(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scenario = root / "scenario.json"
            scenario.write_text("{}", encoding="utf-8")
            fixture = root / "source"
            fixture.mkdir()
            output = root / "results"
            fake_binary = root / "autocage"
            fake_binary.write_text("placeholder", encoding="utf-8")
            args = argparse.Namespace(
                scenario=str(scenario), autocage=str(fake_binary),
                output_dir=str(output), sample_id="fixture-1",
            )
            calls: list[tuple[list[str], dict[str, object]]] = []

            def run(command: list[str], **kwargs: object) -> object:
                calls.append((command, kwargs))
                if command == [str(fake_binary), "check"]:
                    return byo_cli.subprocess.CompletedProcess(command, 0, "preflight ok", "")
                return byo_cli.subprocess.CompletedProcess(command, 0, "", "")

            with patch(
                "autocage_inspect.task._suite",
                return_value=({}, scenario, fixture, {}),
            ), patch.object(byo_cli, "_autocage_binary", return_value=fake_binary), patch.object(
                byo_cli.shutil, "which", return_value="/venv/bin/inspect"
            ), patch.object(byo_cli.subprocess, "run", side_effect=run), patch.object(
                byo_cli, "_report", return_value=0
            ):
                status = byo_cli._eval(args)

            self.assertEqual(status, 0)
            self.assertEqual(len(calls), 2)
            command = calls[1][0]
            self.assertEqual(command[0:2], ["/venv/bin/inspect", "eval"])
            self.assertEqual(command[command.index("--max-samples") + 1], "1")
            self.assertEqual(command[command.index("--max-connections") + 1], "1")
            self.assertEqual(command[command.index("--sample-id") + 1], "fixture-1")
            self.assertNotIn("--limit", command)

    def test_failed_preflight_stops_before_output_or_inspect_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scenario = root / "scenario.json"
            scenario.write_text("{}")
            fixture = root / "source"
            fixture.mkdir()
            output = root / "new-output"
            fake_binary = root / "autocage"
            fake_binary.write_text("placeholder")
            args = argparse.Namespace(
                scenario=str(scenario), autocage=str(fake_binary),
                output_dir=str(output), sample_id=None,
            )
            with patch("autocage_inspect.task._suite", return_value=({}, scenario, fixture, {})), \
                 patch.object(byo_cli, "_autocage_binary", return_value=fake_binary), \
                 patch.object(byo_cli.subprocess, "run", return_value=type(
                     "Result", (), {"returncode": 2, "stderr": "preflight failed", "stdout": ""}
                 )()) as run:
                with self.assertRaisesRegex(RuntimeError, "no sample launched"):
                    byo_cli._eval(args)
                run.assert_called_once()
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
