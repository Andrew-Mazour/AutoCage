from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import maintenance_docs


def make_repo(root: Path, count: int = 0) -> list[Path]:
    (root / "docs").mkdir(parents=True)
    references = []
    targets = []
    for index in range(count):
        actual = f"Guide{index:02d}.md"
        (root / "docs" / actual).write_text(f"# Guide {index}\n", encoding="utf-8")
        references.append(f"[guide {index}](docs/{actual.lower()})")
        targets.append(f"docs/{actual.lower()}")
    (root / "README.md").write_text("\n".join(references) + "\n", encoding="utf-8")
    return targets


class MaintenanceDocsTests(unittest.TestCase):
    def test_dry_run_does_not_modify_documents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            targets = make_repo(root, 8)
            before = (root / "README.md").read_bytes()
            with patch.object(maintenance_docs, "ROOT", root), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(maintenance_docs.main(["--dry-run", "--date", "2026-11-10", "--json"]), 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["eligible_count"], 8)
            self.assertGreaterEqual(report["selected_count"], 3)
            self.assertLessEqual(report["selected_count"], 8)
            self.assertEqual((root / "README.md").read_bytes(), before)
            self.assertEqual(len(targets), 8)

    def test_selection_is_reproducible_and_bounded_to_three_through_ten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_repo(root, 24)
            candidates = maintenance_docs._scan(root)
            first = maintenance_docs._selection(root, maintenance_docs._utc_date("2026-11-10"), "fixed", candidates)
            second = maintenance_docs._selection(root, maintenance_docs._utc_date("2026-11-10"), "fixed", candidates)
            self.assertEqual(first["selected_count"], second["selected_count"])
            self.assertEqual(first["plan_digest"], second["plan_digest"])
            self.assertGreaterEqual(first["selected_count"], 3)
            self.assertLessEqual(first["selected_count"], 10)

    def test_apply_repairs_only_selected_unambiguous_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_repo(root, 12)
            plan = maintenance_docs._selection(
                root, maintenance_docs._utc_date("2026-11-10"), "fixed", maintenance_docs._scan(root)
            )
            selected = plan["_selected"]
            self.assertGreaterEqual(len(selected), 3)
            self.assertLessEqual(len(selected), 10)
            maintenance_docs._apply(root, plan)
            text = (root / "README.md").read_text(encoding="utf-8")
            for item in selected:
                self.assertIn(item["new_target"], text)
            self.assertEqual(len(maintenance_docs._scan(root)), 12 - len(selected))

    def test_case_mismatch_in_relative_image_link_is_repaired(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "docs/Diagram.SVG").write_text("synthetic image\n")
            document = root / "README.md"
            document.write_text("![diagram](docs/diagram.svg)\n")
            candidates = maintenance_docs._scan(root)
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0]["new_target"], "docs/Diagram.SVG")

    def test_check_diff_rejects_paths_outside_documentation_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "src").mkdir()
            (root / "README.md").write_text("# Initial\n")
            (root / "docs/guide.md").write_text("# Guide\n")
            (root / "src/policy.rs").write_text("fn policy() {}\n")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run([
                "git", "-C", str(root), "-c", "user.name=Test", "-c",
                "user.email=test@example.invalid", "commit", "-qm", "fixture",
            ], check=True)
            output = io.StringIO()
            errors = io.StringIO()
            with patch.object(maintenance_docs, "ROOT", root), redirect_stdout(output), redirect_stderr(errors):
                self.assertEqual(maintenance_docs.main(["--check-diff"]), 0)
                (root / "docs/guide.md").write_text("# Corrected guide\n")
                (root / "src/policy.rs").write_text("fn policy() { panic!() }\n")
                self.assertEqual(maintenance_docs.main(["--check-diff"]), 1)
            self.assertIn("src/policy.rs", errors.getvalue())

    def test_ambiguous_casefold_match_is_not_repaired(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "docs/Foo.md").write_text("upper\n")
            (root / "docs/foo.md").write_text("lower\n")
            document = root / "README.md"
            document.write_text("[ambiguous](docs/FOO.md)\n")
            self.assertEqual(maintenance_docs._scan(root), [])

    def test_code_examples_and_external_links_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs").mkdir()
            (root / "docs/Guide.md").write_text("# Guide\n")
            document = root / "README.md"
            document.write_text(
                "`[inline](docs/guide.md)`\n\n````md\n[block](docs/guide.md)\n````\n"
                "[web](https://example.test/docs/guide.md)\n"
            )
            self.assertEqual(maintenance_docs._scan(root), [])

    def test_path_escape_and_symlink_components_are_not_repaired(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as outside:
            root = Path(temporary)
            (root / "docs").mkdir()
            (Path(outside) / "Guide.md").write_text("outside\n")
            document = root / "README.md"
            document.write_text("[escape](../Guide.md)\n")
            self.assertEqual(maintenance_docs._scan(root), [])
            (root / "outside-link.md").symlink_to(Path(outside) / "Guide.md")
            document.write_text("[linked](outside-link.MD)\n")
            self.assertEqual(maintenance_docs._scan(root), [])

    def test_fewer_than_three_candidates_never_applies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_repo(root, 2)
            before = (root / "README.md").read_bytes()
            with patch.object(maintenance_docs, "ROOT", root), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(maintenance_docs.main(["--apply", "--date", "2026-11-10", "--json"]), 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["selected_count"], 0)
            self.assertFalse(report["applied"])
            self.assertEqual((root / "README.md").read_bytes(), before)

    def test_daily_slot_is_deterministic_and_avoids_exact_hour_start(self) -> None:
        day = maintenance_docs._utc_date("2026-11-10")
        self.assertEqual(maintenance_docs._schedule_slot(day), maintenance_docs._schedule_slot(day))
        self.assertIn(maintenance_docs._schedule_slot(day), {"17 02 * * *", "17 08 * * *", "17 14 * * *", "17 20 * * *"})


if __name__ == "__main__":
    unittest.main()
