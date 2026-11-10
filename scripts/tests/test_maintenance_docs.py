from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
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
