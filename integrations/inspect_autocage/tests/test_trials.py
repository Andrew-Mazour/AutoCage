from __future__ import annotations

import unittest
import tempfile
from pathlib import Path

from autocage_inspect.trials import CONDITIONS, build_pilot, build_trial_schedule, persist_trial_plan


class TrialScheduleTests(unittest.TestCase):
    def test_schedule_is_reproducible_and_balanced(self) -> None:
        first = build_trial_schedule(
            repetitions=4, schedule_seed=7813, experiment_id="pilot-run"
        )
        second = build_trial_schedule(
            repetitions=4, schedule_seed=7813, experiment_id="pilot-run"
        )
        self.assertEqual(first, second)
        self.assertEqual(len(first), 16)
        for index in range(4):
            block = first[index * 4:(index + 1) * 4]
            self.assertEqual({(item["variant"], item["arm"]) for item in block}, set(CONDITIONS))
            self.assertEqual({item["trial_order"] for item in block}, {1, 2, 3, 4})
            self.assertEqual(len({item["model_seed"] for item in block}), 1)
        self.assertEqual(
            [sorted(item["condition"] for item in first[i * 4:(i + 1) * 4]) for i in range(4)],
            [sorted(f"{variant}-{arm}" for variant, arm in CONDITIONS)] * 4,
        )
        for position in range(4):
            self.assertEqual(
                len({first[rep * 4 + position]["condition"] for rep in range(4)}), 4
            )

    def test_pilot_is_one_clean_narrow_sample(self) -> None:
        pilot = build_pilot(schedule_seed=11, experiment_id="smoke")
        self.assertEqual(pilot["variant"], "clean")
        self.assertEqual(pilot["arm"], "autocage-narrower")
        self.assertEqual(pilot["plan_kind"], "single-sample-pilot")

    def test_invalid_schedule_inputs_fail(self) -> None:
        for kwargs in (
            {"repetitions": 0, "schedule_seed": 1, "experiment_id": "x"},
            {"repetitions": 1, "schedule_seed": -1, "experiment_id": "x"},
            {"repetitions": 1, "schedule_seed": 1, "experiment_id": "../x"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                build_trial_schedule(**kwargs)

    def test_plan_is_exclusive_and_written_with_restrictive_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            schedule = build_trial_schedule(
                repetitions=1, schedule_seed=5, experiment_id="frozen"
            )
            written = persist_trial_plan(
                work_root=temporary, experiment_id="frozen", schedule=schedule,
                scenario_identity={"scenario_sha256": "a" * 64},
                retain_agent_diagnostics=True,
            )
            assert written is not None
            self.assertEqual(Path(written["path"]).stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                persist_trial_plan(
                    work_root=temporary, experiment_id="frozen", schedule=schedule,
                    scenario_identity={"scenario_sha256": "a" * 64},
                    retain_agent_diagnostics=True,
                )


if __name__ == "__main__":
    unittest.main()
