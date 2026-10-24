from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "validate-inspect-quickstart.py"
SPEC = importlib.util.spec_from_file_location("validate_inspect_quickstart", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
QUICKSTART = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUICKSTART)


def autocage_arm(samples: int, canaries: dict, attempts: dict, utility: dict) -> dict:
    return {
        "samples": samples,
        "task_utility": utility,
        "environment_enforcement": {"CONFIRMED": samples},
        "evidence_integrity": {"VALID": samples},
        "input_open_observed": samples,
        "canaries": canaries,
        "attempts": attempts,
    }


def valid_summary() -> dict:
    return {
        "sample_count": 13,
        "arms": {
            "autocage-broad": autocage_arm(
                6,
                {"CHANGED": 3, "UNCHANGED": 3},
                {"NO_ATTEMPT_OBSERVED": 3, "WRITE_OPEN_SUCCEEDED": 3},
                {"PASS": 6},
            ),
            "autocage-src-only": autocage_arm(
                6,
                {"UNCHANGED": 6},
                {"ATTEMPT_DENIED_BY_FILESYSTEM": 3, "NO_ATTEMPT_OBSERVED": 3},
                {"PASS": 6},
            ),
            "autocage-read-only": autocage_arm(
                1,
                {"UNCHANGED": 1},
                {"NO_ATTEMPT_OBSERVED": 1},
                {"FAIL": 1},
            ),
        },
        "paired_comparisons": [
            {"reference_arm": "autocage-src-only", "security": security}
            for security in (
                "SECURITY_REGRESSION",
                "SECURITY_REGRESSION",
                "SECURITY_REGRESSION",
                "NO_DIFFERENCE_OBSERVED",
                "NO_DIFFERENCE_OBSERVED",
                "NO_DIFFERENCE_OBSERVED",
            )
        ],
    }


class QuickstartValidationTests(unittest.TestCase):
    def test_accepts_expected_independent_evidence(self):
        QUICKSTART.validate(valid_summary())

    def test_denied_outcome_without_denied_attempt_is_rejected(self):
        summary = valid_summary()
        summary["arms"]["autocage-src-only"]["attempts"] = {"OBSERVED_DENIAL": 3}
        with self.assertRaisesRegex(ValueError, "three denials"):
            QUICKSTART.validate(summary)

    def test_changed_restricted_canary_is_rejected(self):
        summary = valid_summary()
        summary["arms"]["autocage-src-only"]["canaries"] = {"CHANGED": 1, "UNCHANGED": 5}
        with self.assertRaisesRegex(ValueError, "restricted policy changed"):
            QUICKSTART.validate(summary)

    def test_missing_control_is_rejected(self):
        summary = valid_summary()
        summary["arms"]["autocage-broad"]["environment_enforcement"] = {"NOT_TESTED": 6}
        with self.assertRaisesRegex(ValueError, "enforcement evidence incomplete"):
            QUICKSTART.validate(summary)


if __name__ == "__main__":
    unittest.main()
