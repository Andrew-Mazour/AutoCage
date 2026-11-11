from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from autocage_inspect.execution import (
    _agent_execution_classification,
    _parse_agent_signal,
    _base_evidence,
)
from autocage_inspect.task import _suite, _m81_diagnostic_profile_allowed

SUMMARY_PATH = Path(__file__).resolve().parents[3] / "experiments/inspect-autocage-v1/summarize.py"
SUMMARY_SPEC = importlib.util.spec_from_file_location("autocage_m81_summary", SUMMARY_PATH)
assert SUMMARY_SPEC is not None and SUMMARY_SPEC.loader is not None
summary = importlib.util.module_from_spec(SUMMARY_SPEC)
SUMMARY_SPEC.loader.exec_module(summary)


def record(*, exit_code: int = 0, timed_out: bool = False,
           changed_paths: list[str] | None = None,
           before: str = "1" * 64, after: str = "1" * 64,
           verifier_exit: int | None = 0, verifier_timed_out: bool = False) -> dict:
    paths = [] if changed_paths is None else changed_paths
    value = {
        "outcome": "verified" if verifier_exit == 0 else "verifier_failed",
        "agent": {"exit_code": exit_code, "timed_out": timed_out, "elapsed_millis": 1234},
        "workspace": {
            "before_manifest_sha256": before,
            "after_manifest_sha256": after,
            "changed_paths": paths,
        },
        "verifier": None,
    }
    if verifier_exit is not None:
        value["verifier"] = {
            "exit_code": verifier_exit,
            "timed_out": verifier_timed_out,
        }
    return value


OBSERVED_NO_ATTEMPT = {
    "state": "OBSERVED",
    "protected_write_attempt": "NO_ATTEMPT_OBSERVED",
}
OBSERVED_DENIAL = {
    "state": "OBSERVED",
    "protected_write_attempt": "ATTEMPT_DENIED_BY_FILESYSTEM",
}


class AgentExecutionOutcomeTests(unittest.TestCase):
    def test_edited_and_verified_is_distinct_from_process_exit_zero(self):
        result = _agent_execution_classification(
            record(changed_paths=["src/calculator.py"], before="1" * 64, after="2" * 64),
            record_valid=True,
            trace=OBSERVED_NO_ATTEMPT,
        )
        self.assertEqual(result["agent_process"], "COMPLETED")
        self.assertEqual(result["final_workspace_delta"], "FINAL_CHANGES_OBSERVED")
        self.assertEqual(result["verifier"], "PASSED")
        self.assertEqual(result["classification"], "EDITS_VERIFIED")
        self.assertEqual(result["changed_paths"], ["src/calculator.py"])

    def test_zero_exit_with_no_final_edit_and_failed_verifier_is_no_observable_edits(self):
        result = _agent_execution_classification(
            record(verifier_exit=1), record_valid=True, trace=OBSERVED_NO_ATTEMPT
        )
        self.assertEqual(result["agent_process"], "COMPLETED")
        self.assertEqual(result["final_workspace_delta"], "NO_FINAL_CHANGES_OBSERVED")
        self.assertEqual(result["verifier"], "FAILED")
        self.assertEqual(result["classification"], "NO_OBSERVABLE_EDITS")
        self.assertEqual(result["protected_write_observation"], "NO_ATTEMPT_OBSERVED")
        self.assertNotIn("denied", result["classification"].lower())

    def test_denied_protected_write_is_separate_from_task_utility(self):
        result = _agent_execution_classification(
            record(verifier_exit=1), record_valid=True, trace=OBSERVED_DENIAL
        )
        self.assertEqual(result["classification"], "NO_OBSERVABLE_EDITS")
        self.assertEqual(result["protected_write_observation"], "DENIED")

    def test_edits_followed_by_verifier_failure_are_classified(self):
        result = _agent_execution_classification(
            record(changed_paths=["src/calculator.py"], before="1" * 64,
                   after="2" * 64, verifier_exit=1),
            record_valid=True, trace=OBSERVED_NO_ATTEMPT,
        )
        self.assertEqual(result["classification"], "EDITS_VERIFIER_FAILED")

    def test_no_edits_can_still_be_a_verified_read_only_task(self):
        result = _agent_execution_classification(
            record(verifier_exit=0), record_valid=True, trace=OBSERVED_NO_ATTEMPT
        )
        self.assertEqual(result["classification"], "NO_EDITS_VERIFIER_PASSED")

    def test_agent_timeout_and_nonzero_exit_are_not_success(self):
        timed_out = _agent_execution_classification(
            record(exit_code=124, timed_out=True, verifier_exit=None),
            record_valid=True, trace={"state": "OBSERVATION_UNAVAILABLE"},
        )
        failed = _agent_execution_classification(
            record(exit_code=2, verifier_exit=None),
            record_valid=True, trace={"state": "OBSERVATION_UNAVAILABLE"},
        )
        self.assertEqual(timed_out["classification"], "AGENT_TIMED_OUT")
        self.assertEqual(failed["classification"], "AGENT_PROCESS_FAILED")
        self.assertEqual(failed["verifier"], "NOT_RUN_AGENT_FAILED")

    def test_invalid_record_and_inconsistent_manifest_are_inconclusive(self):
        invalid = _agent_execution_classification(
            record(), record_valid=False, trace=OBSERVED_NO_ATTEMPT
        )
        inconsistent = _agent_execution_classification(
            record(changed_paths=[], before="1" * 64, after="2" * 64),
            record_valid=True, trace=OBSERVED_NO_ATTEMPT,
        )
        self.assertEqual(invalid["classification"], "EVIDENCE_UNAVAILABLE")
        self.assertEqual(inconsistent["classification"], "EVIDENCE_INCONSISTENT")

    def test_stdout_markers_cannot_persist_arbitrary_text(self):
        raw = (
            'AUTOCAGE_LOCAL_AGENT_METRICS={"agent":"Aider","model":"qwen2.5-coder:7b",'
            '"agent_elapsed_millis":70000,"private_prompt":"do not persist this"}'
        )
        parsed = _parse_agent_signal(raw, "AUTOCAGE_LOCAL_AGENT_METRICS=")
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed["agent_elapsed_millis"], 70000)
        self.assertEqual(parsed["omitted_field_count"], 1)
        self.assertNotIn("private_prompt", json.dumps(parsed))
        self.assertNotIn("do not persist this", json.dumps(parsed))

    def test_legacy_valid_no_edit_record_is_classified_without_claiming_seal_revalidation(self):
        row = {
            "evidence_integrity": "VALID",
            "record": record(verifier_exit=1),
            "trace": OBSERVED_NO_ATTEMPT,
        }
        result = summary._agent_execution(row)
        self.assertEqual(result["classification"], "NO_OBSERVABLE_EDITS")
        self.assertEqual(result["agent_process"], "COMPLETED")
        self.assertEqual(result["process_exit_code"], 0)
        self.assertEqual(result["verifier"], "FAILED")
        self.assertEqual(result["protected_write_observation"], "NO_ATTEMPT_OBSERVED")
        self.assertIn("does not revalidate", result["source"])
        self.assertEqual(
            summary._agent_execution({**row, "evidence_integrity": "INVALID"})["classification"],
            "EVIDENCE_UNAVAILABLE",
        )

    def test_base_result_marks_transcripts_disabled_and_keeps_no_output_text(self):
        evidence = _base_evidence(
            "sample",
            {
                "case": {"case_id": "synthetic", "input_path": "README.md",
                         "protected_path": "config/settings.json",
                         "canary_initial": {"sha256": "0" * 64}},
                "scenario_identity": {},
                "write_policies": {},
                "scenario_id": "synthetic",
                "variant": "clean",
                "arm": "autocage-narrower",
                "task_text": "synthetic",
                "policy_comparison": None,
            },
            Path("/tmp/autocage-m81-test"),
        )
        self.assertEqual(evidence["agent_diagnostics"]["status"], "DISABLED")
        self.assertEqual(evidence["agent_execution"]["classification"],
                         "AGENT_LAUNCH_NOT_CONFIRMED")
        self.assertNotIn("stdout", evidence)
        self.assertNotIn("stderr", evidence)

    def test_retention_is_allowlisted_only_for_the_hash_pinned_fixture(self):
        path = Path(__file__).resolve().parents[3] / "experiments/agent-execution-v1/scenarios/qwen7b-calculator.json"
        suite, scenario_path, fixture_root, scenario = _suite(str(path))
        self.assertTrue(_m81_diagnostic_profile_allowed(suite, scenario_path, fixture_root, scenario))
        with tempfile.TemporaryDirectory() as temporary:
            moved_scenario = Path(temporary) / path.name
            moved_scenario.write_bytes(path.read_bytes())
            self.assertFalse(
                _m81_diagnostic_profile_allowed(suite, moved_scenario, fixture_root, scenario)
            )


if __name__ == "__main__":
    unittest.main()
