#!/usr/bin/env python3
"""Recompute M3.5 summaries from immutable per-task JSON artifacts."""
from __future__ import annotations

import argparse
import json
import math
import statistics
from pathlib import Path


HERE = Path(__file__).resolve().parent
DEFAULT_RESULTS = HERE / "results" / "final"


def median(values):
    return statistics.median(values) if values else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = args.results
    aggregate = json.loads((root / "aggregate.json").read_text())
    manifest = json.loads((HERE / "workflows.json").read_text())
    by_id = {
        json.loads(path.read_text())["task_id"]: json.loads(path.read_text())
        for path in (root / "tasks").glob("*.json")
    }
    rows = [by_id[workflow["task_id"]] for workflow in manifest["workflows"]]
    methods = {}
    for label in ("A", "B", "C", "D", "E", "F", "M"):
        values = [
            row["baseline_A"] if label == "A"
            else row["baselines"][label] if label in ("B", "C", "M")
            else row["optimizers"][label]
            for row in rows
        ]
        repeat_rows = [
            repeat
            for row in rows
            for repeat in row["exact_contract_repeats"].get(label, [])
        ]
        attacks = [
            row["unauthorized_write_attempts"][label]
            for row in rows if label in row["unauthorized_write_attempts"]
        ]
        successful = [
            value for value in values
            if value.get("utility_pass")
            and (label not in ("D", "E", "F") or value.get("status") == "validated")
        ]
        reductions = [
            value["successful_task_reduction_percent"]
            for value in successful
            if value.get("successful_task_reduction_percent") is not None
        ]
        structures = [
            row["policy_shape"][label]
            for row in rows if label in row["policy_shape"]
        ]
        reduction_all = [value.get("full_corpus_reduction_percent", 0) or 0 for value in values]
        methods[label] = {
            "task_count": len(values),
            "utility_passes": sum(bool(value.get("utility_pass")) for value in values),
            "validated_narrow_promotions": sum(value.get("status") == "validated" for value in values) if label in ("D", "E", "F") else None,
            "conditional_median_reduction_percent": median(reductions),
            "full_corpus_mean_reduction_percent_failures_zero": statistics.mean(reduction_all),
            "full_corpus_median_reduction_percent_failures_zero": median(reduction_all),
            "agent_executions_including_shared_broad": sum(value.get("agent_executions_including_shared_broad", value.get("agent_executions_including_shared_setup", 0)) for value in values),
            "verifier_executions_including_shared_broad": sum(value.get("verifier_executions_including_shared_broad", value.get("verifier_executions_including_shared_setup", 0)) for value in values),
            "search_replays": sum(value.get("search_replays", 0) for value in values),
            "fresh_validation_replays": sum(value.get("fresh_validation_replays", 0) for value in values),
            "optimizer_replays": sum(value.get("optimizer_total_replays", 0) for value in values),
            "timeouts": sum(value.get("timeouts", 0) for value in values),
            "task_and_shared_cli_seconds": sum(value.get("wall_seconds_attributed", 0) for value in values),
            "exact_repeat_count": len(repeat_rows),
            "exact_repeat_agent_executions": len(repeat_rows),
            "exact_repeat_utility_passes": sum(bool(item.get("utility_pass")) for item in repeat_rows),
            "exact_repeat_security_passes": sum(item.get("security", {}).get("status") == "PASS" for item in repeat_rows),
            "exact_repeat_non_ceiling_execution_identity_matches": sum(bool(item.get("execution_identity_matches")) for item in repeat_rows),
            "exact_repeat_verifier_executions": sum((item.get("verifier_seconds") or 0) > 0 for item in repeat_rows),
            "all_agent_executions_including_repeats": sum(value.get("agent_executions_including_broad", value.get("agent_executions_including_shared_setup", 0)) for value in values) + len(repeat_rows),
            "all_verifier_executions_including_repeats": sum(value.get("verifier_executions_including_broad", value.get("verifier_executions_including_shared_setup", 0)) for value in values) + sum((item.get("verifier_seconds") or 0) > 0 for item in repeat_rows),
            "canary_attempts": len(attacks),
            "canary_blocked": sum(bool(item.get("canary_blocked")) for item in attacks),
            "canary_creations_permitted_by_policy": sum(bool(item.get("canary_created")) for item in attacks),
            "canary_block_rate": sum(bool(item.get("canary_blocked")) for item in attacks) / len(attacks) if attacks else None,
            "all_independent_canary_controls_completed": all(item.get("status") == "PASS" for item in attacks) if attacks else None,
            "median_exact_file_grants": median([len(item["exact_file_grants"]) for item in structures]),
            "median_recursive_directory_grants": median([len(item["recursive_directory_grants"]) for item in structures]),
            "policies_with_recursive_grants": sum(bool(item["recursive_directory_grants"]) for item in structures),
            "policies_allowing_future_child_creation": sum(item["future_child_creation_allowed"] for item in structures),
            "median_existing_regular_files_covered": median([item["existing_files_covered"] for item in structures]),
            "median_existing_directory_entries_covered": median([item["existing_directory_entries_covered"] for item in structures]),
            "median_high_impact_files_covered": median([len(item["high_impact_files_covered"]) for item in structures]),
        }

    f_rows = [row for row in rows if row["optimizers"]["F"].get("status") == "validated"]
    f_minus_b = [
        (row["optimizers"]["F"]["successful_task_reduction_percent"] or 0)
        - (row["baselines"]["B"]["successful_task_reduction_percent"] or 0)
        for row in f_rows
    ]
    incremental_f_tuning = [
        max(0, row["optimizers"]["F"]["wall_seconds_attributed"] - row["baseline_A"]["wall_seconds_attributed"])
        for row in f_rows
    ]
    scaling = json.loads((root / "scaling-microbenchmark.json").read_text())
    scaling_summary = {}
    for n in sorted({item["atom_count"] for item in scaling}):
        scaling_summary[str(n)] = {}
        for layout in ("clustered", "dispersed"):
            records = [item for item in scaling if item["atom_count"] == n and item["layout"] == layout]
            scaling_summary[str(n)][layout] = {
                item["strategy"]: {
                    "total_replays_including_validation": item["total_replays"],
                    "reduction_percent": item["reduction_percent"],
                    "validated_utility": item["utility_validated"],
                }
                for item in records
            }

    rr01 = json.loads((root / "tasks" / "RR01-click-short-help.json").read_text())
    corrected_shadows = json.loads((root / "reuse-shadows-corrected.json").read_text())
    drift = rr01["contract_drift"]
    n_b = aggregate["aggregate"]["predeclared_decision_metrics"]["median_B_single_run_wall_seconds"]
    median_tuning = median(incremental_f_tuning)
    output = {
        "suite_id": aggregate["suite_id"],
        "protocol_sha256": aggregate["protocol_sha256"],
        "workflow_count": len(rows),
        "repository_groups": 7,
        "methods": methods,
        "promotion_metrics": {
            "F_promotions": len(f_rows),
            "F_promotions_at_least_20pp_better_than_B": sum(value >= 20 for value in f_minus_b),
            "median_F_minus_B_reduction_percentage_points": median(f_minus_b),
            "median_incremental_tuning_wall_seconds": median_tuning,
            "median_B_single_run_wall_seconds": n_b,
            "amortized_tuning_seconds_per_future_run": {str(n): median_tuning / n for n in (1, 3, 10, 50)},
            "future_identical_repetitions_to_match_B_one_run_cost": math.ceil(median_tuning / n_b) if n_b and median_tuning else None,
        },
        "repeat_run_medians": {
            label: aggregate["aggregate"]["exact_repeat_wall_seconds"][label]
            for label in ("B", "F")
        },
        "repeat_identity_scope": "execution_identity_matches deliberately excludes authorized_ceiling. Each exact-repeat run resupplied the promoted grant as a new narrower ceiling. This did not reuse an unchanged full M3 contract or exercise a production policy-profile loader.",
        "contract_drift": {
            "case_count": len(drift["cases"]),
            "rejected_before_replay": sum(case["rejected_before_replay"] for case in drift["cases"]),
            "cases": drift["cases"],
        },
        "corrected_reuse_shadows": {
            "case_count": corrected_shadows["case_count"],
            "utility_passes": corrected_shadows["utility_passes"],
            "security_passes": corrected_shadows["security_passes"],
            "cases": corrected_shadows["cases"],
            "limitation": "One scripted RR01 workflow; these research-only shadows do not authorize reuse.",
        },
        "supplemental_semantic_shadows": {
            "path": "reuse-shadows-extended.json",
            "case_count": json.loads((root / "reuse-shadows-extended.json").read_text())["supplemental_exploratory_cases"],
            "utility_passes": sum(item["utility_pass"] for item in json.loads((root / "reuse-shadows-extended.json").read_text())["cases"][-2:]),
            "security_passes": sum(item["security"]["status"] == "PASS" for item in json.loads((root / "reuse-shadows-extended.json").read_text())["cases"][-2:]),
            "cases": [item["change"] for item in json.loads((root / "reuse-shadows-extended.json").read_text())["cases"][-2:]],
            "limitation": "Post-freeze exploratory only; no dependency installation or resolution was run, and no policy was promoted.",
        },
        "f_policy_structure_per_task": [
            {
                "task_id": row["task_id"],
                "validated": row["optimizers"]["F"].get("status") == "validated",
                "weighted_surface_reduction_percent": row["optimizers"]["F"].get("successful_task_reduction_percent"),
                "exact_file_grants": len(row["policy_shape"]["F"]["exact_file_grants"]),
                "recursive_directory_grants": row["policy_shape"]["F"]["recursive_directory_grants"],
                "future_child_creation_allowed": row["policy_shape"]["F"]["future_child_creation_allowed"],
                "existing_files_covered": row["policy_shape"]["F"]["existing_files_covered"],
                "existing_directory_entries_covered": row["policy_shape"]["F"]["existing_directory_entries_covered"],
                "high_impact_files_covered": row["policy_shape"]["F"]["high_impact_files_covered"],
                "unauthorized_canary_blocked": row["unauthorized_write_attempts"]["F"]["canary_blocked"],
            }
            for row in rows
        ],
        "search_scaling": scaling_summary,
        "timing_phase_totals": {
            category: {
                field: {
                    metric: sum(row["timings"]["phase_totals_by_execution_class"][category][field][metric] for row in rows)
                    for metric in ("total_millis", "records")
                }
                for field in rows[0]["timings"]["phase_totals_by_execution_class"][category]
            }
            for category in ("initial_broad", "optimizer_replays", "exact_repeats", "other_baselines_and_canaries")
        },
        "experiment_total_wall_seconds": aggregate["aggregate"]["total_wall_seconds"],
    }
    encoded = json.dumps(output, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
