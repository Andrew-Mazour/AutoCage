"""Deterministic, counterbalanced schedules for local-agent paired trials."""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
from pathlib import Path
from typing import Any


CONDITIONS = (
    ("clean", "autocage-ceiling"),
    ("clean", "autocage-narrower"),
    ("adversarial", "autocage-ceiling"),
    ("adversarial", "autocage-narrower"),
)
# Williams design for four conditions: every condition appears once per
# position and each directed first-order transition appears once per block.
WILLIAMS_ROWS = (
    (0, 1, 3, 2),
    (1, 2, 0, 3),
    (2, 3, 1, 0),
    (3, 0, 2, 1),
)


def _model_seed(experiment_id: str, schedule_seed: int, repetition: int) -> int:
    identity = f"autocage-local-agent-v1\0{experiment_id}\0{schedule_seed}\0{repetition}".encode()
    return int.from_bytes(hashlib.sha256(identity).digest()[:4], "big") & 0x7FFFFFFF


def build_trial_schedule(
    *, repetitions: int, schedule_seed: int, experiment_id: str
) -> list[dict[str, Any]]:
    if type(repetitions) is not int or not 1 <= repetitions <= 100:
        raise ValueError("repetitions must be an integer between 1 and 100")
    if type(schedule_seed) is not int or not 0 <= schedule_seed <= 0x7FFFFFFF:
        raise ValueError("schedule_seed must be an integer between 0 and 2147483647")
    if not isinstance(experiment_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", experiment_id):
        raise ValueError("experiment_id must contain 1-64 ASCII letters, digits, '_' or '-'")

    rng = random.Random(schedule_seed)
    condition_map = list(CONDITIONS)
    rng.shuffle(condition_map)
    row_order = list(range(len(WILLIAMS_ROWS)))
    rng.shuffle(row_order)
    schedule: list[dict[str, Any]] = []
    for repetition_index in range(repetitions):
        repetition_id = f"rep-{repetition_index + 1:02d}"
        seed = _model_seed(experiment_id, schedule_seed, repetition_index + 1)
        row = WILLIAMS_ROWS[row_order[repetition_index % len(row_order)]]
        for order, condition_index in enumerate(row, start=1):
            variant, arm = condition_map[condition_index]
            schedule.append({
                "experiment_id": experiment_id,
                "repetition_id": repetition_id,
                "trial_order": order,
                "schedule_seed": schedule_seed,
                "model_seed": seed,
                "variant": variant,
                "arm": arm,
                "condition": f"{variant}-{arm}",
            })
    return schedule


def build_pilot(*, schedule_seed: int, experiment_id: str) -> dict[str, Any]:
    if type(schedule_seed) is not int or not 0 <= schedule_seed <= 0x7FFFFFFF:
        raise ValueError("schedule_seed must be an integer between 0 and 2147483647")
    if not isinstance(experiment_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", experiment_id):
        raise ValueError("experiment_id must contain 1-64 ASCII letters, digits, '_' or '-'")
    return {
        "experiment_id": experiment_id,
        "repetition_id": "pilot",
        "trial_order": 1,
        "schedule_seed": schedule_seed,
        "model_seed": _model_seed(experiment_id, schedule_seed, 0),
        "variant": "clean",
        "arm": "autocage-narrower",
        "condition": "pilot-clean-autocage-narrower",
        "plan_kind": "single-sample-pilot",
    }


def persist_trial_plan(
    *, work_root: str | None, experiment_id: str, schedule: list[dict[str, Any]],
    scenario_identity: dict[str, Any], retain_agent_diagnostics: bool,
) -> dict[str, str] | None:
    if work_root is None:
        return None
    root = Path(work_root)
    if root.is_symlink():
        raise ValueError("work_root must not be a symlink")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not root.is_dir():
        raise ValueError("work_root must be a directory")
    plan = {
        "schema_version": 1,
        "experiment_id": experiment_id,
        "schedule_algorithm": "seeded-Williams-square-v1",
        "schedule": schedule,
        "scenario_identity": scenario_identity,
        "diagnostic_retention_opt_in": retain_agent_diagnostics,
        "note": "Model seeds are matched within each repetition; this does not guarantee deterministic output.",
    }
    encoded = (json.dumps(plan, sort_keys=True, indent=2) + "\n").encode()
    target = root / f"{experiment_id}-trial-plan.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(target, flags, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(encoded)
        output.flush()
        os.fsync(output.fileno())
    return {"path": str(target), "sha256": hashlib.sha256(encoded).hexdigest()}
