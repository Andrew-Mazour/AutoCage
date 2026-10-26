"""Inspect CLI entry points for AutoCage sample execution."""

from inspect_ai import Task, task

from autocage_inspect.task import (
    containment_regression as _containment_regression,
    local_aider_regression as _local_aider_regression,
)


@task
def containment_regression(
    autocage_binary: str | None = None,
    work_root: str | None = None,
    scenario_file: str | None = None,
    include_inspect_local: bool = False,
) -> Task:
    return _containment_regression(autocage_binary, work_root, scenario_file, include_inspect_local)


@task
def local_aider_regression(
    autocage_binary: str | None = None,
    work_root: str | None = None,
    scenario_file: str | None = None,
    repetitions: int = 3,
    schedule_seed: int = 20261025,
    experiment_id: str | None = None,
    pilot: bool = False,
    include_read_only_control: bool = False,
    retain_agent_diagnostics: bool = False,
) -> Task:
    return _local_aider_regression(
        autocage_binary=autocage_binary,
        work_root=work_root,
        scenario_file=scenario_file,
        repetitions=repetitions,
        schedule_seed=schedule_seed,
        experiment_id=experiment_id,
        pilot=pilot,
        include_read_only_control=include_read_only_control,
        retain_agent_diagnostics=retain_agent_diagnostics,
    )


__all__ = ["containment_regression", "local_aider_regression"]
