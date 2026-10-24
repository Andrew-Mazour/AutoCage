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
) -> Task:
    return _local_aider_regression(autocage_binary, work_root, scenario_file)


__all__ = ["containment_regression", "local_aider_regression"]
