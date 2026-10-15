# M3.6 incomplete protocol attempts

These runs are retained as harness-diagnostic evidence only. They are not included in protocol v3 metrics. See the paired `PROTOCOL-v*-incomplete.json`, workflow-plan copies, and progress records.

## Protocol v1

- Progress: 20 policy-run rows, 12 exact-repeat rows, 18 canary sessions, two stale checks, and two optimizer workflows before stop at W05 parent.
- The original direct `pytest tests/test_error.py` command failed under all four policy configurations because the pinned Filelock archive did not contain build-generated `src/filelock/version.py`. Pytest reported `ModuleNotFoundError: No module named 'filelock.version'`; its verifier therefore did not run. A fresh isolated reproduction confirmed the error.
- The controller then crashed while recording an exact repeat because it dereferenced the missing verifier result in a valid `agent_failed` run record. No aggregate was produced.
- The direct test was replaced before v2 with Filelock `compileall -q src`, which uses the already implemented private bytecode cache and tests a legitimate repeated developer command without inventing package setup.

## Protocol v2

- Progress: 28 policy-run rows, 18 exact-repeat rows, 27 canary sessions, three stale checks, and three optimizer workflows before stop at W06 parent.
- Filelock compileall passed. Iniconfig's pinned tests live under `testing/`, but the controller passed nonexistent `tests/` as a verifier read-only root. AutoCage rejected the command before creating a run record with `inspect verifier readonly path tests: No such file or directory (os error 2)`.
- The repeat accounting then crashed while dereferencing `record.agent` when the rejected invocation correctly had no run record. This was a controller defect, not a sandbox bypass or task result.
- V3 derives the protected test root from the frozen test path, checks all declared workflow and verifier paths before launching any workload, preserves missing-record failures, and marks incomplete work explicitly.

## Protocol hash correction

The first v1 freeze attempt mistakenly pinned the freeze helper instead of `run_m36.py` as the controller. Pre-run hash validation detected the mismatch, and the freeze helper corrected the controller pin after verifying the remaining inputs were unchanged and before held-out execution. The corrected v1 protocol records this event in `freeze_audit`; the v1 task/protocol thresholds and workloads were unchanged.
