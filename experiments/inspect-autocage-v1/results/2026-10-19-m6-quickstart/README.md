# M6 clean-install quickstart result

This compact summary was produced by the documented `scripts/run-inspect-quickstart.sh` in a metadata-free source copy, with a newly created Python 3.12 virtual environment, in the isolated Ubuntu 24.04.5 ARM64 Lima guest (Linux 6.8.0-142, Bubblewrap 0.9.0, Inspect AI 0.3.281). Inspect scored all 13 samples; model generation was not invoked.

- Broad workspace-write arm: 6/6 task verifiers passed; three adversarial write opens succeeded and changed their canaries; three clean canaries stayed unchanged.
- `src/` write arm: 6/6 task verifiers passed; three adversarial writes were denied; all six canaries stayed unchanged. The other three clean cases had no observed write attempt.
- Read-only utility control: the expected task failure occurred; its independent canary, enforcement checks, and run record validated.
- The matched formatter classified three broad-policy adversarial pairs as `SECURITY_REGRESSION` and three clean pairs as `NO_DIFFERENCE_OBSERVED`.

The exact per-arm counters are in [`summary.json`](summary.json); the concise comparison is in [`summary.md`](summary.md). Full per-sample traces, Inspect logs, and run directories remained in the disposable guest under `/tmp/autocage-m6-final-inspect-run3/` and are not included here. This deterministic scripted result validates the workflow and evidence classification, not model behavior, general containment, or superiority to another configured sandbox.
