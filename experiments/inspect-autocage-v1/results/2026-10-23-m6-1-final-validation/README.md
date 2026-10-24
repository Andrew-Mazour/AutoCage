# M6.1 final release validation

Run date: 2026-10-23 UTC. The evaluation was repeated from a clean source copy in the isolated Lima guest; only this compact summary is included. Per-sample workspaces, Inspect logs, and raw traces remain in the guest under `/tmp`.

## Environment

- Ubuntu 24.04.5 ARM64, Linux 6.8.0-142-generic.
- Bubblewrap 0.9.0; Ubuntu `bwrap//&unpriv_bwrap` AppArmor profile in enforce mode.
- Rust/Cargo 1.75.0; Python 3.12.3; Inspect AI 0.3.281.
- No hosted model calls; the `mockllm/model` placeholder was not used for inference.

## Inspect quickstart

The documented `scripts/run-inspect-quickstart.sh` completed all 13 samples and its independent result validator passed.

- Broad workspace write: 6/6 task verifiers passed; three adversarial protected writes succeeded and changed canaries.
- Static `src/` write policy: 6/6 task verifiers passed; three adversarial writes were denied and all six canaries remained unchanged.
- Read-only utility control: failed its task verifier as expected; the record and security controls were valid.
- The paired comparison found three deliberate adversarial security regressions and three clean comparisons with no observed difference.
- No attempt, denial, and successful write remain separate outcomes. A clean no-attempt result is not evidence that the sandbox blocked an operation or that a model resisted an instruction.
- Median measured sample execution was 359 ms for broad write, 362 ms for `src/`, and 265 ms for the read-only control. This is scripted-run overhead, not a model-backed latency estimate.

## Other release checks

- Rust: 47 unit and 22 Linux integration tests passed; format, strict Clippy, and locked release build passed.
- M0: 41/41 enforcement checks passed; 0 blocked, failed, or untested.
- M4: 26 executions across two replicates, with 26 verifier runs and selected traces; all 12 declared checks passed.
- Python: 20 Inspect adapter tests, 4 quickstart validator tests, 5 M4 parser tests; dependency lock, documentation links, and `pip check` passed.
- The Python wheel declared `Apache-2.0` and included `dist-info/licenses/LICENSE`.

See [the release record](../../../../docs/RELEASE.md) for the full validation and publication status. This scripted evaluation demonstrates detection of the included policy regression; it is not evidence of general model resistance, comprehensive syscall auditing, or superiority to other sandboxes.
