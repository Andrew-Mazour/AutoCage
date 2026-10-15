# Write-policy optimizer v1 experiment

This directory contains deterministic, synthetic workload definitions and a
controller that invokes the AutoCage CLI. **The scripted agents run only
inside the validated Bubblewrap sandbox in the isolated Ubuntu Lima guest.**
The Python controller itself only creates fixtures, calls AutoCage, and reads
results. No model or external service is used.

The frozen 2026-10-11 run met the predeclared M2 continue thresholds. See the
[experiment report](REPORT.md) and checked-in [result package](results/).
Hierarchical search did not outperform fixed greedy or seeded random removal.

## Frozen comparison

The benchmark has 22 task IDs: 16 development tasks and 6 held-out tasks. It
covers read-only work; exact-file edits; multi-file and multi-directory edits;
create, delete, rename, and atomic replacement; pytest; transient files and
caches; nested outputs; joint permissions; branch-sensitive behavior; verifier
tampering; a deliberately incomplete verifier; high-impact files; and root
directory-entry operations.

The controller freezes `tasks.py`'s SHA-256, task split, baselines, fixed random
seed, runtime timeout, and policy-cost weights to `frozen-manifest.json` before
the first trial. Results are written to a fresh directory and the controller
refuses to overwrite non-empty results.

Baselines use the same source snapshot, scripted agent, verifier, timeout,
Bubblewrap runtime, and independent canaries:

| Label | Policy |
|---|---|
| A | Recursive write to the staged workspace |
| B | Static recursive write to existing `src/` and `tests/` directories |
| C | Exact-file/nearest-existing-parent rules inferred from the broad run's final manifest delta. A same-path atomic replacement is not distinguishable from an in-place file edit in the v1 content/mode manifest and is therefore intentionally a limitation of this naive baseline. |
| D | Fixed-order greedy removal from the changed-path seed |
| E | Random-order removal with published xorshift64* seed `0x4155544f43414745` |
| F | Hierarchical split plus sibling-group removal |
| M | Hand-authored narrow oracle reference; not an automatically generated baseline |

D, E, and F each receive an exact copy of A's run record, source baseline,
post-run staged workspace, and private replay contract. Their tuning trials
start from fresh copies of the original source. Candidate verifiers are fixed
Python arguments and read-only `oracle.txt` and `tests/` snapshots. The agent
also attempts a host-canary read, a write to the original source path, and a
write to the staged verifier canary. The external controller checks host and
source canary state; the independent verifier checks its immutable input and
read-only mount.

The staged oracle write is a deliberate unnecessary write attempt included in
each fixture. The broad run permits it and naive changed-file inference may
retain it; narrower candidates can reject it while the verifier reads the
separate immutable baseline. This is synthetic adversarial coverage, not a
claim that real agents make this exact request.

## Cost function

`weighted-write-surface-v1` is an explicit heuristic, not a risk probability:

```text
cost = sum(weight of writable regular files)
     + 10 * number of writable existing directories
```

An ordinary regular file weighs 1. Files under `.github/workflows/`,
`deploy/`, `deployment/`, `infra/`, and `scripts/`, plus root `package.json`,
`pyproject.toml`, and `Cargo.toml`, weigh 10. Recursive grants cover every
descendant regular file and directory in the immutable initial manifest. Exact
file grants cover only the named existing regular file. Raw file and directory
counts, recursive grant count, and rule count are reported separately.

This surface measure does not count unbounded future names a writable directory
could create, distinguish all inode metadata operations, or model exploit
probability. Directory-entry authority is represented by the separate
directory count and its fixed weight. The stage root is counted as a writable
directory for the `.` grant.

## Reproduce in the supported guest

On macOS, first copy only this experiment and the AutoCage source into the
isolated VM; do not configure host home-directory sharing:

```sh
limactl shell autocage-m0 -- mkdir -p /tmp/autocage-m2/experiments
limactl copy --recursive Cargo.toml Cargo.lock src tests autocage-m0:/tmp/autocage-m2/
limactl copy --recursive experiments/write-policy-v1 autocage-m0:/tmp/autocage-m2/experiments/
limactl shell autocage-m0 -- bash -lc 'cd /tmp/autocage-m2 && cargo build --locked --release'
limactl shell autocage-m0 -- bash -lc 'cd /tmp/autocage-m2 && python3 experiments/write-policy-v1/run_benchmark.py --autocage target/release/autocage --results /tmp/autocage-write-policy-v1-results'
```

For the full development check, install Ubuntu's `rust-clippy` package in the
guest and run `cargo fmt --check`,
`cargo clippy --locked --all-targets -- -D warnings`, and
`cargo test --locked` before the release build.

For a development smoke trial, use a fresh results path and a selected task:

```sh
limactl shell autocage-m0 -- bash -lc 'cd /tmp/autocage-m2 && python3 experiments/write-policy-v1/run_benchmark.py --autocage target/release/autocage --results /tmp/autocage-write-policy-smoke --task T02-edit-one'
```

To publish evidence, copy the entire results directory back with
`limactl copy --recursive /tmp/autocage-write-policy-v1-results experiments/write-policy-v1/`.
Keep the experiment results and frozen task definition together. Do not edit
`tasks.py`, the cost weights, or the strategy seed after final comparison; any
change requires a new protocol version and a fresh results directory.

## Result artifacts

- `frozen-manifest.json`: task IDs/split, hashes, weights, and trial budgets.
- `tasks/<ID>.json`: per-task baseline/optimizer outputs, costs, trials,
  canary statuses, timings, and failure classifications.
- `aggregate.json`: raw rows and aggregates, including held-out counts.
- `runs/`: mode-restricted AutoCage run directories with source snapshots,
  staged outputs, patches, records, replay contracts, and individual trial runs.
- `REPORT.md`: concise interpretation after the actual experiment completes.

The checked-in `results/` package retains the frozen manifest, aggregate
metrics, one detailed JSON file per task, and `run-records.tar.gz` containing
689 compact `run.json` and `contract.json` records. It omits the 177 MiB of
repeated staged-file trees produced under the guest's temporary `runs/`
directory; the reproduction command regenerates those trees. Per-task JSON
retains each tested policy, cost, pass/failure classification, replay count,
timeout flag, and canary status.

The initial broad execution is the shared task baseline and is reported
separately. Each optimizer's `total_replays` includes both search and final
validation runs, with the two counts also reported independently. The first
broad run is not hidden in the optimizer replay count.
