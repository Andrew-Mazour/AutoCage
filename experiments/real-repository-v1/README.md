# Real-repository write-policy evaluation

This experiment runs deterministic filesystem tasks against pinned snapshots of
seven permissively licensed Python projects. The scripts and synthetic task
fixtures are not a coding agent: each scripted agent applies the changed file
contents from a pinned upstream target commit and performs declared extra file
operations. It receives no AutoCage policy or optimizer state. Repository code
and pytest run only inside the Bubblewrap sandbox in the isolated Ubuntu Lima
guest.

The final hardened comparison is in
[`results/2026-10-12/final/`](results/2026-10-12/final/) and interpreted in
[`REPORT.md`](REPORT.md). The protocol, tasks, weights, replay cap, and
thresholds were frozen before that run. Two earlier comparisons are retained
with their original protocol copies under `results/2026-10-11/`; they are
superseded and are not the reported result.

## Reproduction

Use the supported disposable Ubuntu 24.04 ARM64 Lima guest with no host
directory mounts. Copy only the repository source and this experiment into the
guest. `prepare.py` fetches pinned Git objects and materializes files; it does
not import, build, or execute repository code. Install the hash-pinned Python
test stack in the guest, then build and run the benchmark:

```sh
limactl copy --recursive Cargo.toml Cargo.lock src tests autocage-m0:/tmp/autocage-m3/
limactl copy --recursive experiments/real-repository-v1 autocage-m0:/tmp/autocage-m3/experiments/
limactl shell autocage-m0 -- bash -lc 'cd /tmp/autocage-m3 && python3 experiments/real-repository-v1/prepare.py --work-root /tmp/autocage-real-repository-v1'
limactl shell autocage-m0 -- bash /tmp/autocage-m3/experiments/real-repository-v1/setup/install-python-runtime.sh
limactl shell autocage-m0 -- bash -lc 'cd /tmp/autocage-m3 && cargo build --locked --release'
limactl shell autocage-m0 -- bash -lc 'cd /tmp/autocage-m3 && python3 experiments/real-repository-v1/run_benchmark.py --autocage target/release/autocage --output /tmp/autocage-m3-real-repository-results'
```

Preparation may need network access to fetch the exact Git commits and pinned
test wheels, but it runs before sandboxed tasks. No task or verifier receives
network access, and no paid API or hosted service is used. A final run refuses
to proceed if the frozen task, preparation, runner, dependency, prepared-fixture,
protocol, or AutoCage binary hashes differ. A changed input requires a new
protocol and a separate results directory.

The frozen final comparison used the task fixture manifest already prepared in
the isolated guest. Its exact hashes and package/kernel versions are recorded
in `protocol.json` and the aggregate JSON. Copy only the result directory back
after the guest run:

```sh
limactl copy --recursive autocage-m0:/tmp/autocage-m3-real-repository-results experiments/real-repository-v1/results/
```

## Comparison arms

| Label | Strategy |
|---|---|
| A | Broad recursive write to the staged workspace |
| B | Fixed conventional source, test, docs, and root configuration paths |
| C | Naive final changed-path inference from a successful broad run |
| D | Fixed-order greedy removal |
| E | Seeded random removal (`0x4155544f43414745`) |
| F | Hierarchical narrowing |
| M | Task-authored narrow reference; not an automatically achievable baseline |

All arms share source snapshots, action scripts, verifier inputs, runtime,
timeouts, cost weights, and sandbox controls. D/E/F start from byte-identical
broad-run evidence. Their budget is 12 optimizer replays including three fresh
final validations. Full-corpus metrics count a failed or inconclusive policy as
zero reduction; the report also gives reductions conditional on successful
tasks. The shared broad run is charged once to each optimizer for per-method
cost and once to the experiment's physical execution total.

## Artifacts

- `tasks.json`: task IDs, pinned commits, license identifiers, patch paths,
  verifier tests, and extra filesystem operations.
- `prepare.py`: safe Git-object fetch/materialization and fixture creation.
- `run_benchmark.py`: frozen comparison controller, independent canaries,
  aggregation, and protocol checks.
- `setup/python-requirements.lock`: exact package versions and wheel hashes.
- `setup/install-python-runtime.sh`: guest-only runtime setup.
- `protocol.json`: final method, metric, split, hashes, timeout, replay budget,
  and predeclared thresholds.
- `results/2026-10-12/final/`: final per-task JSON, aggregates, and M0/M2
  regression evidence.
- `REPORT.md`: results, limitations, and interpretation.
