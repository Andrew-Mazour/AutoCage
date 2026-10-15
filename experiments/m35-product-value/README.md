# M3.5 product-value validation

This experiment checks whether verifier-guided write policies help with repeated,
deterministic repository workflows, whether exact-contract evidence can be
reused safely, how normal source changes invalidate that evidence, and which
staged writes the policies actually prevent. It retains M3's 11 pinned tasks
across seven repositories and adds two declared, standard-library workflow
operations. The historical M3 protocol and raw results are unchanged.

The suite is scripted and does not evaluate model patch discovery. Repository
code, test suites, compileall, and archive generation run only inside the
disposable Ubuntu Lima guest and Bubblewrap sandbox. No network is available to
task or verifier processes. There is no paid inference.

## Freeze and criteria

The predeclared task set, methods, cost schema, replay budgets, exact-reuse
procedure, source drift cases, staged write canary, search-scaling conditions,
and quantitative success criteria are in [PROTOCOL.json](PROTOCOL.json).
Task commits and per-workflow operations are in [workflows.json](workflows.json).
Before final measurement, the protocol binds the controller, RR03 diagnostic,
workflow manifest, release binary, M3 protocol, prepared fixture manifest, and
runtime. Development probes must be stored separately and labeled exploratory.
The final recommendation is **C: pivot the near-term policy-learning approach**.
The policy-value and 10-repeat amortization gates did not pass, and the exact
repeats replayed patch tasks rather than common recurring test/build workflows;
see [REPORT.md](REPORT.md) and `results/final/`.

## Reproduction

Use the already provisioned disposable `autocage-m0` Ubuntu 24.04 ARM64 Lima
guest with no host home or credential mounts. Copy the project source, M3
repository experiment, and M3.5 harness into the guest. Prepare a separate
M3.5 work root by copying only the pinned M3 source snapshots; do not run
repository preparation hooks outside AutoCage.

The final run uses the frozen protocol hash checks in `run_m35.py`. On a clean
supported guest, first prepare the pinned M3 snapshots and Python runtime as
described in the [M3 reproduction guide](../real-repository-v1/README.md).
Then build both AutoCage profiles and run M3.5 from a unique empty work root:

```sh
limactl shell autocage-m0 -- mkdir -p /tmp/autocage-m35/project /tmp/autocage-m35/experiments
limactl copy --recursive Cargo.toml Cargo.lock src tests autocage-m0:/tmp/autocage-m35/project/
limactl copy --recursive experiments/real-repository-v1 experiments/m35-product-value autocage-m0:/tmp/autocage-m35/experiments/
limactl shell autocage-m0 -- bash -lc 'cd /tmp/autocage-m35/project && cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked && cargo test --locked optimizer::tests::m35_controlled_search_scaling_matrix -- --nocapture && cargo build --locked && cargo build --locked --release'
limactl shell autocage-m0 -- bash -lc 'python3 /tmp/autocage-m35/experiments/real-repository-v1/prepare.py --work-root /tmp/autocage-real-repository-v1'
limactl shell autocage-m0 -- bash /tmp/autocage-m35/experiments/real-repository-v1/setup/install-python-runtime.sh
limactl shell autocage-m0 -- bash -lc 'python3 /tmp/autocage-m35/experiments/m35-product-value/run_m35.py --autocage /tmp/autocage-m35/project/target/release/autocage --debug-autocage /tmp/autocage-m35/project/target/debug/autocage --work-root /tmp/autocage-m35-run-1 --output /tmp/autocage-m35-run-1/results/final'
```

M3.5 has no production policy-profile loader. The harness first seal-inspects
each F record, then resupplies the validated grants as an explicit policy to
three new `run` invocations with the same source, commands, roots, runtime, and
listener endpoint. This demonstrates explicit command-line re-supply; it is
not a production profile cache. Research-only stale-policy shadows omit a record contract
and can never create promotable evidence. The separate contract-drift check
uses the production `tune` command and requires it to reject incompatible
inputs before a replay.
The repeat runs re-supply F's grants as a new, narrower run ceiling. The
execution-identity comparison deliberately excludes `authorized_ceiling`, so
these do not repeat an identical full M3 contract. No production loader or
cross-snapshot reuse was tested.

## RR03 diagnostic

`diagnose_rr03.py` uses the immutable M3 fixture and raw trial policy. It runs
the frozen verifier with the broad ceiling, exact-file reference, first
decomposition candidate, and zero-write control. A second diagnostic changes
only pytest's cache directory to private `/tmp`, explicitly labeled as a
different verifier contract. No M3 metric or result is rewritten.

The RR03 diagnosis found: broad root-write and exact-file-write with the
private-`/tmp` cache variant both passed all 73 tests; exact-file and M3's
first root decomposition passed the test bodies but the frozen verifier exited
1 when pytest could not create cache files at the workspace root; zero writes
failed at the intended source edit. With the original snapshot and verifier,
root recursive write authority is therefore required by pytest's cache side
effect. This is classification A for the current policy vocabulary, not a
coding-task failure; the `/tmp` variant is a distinct, diagnostic-only verifier.

`run_m2_compat.py` only adapts the historical M2 controller's obsolete `tune`
invocation to the current CLI by resupplying the exact pinned agent, verifier,
and workspace values. It does not alter the frozen task set or optimizer.

## Artifacts

- `PROTOCOL.json`: criteria and protocol hashes.
- `workflows.json`: pinned workflow selection and operation descriptions.
- `run_m35.py`: frozen controller for optimizer comparisons, exact repeats,
  source-drift checks, policy-shape metrics, and independent staged canaries.
- `diagnose_rr03.py`: bounded independent diagnosis.
- `diagnose_reuse_shadows.py`: corrected host-canary shadow diagnostic plus two
  explicitly post-freeze exploratory cases (a passing test addition and a
  consistent dependency-group/lockfile edit). Neither artifact authorizes
  policy reuse.
- `analyze_results.py`: dependency-free summarizer over frozen per-task JSON.
- `run_m2_compat.py`: compatibility-only M2 regression adapter; historical M2
  reports and raw results remain untouched.
- `results/final/`: per-workflow JSON, controlled scaling JSON, aggregate and
  analysis data, environment inventory, reuse shadows, RR03 evidence, and
  compact M0/M2 regression records.
- `REPORT.md`: interpretation, product decision, limits, and reproduction.

**Diagnostic correction:** the frozen controller's first RR01 stale-policy
shadow output initialized its synthetic host file with a marker that the M3
controller did not recognize. Its host-canary status fields are invalid. The
corrected diagnostic repeats the seven predeclared shadows with the expected
marker and is stored in `results/final/reuse-shadows-corrected.json`. This
does not change the frozen primary comparison, thresholds, or M3 results. The
frozen “dependency declaration” case only adds an unused requirements file;
the separate exploratory diagnostic changes the actual project dependency
group and lock metadata without installing or resolving dependencies.

Do not infer exploit probabilities from weighted exposure. Report exact-file
and recursive grants, present-tree coverage, future-child creation, and actual
blocked operations separately.
