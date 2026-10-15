# AutoCage write-policy v1 experiment report

**Run date:** 2026-10-11
**Verdict:** **PASS against the predeclared M2 go/no-go thresholds; INCONCLUSIVE on whether hierarchical search adds value over simpler removal strategies.**
**Environment:** isolated Lima guest, Ubuntu 24.04.5 LTS ARM64, Linux 6.8.0-142-generic, Bubblewrap 0.9.0, Rust 1.75.0, Python 3.12.3. Ubuntu's official `bwrap-userns-restrict` AppArmor profile was enforced and `kernel.apparmor_restrict_unprivileged_userns` remained `1`. No host home or credential directories were shared.

## Result in brief

All 22 tasks passed under the broad authorized workspace ceiling. The hierarchical optimizer preserved verifier utility on all 22 selected policies: 20 were narrowed and passed three fresh validation replays; two root-level directory-entry tasks remained at the already-verified broad ceiling and were reported as inconclusive. The selected policy's independent host, source, and verifier-input canaries passed on all 22 tasks.

The median weighted writable-surface reduction for the selected hierarchical policies was **91.9% overall** and **75.6% on the six held-out tasks**. Median optimizer cost was **7 replays** overall and **6.5** held out, including all final validation replays; the maximum was 12. The initial broad run is additional and reported separately. No timeout or malformed trial record occurred.

This supports bounded verifier-guided filesystem-write narrowing on these deterministic fixtures. It does **not** support a claim that hierarchical grouping is more efficient: fixed greedy and seeded random search reached the same median final cost with one fewer median replay, and hierarchical search rejected more candidates.

## Frozen protocol and environment

The final rerun used the predeclared `write-policy-v1` protocol with 22 task IDs (16 development, 6 held out), the same source fixture, scripted executable, verifier, Bubblewrap runtime, environment, and 25-second command timeout for every baseline. Cost weights, high-impact path prefixes, xorshift64* seed `0x4155544f43414745`, and optimizer cap of 12 total replays were frozen in [`results/frozen-manifest.json`](results/frozen-manifest.json) before task execution. The manifest records SHA-256 identities for tasks, harness, and release binary. The final tested binary SHA-256 is `1464be8adf7c985de3dccbf87fea7357e805e12b9ac05a9ea6c1fbe8e66adb8c`.

Every optimizer received a copy of the broad run's contract and stage evidence, but executed each candidate against a fresh copy of the original source. Narrow policies remained subsets of the explicit workspace-write ceiling. Three fresh verifier/canary passes are included in each optimizer budget before a narrow policy is promoted. No model API, paid service, external network, or cloud resource was used.

The controller and all scripted agents ran in the disposable Ubuntu guest. Independent checks verified the original source tree, a synthetic outside-host canary, the immutable verifier test snapshot, and verifier read-only behavior. For failed candidate runs where a denied task write stopped the agent before verifier launch, the verifier canary is explicitly marked **NOT TESTED**; the candidate is rejected and cannot be promoted. Such denials are not counted as sandbox escapes.

## Test and build results

In the same guest, the tested Rust source passed:

- `cargo fmt --check`
- `cargo clippy --locked --all-targets -- -D warnings`
- `cargo test --locked`: **33 unit tests and 11 Linux integration tests passed**
- `cargo build --locked --release`
- Python AST parsing for `run_benchmark.py` and `tasks.py`

The integration suite retains M1 checks and adds exact-file inode writes versus denied directory-entry operations, recursive-directory create/delete/rename/atomic-replacement behavior, explicit read-only behavior, replay validation, and source-drift rejection. No host security settings were changed during M2.

## Baseline comparison

Reduction is computed only among tasks whose reported policy preserved verifier utility, avoiding credit for narrow policies that fail the task. The broad workspace baseline has cost 197 for each fixture under `weighted-write-surface-v1`. “Optimizer replays” includes search and final validation; the initial broad run is one additional execution.

| Strategy | Utility preserved | Median reduction on utility-passing tasks | Median search replays | Median final validations | Median optimizer replays | Max optimizer replays | Median tune wall time |
|---|---:|---:|---:|---:|---:|---:|---:|
| A — broad workspace write | 22/22 | 0.0% | — | — | — | — | — |
| B — static `src/` + `tests/` | 14/22 | 69.5% | — | — | — | — | — |
| C — naive changed-file policy | 18/22 | 96.4% | — | — | — | — | — |
| D — fixed greedy removal | 22/22 | 91.9% | 3 | 3 | 6 | 12 | 0.401 s |
| E — seeded random removal | 22/22 | 91.9% | 3 | 3 | 6 | 12 | 0.411 s |
| F — hierarchical optimizer | 22/22 | 91.9% | 4 | 3 | 7 | 12 | 0.442 s |
| M — manual narrow oracle reference | 22/22 | 91.9% | — | — | — | — | — |

Median executions including the initial broad run were 7 for D/E and 8 for F. All three search strategies returned a narrower three-pass validated policy on 20 tasks and the broad known-good ceiling, marked inconclusive, on the same two tasks: `T18-root-entry-create` and `T22-root-atomic-package`.

The held-out set contained `T17` through `T22`. F passed all six, narrowed four with three validations, and left the two root-entry cases broad. Its held-out median reduction was 75.6% and median optimizer cost was 6.5 replays.

### What each baseline shows

- **Static B** passed 14 tasks. It failed cross-directory writes, config/generated output, transient output/cache, the high-impact file, and root-level entry operations. A fixed directory allowlist can be too narrow for developer tasks.
- **Naive C** was highly narrow when it passed, but failed `T09-atomic-replace`, `T11-transient-temp`, `T16-transient-cache`, and `T22-root-atomic-package`. The v1 manifest records path, type, mode, size, and content digest, but not the staged inode identity before execution; a same-path atomic replacement is therefore indistinguishable from an in-place edit and maps to `FileContents`. It also cannot reveal deleted temporary files. C is the intentionally simple final-delta baseline, not an operation tracer.
- **D/E/F** all retained utility on those four cases within the 12-replay cap; `T22` remained at the broad ceiling. For the 18 tasks where C passed, F had a 96.95% median reduction versus C's 96.45%; this small paired difference is descriptive, not evidence of statistical superiority. Across the full suite D/E/F had the same median selected-policy cost.
- **M** is an oracle-style hand-authored reference from the known fixture task, not a deployable inference method.

## Search outcomes and failure classifications

Across 22 tasks, D rejected 30 candidates, E rejected 29, and F rejected 49. Every rejected search candidate in these runs ended with the scripted agent failing on a denied write (exit 1); there were no timeouts, verifier-canary failures, host/source probe breaches, or invalid records. Rejected attempts are expected false denials during search and do not count as escape evidence. The final selected policies were validated independently.

The two broad fallbacks expose a real limit in this policy vocabulary. Creating a root file or atomically replacing a root file requires write authority on the staged workspace root under Bubblewrap's mount semantics. The backend cannot grant only the root file's directory-entry operations. AutoCage therefore reports no narrower validated policy rather than presenting an exact-file rule that cannot perform the operation.

## Cost definition and interpretation

The frozen objective is `weighted-write-surface-v1`:

```text
sum(weight for every existing writable regular file)
+ 10 × number of existing writable directory entries
```

Ordinary files weigh 1; files under `.github/workflows/`, `deploy/`, `deployment/`, `infra/`, and `scripts/`, plus root `package.json`, `pyproject.toml`, and `Cargo.toml`, weigh 10. A recursive directory grant covers descendant files and directories; `DirectoryTree(".")` additionally counts the staged root. File count, directory count, grant count, and the separate file/directory-entry subtotals are stored in each JSON record. This is a transparent heuristic, not a probability of compromise, and does not bound future filenames created under a writable directory.

## What the experiment does and does not establish

It establishes that the tested Bubblewrap mount vocabulary can enforce recursive-directory and exact-file grants, and that deterministic replay can recover verified task utility missed by a final-delta allowlist while substantially reducing the measured existing-path surface on these fixtures. It also demonstrates why final verifier success is bounded evidence: `T20-incomplete-verifier` intentionally accepts an incorrect file and all strategies preserve that weak outcome.

It does not establish correctness of arbitrary coding changes, required permissions for untested paths or future behavior, stochastic-agent pass rates, real repository performance, safety against kernel/Bubblewrap defects, or aggregate CPU/memory/process isolation. The scripted suite deliberately uses small repositories and fixed operations; results must not be generalized as a real-world security guarantee.

## Research conclusion and recommendation

**Formal M2 gate: PASS.** Every predeclared continue threshold was met: utility retained for every broad-passing task, all selected-policy canaries passed, median reduction exceeded 25% overall and held out, and replay cost remained below 12 median.

**Search novelty claim: INCONCLUSIVE / unsupported.** Hierarchical grouping did not outperform fixed greedy or random removal in this suite. The clearest measured value is the combination of a strict developer ceiling, operation-aware file/directory grants, fresh verifier replay, explicit inconclusive fallback, and evidence records. Naive change inference is cheaper and narrower on tasks it handles, but misses transient and directory-entry requirements.

Proceed with the planned repeatability/record-hardening milestone before real-agent integration. Keep greedy and random as mandatory comparators; do not claim the current hierarchical algorithm is a superior optimizer. Add a pinned subset of real repository tasks and repeatability measurements before relying on these results for a product-facing profile.

## Reproduction and artifacts

Run from a clean supported Ubuntu guest as described in [`README.md`](README.md). The results directory contains the frozen manifest, aggregate metrics, one JSON record per task with all candidate policies/costs/classifications, and `run-records.tar.gz` with 689 compact `run.json`/`contract.json` records. It omits the 177 MiB of repeated staged-file trees generated under the guest's temporary `runs/` directory; rerunning the documented command regenerates them. This keeps the checked-in evidence compact while retaining per-trial records.
