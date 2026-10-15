# M3.5 Product-Value Validation

**Research recommendation: C — pivot the near-term policy-learning approach.** The study validates bounded narrowing and selected write blocking, but it does not establish product value for common recurring test/build workflows or justify full M4. The 10-run amortization and policy-value gates failed, and the “repeats” reran the same source-changing patch task from an identical parent snapshot. Treat exact-snapshot workflow profiles as a hypothesis for later evaluation, not a proven target category.

## Scope and reproducibility

The primary comparison ran 11 scripted workflows across seven repository groups: click, packaging, python-dotenv, attrs, filelock, iniconfig, and pluggy. It reused M3's pinned real-source tasks and verifiers; they are not 11 independent repositories or a newly held-out sample. The tasks apply pinned upstream patches to fresh parent snapshots. W02 adds a deterministic standard-library source archive; W04 adds hash-based `compileall`. These are explicit extra operations, not the projects' official release/build pipelines. No task tests model patch discovery or uses paid inference. The exact-repeat arm repeats these same patch-and-verify transformations from fresh copies of the same parent. It does not directly model a developer rerunning only tests/builds on a committed result or a maintenance workflow across successive repository versions.

The guest was Ubuntu 24.04.5 ARM64, Linux `6.8.0-142-generic`, Bubblewrap 0.9.0, Python 3.12.3, Rust/Cargo 1.75.0. All repository tasks, verifiers, security probes, and shadow runs executed inside AutoCage in the isolated Lima guest. Required VM setup and pinned repository/runtime preparation are described in [README.md](README.md); task commit pairs and operations are in [workflows.json](workflows.json) plus the unchanged M3 [tasks.json](../real-repository-v1/tasks.json).

The frozen primary protocol and exact controller/runtime hashes are in [PROTOCOL.json](PROTOCOL.json). Raw records are in [`results/final/`](results/final/), with deterministic derived metrics in [`analysis.json`](results/final/analysis.json). The frozen M3 report and results were not rewritten. The primary M3.5 run took 350.44 seconds wall time and had no task timeouts.

## Outcome distinctions

- Broad staged-workspace policy A completed and passed its verifier on **11/11** tasks.
- F promoted a narrower policy on **9/11** tasks, each with three fresh validations. On the other two it retained the known-good broad ceiling and reported inconclusive optimization. Those are not task failures and are not optimization successes.
- Thus the task utility was already achieved by A on all 11; F demonstrated validated narrowing on nine. It did not improve the task that had completed before tuning.

This timing limits the immediate security value: the first task execution receives the broad authorized ceiling, and optimization begins only after that task and verifier have completed. The narrower policy can prevent an out-of-scope staged edit only on a later execution where the user explicitly re-supplies the grants. The first run still benefits from the disposable stage, no-egress boundary, and reviewable patch, but not from the policy AutoCage learns afterward. Because there is no production profile loader and any source change invalidates learned evidence, the user currently bears the tuning cost and manual policy handoff before receiving that additional write restriction.

The two F fallbacks have different causes. RR02 creates `build/click-source.tar`, requiring a new root-level `build/` entry that the current candidate vocabulary cannot grant without root directory authority. RR03's frozen pytest verifier writes `.pytest_cache` and temporary cache entries at the workspace root. Its source edit works with an exact-file grant, but that verifier side effect requires root directory authority. The bounded [RR03 diagnosis](results/final/rr03-diagnostic.json) passed all 73 tests under the broad policy; exact-file write plus original verifier failed only at pytest cache creation; exact-file plus a diagnostic `/tmp` cache verifier passed. This is a current-vocabulary limitation, not a task failure or a search defect. M3's RR03 result remains unchanged.

## Baseline comparison

Reduction columns use the frozen `weighted-write-surface-v1`. “Full median” scores failed/inconclusive policies as zero; conditional median includes only utility-passing policies. The independent attack attempted to create a canary under the workflow's verifier/test root. Block rates count all 11 attempts, including paths that a policy explicitly permitted. Agent/verifier execution counts include the shared broad run, and B/F include their later exact-source repeats.

| Method | Verified task policies | Narrow promotions / safe fallbacks | Conditional median; full-corpus median / mean reduction | Search + validation replays | Agent / verifier executions | Test-root canaries blocked |
|---|---:|---:|---:|---:|---:|---:|
| A — broad | 11/11 | — | 0.0%; 0.0% / 0.0% | 0 | 11 / 11 | 0/11 |
| B — static | 9/11 | — | 45.7%; 44.6% / 38.2% | 0 | 44 / 40, including 33 repeats | 0/11 |
| C — changed paths | 8/11 | — | 91.2%; 76.2% / 50.6% | 0 | 22 / 19 | 9/11 |
| D — greedy | 9/11 | 9 / 2 | 88.1%; 76.2% / 52.5% | 49 + 27 = 76 | 87 / 69 | 6/11 |
| E — seeded random | 9/11 | 9 / 2 | 88.1%; 76.2% / 57.7% | 49 + 27 = 76 | 87 / 68 | 8/11 |
| F — hierarchical | 9/11 | 9 / 2 | 88.1%; 76.2% / 65.5% | 55 + 27 = 82 | 120 / 86, including 27 repeats | 8/11 |
| M — manual reference | 7/11 | — | 94.2%; 85.4% / 58.4% | 0 | 11 / 8 | not tested |

For D/E/F, the 9 promoted policies passed all three fresh validations. Their two remaining rows are safe broad fallbacks after A succeeded; they are not counted as narrowed utility passes. C illustrates why the conditional score is not enough: it has the highest narrowed conditional score, yet failed three workflows. M is a hand-authored reference, not a true oracle; it passed only seven tasks and had no canary arm.

The 27/27 F repeats preserved utility and all recorded independent controls. The 33 B repeats preserved utility on 27 and had six false denials across the two B-incompatible tasks. These repeats re-supplied the sealed F grants as a new, narrower run ceiling. The comparison's `execution_identity_matches` intentionally excludes `authorized_ceiling`; it therefore does **not** establish reuse of the identical full M3 contract. There is no production profile loader. The harness inspected F's seal, then supplied its grants to fresh `run` commands.

## Concrete write prevention and surface limits

The static B policy allowed test-root canary creation in all 11 cases. F blocked it in **8/11 (72.7%)**; D blocked 6/11 and seeded E blocked 8/11. Every positive/negative canary control matched the policy and all independent controller checks completed. F exceeded B by 72.7 percentage points on this operation, but missed the predeclared F threshold of 80% blocked attempts. This demonstrates one kind of staged modification prevented before it could enter the review diff on a later constrained replay. The initial broad run and reviewable patch remain unchanged; the test does not prove safety for other writes or replace patch review.

Among F's nine promoted policies, three used exact-file grants only; six included recursive directory grants. Those six permit future child creation without a finite path bound. Median policy structure across the promoted set was 3 exact-file grants and 1 recursive-directory grant, covering 9 existing files and 1 existing directory entry; four policies included at least one frozen high-impact file. Two broad fallbacks also allow arbitrary future children. The original weighted metric counts only entries in the initial tree, so its reduction can overstate restriction where recursive grants permit new files. The report keeps that heuristic and its weights unchanged and publishes rule shapes and actual blocked operations separately in per-task records.

The predeclared policy-value threshold required at least 8 of 10 expected promotions to improve over B by 20 percentage points. Seven of the nine observed promotions met that paired difference; the required count was not reached. The F canary block threshold also failed. The 42.9-point median paired reduction advantage over B is useful evidence, but does not convert either missed threshold into a pass.

## Reuse and actual cost

| Evidence path | Attempts | Utility | Independent security / contract result | Reuse interpretation |
|---|---:|---:|---:|---|
| B static-policy exact-source repeats | 33 | 27/33 | 30/33 security checks pass | Six false denials across the two B-incompatible tasks. |
| F narrow-policy exact-source repeats | 27 | 27/27 | 27/27 controls pass | Grants were explicitly re-supplied as new narrower ceilings; not a production policy load or identical full-contract reuse. |
| Production contract drift checks | 8 | Not run | 8/8 rejected before replay | Source, command, verifier, or runtime identity drift invalidated the contract. |
| RR01 research-only shadows | 9 | 9/9 | 9/9 controls pass | One task only; no contract was issued and no policy was promoted. |

Under the exact-source workflow test, all three fresh F repetitions passed for each of nine promoted tasks. This is explicit grant re-supply for the same source/commands/verifier/runtime, not automatic policy loading. The production `tune` path was then tested against eight incompatible contracts: five source-tree changes, agent argv, verifier argv, and runtime binary. **All eight were rejected before any replay.**

The seven predeclared RR01 source/argv shadows all passed utility after correcting the host-canary marker in a separate diagnostic; all seven security controls passed. Two post-freeze exploratory shadows also passed: a new behavior-asserting test in the verifier file, and an actual `typing-extensions` addition to the test dependency group with the corresponding lock entry. No dependency was installed, resolved, or downloaded in that supplementary case. These nine shadow trials all used one scripted RR01 task, wrote no contracts, and promoted no policy. They show empirical sufficiency for small edits in one workflow, not a safe generalization rule. See [`reuse-shadows-extended.json`](results/final/reuse-shadows-extended.json). The earlier frozen per-task shadow fields use the wrong host-canary marker and must not be interpreted as successful or failed security evidence; the corrected diagnostic supersedes only that exploratory security check and leaves primary results untouched.

The exact-contract rules invalidate policy evidence after every tested source, command, verifier, or runtime change—even when the shadow workflow still passed. This protects correctness but sharply limits reuse in an actively edited checkout. The same-snapshot arm covers nine patch-and-verify tasks; only RR01 received source-drift shadows. These results do not establish that a policy is useful for ordinary repeated builds/tests or remains safe across changing repository versions. Same-snapshot repetition and reuse across changing repository versions are different capabilities.

The median incremental F tuning wall time on promoted workflows was **4.57 s**, versus **0.299 s** for one static B run. At 10 future identical runs, this is 0.457 s of tuning per run and misses the predeclared latency break-even gate. It reaches the static run's latency at about 16 identical repetitions; at 50, the arithmetic amortization is 0.091 s per run. That calculation assumes no change in source/command/verifier/runtime and says nothing about policy safety across versions. Median repeat CLI wall was 0.493 s for F and 0.553 s for B; AutoCage does not claim a runtime speedup. These are scripted-task costs. Model-backed replays were not measured, so they cannot substantiate practical affordability for coding agents.

The median per-workflow F optimizer cost was 10 replays, including seven search replays and three final validations; individual values are in raw records. Model-backed replay cost was not measured. As a sensitivity illustration only, if one full agent/verifier replay took 30 seconds, 2 minutes, or 10 minutes, ten replays would take about 5 minutes, 20 minutes, or 100 minutes, respectively, in addition to the initial run. The scripted results cannot establish that model-backed tuning is affordable.

Run records separately attribute preflight and workspace-staging timings: 11 broad executions recorded 25 ms preflight and 1.203 s staging total; 234 optimizer executions recorded 590 ms preflight and 19.150 s staging; 60 B/F exact repeats recorded 159 ms preflight and 4.908 s staging. CLI wall times include process startup, staging, task/verifier, and persistence. Millisecond-granularity Bubblewrap argument-compilation timings were recorded as zero and are below useful resolution; they are not zero-cost claims.

## Search scaling microbenchmark

The separate deterministic atom-count matrix validates all candidate policies at 4, 8, 16, 32, and 64 atoms in clustered and dispersed layouts. Total replay counts include three validations:

| Atoms | Greedy/random | Hierarchical clustered | Hierarchical dispersed |
|---:|---:|---:|---:|
| 4 | 8 | 7 | 7 |
| 8 | 12 | 11 | 13 |
| 16 | 20 | 15 | 25 |
| 32 | 36 | 23 | 49 |
| 64 | 68 | 39 | 97 |

Grouping helps substantially when required atoms are clustered and costs more when they are dispersed. It failed the predeclared requirement to be at least 20% cheaper at 16/32/64 in both layouts. This synthetic microbenchmark does not establish production scalability. Keep hierarchical search experimental; greedy is the simpler default candidate for future user-facing work unless another frozen test demonstrates a repeatable advantage.

## Criteria and recommendation

The exact-repeat, contract-rejection, utility-preservation-with-safe-fallback, and individual canary-control conditions passed. The minimum promotion advantage, 80% F canary block rate, and 10-run amortized-latency conditions failed. There were no task timeouts. Thus the M3.5 quantitative gate is **not passed**.

**Research recommendation C — pivot policy learning before agent integration.** M3.5 shows that narrower writes can block a test-root create operation that the selected static policy permits, but it misses the frozen policy-value and 10-run cost gates. More importantly, the study's repeated arm replays identical source-changing patch tasks; it is not direct evidence for common recurring CI or maintenance workflows. Keep the optimizer as a research feature. The next experiment should compare a developer-authored, pre-execution workflow profile against the current static policy on actual repeatable test/build/generation commands across changing source revisions. Preserve exact contract rejection for learned policies; do not generalize or promote cross-snapshot reuse. Do not begin full M4 real-agent integration until that experiment establishes a stable use case. This does not claim that a profile pivot is already proven better; it is the smallest next comparison that addresses the demonstrated timing and reuse mismatch.

## Reproduction and artifacts

Run the environment setup, pinned M3 preparation, and commands in [README.md](README.md). Then recompute summaries from the per-task files:

```sh
python3 experiments/m35-product-value/analyze_results.py \
  --output experiments/m35-product-value/results/final/analysis.json
```

The frozen primary evidence includes `aggregate.json`, `environment.json`, and 11 `tasks/*.json` files. Supplemental evidence contains the corrected reuse shadows, RR03 diagnosis, scaling matrix, and M0/M2 compatibility regression records. No original checkout edits, host credential access, host security changes, network egress, or paid inference were used.
