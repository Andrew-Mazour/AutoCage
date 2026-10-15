# M3 real-repository write-policy evaluation

**Final run:** 2026-10-11 guest-local time, isolated Ubuntu 24.04.5 ARM64,
Linux `6.8.0-142-generic`, Bubblewrap 0.9.0. The run binds to AutoCage release
binary SHA-256
`331def046e49f2c3720bdbc40afd8841917350686b5513c37b8661c6ae470808` and
protocol SHA-256
`11117c95fa81ead2805505030f283518ae399d20d70ec4bf2938e3a7b0ab472b`.
The complete per-task and aggregate records are in
[`results/2026-10-12/final/`](results/2026-10-12/final/).

## Result in brief

The held-out numeric thresholds were met: F preserved utility on 7/7 tasks,
reduced the median full-corpus weighted write surface by 76.2%, and used a
median of 11 optimizer replays, including its three fresh validations. Its
held-out mandatory canaries had zero failures and zero untested checks.

The all-task utility gate was not met: F returned an inconclusive broad fallback
on development task RR03 after two rejected candidates. The other ten tasks
produced a validated F result. This is an incomplete optimization, not a
promoted unsafe policy; it still means AutoCage did not produce a narrower
validated policy for every broad-baseline-passing task. M3's overall research
verdict is therefore **INCONCLUSIVE**. The run supports useful narrowing on
these held-out tasks but does not establish general coding-agent usefulness or
hierarchical search superiority.

## Frozen method

The frozen suite has 11 tasks from seven open-source repositories: four
development tasks from two repositories and seven held-out tasks from five
repositories. RR01/RR02 share click; RR03/RR04 share packaging; RR05/RR06 share
python-dotenv; RR09/RR11 share iniconfig. These are task samples, not 11
independent repositories.

The scripted agents apply target-commit file blobs to the pinned parent
snapshot, plus the task's declared create/delete/rename/atomic-replace action.
Repository tests and task commands are run in AutoCage. Preparation reads Git
objects and sets up pinned dependencies outside the task sandbox, but does not
execute repository build hooks. The scripts are not language models and do not
test whether an agent can discover or correctly author a patch. They isolate
filesystem-policy behavior against real source trees and project verifiers.

| Task | Repository / license | Parent → target commit (abbreviated) | Changed paths and extra operation | Verifier; observed passing tests |
|---|---|---|---|---|
| RR01 | click / BSD-3-Clause | `6d5bac5c` → `f67c2bb6` | `src/click/utils.py` | `tests/test_utils/test_make_default_short_help.py`; 36 |
| RR02 | click / BSD-3-Clause | `06b2a678` → `9f0bcdf0` | `src/click/core.py`, `docs/parameters.md`, `docs/upgrade-guides.md` | `tests/test_arguments.py`, `tests/test_deprecations.py`, `tests/test_options.py`; 971 |
| RR03 | packaging / Apache-2.0 OR BSD-2-Clause | `2aada00b` → `fa52d723` | `src/packaging/pylock.py` | `tests/test_pylock.py`; 73 |
| RR04 | packaging / Apache-2.0 OR BSD-2-Clause | `2c87a33f` → `2aada00b` | `src/packaging/specifiers.py` | `tests/test_requirements.py`, `tests/test_specifiers.py`; 7,388 |
| RR05 | python-dotenv / BSD-3-Clause | `79141480` → `0b288059` | `src/dotenv/main.py` | `tests/test_main.py`; 156 |
| RR06 | python-dotenv / BSD-3-Clause | `828bdfe5` → `6a49d6d8` | `src/dotenv/cli.py`, `src/dotenv/main.py`; atomic replace of `main.py` | `tests/test_cli.py`, `tests/test_main.py`; 185 |
| RR07 | attrs / MIT | `f616f732` → `5aa76a44` | validator source/stub, docs, and new changelog file | `tests/test_validators.py`; 168 |
| RR08 | filelock / MIT | `4c6f32f2` → `a5fb607a` | `src/filelock/_read_write.py`; transient create/rename/delete in `src/filelock` | `tests/test_read_write_fd_fallback.py`; 20 passed, 4 upstream macOS-only cases deselected |
| RR09 | iniconfig / MIT | `40d8c03a` → `d2dcb728` | `src/iniconfig/_parse.py` | `testing/test_iniconfig.py`; 54 |
| RR10 | pluggy / MIT | `0b7e46a2` → `44474dd3` | plugin manager source and changelog; transient create/delete in `src/pluggy` | `testing/test_pluginmanager.py`; 75 |
| RR11 | iniconfig / MIT | `6bc55287` → `f1d82282` | packaging metadata, source, and stub deletion | `testing/test_iniconfig.py`; 42 |

The complete commit IDs, URLs, paths, task operations, and oracle grants are in
[`tasks.json`](tasks.json). Each task's prepared snapshot hash, verifier hash,
and operation outcomes are in its JSON record.

## Runtime and reproducibility

The sandbox had no egress. Pinned Python was 3.12.3; pytest 9.1.1 and its
plugins were installed from the SHA-256-pinned wheel lock. The guest also used
Bubblewrap `0.9.0-1ubuntu0.3` and the package versions in `protocol.json`.
RR08 used a fixed Linux filter for four upstream macOS-only tests; selected
tests were not skipped. The protocol's total-task cap was 12 optimizer replays
per strategy, including three final validations, with a 120-second task
timeout. The published seed was `0x4155544f43414745`.

The final protocol changed only the executable identity after contract
hardening. Task IDs/split, costs, baseline definitions, weights, timeout,
replay budget, validations, and thresholds were unchanged. The earlier runs and
their matching protocol copies remain under `results/2026-10-11/` as
superseded records; they are not mixed into these aggregates.

The protocol's predeclared acceptance required: every broad-baseline-passing
task to retain verifier utility; zero mandatory canary escapes with every
required check actually run; at least 25% held-out full-corpus median reduction;
and at most 12 median optimizer replays. The held-out threshold is met, but the
all-task utility condition is incomplete because RR03 F has no promoted policy.
The pivot signal was below 15% held-out reduction or material held-out false
denials; neither occurred. The project-wide gate is still inconclusive rather
than passed because of the explicit all-task utility requirement.

## Aggregate comparison

“Full median / mean” counts failed and inconclusive policies as zero
reduction. “Conditional median” only summarizes tasks that produced a passing
policy and is shown separately to expose success-conditioned bias. Replay
counts exclude each method's initial broad run and include final validation.
Per-method agent/verifier and wall totals are attributed costs: the common broad
run is charged to each optimizer for fair per-method comparisons. The run had
293 unique physical agent executions across all arms. Attributed wall time
includes replay and controller time; the separate controller column is also
reported. No arm timed out.

| Method | Utility | Conditional median reduction | Full-corpus median / mean reduction | Median optimizer replays | Search + fresh validation replays | Attributed agent / verifier executions | Attributed wall / controller seconds |
|---|---:|---:|---:|---:|---:|---:|---:|
| A Broad | 11/11 | 0.0% | 0.0% / 0.0% | 0 | 0 + 0 | 11 / 11 | 8.9 / 2.6 |
| B Static | 10/11 | 47.3% | 45.7% / 43.4% | 0 | 0 + 0 | 11 / 11 | 7.3 / 1.1 |
| C Changed paths | 8/11 | 99.1% | 94.2% / 60.7% | 0 | 0 + 0 | 22 / 19 | 14.0 / 10.1 |
| D Greedy | 10/11 | 96.6% | 94.2% / 62.6% | 7 | 51 + 30 | 92 / 73 | 61.2 / 13.4 |
| E Seeded random | 10/11 | 96.6% | 94.2% / 67.8% | 7 | 51 + 30 | 92 / 72 | 61.0 / 13.0 |
| F Hierarchical | 10/11 | 96.6% | 94.2% / 75.5% | 8 | 57 + 30 | 98 / 63 | 54.8 / 13.7 |
| M Manual reference | 9/11 | 98.9% | 94.2% / 76.5% | 0 | 0 + 0 | 11 / 10 | 7.2 / 1.2 |

The held-out slice is the more relevant comparison for claims about unseen
repositories:

| Method | Utility | Full-corpus median / mean reduction | Median optimizer replays | Agent / verifier executions | Wall / controller seconds | Security failures / not tested |
|---|---:|---:|---:|---:|---:|---:|
| A Broad | 7/7 | 0.0% / 0.0% | 0 | 7 / 7 | 4.1 / 1.0 | 0 / 0 |
| B Static | 7/7 | 45.7% / 46.3% | 0 | 7 / 7 | 3.7 / 0.6 | 0 / 0 |
| C Changed paths | 4/7 | 76.2% / 52.7% | 0 | 14 / 11 | 5.5 / 4.7 | 0 / 3 |
| D Greedy | 7/7 | 76.2% / 55.7% | 8 | 69 / 56 | 40.4 / 7.8 | 0 / 0 |
| E Seeded random | 7/7 | 76.2% / 63.9% | 8 | 69 / 55 | 40.3 / 7.7 | 0 / 0 |
| F Hierarchical | 7/7 | 76.2% / 76.0% | 11 | 74 / 46 | 33.9 / 8.1 | 0 / 0 |
| M Manual reference | 6/7 | 88.2% / 77.5% | 0 | 7 / 6 | 3.5 / 0.6 | 0 / 1 |

The process-start plus preflight control had a median of 2.12 ms over five
samples; this is excluded from task replay wall time. It is small next to a
complete task replay, although real model-agent replay duration was not tested.

## Task-level outcomes and failures

- **RR03 packaging:** broad A passed; B and M did not verify. D/E/F each made
  two search trials and returned inconclusive without final validation. The
  first candidate ran the agent but failed its verifier; the next zero-write
  candidate failed in the agent. There were no timeouts or canary escapes. The
  optimizer retained the broad result and did not claim a narrowed policy.
- **Naive C:** failed before a useful verifier result on RR06, RR08, and RR10.
  The broad ceiling passed these tasks. Its 99.1% successful-task conditional
  median obscures its 8/11 overall success rate and three tasks with
  unexecuted security checks; zero-reducing failures lower its full-corpus
  mean to 60.7%.
- **B and M:** both failed RR03; M also failed RR10. These are not optimizer
  false grants, but narrow policies that did not preserve the verifier.
- **D/E/F:** each failed to produce a promotable result for RR03; other ten
  tasks produced validated policies. Across the held-out tasks, all three
  strategies passed all seven.

There were zero timeouts and zero measured security-canary failures. F had one
NOT TESTED promotion-check entry overall because RR03 never reached fresh
validation; the held-out F slice had zero untested mandatory checks. C and M
also have untested entries where their agent failed before verifier/canary
execution. Those entries are not counted as passes.

## Algorithm and cost assessment

On the held-out slice, F's 76.0% mean full-corpus reduction exceeded D's 55.7%
and E's 63.9%, while all three had the same 76.2% full-corpus median. F used a
median of 11 optimizer replays versus 8 for D/E, and had more agent executions
(74 vs. 69). Its attributed wall time was lower (33.9s vs. 40.4/40.3s) because
more rejected agent trials terminated before starting pytest; this is not
evidence that hierarchy is intrinsically faster. On the full corpus, F,
greedy, and random all had the same 96.6% conditional median and 94.2%
full-corpus median. F's higher full-corpus mean is driven by a few held-out
tasks, with seven held-out tasks and five repository groups too few to establish
a stable advantage.

Changed-file inference was narrower when it succeeded, but it failed three
held-out tasks. A developer cannot use that conditional reduction alone as a
comparison. Static B passed all seven held-out tasks with no optimizer
replays and a 45.7% median full-corpus reduction. AutoCage F adds about 30.5
median percentage points over that fixed policy on this sample, at the cost of
11 task replays at the median.

The exposure cost is still a heuristic over the existing staged tree, not an
exploit probability. This run does not count future filenames a recursive
directory may create. The repository snapshots ranged from 16 to 178 regular
files and 22 KB to 2.1 MB, but the candidate seeds contained only one to four
atoms. There was no controlled atom-count or repository-size scaling series;
the experiment cannot support an optimizer complexity/scaling claim. Long test
suites dominate replay time (RR04 alone ran 7,388 tests), while real model
execution could be much more expensive than these scripted actions.

## Is post-run tuning useful?

The first broad run completes the task; tuning happens after that and adds full
agent/verifier replays. There is no first-task latency or authority benefit to
the task that has already completed. On this fixture suite the added cost was
measurable: F attributed 87 optimizer replays (57 search + 30 fresh validation)
and 54.8 seconds over 11 tasks, on top of the 11 broad executions. Real model
agent replay cost is unknown and could be much higher.

The current contract intentionally binds a tuned result to the exact source
snapshot and workspace path, executable and argv digests, verifier executable,
declared readonly verifier roots, timeout, runtime, backend, environment, and
authorized ceiling. A changed source file, task prompt/argv, verifier input, or
runtime invalidates reuse. This limits policy reuse across ordinary successive
coding tasks. A same-snapshot repeat of a fixed test/build/maintenance command
is the most plausible use: the developer can reapply the retained grants as an
explicit run ceiling. M3 does not yet provide a policy-file loader or
cross-snapshot reuse, and no repeated-run experiment measured that benefit.

The evidence therefore favors investigating repeatable, pinned repository
workflows (test, lint, generation, release checks) before positioning AutoCage
as a permission optimizer for arbitrary one-off natural-language coding tasks.
The minimal follow-up should test the same declared workflow across controlled
source changes and task repeats, while preserving exact verifier/runtime checks
and separately measuring false denials. Do not weaken fingerprints to create
apparent reuse.

## M3 engineering checks

On the final source and Linux guest:

- `cargo fmt --check`: passed.
- `cargo clippy --locked --all-targets -- -D warnings`: passed.
- `cargo test --locked`: 38 unit tests and 20 Linux integration tests passed.
- `cargo build --locked --release`: passed.
- M0 feasibility harness rerun: 41/41 PASS.
- M2 22-task regression rerun: broad utility 22/22; greedy and random 22/22;
  hierarchical 22/22; median reductions and ordering unchanged; all F canaries
  passed and no timeouts.
- M3 frozen real-repository suite: 11 tasks; all broad baselines passed; F
  validated 10 tasks and returned one safe inconclusive result; held-out F was
  7/7; no timeouts or measured canary escape.

## Verdict and recommendation

The result supports the bounded claim that replay-based write-policy
optimization can find useful narrower policies on some real repository tasks.
It does not show that F is consistently better than simpler search, that the
search is economical for a model-driven agent, or that the task-exact policy is
useful for normal cross-task coding workflows. Keep the optimizer as a research
feature, do not claim hierarchical superiority, and do not begin M4 agent
integration yet. First resolve the RR03 inconclusive behavior and run a
predeclared repeatable-workflow reuse experiment. The current M3 result is
**INCONCLUSIVE** against the complete utility-preservation criterion.
