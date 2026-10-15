# M3.6 — Pre-execution policy value validation

**Verdict: B — keep deterministic profiles as experimental infrastructure and pivot the primary contribution.** Protocol v3 completed on 2026-10-15 in the isolated Ubuntu 24.04.5 ARM64 Lima guest. The eight held-out workflow types span six permissively licensed repositories; each ran at pinned parent and target commits. This is a feasibility/product signal, not a statistically powered generalization claim. The frozen protocol and complete per-run records are in [`PROTOCOL.json`](PROTOCOL.json) and [`results/v3-final/results.json`](results/v3-final/results.json).

## Decision in brief

The proposal rules established useful **first-run** restrictions: read-only staged workspaces for tests and compileall whose outputs were redirected to private `/tmp`, and one recursive `dist/` grant for local wheel output. They preserved utility on all 16 held-out source/revision cases and blocked all 96 tested out-of-scope writes. Profile generation had a 4.5 ms median, with no full-task search replay.

But a competent static policy and a developer-authored policy produced the **same grants** as the proposal in every case. They had the same 16/16 utility and 96/96 canary results, without profile generation or a proposal-acceptance flag. Human authoring/review time was not measured. Therefore the experiment does not meet its predeclared differentiation criterion, and it does not justify choosing AutoCage over a configurable existing sandbox for these workflows. Post-run greedy tuning reached the same policy on all eight target revisions at four full replays per workflow.

## Protocol and workloads

The frozen v3 set evaluated complete Git archives at both pinned revisions. Parent/target pairs are repeated observations of each workflow, not independent repositories. The direct Filelock pytest selection in incomplete v1 could not collect tests because the archive omitted the build-generated `src/filelock/version.py`; v2 replaced that task with real source-tree compileall. No completed v1/v2 aggregate is included here.

| ID | Repository / license | Workflow | Parent → target commit |
|---|---|---|---|
| W03 | [python-dotenv](https://github.com/theskumar/python-dotenv) / BSD-3-Clause | `pytest tests/test_parser.py` | `791414804eff08a23f0b7970968e1717e3b28e66` → `0b2880591780a426b0551436f47a17e7a76d954f` |
| W04 | [attrs](https://github.com/python-attrs/attrs) / MIT | `pytest tests/test_filters.py` | `f616f732c6c5f87a8f7a762176422baed250a6be` → `5aa76a4450c311d87eda43946ec0ecd743572649` |
| W05 | [filelock](https://github.com/tox-dev/filelock) / MIT | `compileall -q src` | `4c6f32f2797b2883bbcb0cca1ee81211d3e09c12` → `a5fb607a8655035bb6d5ae4326637e25cf1af849` |
| W06 | [iniconfig](https://github.com/pytest-dev/iniconfig) / MIT | `pytest testing/test_iniconfig.py -k 'not bom'` | `40d8c03a1553953350d787e45f1cb768e2c14e6a` → `d2dcb7289291e7e7019c183659814d42f7264b2d` |
| W07 | [pluggy](https://github.com/pytest-dev/pluggy) / MIT | `pytest testing/test_hookcaller.py` | `0b7e46a29a5bc853b9b465f235175464fef740a0` → `44474dd303ede8f22db180ca0a74e255b1fcfb2e` |
| W08 | [attrs](https://github.com/python-attrs/attrs) / MIT | `compileall -q src` | `f616f732c6c5f87a8f7a762176422baed250a6be` → `5aa76a4450c311d87eda43946ec0ecd743572649` |
| W10 | [click](https://github.com/pallets/click) / BSD-3-Clause | Offline local wheel to `dist/` | `6d5bac5c712195cbfa9666ba0ecbf0573cdea356` → `f67c2bb6c2f055c1c7a57cd46c3697fc26a7742e` |
| W11 | [attrs](https://github.com/python-attrs/attrs) / MIT | `pytest tests/test_validators.py` | `f616f732c6c5f87a8f7a762176422baed250a6be` → `5aa76a4450c311d87eda43946ec0ecd743572649` |

Pytest caches and Python bytecode were directed to per-workflow private `/tmp`. The wheel command disabled dependency resolution and build isolation; its output verifier was pinned and mounted read-only. M3's pinned Python test environment and hash-checked build backend were prepared before task execution. Every task and verifier ran in the same no-egress Bubblewrap boundary. The scripted commands test filesystem policy behavior; they do **not** test a model or an agent discovering and implementing a code change.

## First-run comparison

All four policy arms use the same 16 task/revision cases. A broad workspace ceiling is the positive control. B is a reasonable static command configuration, C is an explicitly authored task profile with the same semantics, and D is the accepted deterministic AutoCage proposal plus a separate workspace-root maximum ceiling. E is the existing post-run greedy optimizer, run on the eight target revisions after the broad run.

| Method | Verified utility | Median weighted writable exposure | Median reduction vs broad | Out-of-scope canary operations blocked | Full task replays before protected first run |
|---|---:|---:|---:|---:|---:|
| A — broad workspace writes | 16/16 | 328 (range 94–522) | 0% | 0/96 (broad positive control modified 96/96) | 0 |
| B — competent static | 16/16 | 0 (wheel cases: 10) | 100% | 96/96 | 0 |
| C — developer-authored profile | 16/16 | 0 (wheel cases: 10) | 100% | 96/96 | 0 |
| D — pre-execution suggestion | 16/16 | 0 (wheel cases: 10) | 100% | 96/96 | 0 |
| E — post-run greedy, target revisions only | 8/8 policies validated | 0 (wheel: 10) | 100% median | 48/48 | 4 per workflow, after broad success |

Every canary operation attempted in-place writes to six synthetic locations: unrelated source, unrelated test, build configuration, repository automation, deployment configuration, and sensitive configuration. The trusted controller inspected the staged files and source-checkout hashes. Every A/B/C/D control executed and matched the compiled grant behavior; E ran the same controls for each target revision. These are tested staged-write operations, not proof against all filesystem operations or host escape.

B, C, and D compiled **identical grants in all 16 paired cases**: no workspace write grants for pytest/compileall, and only recursive `dist/` for wheel output. D's policy score was 100% lower at the median than broad A under the unchanged `weighted-write-surface-v1`; its mean reduction was 99.76%. The score is based on existing tree entries and is not an exploitation probability. The `dist/` grant allows creation of arbitrary future descendants below that directory, which the current-tree score does not measure.

## Cost and reuse

- D generated 16 proposals (one per source/revision) with 4.5 ms median, 3.6 ms mean, and 6 ms maximum measured CLI time. It made no full-task replay before its first protected run. B and C need no proposal and produce the same policy.
- D passed three additional fresh exact-source repetitions per proposal: **48/48**. These prove repeated execution against the same source, command, verifier, and runtime; they do not make the proposal reusable after contract drift.
- The post-run E arm found validated policies on **8/8** target revisions. Each used one search replay plus three final validations: four full agent/verifier replays per workflow, **32 total**. Median `tune` CLI wall time was 1.885 s and total was 15.525 s. Initial broad runs were shared with A and are not double-counted.
- Across the final study the controller recorded 221 agent-like child processes (including 72 independent canary commands), 149 verifier executions, 64 initial policy-comparison sessions, 48 exact repeats, 32 optimizer replays, and five research-only shadow task runs. There were zero sessions without a run record. Fourteen stale-profile attempts stopped before task or verifier execution.
- The D CLI requires explicit `--accept-proposal` and an independently supplied ceiling; no interactive permission prompts or corrections occurred in this noninteractive experiment. We did not measure human time to author, understand, or review B/C/D policies. Therefore the protocol's human-effort branch is **NOT TESTED**, and zero rule counts do not stand in for measured effort.

All eight parent-to-target stale profile attempts and all six controlled source/command changes rejected before execution. Fresh proposals on both pinned revisions preserved utility. A research-only wheel shadow with an explicitly reauthorized old `dist/` grant passed five source/config changes; command-argument drift had no shadow run. This one workflow does not authorize production reuse. Stable user-authorized templates and empirical policy evidence remain different concepts; production proposal identity remains bound to the exact source and command.

## Security meaning and RR03

These policies prevented out-of-scope changes from entering the staged workspace, where they could otherwise appear in the review patch. They do not protect the original checkout beyond the existing copy-based boundary: the source is never mounted in the sandbox and changes are not automatically applied. Narrower write grants add defense against unwanted changes within the stage, but they do not replace patch review and do not constrain reads, executables, or model behavior in granted paths.

M3.5's RR03 diagnosis remains unchanged: the edit to `src/packaging/pylock.py` worked under an exact-file write grant, but the original pytest verifier attempted to create `.pytest_cache` at the workspace root. That directory-entry operation required root directory authority and caused no validated narrow promotion under the frozen verifier. In M3.6's explicitly configured pytest workflow, cache output went to `/tmp`; this legitimate command configuration let the pre-execution readonly profile run. This does not revise the M3.5 result or imply that arbitrary pytest plugins have no other writes; the proposal reports those behaviors as unresolved.

## Incomplete attempts and harness corrections

The first v1 held-out attempt stopped at W05 because the Filelock Git archive lacked its generated `src/filelock/version.py`; direct pytest collection failed under the broad policy before the verifier ran. The reporting controller then raised on a null verifier field. V2 replaced W05 with compileall, but stopped at W06 before any task process because the verifier root was incorrectly hard-coded to `tests/` instead of the repository's `testing/`; the repeat summarizer also assumed a run record. These partial runs are marked `INCOMPLETE`, with no missing check treated as a pass and no aggregate combined into v3. V3 derives the verifier root from the pinned test path, preflights all task/verifier paths, and records absent run records as failures rather than crashing. See archived protocols, plans, and progress JSON under `results/incomplete-v1/` and `results/incomplete-v2/`.

The first v1 protocol freeze also pointed its controller hash at the freeze helper. That was caught before held-out execution, corrected and audited; the incomplete protocol file remains preserved. V2/v3 tasks, cost weights, security controls, and thresholds were unchanged by the v3 harness corrections.

## Criteria and conclusion

The final v3 execution passed all applicable required controls: broad positive canaries, static/authored/proposed negative canaries, task utility, exact-contract repetitions, and stale-policy rejection. The predeclared zero-replay and profile-generation thresholds passed. No timeout, task failure, source modification, or missing final security control occurred.

The predeclared minimum differentiation criterion for recommendation A did **not** pass: D blocked zero percentage points more canary writes than competent static B, and human authoring/review effort was not measured. Therefore the result is **B — retain workflow suggestions as experimental infrastructure, pivot the core innovation, and do not start full M4 agent integration on the strength of profile synthesis alone**.

The main product value that is established is a small, explainable ruleset that can emit first-run policy suggestions within a developer ceiling. It performs like a good handwritten static policy on this narrow Python sample. The study does not establish lower configuration effort, general task-to-policy inference, stochastic-agent utility, model-backed replay affordability, or a reason to replace nono/OpenShell/Codex sandboxing for a general coding agent.

### M3.5 wording clarification

The historical M3.5 report's “latency break-even” wording for roughly 16 repetitions is inaccurate. Dividing its measured one-time tuning cost across assumed later runs is only amortized overhead accounting. The optimizer does not inherently make later runs faster, and no recovered execution latency was measured. M3.5's observed times and frozen result are unchanged.
