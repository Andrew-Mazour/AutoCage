# AutoCage implementation roadmap

**Status (2026-10-15):** M0–M3.6 implementation and scoped evaluation are complete. M3's historical verdict remains **INCONCLUSIVE** because RR03 had no validated narrow policy under its frozen verifier. M3.5 found concrete test-root write blocking in selected cases, but its patch-task repeats did not establish recurring-workflow value. M3.6 found that deterministic pre-execution suggestions preserve utility and block staged writes, yet are identical to a competent static policy and have no measured user-effort advantage. Final recommendation **B**: retain profiles as experimental infrastructure and pivot the main contribution to an agent-containment evaluation prototype. The historical 16-repeat M3.5 calculation is amortized tuning overhead only, not latency savings or a latency break-even. See the [M2 report](../experiments/write-policy-v1/REPORT.md), [M3 report](../experiments/real-repository-v1/REPORT.md), [M3.5 report](../experiments/m35-product-value/REPORT.md), and [M3.6 report/evidence](../experiments/m36-preexecution-value/REPORT.md).

Effort assumes one student working part-time and is an estimate. Each stage has a stop/go review. Security tests are part of each deliverable.

## M0 — Linux feasibility gate

**Execution status (2026-10-11): PASS.** Evidence: [`m0-20261011-ubuntu-24.04-arm64.json`](../experiments/m0-linux-feasibility/results/m0-20261011-ubuntu-24.04-arm64.json) and the [human-readable report](../experiments/m0-linux-feasibility/results/REPORT.md). Environment: Ubuntu 24.04.5 ARM64, Linux 6.8.0-142, Bubblewrap 0.9.0, EUID 501. The final harness run passed **41/41 checks**, with no FAIL, BLOCKED, or NOT TESTED results. Ubuntu's official `bwrap-userns-restrict` profile was loaded in enforce mode; `kernel.apparmor_restrict_unprivileged_userns` remained `1`, and Bubblewrap remained non-setuid.

**Measured findings:** all required namespaces worked individually and together; the child ran with the enforced `unpriv_bwrap` profile, zero capability sets and `NoNewPrivs=1`; nested userns creation was blocked only when Bubblewrap's `--disable-userns --assert-userns-disabled` flags were present. Readonly-stage, exact-file and writable-directory mounts worked, including nested readonly precedence. Exact-file mounts permit content writes but not create/unlink/rename/atomic replacement; a parent-directory grant is required for those operations. Raw source hard links can expose/mutate an outside inode, so staging must copy file bytes. Bubblewrap preserves explicitly inherited FDs; a controller launch with `close_fds` blocked the synthetic canary. Network namespace, child network inheritance, timeout cleanup, and Python/pytest canaries passed. See the report for the official profile's broad permissions and M0's limits.

**Reproduction:** on a clean ARM64 Ubuntu 24.04 guest with no host directory mounts, run `setup/install-guest-deps.sh` as the ordinary user. It checks for conflicting Bubblewrap profiles before installing packages, loads only the official Ubuntu profile, verifies the global restriction and enforced profiles, then runs an unprivileged smoke probe. The setup also installs the Rust toolchain and M1 test utilities. Run the complete harness as described in [`experiments/m0-linux-feasibility/README.md`](../experiments/m0-linux-feasibility/README.md).

**Gate decision:** M0 is passed for the measured guest/configuration; M1 may proceed. This does not prove escape resistance or availability isolation. Keep namespace/profile preflight fail-closed on other systems and do not disable AppArmor's global restriction, set Bubblewrap setuid, or fall back to shared networking.

## M1 — Minimal fail-closed runner

**Status:** **PASS / complete for the scoped M1 runner** (2026-10-11). The exact Linux environment and suite are recorded in the [M1 report](../experiments/m1-runner/REPORT.md).

**Effort:** 2–3 weeks.

**Files:** one Rust binary: `src/main.rs`, `src/error.rs`, `src/cli.rs`, `src/preflight.rs`, `src/workspace.rs`, `src/policy.rs`, `src/backend/bubblewrap.rs`, `src/runner.rs`, and `src/record.rs`; Linux integration tests in `tests/linux_runner.rs`. Verifier execution remains a small runner responsibility; no separate verifier module is justified yet.

**Implemented:** fail-closed `check` and non-interactive `run`; unprivileged Ubuntu/ARM/kernel/AppArmor/Bubblewrap preflight and a live namespace probe; root-owned non-setuid Bubblewrap and trusted `diff` executable checks; safe private workspace copy with omission reporting, symlink/special-file handling, hard-link breakage, manifests and hashes; required namespace/mount configuration, nested-userns denial, closed non-stdio descriptors and cleared environment; bounded agent/verifier process groups; optional verifier argv and read-only baseline overmounts; review patch and mode-0600 JSON record. No network, no automatic apply, and no policy search.

**Tests:** `cargo fmt --check` passed; `cargo test --locked` passed **22 unit tests and 6 Linux integration tests**; `cargo build --locked --release` passed. Integration tests exercised the live namespace preflight; source-copy isolation; synthetic host-file and host-environment canaries in the agent and a child; verifier read-only overwrite and sibling-creation denials; host loopback listener isolation; separate verifier-failure status; timeout of a command and a detached-session descendant; JSON/patch output. Unit tests covered argument boundaries, grant validation, verifier-root overlap/symlink/traversal rejection, staging omissions/symlinks/special files/hard links, Bubblewrap flags and FD closure. M0 separately validates exact-file versus recursive-directory mount semantics. Missing-profile/bwrap failure injection, macOS execution, Unicode integration paths, and arbitrary repository workloads have not been tested.

**Acceptance/done:** met in the named isolated guest: scripted Python command and pytest verifier passed; verifier tampering and unauthorized access were denied; source checkout remained unchanged; timeout returned 124 and removed a detached child; verifier failure returned 3; records and patches were emitted. This is selected canary coverage, not a general sandbox proof.

**Invariants:** all threat-model invariants; no host checkout mount; no fallback; deny-by-default network; source hard links broken; AppArmor global restriction remains enabled; required Bubblewrap profile is enforced; `--assert-userns-disabled` is mandatory; no unapproved FD crosses exec.

**Risks/limits:** only Ubuntu 24.04 ARM64 with the expected AppArmor profile and Bubblewrap >=0.9 is accepted; commands are non-interactive; no aggregate CPU/memory/process limits; arbitrary source secrets are not detected; project-specific dependencies may not exist in the read-only system runtime; verifier code can still be malicious or incomplete. **Outside scope:** tuning, real agents, network access, Landlock/seccomp profiles, package downloads, automatic apply, PTY support.

## M2 — Early optimizer proof of concept

**Status:** **PASS against the predeclared M2 thresholds** (2026-10-11). Evidence is the frozen manifest, per-task JSON, compact run-record archive, and [report](../experiments/write-policy-v1/REPORT.md).

**Implemented:** versioned `FileContents` and `DirectoryTree` policies; ceiling-subset validation and normalized path checks; readonly-base Bubblewrap compilation with exact-file/directory writable mounts; opt-in replay contracts; runtime/source/executable identity checks; fresh-snapshot verifier replay; changed-manifest candidates; cost-aware hierarchical, fixed greedy, and seeded-random strategies; three fresh promotion validations; `run`, `tune`, and `inspect` CLI paths; 22 scripted tasks split 16 development/6 held out; baselines A–F and manual oracle M.

**Files:** `src/policy.rs`, `src/backend/bubblewrap.rs`, `src/optimizer.rs`, `src/contract.rs`, `src/digest.rs`, `src/record.rs`, `src/runner.rs`, `src/cli.rs`, `src/main.rs`, `tests/linux_runner.rs`, and `experiments/write-policy-v1/`.

**Measured:** the broad baseline passed 22/22 tasks. Hierarchical optimization retained a verifier-passing selected policy on 22/22 tasks: 20 policies were narrowed and passed three fresh validations; two root-level directory-entry tasks remained at the broad ceiling as inconclusive. All 22 selected-policy security-canary checks passed. Median weighted write-surface reduction was 91.9% across all tasks and 75.6% on the six held-out tasks. Median optimizer cost, including final validation, was 7 replays overall (6.5 held out); maximum was 12. No timeout occurred. Rejected candidates exited on denied task writes; no canary escape was observed.

**Comparison finding:** naive changed-file inference was narrower when it happened to pass but preserved utility on only 18/22 tasks because final manifests miss transient writes and exact-file rules cannot perform atomic replacement. All three replay optimizers preserved utility on 22/22, but hierarchical search had the same median final cost as greedy and random, one more median replay, and more rejected candidates. The task-specific search direction is promising; the current claim that hierarchical grouping improves search efficiency is not supported. See the experiment report before choosing a production default.

**Tests:** `cargo fmt --check`, strict Clippy, locked test suite (33 unit + 11 Linux integration), and locked release build passed in Ubuntu. Benchmark: 22/22 tasks; 20 validated narrow policies; 2 expected broad fallbacks; 0 timeouts; all selected-policy canaries passed. The full M2 suite must be rerun if policy, task, verifier, weight, baseline, or optimizer logic changes.

**Invariants:** subset policies only; no denial-triggered widening; fresh source snapshot for every replay; independent protected-resource canaries; exact-file grants never treated as directory-entry authority; three validation replays counted inside the cap; no automatic application to the source checkout.

**Remaining risks:** all tasks are synthetic and deterministic; verifier quality is task-specific; CPU/memory/process totals are not constrained; failed candidate runs that stop before the verifier leave that candidate's verifier canary NOT TESTED (the candidate is rejected); the supported guest is a single Ubuntu/ARM64/kernel configuration. **Outside scope:** real agents, LLMs, network support, package downloads, file-read minimization, dynamic mutation, applying patches.

## M3 — Repeatability, records, and real-repository validation

**Status:** implementation complete; research verdict **INCONCLUSIVE** (2026-10-12). See the [real-repository report](../experiments/real-repository-v1/REPORT.md), [frozen protocol](../experiments/real-repository-v1/protocol.json), and [final raw artifacts](../experiments/real-repository-v1/results/2026-10-12/final/).

**Implemented:** schema-versioned replay contracts; source, agent/verifier executable and argv-digest, verifier-root, runtime, backend, environment, timeout, and ceiling identity checks; verifier-root coverage checks for explicit workspace path arguments; private atomic record persistence and evidence seals; interrupted-run recovery; corrupt/missing-record invalidation; secret-value redaction; deterministic candidate ordering and replay accounting. No policy is reusable after contract drift. The contract stores argument digests and counts, not raw argv values; callers must resupply the exact commands for tuning.

**Tests:** final source passed 38 Rust unit tests, 20 Linux integration tests, `cargo fmt --check`, strict locked Clippy, and locked release build in the isolated Ubuntu guest. M0 passed 41/41 and the M2 22-task regression remained unchanged. M3 used 11 deterministic tasks over seven pinned repositories (four development tasks/two repos; seven held-out tasks/five repos). The broad baseline passed 11/11. F validated 10/11, including 7/7 held out; RR03 returned a safe inconclusive result. No timeouts or measured canary escapes; one F promotion check was NOT TESTED because RR03 did not reach fresh validation.

**Measured outcome:** held-out F had 76.2% median full-corpus reduction and 11 median optimizer replays, meeting those numeric gates. Across the full corpus it had 94.2% median and 75.5% mean reduction when the inconclusive task is scored as zero, but it did not meet the all-task utility-preservation requirement. Greedy/random matched F's held-out median reduction at 8 median replays; the sample does not establish hierarchy as superior. Naive changed-path inference reached a high conditional reduction but failed three held-out tasks, demonstrating why failed/inconclusive tasks are included as zero in full-corpus results.

**Product finding:** tuning happens after the first task, consumes full agent/verifier replays, and is bound to an exact source/argv/verifier/runtime contract. M3 did not measure repeated-workflow reuse or add a cross-task policy loader. Repeated pinned test/build/maintenance workflows are a plausible target; test this before M4. Do not weaken fingerprints to make policies reusable across changed snapshots.

**Acceptance:** record-hardening and M2 regression criteria passed. Real-repository research outcome is inconclusive, not a project-wide pass. RR03's safe fallback, no hierarchy advantage, no controlled scaling study, and no stochastic/real-agent evaluation remain explicit limitations.

**Outside scope:** cross-task policy reuse, stochastic agent repetitions, databases, graph stores, eBPF/ptrace tracing, M4 agent integration, network access, and broader sandbox claims.

## M3.5 — Product-value validation

**Status:** implementation and frozen experiment complete; quantitative gates **not passed**; research recommendation **C: pivot the near-term policy-learning approach**. Historical M3 results remain unchanged. Evidence is in the [M3.5 report](../experiments/m35-product-value/REPORT.md), [frozen protocol](../experiments/m35-product-value/PROTOCOL.json), and [raw/derived results](../experiments/m35-product-value/results/final/).

**Measured:** broad utility was 11/11; F promoted nine narrow policies and retained the successful broad ceiling on two inconclusive optimization outcomes. F blocked 8/11 test-root creation canaries versus B's 0/11. All 27 explicitly re-supplied same-snapshot F repeats passed. Tuning's median incremental wall time was 4.57 seconds versus 0.299 seconds for one static run, so the predeclared 10-repeat overhead-amortization gate failed. Dividing that cost over about 16 hypothetical runs is arithmetic allocation only; it does not imply a latency benefit or recovered time. All eight changed source/argv/runtime contracts were rejected before replay. A single RR01 policy remained utility-sufficient in nine exploratory changes, but these shadows are not production reuse evidence. The predeclared promotion-improvement and 80% canary-rate thresholds also failed. The task repeats replayed pinned source-changing patches from identical parent snapshots; normal recurring test/build jobs across source revisions were not directly tested. Hierarchy helped clustered synthetic permission atoms and cost more on dispersed layouts.

**Engineering changes:** M3 run records now capture preflight, staging, policy-validation, Bubblewrap-argument compilation, and supervisor timing fields at millisecond resolution. Added reproducible M3.5 protocol/workflow definitions, RR03 diagnosis, corrected reuse-shadow diagnostics, result analysis, and the controlled scaling test. No production policy loader, cross-snapshot reuse, model integration, or authority widening was added.

**Definition of done:** all M0/M2/M3 regressions and Rust checks pass; 11 primary patch-and-verify tasks, exact repeats, contract drift, independent write canaries, RR03 diagnosis, and scaling matrix ran inside the isolated guest. A research-only shadow marker bug was corrected in separate diagnostics; the frozen primary comparison remains unchanged. The suite does not directly represent recurring test/build workflows across source revisions. See the report for gate failures and instrumentation limitations.

## M3.6 — Pre-execution profile-value comparison

**Status: complete, final verdict B.** Evidence is in [`experiments/m36-preexecution-value/REPORT.md`](../experiments/m36-preexecution-value/REPORT.md), the v3 [protocol](../experiments/m36-preexecution-value/PROTOCOL.json), and [raw results](../experiments/m36-preexecution-value/results/v3-final/results.json). Protocol v3 executed eight workflow types at two pinned revisions across six Python repositories. A, B, C, and D each preserved utility on 16/16 cases. B, C, and D compiled identical grants and each blocked 96/96 independent canary writes; profile generation had a 4.5 ms median and required no full-task replay. E found the same policy on all eight target workflows after four full task replays each. All stale proposals were rejected; fresh proposals worked on both paired revisions. Authoring/review time was NOT TESTED. The minimum-differentiation criterion failed, so automated suggestions remain experimental infrastructure rather than a demonstrated product advantage.

The v1 and v2 attempts stopped incomplete due harness defects; they are separately archived and excluded from v3. M3.6 does not measure model coding ability or stochastic agents. It does not authorize policy reuse across snapshots.

## M4 — Agent containment evaluation prototype (recommended next; not started)

M3.6 did not establish differentiation for pre-execution profile suggestions. The next contribution should test whether AutoCage's existing OS boundary contains unwanted effects from an untrusted coding-agent process while allowing a legitimate repository task to complete. This is an implementation/evaluation milestone, not another product-value gate.

**First deliverables:** an experiment harness under `experiments/agent-containment-v1/`; pinned benign and malicious-repository/tool-output fixtures; a scripted arbitrary-executable agent that makes deterministic task and out-of-scope-write attempts; independent host/stage canaries; and baselines for unrestricted staged writes, competent static policy, and native agent permission controls where a free local path exists. Use the existing Bubblewrap backend and records. First validate repeatable security mechanics; add one local model-compatible agent only if it can run without paid inference or host credentials. Do not route model traffic through the namespace via an unreviewed proxy.

**Acceptance:** successful legitimate-task execution and independently measured containment outcomes are reported separately; all required canaries execute; original checkout and guest host canaries remain unchanged; network remains unavailable; exact commands/model/runtime are recorded; at least 20 paired stochastic runs are required before any claim of model utility parity. State clearly what the sandbox prevents and what the agent can still read or alter. A passing verifier alone is not security evidence.

**Outside scope:** cross-snapshot empirical policy reuse, automatic permission widening, credential brokering, new sandbox backends, paid inference, and claims about arbitrary one-off coding prompts.

## M5 — External benchmark

**Effort:** 3–5 weeks; may overlap M4.

**Files:** experiments/authbench/, benchmark adapters, pinned task manifest, baselines, raw results, analysis script, evaluation doc updates.

Audit AuthBench license, task setup, image reproducibility, and protocol. Start with a declared subset, then expand if feasible. Use scripted agents for zero-cost enforcement/policy experiments; local open-weight model is a separate optional result. Compare identical task/agent/runtime under ceiling, static, manual, naive, AutoCage, and fair nono/OpenShell integrations where possible.

**Acceptance:** pinned inputs and commands reproduce raw metrics without paid services; utility and sensitive exposure are separate; failures and missing tasks disclosed.

**Out of scope:** leaderboard claims, unreviewed paid inference, synthetic-only security claims.

## M6 — Linux release candidate

**Effort:** 2–4 weeks.

Add CI on pinned Ubuntu, install/troubleshooting guide, threat model, architecture diagram, benchmark report, dependency audit, versioned schemas, failure injection, and pre-1.0 release.

**Acceptance:** clean VM reproduces documented usage; fail-closed behavior is visible; no secret collection; every claim maps to tests/results; known limits are prominent.

**Out of scope:** macOS enforcement, Windows, enterprise fleet management, production-grade security claims.
