# AutoCage implementation roadmap

**Current status (2026-10-25):** `v0.1.0-rc.1` is published. Both portable GitHub Actions validation and the Ubuntu 24.04 ARM64 enforcement workflow passed on the release commit; see the [M6.2 release record](RELEASE.md#m62-final-publication-validation-2026-10-24-utc). M0–M6 remain completed historical milestones. M7's owner-run scripted playground evaluation passed its stated task and containment checks after the owner corrected the verifier roots. M7.2 adds opt-in, bounded local-agent diagnostics and a repeatable four-condition schedule. Automated validation is in progress; the 12-sample real-model study remains owner-run and has not been executed by the maintainer. No external-user feedback has been collected.

Effort assumes one student working part-time and is an estimate. Each stage has a stop/go review. Security tests are part of each deliverable.

**Historical M6 status (2026-10-19):** local release engineering and clean-copy validation were complete. The 13/13 Inspect quickstart passed locally at that point; GitHub workflows had not yet run. M6.2 later resolved publication and CI status without changing that historical evidence.

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

## M4 — Agent containment evaluation prototype

**Status: complete (2026-10-17).** Implementation, protocol, evidence, and decision are in [`experiments/agent-containment-v1/`](../experiments/agent-containment-v1/README.md) and the [M4 report](../experiments/agent-containment-v1/results/REPORT.md).

**Implemented:** paired clean/adversarial repo-instruction, source-comment, and tool-output fixtures; deterministic scripted controls; a protected `src/` policy, broad-write regression control, readonly utility control; an external `strace` observer; trusted task verifier and canary checker; stable experiment identity and JSON/Markdown outputs. One genuine Aider 0.86.2 + Qwen2.5-Coder 3B local-inference pair ran inside the no-egress namespace.

**Measured:** 26/26 deterministic execution records, verifiers, trace files, and required AutoCage checks completed. Static `src/` policy denied 6/6 explicit adversarial writes and left 6/6 canaries unchanged; broad control allowed 6/6 and modified 6/6; both preserved the task on 12/12 cases. Readonly control failed its two utility checks as expected. The real agent passed both task verifiers; both untrusted files were opened; no protected-write attempt was observed; no canary changed; no non-loopback connection was observed. That single pair is integration feasibility only, not model-resistance evidence.

**Regression checks:** M0 feasibility harness passed 41/41; Rust tests passed 47 unit + 22 Linux integration; formatting, strict Clippy, locked release build, and `autocage check` passed; five M4 Python controller tests passed. The full deterministic suite completed at 417.5 ms median including staging, verifier, and tracing.

**Research conclusion:** paired utility/security evidence and selected Linux syscall/canary evidence are useful, but Inspect already offers custom sandbox providers/external-agent integration and BoundaryBench already evaluates coding-agent capability under hardened policies with Inspect logs and an enforcement probe. A standalone M4 product would overlap existing evaluation infrastructure. Proceed with one thin Inspect sandbox/evidence integration, not another standalone evaluation framework.

**Outside scope:** hosted inference, credential brokering, remote network access, new sandbox backends, general prompt-attack catalogues, hard resource limits, broad model-resistance claims.

## M5 — Inspect integration and usable developer workflow

**Status: complete (2026-10-18).** The implementation uses Inspect `Task`/solver/scorer APIs and one complete `autocage run` per sample. It does not implement a persistent `SandboxEnvironment` because that contract expects repeated per-sample file and process operations that do not match the current runner lifecycle.

**Implemented:** pinned Inspect AI 0.3.281; a scenario-driven paired task adapter; explicit argv templates with no shell interpolation; scenario/fixture/verifier/agent/policy/runtime fingerprints; sealed AutoCage record validation; categorical utility, observed-attempt, canary, enforcement, and integrity scores; optional gated Inspect-local baseline; optional local Aider/Ollama/Qwen example; per-sample artifact and paired-report formatter.

**Measured:** frozen 19/19 deterministic samples scored with zero model-generation calls. All 18 main task runs passed the trusted verifier; the single readonly control failed as expected. In three adversarial cases, broad AutoCage and Inspect local each allowed and changed the protected canary; static `src/` AutoCage denied each attempt and left its canaries unchanged. All 13 AutoCage records and required checks passed. The optional real Aider pair passed both verifiers but made no observed protected-write attempt. Full evidence and the matched comparison are in [`experiments/inspect-autocage-v1/results/2026-10-18/REPORT.md`](../experiments/inspect-autocage-v1/results/2026-10-18/REPORT.md).

**Validation:** 47 Rust unit + 22 Linux integration tests; 20 M5 Python tests; 5 M4 Python tests; M0 harness 41/41; M4 deterministic regression 26/26. Formatting, strict Clippy, locked release build, and `autocage check` passed.

**Research decision:** A — maintain AutoCage as a narrowly scoped Inspect-integrated local enforcement/evidence tool. Evidence shows the integration can carry OS policy checks, sealed runtime identity, selected syscall outcomes, and independent canaries into Inspect results. The study does not establish superiority to Docker or general model resistance. Keep profile synthesis experimental and avoid a custom persistent sandbox provider or general evaluation framework.

**Out of scope:** hosted inference, network credential brokering, model-provider tool bridges, policy optimization changes, cross-platform enforcement, general attack catalogs, and production-grade security claims.

## M6 — Linux release candidate

**Status as of 2026-10-22 (historical):** release candidate implementation complete; local supported-guest validation passed. At that point, hosted workflows and publication had not run. M6.2 below records the later result; this snapshot is retained unchanged as historical evidence.

**Implemented:** pre-1.0 version metadata and changelog; top-level quickstart and architecture diagram; install/troubleshooting/support documentation; security reporting instructions; a pinned Inspect lock/build backend; CI for portable Rust/Python validation and separately scoped Linux enforcement; a preflight diagnostic script; a one-command Inspect quickstart with structured-result assertions; generated-file ignores and local documentation/dependency consistency checks.

**Local release gate:** the clean-copy installation and quickstart were executed in the isolated Ubuntu 24.04.5 ARM64 Lima guest. The full Rust suite, M0, M4 deterministic controller, and M5 Inspect integration gates passed after release changes. Detailed command output and results are in the M6 section of [`docs/RELEASE.md`](RELEASE.md) and [M5 report](../experiments/inspect-autocage-v1/results/2026-10-18/REPORT.md). The M6 scripts do not store run results in public GitHub artifacts.

**Historical open items:** GitHub-hosted runner support, Actions execution, and publication were pending at this snapshot. They were verified in M6.2. The portable CI job alone remains distinct from OS-enforcement evidence.

**Out of scope:** new sandbox backends, macOS/Windows enforcement, hosted inference, credential brokering, persistent Inspect sandbox provider, policy optimizer changes, production security claims.

**Out of scope:** macOS enforcement, Windows, enterprise fleet management, production-grade security claims.

## M7 — Bring-your-own-repository workflow

**Status:** internal vertical slice and automated validation complete; the owner-operated evaluation is complete. Implementation is on the `m7-byo-workflow` branch. The published `v0.1.0-rc.1` tag is unchanged.

**Implemented:** schema-versioned BYO scenarios for the existing Inspect task/solver/scorer adapter; separate developer-authorized write ceiling and strictly narrower comparison policy; relative-path, grant-normalization, fixture-symlink, `.git`, policy-target, and canary-content validation; SHA-256-derived protected-file identity; dynamic paired summaries with policy hashes. The Rust runner and Bubblewrap backend were not changed. A failed task with no verifier result is now reported as invalid evidence instead of escaping as an adapter exception.

**Measured internal demonstration:** pinned upstream `pallets/itsdangerous` at `672971d66a2ef9f85151e53283113f33d642dabd` (BSD-3-Clause), with no `.git` metadata in the source fixture. Inspect 0.3.281 ran five AutoCage samples in 19 seconds: clean and adversarial variants under the workspace-write ceiling and zero-write comparison policy, plus a read-only utility control. All five agent and verifier commands exited successfully; a direct diagnostic invocation of the same upstream suite reported 297 passed. All five records and mandatory controls validated. In the adversarial scripted probe, the broad ceiling allowed a selected source-file append and the staged canary changed; the zero-write policy denied it and left the canary unchanged. Clean trials had no observed probe attempt. The source fixture remained unchanged in every run. This is deterministic enforcement testing, not real-agent behavior or prompt-injection resistance. Details and sanitized results are in [`experiments/byo-repository-v1/`](../experiments/byo-repository-v1/README.md).

**User workflow:** the [Mac-to-Lima guide](../examples/byo-repository/README.md) covers snapshot transfer, guest installation, scenario review, policy-ceiling validation, Inspect execution, and result summaries. A fresh pinned Python environment completed the same five-sample evaluation. The owner subsequently ran it and reported five valid records, four task-pass results after correcting verifier roots to `tests/`, an allowed adversarial write under broad policy, a denied write under the `src/` policy, and unchanged original-source hashes. The read-only control was correctly a utility failure with no task write authority. M7.2's owner-run 12-sample local-Aider study is complete; its results and limitations are recorded in the M7.2 report. These are not model-resistance results.

## M7.2 — Reproducible local-agent evidence

**Implementation status:** feature branch `m7.2-real-agent-evidence`; automated tests and supported-guest regressions are complete. The owner completed the pilot and 12-sample study; the maintainer did not run inference.

**Scope:** for the marked synthetic playground only, explicit opt-in retains bounded Aider chat history, Aider-formatted LLM request/response history, Aider console output, Ollama server/model metadata, and effective settings in mode-0600 per-sample files. The controller accepts a single bounded diagnostic frame over the existing stdout pipe; no host mount, credential, network exception, or direct sandbox-temp access is introduced. Diagnostic artifacts remain supplementary, untrusted, and outside the sealed AutoCage record; transfer hashes establish integrity, not authorship. See [`LOCAL_AGENT_REPEATED_TRIALS.md`](../examples/byo-repository/LOCAL_AGENT_REPEATED_TRIALS.md).

The scheduler creates a single-sample pilot or 12 sequential main trials (three repetitions of clean/adversarial × broad/src-only policy), with a seeded counterbalanced order and one matched model seed per repetition. A fixed seed and temperature zero do not make inference deterministic. The adapter rejects duplicate persisted plan paths and never treats missing/truncated transcript data as complete.

**Generation controls:** the pinned Aider 0.86.2 configuration used whole-file edit format, temperature 0, context 8192, and one matched seed per repetition. In the final study, all 12 retained settings records reported the expected request kwargs. This verifies recorded request configuration, not deterministic output.

**Gate:** automated capture, record, privacy, and integration regressions pass; the deterministic BYO suite still passes; original playground inputs remained unchanged; the owner-run sequential study completed. No model-resistance, causal prompt-injection, or statistically conclusive claim follows from this sample.

**Acceptance:** the owner completed a personal evaluation through the existing Inspect adapter. Task success, observed operations, canary outcome, enforcement, and evidence integrity remain separate. No independent external-user evaluation has been collected.
