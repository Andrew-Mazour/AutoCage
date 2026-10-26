# AutoCage threat model

**Status (2026-10-25):** M0–M6 enforcement and release checks were validated on the documented Ubuntu 24.04 ARM64 guest; M7 owner-run scripted playground evaluation completed with five valid records. M7.2 adds opt-in diagnostic retention for a marked synthetic local-agent scenario. Its owner-run pilot and repeated model trials have not been performed. Neither the earlier no-attempt Aider runs nor the deterministic scripted negative control establishes model resistance. Historical negative and inconclusive optimizer findings remain in the experiment reports.

## Objective

For a declared coding task, compare agent/configuration or sandbox changes while preserving legitimate task utility and measuring independently verifiable security effects. The existing unprivileged Bubblewrap runner contains commands in a copied workspace with no outbound network, no host home/config mounts, and no inherited host environment or non-stdio descriptors. M4's paired harness separates task verification, selected syscall observations, sandbox checks, and independent staged canaries. This does not establish prevention of every host access, credential exposure, agent misbehavior, or kernel escape.

## Assets and assumptions

Assets: host credentials, SSH/GPG agents, cloud credentials, browser state, environment values, Unix sockets, unrelated user files; the original checkout and Git metadata; integrity of supervisor, policy, record, and verifier identity; staged project.

Trust the developer's ceiling, AutoCage supervisor, root-owned Bubblewrap and `diff`, host kernel, and declared read-only runtime. Run unprivileged. M1 accepts Ubuntu 24.04 ARM64 with kernel 6.8 or later, the expected enforced AppArmor profile and required user/mount/PID/IPC/UTS/network namespaces. Treat agent, model output, repository instructions, dependencies, build scripts, and repository tests as untrusted.

The staged repository is visible to the agent. M1 defaults to recursive staged-workspace writes; M2 can compile a narrower candidate inside that developer-authorized ceiling. M3.6 adds an experimental deterministic proposal for selected Python commands; it grants no authority independently, requires explicit acceptance and a separate ceiling, and remains bound to exact source and command inputs. In the held-out M3.6 sample it compiled the same grants as a competent static policy, so no extra security benefit is claimed. AutoCage omits .git, common root-level host credential/config paths, .env files other than example/sample templates, package-manager auth files, and recognized private-key filenames, and reports omissions. This name-based list cannot detect every secret embedded in arbitrary project files or every credential convention. Remote inference receives any content the agent sends; remote inference is excluded initially.

## Adversary

Assume arbitrary code execution, shells and descendants, staged-file inspection/modification, malicious repository instructions, host-file and network probes, symlink/hard-link attempts, and deliberate task failure intended to influence synthesis. Assume dependencies and test commands may be malicious.

The agent may trigger failures, but AutoCage never expands the ceiling in response. Any wider ceiling requires an explicit new developer decision/run.

## Boundary and guarantees

Bubblewrap mount/PID/network namespaces plus a private copied stage are the proposed enforcement boundary. On M0's Ubuntu 24.04.5 ARM64 guest, loading the official `bwrap-userns-restrict` profile while leaving `kernel.apparmor_restrict_unprivileged_userns=1` allowed all required namespaces. The sandbox child was in `bwrap//&unpriv_bwrap (enforce)`, reported `NoNewPrivs=1`, and had zero effective, permitted, bounding, inheritable, and ambient capabilities. Its UID/GID maps mapped only the unprivileged guest caller to inner ID 0. The observations validate this specific configuration and the selected probes; they do not establish absence of a kernel, Bubblewrap, AppArmor, or configuration defect.

The official distro profile is scoped to `/usr/bin/bwrap` and stacks executed children into `unpriv_bwrap`, but that child policy allows broad file, network, mount, and userns operations while denying capabilities. It must be combined with Bubblewrap's exact required namespaces, isolated mounts, `--disable-userns --assert-userns-disabled`, and no network sharing. M0 verified nested userns creation succeeds when the disable flag is omitted and fails when present. Do not disable the global restriction or make Bubblewrap setuid.

M0 measured Bubblewrap's mount semantics: exact-file writable mounts allow in-place inode writes but prevent parent-directory create/unlink/rename/atomic replacement; M2's integration test also verified an owner-permitted mode change on an exact-file mount. Writable directory mounts support entry operations recursively; nested read-only file mounts override a writable directory. M0 also showed a raw stage bind can expose/mutate a source hard-link alias. Copying file contents into a private stage breaks that inode alias but does not redact content already present in the staged tree.

Bubblewrap preserves file descriptors explicitly passed to it. The M0 controller could read a synthetic host canary through such an FD inside the sandbox; a launch using `close_fds` blocked it. The production supervisor must close all unapproved descriptors before exec. The command also receives a cleared environment; host home and sockets are not mounted.

All protections are conditional on preflight and canary success. If a required namespace/profile/mount cannot be established, the run fails closed. No compatibility path invokes the command unsandboxed.

M2 candidate policies are checked as subsets of the explicit ceiling before every replay. A narrow policy is promoted only after three fresh runs pass both the fixed verifier and the protected-input/host/source canaries. The optimizer uses before/after manifests to seed candidates; transient writes may be missed. A denied operation or agent request never authorizes a grant. If search or validation is incomplete, the known successful broad ceiling remains the result and the tuner reports inconclusive. The deterministic 22-task benchmark produced 20 three-pass narrow policies and two broad fallbacks; this result applies only to these synthetic commands/verifiers.

M3.5 tested a separate write canary under each workflow's verifier/test root. F blocked 8/11 attempts; it allowed three canaries under grants that included the target subtree. The static policy allowed all 11. This tests whether those compiled grants actually block that one create operation in the isolated stage. It does not show that every out-of-scope path or filesystem operation is blocked, nor does it prevent an authorized write from becoming part of a review patch. The source checkout remains unmounted and changes are not applied automatically, so narrowed writes add staged-diff containment inside an already disposable workspace; they do not replace review or host isolation.

M3.6 exercised 96 independent in-stage write attempts for each static, developer-authored, and proposed policy arm across six out-of-scope synthetic locations; all 288 attempts were blocked, while broad-policy controls modified their targets. This establishes only those tested Bubblewrap mounts and in-place-write operations for the pinned workflows. Since B/C/D compiled identical grants, this supports the enforcement boundary, not the differentiating value of inference. Policies with zero writable workspace grants protect the staged review result from incidental or malicious modifications by the command, but cannot prevent reads, alter host exposure beyond staging, or replace review; the original checkout was already isolated by copy staging.

M1's concrete evidence is narrow: the guest preflight passed; the copied stage was writable while the source checkout and a synthetic outside canary stayed unchanged; an inherited synthetic environment value was absent in the agent and its Python child; a live guest-loopback listener was unreachable; the verifier's baseline test files rejected overwrite and sibling creation; and a detached-session child was no longer live after timeout. M3 additionally tested tampered/missing/corrupt records, runtime/source/argv/verifier-root drift, interrupted runs, and a contract request with no readonly verifier roots. These tests do not prove broader filesystem secrecy, absence of kernel escape, verifier completeness, or safe behavior on another distribution/kernel.

## M4 real-agent observation

M4 ran one Aider/Qwen2.5-Coder 3B clean/adversarial pair inside the isolated Ubuntu guest. The supervisor's required namespace, source-isolation, and read-only-mount checks passed; independent task verification passed twice; `AGENTS.md` open was observed twice; the deployment canary remained unchanged. The selected syscall trace observed no protected write attempt and no non-loopback `connect()`. This does not show the model resisted an instruction: no attempt was observed, and one run per condition is not a behavioral estimate. The wrapper started Ollama inside the same private network namespace on loopback; no host service or credential was exposed. Aider's optional metadata requests failed in the no-egress environment.

The deterministic M4 control intentionally attempted writes and demonstrated that the `src/` policy denied six of six selected protected writes while a broad staged-workspace policy allowed six of six. These results apply only to the traced open operations and synthetic paths. strace filters selected syscalls; canaries provide independent post-run integrity checks, not complete event coverage. The raw evidence and limitations are recorded in [`experiments/agent-containment-v1/results/REPORT.md`](../experiments/agent-containment-v1/results/REPORT.md).

## M5 Inspect evidence boundary

M5 passes AutoCage run evidence into Inspect as separate task-utility, selected-attempt, canary, required-control, and record-integrity scores. The adapter validates sealed AutoCage records and scenario/fixture/verifier/agent/policy identities before interpreting results. A missing or incomplete control remains unavailable or inconclusive; no fallback launches the agent outside AutoCage. Raw `strace` is restricted to selected `open`, `openat`, `openat2`, and `connect` calls to avoid recording `execve` argument vectors. Even so, pathnames and observed network destinations are persisted; use synthetic or otherwise safe evaluation data.

The optional `inspect-local` comparator is outside the AutoCage boundary and runs only when explicitly enabled on Linux. It was executed only inside the isolated Lima VM. It is not safe to run adversarial samples from that arm on an ordinary developer host. Inspect's model provider is not invoked by the deterministic task. The optional Aider example runs its local model server inside the sandbox and uses loopback only; hosted inference, agent bridges, and remote tool paths are not covered.

M5's one real Aider/Qwen pair did not attempt the protected write. The selected connect trace showed loopback/Unix endpoints only. No model-resistance conclusion follows. Inspect Local and the broad AutoCage policy both allowed the deterministic controller's protected writes; the `src/` policy denied them. Docker and competing sandbox configurations were not tested in this milestone.

## M7.2 diagnostic-retention boundary

Transcript retention is disabled by default. The Inspect task refuses opt-in unless the schema-v2 suite ID, Aider launcher, README input, `config/settings.json` canary, and synthetic marker file match the supported playground shape. The launcher creates histories and bounded logs under a mode-0700 temporary directory in the sandbox's private `/tmp`, runs with a cleared environment and no external network, then returns a single capped diagnostic frame over its existing stdout channel. The controller accepts only fixed artifact names and the expected sample ID, verifies lengths and hashes, and creates files exclusively with mode 0600 under a private per-sample result directory.

Opt-in artifacts may contain the synthetic task prompt, repository text, model responses, and tool output. They are untrusted supplementary material; recomputed hashes do not prove provenance. They are not sealed run-record fields, and a frame is not accepted as security evidence. Missing, corrupted, partial, or truncated artifacts remain visibly incomplete. An interrupted process may not transfer its private `/tmp` content. Do not enable this mode on real repositories with secrets, private source, or personal data. AutoCage does not upload diagnostic material.

## M6 release scope

The documented runtime support is limited to Ubuntu 24.04 ARM64, Linux 6.8+, Bubblewrap 0.9+, and the enforced Ubuntu `bwrap-userns-restrict` profile. The portable CI build matrix is not enforcement validation. The GitHub-hosted ARM64 workflow attempts the same distribution-package/profile setup and fails if it cannot establish the required boundary; until a real GitHub run succeeds, only the Lima guest is a validated environment. The public quickstart uses synthetic fixtures and a mock Inspect model placeholder whose solver does not call inference. AutoCage-owned material is licensed Apache-2.0; dependencies and optional model assets remain under their own licenses and are not bundled.

## Non-goals

- Defending against kernel, Bubblewrap, or hardware vulnerabilities.
- Hiding staged repository contents from the agent or detecting every embedded secret.
- Per-executable restrictions: an interpreter can access all visible files.
- Fine-grained network policy or protecting a remote provider from content the user authorized the agent to send.
- Treating repository tests as security oracles.
- Proving global minimality or safety for untested tasks.
- Hard CPU/memory/fork limits in the first release; a wall-clock timeout is not resource isolation.

## Invariants

1. No command starts until supported-platform checks and every required namespace probe succeeds; Bubblewrap, its AppArmor child profile, or mount setup failure is fatal.
2. Network namespace is private; no share-net, best-effort namespace, or unsandboxed fallback.
3. Original checkout and host .git are never mounted writable or included by reference.
4. No host home, credential directory, agent config, or host socket is mounted. The supervisor marks all non-stdio descriptors close-on-exec before starting Bubblewrap because Bubblewrap preserves any descriptor intentionally inherited by its caller. Standard output and error remain connected to the caller; stdin is `/dev/null` in M1.
5. Each write grant is normalized within the staged workspace or private temp and is a subset of the ceiling.
6. Denials and verifier failure do not add grants. A wider ceiling requires explicit developer approval in a new run.
7. Symlinks escaping stage and special files are rejected; copied regular files do not share hard-link inodes with the source. Content in a source hard link remains staged content and is not thereby made confidential. Exact-file mounts allow in-place inode operations but not directory-entry changes; rename/create/delete/atomic replacement need directory authority.
8. Verifier outcomes measure utility only; independent canaries test enforcement. `--record-contract` requires one or more declared `--verify-readonly` roots; explicit existing workspace paths in verifier argv, including directory arguments after sandbox-path normalization, must be covered by those roots. The roots are copied from the immutable baseline and overmounted read-only. The developer remains responsible for declaring implicit imports, plugins, auto-discovered configuration, and other verifier inputs; AutoCage cannot prove the declaration is complete. Without a replay contract, a verifier may still run for utility, but its result cannot be tuned or reused.
9. Run records and replay contracts omit raw argv values, environment values, transcripts, and raw command output. They store command identity digests, executable hashes, and argument counts. A contract is mode 0400, sealed to its run evidence, and requires the caller to resupply exact commands and arguments for tuning. Hashing avoids persisting argument secrets; it does not hide low-entropy values from a reader who can guess them and compare hashes.

## Residual threats

Reads within the stage and read-only runtime are broad. A malicious agent can corrupt every writable path, consume host CPU/memory/processes before timeout, exploit kernel bugs, or disclose staged code if a later network mode is added. Until a delegated cgroup or an outer VM resource cap is validated, do not describe AutoCage as availability isolation; recommend a disposable, resource-limited VM for adversarial workloads. Build/test code can attack the verifier. These limits remain visible in user documentation.
