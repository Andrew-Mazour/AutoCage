# M1 minimal runner report

**Run date:** 2026-10-11 UTC
**Status:** **PASS for the scoped M1 runner**
**Environment:** disposable Lima VM, Apple Virtualization, `mounts: null`; Ubuntu 24.04.5 ARM64, Linux `6.8.0-142-generic`, ordinary user EUID 501. No host home, checkout, credentials, sockets, or security settings were shared or modified.

This report records tested behavior of the first Rust runner. It is not a sandbox escape proof, a production security certification, or evidence that an arbitrary repository toolchain will run.

## Guest and security configuration

- Bubblewrap `0.9.0`, mode `0755`, root-owned, not setuid.
- AppArmor enabled; `kernel.apparmor_restrict_unprivileged_userns=1`.
- Ubuntu's official `bwrap-userns-restrict` profile loaded in enforce mode; the sandbox child reported `bwrap//&unpriv_bwrap (enforce)`.
- Rust/Cargo `1.75.0`; `rustfmt 1.7.0-stable`; Python `3.12.3`; pytest `7.4.4`; GNU diffutils `3.10`.
- Preflight observed child UID/GID maps limited to the caller, all five capability sets zero, `NoNewPrivs=1`, distinct user/mount/PID/IPC/UTS/network namespaces, nested-userns creation denied, and no default route.

M0's full [feasibility report](../m0-linux-feasibility/results/REPORT.md) has 41 PASS and validated the same guest's mount/network primitives, including exact-file and recursive-directory write behavior.

## Executed commands and result

Source and tests were copied into the guest; the build used the checked-in lockfile. The exact commands were:

```sh
limactl shell autocage-m0 -- mkdir -p /tmp/autocage-m1-dev
limactl copy --recursive Cargo.toml Cargo.lock src tests autocage-m0:/tmp/autocage-m1-dev/
limactl shell autocage-m0 -- bash -lc 'cd /tmp/autocage-m1-dev && cargo fmt --check'
limactl shell autocage-m0 -- bash -lc 'cd /tmp/autocage-m1-dev && cargo test --locked'
limactl shell autocage-m0 -- bash -lc 'cd /tmp/autocage-m1-dev && cargo build --locked --release'
limactl shell autocage-m0 -- /tmp/autocage-m1-dev/target/release/autocage check
```

All passed: formatting check, **22 unit tests**, **6 Linux integration tests**, optimized release build, and release-binary live preflight. No M1 test was blocked or skipped. The release preflight printed `AutoCage preflight passed`, Ubuntu 24.04/Linux 6.8.0-142, Bubblewrap 0.9.0, and the enforced `bwrap//&unpriv_bwrap` profile.

Integration test outcomes:

| Test | Status | Evidence |
|---|---|---|
| `check_runs_the_required_fail_closed_namespace_probe` | PASS | The built program's live Bubblewrap child probe satisfied the supported profile, namespace, identity, and capability checks. |
| `copied_workspace_runs_command_and_readonly_verifier_then_records_review_artifacts` | PASS | Python changed the stage but not the source; host file/env canaries were inaccessible in the command and a Python child; baseline verifier files rejected overwrite and sibling creation; pytest passed; record mode was `0600`. |
| `command_timeout_is_recorded_and_returns_124` | PASS | A sleeping command returned 124 and the record classified its timeout. |
| `network_namespace_blocks_a_live_host_loopback_listener` | PASS | A host-side positive-control connection reached a synthetic listener; Python in the sandbox could not connect to it. |
| `verifier_failure_is_reported_separately_from_agent_failure` | PASS | Agent success plus verifier exit 1 produced `verifier_failed` and CLI exit 3. |
| `timeout_kills_a_descendant_that_started_a_new_session` | PASS | The agent started a separate-session descendant; after timeout, the host `/proc` scan found no live process with its unique synthetic marker. |

The unit suite also checked Bubblewrap's required flags and absence of `--share-net`, close-on-exec handling of a deliberately inheritable host canary descriptor, CLI argv preservation, policy validation, verifier-root overlap/symlink/traversal rejection, and stage-copy handling for credentials-by-name, symlinks, hard links, special files, and manifests.

## Implemented M1 boundary

`autocage check` and `autocage run` are implemented. `run` accepts an explicit workspace, optional new run directory, timeout, verifier program/arguments and selected verifier read-only roots, then an arbitrary executable plus argv after `--`. It does not invoke a shell or pass the caller's environment through. stdin is `/dev/null`; stdout/stderr stream to the caller. Non-stdio descriptors are close-on-exec before Bubblewrap.

Each run creates a private owner-only directory outside the original checkout. The supervisor copies file contents into `baseline/` and `stage/`, omits `.git` and the implemented credential-pattern list, rejects special files and escaping symlinks, reports omissions, and hashes manifests. Bubblewrap mounts `/usr` read-only with runtime aliases, a fresh `/proc` and `/dev`, private `/tmp` and empty HOME, and the copied workspace recursively writable at `/workspace`. It always requires user, mount, PID, IPC, UTS, and network namespaces plus `--disable-userns --assert-userns-disabled`; there is no shared-network or unsandboxed fallback. The runner records outcomes and emits a review patch without applying changes to the source checkout.

The optional verifier gets the same fixed filesystem ceiling. Requested roots are taken from the immutable baseline copy and overmounted read-only. Other stage files remain writable, so this protects only those selected paths and does not make a repository verifier a security oracle.

### Write-granularity decision

Bubblewrap behavior supports the planned candidate vocabulary, with the observed caveat from M0: exact-file writable mounts permit in-place content edits, while create/unlink/rename/atomic replacement require writable parent-directory authority. Recursive directory mounts support these operations throughout that tree; later nested read-only mounts can protect selected paths. M1 intentionally compiles only one recursive workspace-write baseline and rejects narrower grants. Policy narrowing is M2 work and has not been demonstrated by this run.

## Not tested / remaining limitations

- Failure injection for missing or unenforced AppArmor profiles, missing Bubblewrap/diff, namespace denial, or changed kernel configuration. The actual preflight passed; fail-closed behavior is implemented but these deployment failures were not simulated.
- macOS enforcement, other Linux distributions/architectures/kernels, arbitrary repositories, or a real coding agent.
- Internet-service connection attempts in this M1 suite; M0 tested no-route/network isolation with reserved and synthetic local targets, and M1 tested a live guest-loopback service.
- Interactive stdin/PTY, package downloads, remote inference, host credential brokering, automatic apply-back, or policy optimization.
- Hard CPU, memory, process-count, or aggregate I/O limits. Timeout is not availability isolation.
- Full filesystem confidentiality: every non-omitted staged file is visible to the command, the name-based omission list is incomplete, and `/usr` is broadly readable.

The measured result supports moving on to M2's deterministic optimizer proof of concept only after the owner elects to begin that milestone. It does not establish that task-specific narrowing is useful; no optimizer was implemented or evaluated here.
