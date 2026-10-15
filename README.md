# AutoCage

AutoCage is a research-stage Linux sandbox runner with an experimental pre-execution filesystem-policy suggestion prototype for a few deterministic Python workflows.

It uses Bubblewrap to run commands in a copied workspace with no outbound network and developer-authorized filesystem write limits. Suggestions never grant authority: they must be reviewed, explicitly accepted, and remain within a separately supplied ceiling. A verifier pass shows utility on that run; it does not prove general correctness, security, or a global permission minimum.

## Status

M0 passed 41 Linux feasibility checks; M1 established the fail-closed runner; M2 implemented bounded verifier-guided write-policy search; M3 hardened exact replay contracts; and M3.5 showed selected staged-write blocking but did not establish practical value for recurring workflows. M3.6 tested eight repeatable workflows at two pinned revisions across six Python repositories. Static, developer-authored, and AutoCage-suggested policies all preserved utility 16/16 and blocked the same 96/96 canary writes. The suggestions matched competent static policies exactly; human authoring effort was not measured. The project direction is **B: keep profiles as experimental infrastructure and pivot the primary contribution toward agent-containment evaluation**. No real-agent performance evidence has been collected. See the [M3.6 report](experiments/m36-preexecution-value/REPORT.md), [protocol](experiments/m36-preexecution-value/PROTOCOL.json), and [raw results](experiments/m36-preexecution-value/results/v3-final/results.json).

## Intended workflow

    autocage run --workspace . --record-contract \
      --verify-command /usr/bin/pytest --verify-arg -q \
      --verify-readonly tests \
      -- /usr/bin/python3 -m pytest -q

    autocage tune RUN_DIR --max-replays 12 --strategy greedy
    autocage inspect RUN_DIR

The experimental profile workflow is limited to declared `python-test`, `python-compileall`, and offline `python-wheel` commands:

    autocage propose --workspace . --workflow python-test -- \
      /usr/bin/env PYTHONPATH=/workspace/src \
      /usr/bin/python3 -m pytest tests -q -o cache_dir=/tmp/autocage-pytest-cache \
      > proposal.json

Review the emitted JSON, then accept it only with an explicit maximum ceiling, for example `--accept-proposal proposal.json --ceiling-dir .`. Proposals bind to the exact source snapshot and command; source or command drift requires a new proposal. M3.6 found no measured protection or effort advantage over writing the equivalent static policy directly.

The command after `--` is passed as argv without shell interpolation. AutoCage copies the repository into a private run directory, runs the command and its descendants with a cleared environment, no outbound network, and the authorized write ceiling over that copy plus private temporary storage, then runs the verifier with selected paths overmounted read-only. After an initially verified run, `tune` tests narrower candidate policies against fresh copies and only promotes one after three fresh verifier/canary passes. It leaves a patch and JSON record for review and never changes the original checkout. `--record-contract` stores command identities and argument digests, not raw argument values. It requires at least one `--verify-readonly` root; declare every workspace-resident verifier code, test, and configuration root there. `tune` requires the exact commands and arguments to be supplied again.

The required experiments use deterministic commands and scripted fixtures, not paid inference. Remote inference, credential brokering, and network policy remain deferred; real-agent support has not been validated. Learned tuning evidence remains bound to exact source, verifier, commands, and runtime. There is no cross-snapshot learned-policy reuse. M3.6 profile proposals also bind to the exact source and command and must be regenerated after changes.

## Scope

- Linux first; Bubblewrap is the initial namespace and mount backend.
- Stage a private copy of the project; do not expose the original Git metadata, home directory, credentials, host sockets, inherited environment, or unapproved file descriptors. The supervisor must close unapproved descriptors before Bubblewrap; Bubblewrap preserves any explicitly inherited FD.
- Keep the policy ceiling limited to the staged workspace, private temporary storage, and read-only runtime files. Network is denied.
- Optimize exact existing-file inode writes and recursive filesystem directory writes within the staged workspace. File grants do not permit create, unlink, rename, or atomic replacement. Read access to the staged project is broad; executable, credential, and network policy synthesis are deferred.
- Keep the core free to build and run: no hosted services or paid inference. Scripted agents provide deterministic tests; local inference is optional.

## Development environment

The development host is an ARM64 Mac running macOS 26.6.2. Homebrew 6.0.14 and Lima 2.2.1 are installed. A dedicated Lima VM uses Apple Virtualization, Ubuntu 24.04.5 ARM64, and Linux 6.8.0-142; its generated configuration has `mounts: null`. The VM has no shared host home or checkout. M0 required Ubuntu's `apparmor-profiles` and `apparmor-utils`, then loaded the packaged `/usr/share/apparmor/extra-profiles/bwrap-userns-restrict` profile. `kernel.apparmor_restrict_unprivileged_userns` remains `1`; `/usr/bin/bwrap` is not setuid. See the reproduction instructions in the [M0 harness README](experiments/m0-linux-feasibility/README.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Roadmap](docs/ROADMAP.md)
- [Decision log](docs/DECISIONS.md)
- [Evaluation plan](docs/EVALUATION.md)
- [M3 real-repository report](experiments/real-repository-v1/REPORT.md)
- [M3.5 product-value report](experiments/m35-product-value/REPORT.md)
- [M3.6 pre-execution profile report](experiments/m36-preexecution-value/REPORT.md)

AutoCage does not enforce Linux namespaces on macOS. Run Linux development and enforcement experiments in the disposable Lima guest; the Mac host does not need Bubblewrap, QEMU, Docker, or Podman.

## Linux development and tests

The supported implementation target is the isolated Ubuntu ARM64 guest described above. Run M0 setup there to install the distro Rust toolchain, Bubblewrap, diffutils, pytest, and the official AppArmor profile. Transfer only source and tests into the guest, then run:

    cargo fmt --check
    cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked
    cargo build --locked --release

The runner supports non-interactive commands: stdin is `/dev/null`; no pseudo-terminal or arbitrary environment passthrough is provided. The runner requires Ubuntu 24.04 ARM64, Linux 6.8+, enforced AppArmor profiles, and Bubblewrap 0.9+. It fails closed outside that tested configuration. M2 benchmark reproduction steps and the exact environment are in [`experiments/write-policy-v1/README.md`](experiments/write-policy-v1/README.md).
