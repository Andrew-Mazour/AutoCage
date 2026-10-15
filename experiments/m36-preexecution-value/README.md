# M3.6 Pre-Execution Policy Value

This experiment compares four pre-run configurations with the existing post-run optimizer on recurring commands from pinned Python repositories. The experimental `propose` command supports only explicit pytest, compileall, and local offline wheel workflows. Suggestions grant no authority; `run --accept-proposal` also requires a separate developer ceiling and recomputes the suggestion against the exact staged snapshot and command.

## State

Protocol v3 and `workflow-plan.json` freeze the held-out set, thresholds, costs, and methods. Development-only W01, W02, and W09 are excluded from the held-out aggregate. V1 and v2 attempts are preserved as `PROTOCOL-v1-incomplete.json` / `workflow-plan-v1-incomplete.json` and `PROTOCOL-v2-incomplete.json` / `workflow-plan-v2-incomplete.json`, with evidence in `results/incomplete-v1/` and `results/incomplete-v2/`. V1 exposed a missing build-generated Filelock version file; v2 retained the justified Filelock compileall workflow but exposed an incorrect Iniconfig verifier root and record-accounting edge cases. Neither incomplete attempt is combined with the v3 aggregate.

The primary workloads are real repository test/build commands on complete pinned parent and target Git archives. The setup script only materializes Git archives and adds the declared `dist/` output plus a small trusted wheel verifier to wheel fixtures. No repository code is run during preparation. All repository commands and verifiers run through AutoCage in the isolated Ubuntu Lima guest.

## Guest prerequisites

Use the existing Ubuntu 24.04 ARM64 Lima guest with the M0 Ubuntu AppArmor profile enabled. The host home directory, credentials, and host sockets are not mounted in the guest.

The test environment uses the M3 pinned pytest stack from `../real-repository-v1/setup/python-requirements.lock`. Wheel workflows additionally use the pinned `flit_core` wheel in `setup/python-build-requirements.lock`. Download build dependencies before task execution, verify their hashes, and install them into a guest-local directory:

```sh
limactl copy --recursive Cargo.toml Cargo.lock src tests experiments/m36-preexecution-value experiments/real-repository-v1/tasks.json experiments/real-repository-v1/prepare.py autocage-m0:/tmp/autocage-m36/project/
limactl shell autocage-m0 -- bash /tmp/autocage-m36/project/experiments/m36-preexecution-value/setup/download-build-deps.sh /tmp/autocage-m36/wheelhouse
limactl shell autocage-m0 -- bash /tmp/autocage-m36/project/experiments/m36-preexecution-value/setup/install-build-deps.sh /tmp/autocage-m36/wheelhouse /tmp/autocage-m36/site
```

The `flit_core` download is a public, hash-pinned, free wheel. Its download is preparation only. AutoCage agent and verifier processes retain the tested private network namespace and receive no egress.

## Prepare pinned snapshots

On a clean guest, fetch the pinned Git objects before sandboxed execution. The existing M3 preparation script is safe to run: it reads Git object archives and never imports or executes repository code.

```sh
limactl shell autocage-m0 -- bash -lc 'cd /tmp/autocage-m36/project && python3 experiments/real-repository-v1/prepare.py --work-root /tmp/autocage-real-repository-v1'
limactl shell autocage-m0 -- bash -lc 'cd /tmp/autocage-m36/project && python3 experiments/m36-preexecution-value/prepare_workflows.py --work-root /tmp/autocage-m36/evaluation-v3 --git-root /tmp/autocage-real-repository-v1/git-objects'
```

Preparation refuses to overwrite snapshots. Use a new guest-local work root for each final run. It writes a manifest with the exact source commits and tree digests.

## Build and run

After the workflow plan, fixture preparation, Rust sources, and tests are final,
build the locked release binary and freeze the exact inputs once. The freeze
helper refuses to overwrite existing hashes/runtime metadata; copy the resulting
`PROTOCOL.json` back to the host repository and commit it before final evaluation.

```sh
limactl shell autocage-m0 -- bash -lc 'cd /tmp/autocage-m36/project && cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked && cargo build --locked --release'
limactl shell autocage-m0 -- bash -lc 'cd /tmp/autocage-m36/project && python3 experiments/m36-preexecution-value/freeze_protocol.py --autocage target/release/autocage'
limactl copy autocage-m0:/tmp/autocage-m36/project/experiments/m36-preexecution-value/PROTOCOL.json experiments/m36-preexecution-value/PROTOCOL.json
limactl shell autocage-m0 -- bash -lc 'cd /tmp/autocage-m36/project && python3 experiments/m36-preexecution-value/run_m36.py --autocage target/release/autocage --work-root /tmp/autocage-m36/evaluation-v3 --output /tmp/autocage-m36/results/v3-final'
```

The final controller refuses to run if the frozen protocol, workflow plan, prepared snapshots, pinned Python package inventory, or AutoCage binary hash changes. It records task utility, proposal validation, policy costs, canary evidence, verifier results, replay counts, and execution timings separately. A failed, unexecuted, or missing required canary is never a pass.

## Interpretation limits

The `python-test` and `python-compileall` profiles should need no staged-workspace write grant when cache output is directed to private `/tmp`. The `python-wheel` profile may suggest one recursive grant only for an existing, explicit output directory such as `dist/`; it will not infer build-backend side effects. This ruleset is a conservative demonstrator, not general repository analysis or evidence that a build backend is trustworthy.

The M3.5 exact run-contract behavior remains unchanged. A profile generated for one source snapshot is rejected after source or command drift; each revision gets a freshly generated suggestion. A research-only shadow reauthorizes the old policy as an explicit ceiling on the changed source and does not promote or reuse the old proposal.
