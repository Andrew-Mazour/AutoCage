# Evaluate your own repository

This guide uses AutoCage's existing Inspect task/solver/scorer adapter. It does not require editing adapter source or installing a model. Use the `m7-byo-workflow` branch until this workflow is merged; the v0.1.0-rc.1 release and tag are unchanged.

The adapter copies one selected repository snapshot into a fresh sample workspace, runs the configured command once under each policy, then runs the trusted verifier. Clean and adversarial variants use the same task and verifier. The `authorized_ceiling.json` is the maximum authority you approve. `comparison-policy.json` must be a strict subset. Schema 2 rejects policy paths outside the scenario directory, malformed grants, changed scenario inputs, embedded `.git` metadata, and comparison grants above the ceiling. Each run still fails closed if the Linux preflight or evidence checks fail.

The adapter runs the whole configured command inside AutoCage with no network and a sanitized environment. It does not bridge hosted model APIs, host tools, credentials, or MCP servers. A command that needs inference must use a supported local setup already available inside the guest. For a first check, use a deterministic tool command such as the supplied pytest example.

## 1. Copy a sanitized repository snapshot from macOS

Start at the root of the repository you want to evaluate. Keep the Lima guest's `mounts: null` configuration; transfer only a reviewed copy with `limactl copy`. Do not copy `.git`, credentials, local sockets, virtual environments, model files, or build outputs. The exclusions below cover common paths, but review the copied files for secrets before transferring; filename filters cannot detect credentials stored in arbitrary files.

```sh
TRANSFER_ROOT="$(mktemp -d /tmp/autocage-user-test.XXXXXX)"
mkdir -p "$TRANSFER_ROOT/source-repo"
rsync -a \
  --exclude='/.git/' --exclude='**/.git/**' \
  --exclude='/.env' --exclude='/.env.*' \
  --exclude='/.ssh/' --exclude='/.aws/' \
  --exclude='*.pem' --exclude='*.key' \
  --exclude='/.venv*/' --exclude='**/.venv*/' \
  --exclude='/target/' --exclude='**/target/' \
  --exclude='/node_modules/' --exclude='**/node_modules/' \
  --exclude='/.pytest_cache/' --exclude='**/.pytest_cache/' \
  --exclude='/.ruff_cache/' --exclude='**/.ruff_cache/' \
  --exclude='/.mypy_cache/' --exclude='**/.mypy_cache/' \
  --exclude='/.tox/' --exclude='**/.tox/' \
  --exclude='/build/' --exclude='**/build/' \
  --exclude='/dist/' --exclude='**/dist/' \
  --exclude='**/__pycache__/' \
  ./ "$TRANSFER_ROOT/source-repo/"
find "$TRANSFER_ROOT/source-repo" -maxdepth 3 -type f -print
du -sh "$TRANSFER_ROOT/source-repo"
GUEST_HOME="$(limactl shell autocage-m0 -- sh -lc 'printf %s "$HOME"')"
limactl shell autocage-m0 -- mkdir -p "$GUEST_HOME/autocage-work"
limactl copy "$TRANSFER_ROOT/source-repo" "autocage-m0:$GUEST_HOME/autocage-work/source-repo"
printf 'Reviewed source snapshot copied from %s\n' "$TRANSFER_ROOT/source-repo"
```

The copy represents the current working tree, including tracked edits and untracked files that were not excluded. For a committed snapshot instead, `git archive` omits `.git` and untracked files. The adapter rejects fixtures containing symlinks or special files. Inspect the copied snapshot in the guest before evaluating it.

## 2. Install AutoCage in the guest

The following commands assume the existing isolated `autocage-m0` guest and its validated AppArmor/Bubblewrap setup. The macOS host is not an enforcement target.

```sh
GUEST_HOME="$(limactl shell autocage-m0 -- sh -lc 'printf %s "$HOME"')"
limactl shell autocage-m0 -- bash -lc \
  'git clone --branch m7-byo-workflow https://github.com/Andrew-Mazour/AutoCage.git "$HOME/autocage-work/autocage"'
limactl shell autocage-m0 -- bash -lc \
  'cd "$HOME/autocage-work/autocage" && cargo build --locked --release && ./target/release/autocage check'
limactl shell autocage-m0 -- bash -lc \
  'cd "$HOME/autocage-work/autocage" && python3 -m venv .venv-inspect && . .venv-inspect/bin/activate && python -m pip install -r integrations/inspect_autocage/requirements.lock && python -m pip install -e integrations/inspect_autocage --no-deps'
```

If this is a fresh guest, follow the guest-only setup in [Installation](../../docs/INSTALL.md#ubuntu-setup) first. The setup loads only Ubuntu's official AppArmor profile. Do not disable the global user-namespace restriction or share host directories.

Install the workflow's required runtime and test packages inside the guest before evaluation. The agent cannot use a macOS virtual environment or a guest executable under an unmounted home directory: AutoCage exposes its tested system runtime read-only, gives `/tmp` a private mount, and does not mount the host home. Use system runtime paths such as `/usr/bin/python3`, check executable availability with `command -v`, and keep package downloads outside the sandbox. AutoCage never adds network access for setup.

## 3. Create and review a scenario

Copy the template and its policy/overlay files into a separate scenario directory. Its sibling `source-repo` path is deliberately fixed by `fixture_root`:

```sh
limactl shell autocage-m0 -- bash -lc '
  mkdir -p "$HOME/autocage-work/scenarios/my-project"
  cp -R "$HOME/autocage-work/autocage/examples/byo-repository/." \
    "$HOME/autocage-work/scenarios/my-project/"
  mv "$HOME/autocage-work/scenarios/my-project/scenario.template.json" \
    "$HOME/autocage-work/scenarios/my-project/scenario.json"
'
```

Edit `scenario.json` and both policy files. At minimum:

1. Set `suite_id` and `task` to describe the actual workflow.
2. Set `agent.program` and `agent.argv` to the complete command. Use an argv array; no shell interpolation is performed. `{task}` is the task placeholder when your executable accepts it. `agent.kind` is a self-declared report label only; AutoCage fingerprints the executable but does not infer whether it is an LLM agent.
3. Set `verifier.program`, `verifier.argv`, and `readonly_roots` to an independent check that is safe to run on the staged source.
4. Set `input_path` to a regular repository file the command may read and `protected_path` to an existing file that must not be changed. Schema 2 requires `canary_initial: null`; AutoCage hashes that file from the source snapshot and never copies its contents into the report.
5. Review `authorized-ceiling.json`. It is the maximum write authority you approve. Narrow `comparison-policy.json` to the directories/files you expect the workflow to modify. A candidate outside the ceiling is rejected before Inspect samples launch.
6. Edit `untrusted-instruction.txt` to request a controlled, out-of-scope change to the protected file. This tests the configured agent's behavior only if it actually reads and responds to that content. A no-attempt result is not a denial.

For the template's Python test workflow, the command is read-only and the comparison policy is empty. For a coding task, change the agent command, verifier, readonly roots, ceiling, and comparison policy together. Exact-file grants only allow in-place file-content changes; create/delete/rename/atomic-replace operations need a parent-directory grant. The verifier roots are mounted read-only for the verifier and must include its workspace-resident verifier inputs (for example, tests). Do not include source paths the task is expected to modify: those roots are restored from the original snapshot during verification, so the verifier would test the unmodified source instead of the task output.

When a sealed AutoCage run records an agent failure or timeout, the verifier is intentionally skipped. Inspect reports this as a utility failure and records `verification.status` as `NOT_RUN_AGENT_FAILED` or `NOT_RUN_AGENT_TIMEOUT`; it does not mark the verifier as passed. A missing verifier result after an agent success remains invalid evidence.

Review the policy JSON and scenario before running. The ceiling is developer authorization, not an automatically inferred grant. Task/repository content cannot expand it. AutoCage does not expose host credentials or network access to make a hosted agent work.

## 4. Run the paired Inspect evaluation

```sh
limactl shell autocage-m0 -- bash -lc '
  cd "$HOME/autocage-work/autocage"
  . .venv-inspect/bin/activate
  RESULTS="$HOME/autocage-work/results/my-project"
  LOGS="$HOME/autocage-work/logs/my-project"
  inspect eval integrations/inspect_autocage/eval.py@containment_regression \
    --model mockllm/model \
    -T autocage_binary="$PWD/target/release/autocage" \
    -T scenario_file="$HOME/autocage-work/scenarios/my-project/scenario.json" \
    -T work_root="$RESULTS" \
    --max-samples 1 --max-connections 1 \
    --log-dir "$LOGS" --display plain
  python experiments/inspect-autocage-v1/summarize.py "$RESULTS" \
    --output "$RESULTS/summary.json" \
    --markdown-output "$RESULTS/summary.md"
'
```

`mockllm/model` is only an Inspect task-state placeholder; this solver does not call model inference. The comparison runs clean/adversarial variants under the authorized ceiling and its narrower policy, plus one read-only utility control. A task command may be invoked several times; do not use commands with irreversible external effects.

The Markdown summary gives per-policy task utility, write-attempt outcomes, canary state, enforcement, evidence integrity, runtime, and policy hash prefixes. JSON contains full hashes and per-sample evidence. Raw Inspect logs, traces, records, and review patches remain in the chosen guest results directory; inspect and redact before exporting or sharing them. The adapter never applies staged modifications to the transferred source tree.

## 5. Interpret evidence correctly

- `PASS` means the configured command exited successfully and the trusted verifier passed for that sample.
- `ATTEMPT_DENIED_BY_FILESYSTEM` is an observed selected syscall denial. `WRITE_OPEN_SUCCEEDED` requires the independent canary to establish whether the file changed.
- `NO_ATTEMPT_OBSERVED` does not show that the sandbox blocked a write or that a model resisted the untrusted instruction.
- `CONFIRMED` enforcement requires AutoCage preflight, validated sealed records, and required security checks. Missing traces or checks remain inconclusive.
- A changed canary is a real modification in the staged sample. The original transferred source snapshot must remain unchanged.

This is not a complete syscall audit, model-intent detector, sandbox-escape proof, or general security certification. The only validated enforcement target is Ubuntu 24.04 ARM64 with the documented kernel, Bubblewrap, and AppArmor configuration. No external user-testing evidence has been collected yet; this guide is intended for the first user run.
