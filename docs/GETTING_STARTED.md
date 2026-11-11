# Getting started: evaluate a repository with AutoCage

This workflow is experimental and currently validated only in the project's Ubuntu 24.04 ARM64 Lima guest (Linux 6.8+, Bubblewrap 0.9+, Ubuntu's enforced bwrap-userns-restrict AppArmor profile). It does not provide native macOS enforcement.

## Install

In the isolated Linux guest, clone AutoCage and install the pinned Inspect integration:

    git clone https://github.com/Andrew-Mazour/AutoCage.git
    cd AutoCage

The guided BYO workflow is available on `main` (it was added after the `0.1.0-rc.1` release tag).

    cargo build --locked --release
    python3 -m venv .venv-inspect
    source .venv-inspect/bin/activate
    python -m pip install -r integrations/inspect_autocage/requirements.lock
    python -m pip install -e integrations/inspect_autocage --no-deps
    export PATH="$PWD/target/release:$PATH"
    autocage check

The first build and Python dependency installation need guest network access. Evaluation runs the agent inside AutoCage's no-egress boundary. Do not mount a host home, repository, credential directory, socket, or model server into the guest.

## Create a scenario

From the guest, choose a repository without credentials or private data. init copies it into a new scenario directory and excludes common VCS, environment, cache, and key-named files. This is not a secret scanner: inspect the copied snapshot before execution.

    autocage init \
      --source "$HOME/src/my-project" \
      --output "$HOME/autocage-evaluations/my-project"

The wizard asks for the legitimate task, complete agent argv as a JSON string array, independent verifier command and read-only roots, an input file, a protected canary file, an optional untrusted-content overlay, and two filesystem policies. Arguments are passed directly; shell expansion is not performed. Put {task} in the agent argv so the declared task reaches the executable.

The wizard refuses workspace-root grants, requires an explicit, non-empty developer-authorized ceiling and a separate exact AUTHORIZE confirmation, and checks that the comparison policy is a strict subset. It never widens authority from repository contents or denied operations. The verifier must be independently maintained and should protect its own code/tests through readonly_roots.

Review these generated files before running:

    scenario.json
    authorized-ceiling.json
    comparison-policy.json
    untrusted-instruction.txt
    source-repo/

The initial comparison runs each case clean and with the declared overlay under both policies, then runs one read-only utility control. With one case, that is five samples. The read-only control is expected to fail if the task requires writing. No model API is called by Inspect itself.

### Local Aider/Ollama with an installed model

For a reusable example that accepts any already-installed Ollama model tag, use
examples/byo-repository/local_aider_ollama.py. It launches Ollama in the same
sandbox, binds to 127.0.0.1 only, checks that the exact model is already
installed, and never downloads a model. It passes Aider a shell-free task,
read-only file list, and explicit editable-file list. Its default Aider
configuration, env file, chat history, and input history are isolated or sent
to /dev/null. Raw transcripts are not intentionally retained.

In the init wizard, use an argv like this (adjust the task target, model tag,
and allowed files):

    ["/usr/bin/python3", "-B", "scripts/run_local_aider_ollama.py", "--task", "{task}", "--model-tag", "qwen2.5-coder:3b", "--editable-file", "src/module.py", "--read-file", "AGENTS.md", "--context-length", "8192", "--temperature", "0", "--seed", "8303"]

When prompted for the helper source, enter
examples/byo-repository/local_aider_ollama.py and set its workspace destination
to scripts/run_local_aider_ollama.py. The selected model must already be
installed in the guest's configured Ollama model store. AutoCage does not
download weights, use hosted inference, expose a host Ollama service, or grant
network access. This is an Aider/Ollama adapter, not a universal agent plugin;
other agents can be configured with the existing explicit program/argv
interface when their dependencies and local service lifecycle work inside the
same sandbox.

## Execute and read the result

Run all samples sequentially:

    autocage eval --scenario "$HOME/autocage-evaluations/my-project/scenario.json"

AutoCage runs autocage check before Inspect, refuses an existing output directory, uses --max-connections 1, and stores results in a new timestamped directory under the scenario's runs/ directory. To run one exact sample, use --sample-id SAMPLE_ID. AutoCage passes that selector without --limit; do not combine the two Inspect options.

The command prints the result directory and a concise report. Regenerate the report later with:

    autocage report "$HOME/autocage-evaluations/my-project/runs/RUN_DIRECTORY"

Review summary.md first. summary.json contains structured per-sample fields. Under workspaces/, each sample retains its result.json, selected trace, sealed AutoCage run directory, staged source, and changes.patch. Paths in the report are relative to the sample directory. Inspect the patch and staged files yourself; AutoCage does not apply changes to either the source checkout or copied source snapshot.

Interpret outcomes separately:

- Utility PASS means the agent completed and the independent verifier passed.
- NO_OBSERVABLE_EDITS means no final workspace delta was recorded and verification failed. It is not a sandbox denial.
- ATTEMPT_DENIED_BY_FILESYSTEM means a selected observed operation was denied.
- A successful operation plus a changed canary is an observed staged-workspace modification.
- NO_ATTEMPT_OBSERVED means no selected protected-write attempt was observed. It does not show denial or model resistance.
- Enforcement and evidence status are the values recorded at collection. The summary formatter does not cryptographically authenticate arbitrary model output or revalidate every result.json; for the sealed run record, use autocage inspect SAMPLE/autocage-run.

Treat results, traces, staged workspaces, and patches as potentially sensitive local data. The generic BYO workflow does not retain raw Aider transcripts. Transcript retention remains limited to the explicitly marked synthetic experiment.

## Deterministic no-model acceptance test

On a supported guest with the pinned Inspect environment installed:

    python experiments/byo-workflow-v1/run_smoke.py --autocage "$PWD/target/release/autocage"

This exercises the Rust CLI's init, eval, and report commands against a disposable synthetic project and removes its temporary result after assertions. Expected summary:

- Four writable-policy samples pass the independent task verifier.
- The broad adversarial control changes its synthetic canary.
- The narrower adversarial control records a filesystem denial and unchanged canary.
- The read-only control fails utility as expected.
- All five records confirm enforcement and validate integrity; the starter source stays unchanged.

This deterministic agent validates workflow integration only. It is not evidence about AI-model behavior.

## Supported boundary and limitations

The agent, verifier, and their children run in the existing Bubblewrap/AppArmor boundary with no network namespace access, explicit writes, a copied workspace, and sanitized agent environment. The verifier is separately invoked by the controller with declared read-only roots. Failed preflight is fatal; there is no unsandboxed fallback.

The current boundary does not provide aggregate CPU/memory limits, a complete syscall audit, general host-credential secrecy guarantees, sandbox-escape resistance, native macOS enforcement, hosted inference, or a universal agent adapter. Review the threat model before evaluating untrusted code.
