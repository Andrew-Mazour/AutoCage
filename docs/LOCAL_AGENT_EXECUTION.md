# Local agent execution

AutoCage's core runner accepts an explicit executable and argv array. It does
not invoke a shell, pass through the host environment, or infer permission
grants from agent requests. The Inspect adapter stages a fresh workspace,
executes the full command inside AutoCage, runs the declared trusted verifier,
and reports task and security evidence separately.

## Local Aider with an installed Ollama model

The example launcher at
examples/byo-repository/local_aider_ollama.py supports Aider with any exact
Ollama model tag that is already installed in the guest's configured model
store. It is not tied to a Qwen model. The launcher:

- starts Ollama inside the AutoCage process tree with OLLAMA_HOST bound to
  127.0.0.1 and a scrubbed environment;
- checks the local model-list endpoint for the exact tag and fails without
  calling a pull or download endpoint;
- passes Aider a task, read-only file list, and explicit editable-file list;
- writes temporary settings and an empty Aider config in private /tmp;
- disables repository/user env-file discovery, auto-commits, analytics, chat
  history, and input-history retention;
- relies on AutoCage's outer timeout for supervision and terminates Ollama on
  normal completion.

The helper emits one schema-filtered operational marker containing the tool
versions, selected local model tag, readiness time, and agent duration. Inspect
labels this marker as untrusted process output, not security evidence. The
AutoCage sealed run record does not cryptographically attest to the Ollama
model contents; the scenario and argv identify the declared tag, while the
marker is only a process-reported observation. No raw prompt, response, or
transcript is intentionally retained by this helper.

The adapter does not mount a host service, host directory, socket, or credential.
The guest model store is mounted read-only by the existing runtime. Model
weights must already be installed in that store. No hosted provider or
external network access is supported by this example.

A typical init wizard agent argv is:

    ["/usr/bin/python3", "-B", "scripts/run_local_aider_ollama.py", "--task", "{task}", "--model-tag", "qwen2.5-coder:3b", "--editable-file", "src/module.py", "--read-file", "AGENTS.md", "--context-length", "8192", "--temperature", "0", "--seed", "8303"]

When asked for a helper source, select
examples/byo-repository/local_aider_ollama.py and stage it as
scripts/run_local_aider_ollama.py. Replace the model tag with an exact model
already listed by the guest Ollama installation. This is a local Aider/Ollama
integration, not evidence that every coding-agent executable is compatible.

## Reproducible synthetic demonstration

The small M8.3 integration scenario is in
experiments/agent-integration-v1/. It selects one clean, synthetic sample using
a preinstalled guest model, writable src/ only, a read-only tests/ verifier,
and an independent config canary. It has an adversarial overlay for optional
manual testing, but the documented one-sample command selects the clean
condition. The deterministic M4 suite remains the source of positive and
negative enforcement controls.

Follow that directory's README. Run inspect eval through the AutoCage CLI or
Inspect adapter only after autocage check passes. Review the report and sealed
record; do not treat NO_ATTEMPT_OBSERVED as a denial. Generated patches are
never applied automatically.
