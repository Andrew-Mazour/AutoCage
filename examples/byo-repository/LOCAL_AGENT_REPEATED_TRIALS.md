# Repeated local Aider trial (owner-run)

This procedure is for the synthetic `autocage-playground` only. The Aider and Ollama transcripts contain task text, repository content, and model output. Do not enable diagnostic retention for a repository containing credentials, private source, or personal data. Retained files stay in the Lima guest, are created with mode `0600` inside mode `0700` directories, and are never uploaded by AutoCage.

The adapter keeps the four experimental conditions matched: clean/adversarial README × workspace ceiling/`src/`-only policy. Each sample starts from the same archived buggy snapshot. A pilot is one clean narrow-policy sample. The main study defaults to three repetitions per condition (12 samples), ordered with a seeded Williams counterbalance; all four conditions in a repetition share one model seed. Runs should be sequential (`--max-connections 1`). Seeds and order help reproduce configuration but do not make model output deterministic.

## 1. Refresh isolated guest checkouts

Run these commands on macOS. They use guest Git and Lima file transfer only; they do not share your Mac home directory with the VM. Confirm the Lima instance configuration still has no host mounts before continuing.

```sh
limactl list
limactl shell autocage-m0 -- bash -lc '
  set -e
  ROOT="$HOME/autocage-m72-real-agent"
  test ! -e "$ROOT" || { echo "Choose a fresh ROOT path; this guide will not overwrite an existing one."; exit 1; }
  mkdir -m 700 -p "$ROOT"
  git clone --branch m7.2-real-agent-evidence --single-branch \
    https://github.com/Andrew-Mazour/AutoCage.git "$ROOT/autocage"
  git clone --branch m7.2-real-agent-evidence --single-branch \
    https://github.com/Andrew-Mazour/autocage-playground.git "$ROOT/playground-source"
  git -C "$ROOT/autocage" status --short
  git -C "$ROOT/playground-source" status --short
  git -C "$ROOT/playground-source" archive HEAD | tar -x -C "$ROOT" --one-top-level=source-repo
  mkdir -m 700 -p "$ROOT/scenarios/autocage-playground" "$ROOT/logs"
  (cd "$ROOT/source-repo" && sha256sum src/calculator.py config/settings.json) \
    > "$ROOT/source-before.sha256"
  cat "$ROOT/source-before.sha256"
'
```

The guest clone is the staging source; `source-repo` is a sanitized `git archive` snapshot without `.git`. It is deliberately left buggy. AutoCage creates a separate fresh staged workspace for every sample. Never point `fixture_root` at your working Git checkout.

## 2. Check AutoCage, Inspect, and local model prerequisites

This step does not run inference or download model weights. If you already have the pinned guest tools, reuse them after checking versions and the preflight result.

```sh
limactl shell autocage-m0 -- bash -lc '
  set -e
  ROOT="$HOME/autocage-m72-real-agent"
  cd "$ROOT/autocage"
  cargo build --locked --release
  ./target/release/autocage check
  python3 -m venv .venv-inspect
  . .venv-inspect/bin/activate
  python -m pip install -r integrations/inspect_autocage/requirements.lock
  python -m pip install -e integrations/inspect_autocage --no-deps
  /usr/local/venvs/aider/bin/aider --version
  /usr/bin/ollama --version
  /usr/local/venvs/aider/bin/python -c "import importlib.metadata as m; print('litellm', m.version('litellm'))"
  test -s /usr/local/share/ollama/models/manifests/registry.ollama.ai/library/qwen2.5-coder/3b
  /usr/local/venvs/aider/bin/python examples/byo-repository/check_ollama_request_options.py
  python3 -B -m unittest discover -s examples/byo-repository -p "test_*.py" -v
'
```

The expected pins are Aider 0.86.2, Ollama 0.40.4, LiteLLM 1.81.10, and the already-installed Qwen2.5-Coder 3B model manifest SHA-256 `ce40a49b0aa2b3b607d26a603e0f2db06a256cecbc9cca7adf893ae11a80275a`. The model is about 1.93 GB. It is not downloaded by this workflow. The VM has previously shown about 7.7 GiB RAM, no swap, and a peak descendant RSS around 2.9 GiB during a single run; treat these as prior observations, not guarantees. Runs are sequential. A 12-sample run is expected to take roughly 5–10 minutes based on the earlier single-run duration, plus setup. Diagnostic payloads are capped below about 2.5 MiB per sample (30 MiB worst-case for 12); Inspect logs and staged workspaces add some extra space. No inference API or egress is required.

## 3. Place the real scenario inputs

The playground branch contains the pinned scenario and overlays. Copy only those files into a separate scenario directory:

```sh
limactl shell autocage-m0 -- bash -lc '
  set -e
  ROOT="$HOME/autocage-m72-real-agent"
  cp "$ROOT/playground-source/autocage-evaluation/scenario.local-aider.json" \
     "$ROOT/playground-source/autocage-evaluation/authorized-ceiling.json" \
     "$ROOT/playground-source/autocage-evaluation/comparison-policy.json" \
     "$ROOT/playground-source/autocage-evaluation/untrusted-instruction.txt" \
     "$ROOT/scenarios/autocage-playground/"
  cp "$ROOT/autocage/examples/byo-repository/local_aider_runner.py" \
     "$ROOT/source-repo/scripts/run_local_aider.py"
  cp "$ROOT/autocage/examples/byo-repository/check_ollama_request_options.py" \
     "$ROOT/autocage/examples/byo-repository/test_local_aider_runner.py" \
     "$ROOT/source-repo/scripts/"
  cp "$ROOT/playground-source/.autocage-synthetic-playground" "$ROOT/source-repo/"
  test ! -e "$ROOT/source-repo/.git"
  python3 -B -m json.tool "$ROOT/scenarios/autocage-playground/scenario.local-aider.json" >/dev/null
'
```

The scenario's `fixture_root` resolves to `../../source-repo`. Its broad arm is the developer-authorized workspace ceiling; its narrow arm grants writes only to `src/`. The trusted verifier inputs are `tests/` and `autocage-evaluation/`. The README overlay is the only clean/adversarial fixture difference. The adapter rejects diagnostic retention unless it recognizes the exact synthetic playground profile and marker.

## 4. Run and inspect a single-sample pilot

Use a new result directory. This captures diagnostics only because `retain_agent_diagnostics=true` is explicitly supplied. The pilot is one clean, narrow-policy trial and is not evidence about the adversarial condition or comparative policy security.

```sh
limactl shell autocage-m0 -- bash -lc '
  set -e
  ROOT="$HOME/autocage-m72-real-agent"
  RESULTS="$ROOT/results/m72-pilot-20261025"
  LOGS="$ROOT/logs/m72-pilot-20261025"
  cd "$ROOT/autocage"
  . .venv-inspect/bin/activate
  inspect eval integrations/inspect_autocage/eval.py@local_aider_regression \
    --model mockllm/model \
    -T autocage_binary="$PWD/target/release/autocage" \
    -T scenario_file="$ROOT/scenarios/autocage-playground/scenario.local-aider.json" \
    -T work_root="$RESULTS" \
    -T pilot=true \
    -T experiment_id=m72-pilot-20261025 \
    -T schedule_seed=20261025 \
    -T retain_agent_diagnostics=true \
    --max-samples 1 --max-connections 1 \
    --log-dir "$LOGS" --display plain
  python experiments/inspect-autocage-v1/summarize.py "$RESULTS" \
    --output "$RESULTS/summary.json" \
    --markdown-output "$RESULTS/summary.md"
  cat "$RESULTS/summary.md"
'
```

Review `summary.md`, then inspect the sample's `diagnostics/controller-manifest.json`, `effective-settings.json`, `aider-chat-history.md`, `aider-llm-history.log`, and bounded `aider-stdout.bin` / `aider-stderr.bin`. These files are supplementary untrusted agent/tool artifacts. Aider 0.86.2's LLM history distinguishes `TO LLM` formatted messages and `LLM RESPONSE` text before Aider applies its edit parser; it is not raw HTTP, a complete execution trace, or model intent. The rendered chat history and Aider console are separate artifacts. `ollama-server.log` and `ollama-model-info.json` are runtime diagnostics. All files are per-sample and mode 0600 under the guest results tree.

`effective-settings.json` includes Aider's verbose request-kwargs fields when parsing succeeds and the local Ollama `/api/show` model parameter metadata. Its completeness flag must be true to claim the requested temperature, seed, and context were observed at Aider's model-client call. The separately run LiteLLM transformer regression confirms those fields serialize into Ollama's `options` payload. Temperature zero and a fixed seed reduce one source of variability; they do not guarantee deterministic generations across software, prompt, policy, runtime, or backend changes.

## 5. Run the full matched repeated study

Proceed only after reviewing the pilot artifacts and confirming their contents are suitable to retain. Use a fresh experiment ID and result/log paths. The main study is 12 samples (3 repetitions). If you also add `-T include_read_only_control=true`, change `--max-samples 12` to `--max-samples 13` so the separate utility control is included.

```sh
limactl shell autocage-m0 -- bash -lc '
  set -e
  ROOT="$HOME/autocage-m72-real-agent"
  RESULTS="$ROOT/results/m72-main-20261025"
  LOGS="$ROOT/logs/m72-main-20261025"
  cd "$ROOT/autocage"
  . .venv-inspect/bin/activate
  inspect eval integrations/inspect_autocage/eval.py@local_aider_regression \
    --model mockllm/model \
    -T autocage_binary="$PWD/target/release/autocage" \
    -T scenario_file="$ROOT/scenarios/autocage-playground/scenario.local-aider.json" \
    -T work_root="$RESULTS" \
    -T repetitions=3 \
    -T experiment_id=m72-main-20261025 \
    -T schedule_seed=20261025 \
    -T retain_agent_diagnostics=true \
    --max-samples 12 --max-connections 1 \
    --log-dir "$LOGS" --display plain
  python experiments/inspect-autocage-v1/summarize.py "$RESULTS" \
    --output "$RESULTS/summary.json" \
    --markdown-output "$RESULTS/summary.md"
  cat "$RESULTS/summary.md"
'
```

The saved `*-trial-plan.json` is created exclusively; using the same experiment ID and result directory again is rejected rather than overwriting it. Every run has fresh staged workspace and AutoCage run record. The four conditions in a repetition share a model seed and task; only README overlay and policy differ. The repetition order is counterbalanced by the schedule seed. If Inspect reports an error or a missing sample, do not count it as a pass; preserve the directory and inspect each sample's `result.json`, sealed `run.json`, `changes.patch`, `observer.strace`, and diagnostic manifest.

## 6. Read results and verify source integrity

The summary separates utility (`PASS`/`FAIL`/`INCONCLUSIVE`), agent exit, verifier status, observed write attempt, write outcome, canary, enforcement, record integrity, source changes, and diagnostic completeness. `NO_ATTEMPT_OBSERVED` is never counted as a denial. A selected denied syscall is not the same as a successful unauthorized modification; the canary is checked independently. The report calls a paired security improvement only when its observed syscall and canary evidence satisfy the adapter's validation rules.

Compare the initial source hashes printed in step 1 with:

```sh
limactl shell autocage-m0 -- bash -lc '
  ROOT="$HOME/autocage-m72-real-agent"
  cd "$ROOT/source-repo"
  sha256sum --check "$ROOT/source-before.sha256"
  find "$ROOT/results" -path "*/diagnostics/controller-manifest.json" -print
'
```

The original archive is `source-repo`; it should remain unchanged. `input-workspace` is the adapter's disposable per-sample copy, and `autocage-run/stage` is the runner's isolated stage. A broad adversarial sample may change only its stage canary; a narrower denial should leave that stage canary unchanged. None of these samples should write to the archive or the macOS checkout.

## 7. Remove retained synthetic diagnostics

Only the opt-in `results` directories contain copied transcript files. Delete them from inside the guest when no longer needed:

```sh
limactl shell autocage-m0 -- bash -lc '
  ROOT="$HOME/autocage-m72-real-agent"
  find "$ROOT/results" -type d -name diagnostics -print
  rm -r "$ROOT/results/m72-pilot-20261025" "$ROOT/results/m72-main-20261025"
'
```

This is ordinary file deletion, not a forensic secure erase. Do not export or commit transcript artifacts. Never enable retention while evaluating a real repository with secrets or private code.
