# AutoCage project status

**Reviewed baseline:** main commit cd4a41084a6e471237eb3c89fef3c06f9d3d5ae2; PRs #3–#6 merged; latest tag at review is prerelease v0.1.0-rc.1. Post-M8.3 [portable CI](https://github.com/Andrew-Mazour/AutoCage/actions/runs/42949229537) and [Linux enforcement/Inspect CI](https://github.com/Andrew-Mazour/AutoCage/actions/runs/42949229540) passed. Historical reports remain unchanged.

## Current decision

Implementation is complete for the scoped product. Pause feature work pending the owner acceptance run and one independent developer walkthrough. Neither is complete. Maintainer and synthetic evidence is not a substitute.

AutoCage is a pre-1.0 local Linux execution and evidence layer for Inspect AI. Its strongest demonstrated contribution is the combination of a tested Bubblewrap/AppArmor boundary, task verification, selected OS-operation observations, independent canaries, and inspectable evidence. There is no head-to-head evidence that AutoCage is more secure or easier than a competently configured alternative.

## Milestones and evidence

| Milestone | Actual evidence | Important limit |
|---|---|---|
| M0 | 41/41 feasibility checks on the supported Lima guest: namespaces, mount behavior, AppArmor, network isolation, canaries, cleanup. [Report](../experiments/m0-linux-feasibility/results/REPORT.md) | Not escape resistance or aggregate resource isolation. |
| M1 | Rust runner: 22 unit and 6 live Linux integration tests. [Report](../experiments/m1-runner/REPORT.md) | Not production security certification. |
| M2 | 22 deterministic tasks; 20 narrower policies validated and 2 retained the broad ceiling. [Report](../experiments/write-policy-v1/REPORT.md) | Hierarchical search showed no consistent advantage. |
| M3 | Real-repository study: broad utility 11/11; hierarchical narrow validation 10/11; RR03 had no validated narrow policy within budget. [Report](../experiments/real-repository-v1/REPORT.md) | No practical policy-reuse advantage shown. |
| M3.5 | 9/11 workflows got narrow policies; constrained same-source repeats passed 27/27. [Report](../experiments/m35-product-value/REPORT.md) | Policy-value/amortization targets failed; not cross-version reuse. |
| M3.6 | Eight workflow types over 16 revisions; static, authored, and suggested policies passed 16/16 and blocked the same 96/96 canaries. [Report](../experiments/m36-preexecution-value/REPORT.md) | Suggestions matched competent static policies. |
| M4 | 26 deterministic containment controls and a local-agent feasibility pair. [Report](../experiments/agent-containment-v1/results/REPORT.md) | Agent made no observed protected-write attempt. |
| M5 | Inspect adapter; 19 deterministic samples and three deliberate broad-write regressions detected. [Report](../experiments/inspect-autocage-v1/results/2026-10-18/REPORT.md) | No superiority claim. |
| M6 / M6.1 | Apache-2.0 prerelease, reproducible quickstart and CI. [Release record](RELEASE.md) | Pre-1.0; not production-hardened. |
| M7 / M7.1 | BYO CLI and owner-run calculator playground; five samples separated utility, enforcement, and canary outcomes. | Initial task executor was scripted. |
| M7.2 | Owner-run local Aider/Ollama study passed 12/12 task checks with valid evidence and unchanged sources. [Report](../experiments/agent-containment-v1/M7.2-REPORT.md) | No protected-write attempt observed. |
| M8.1 | Separates process completion, edits, verifier outcomes, and security evidence; bounded synthetic diagnostics. | Backtester no-edit cause remains unresolved. |
| M8.2 | autocage init/eval/report and deterministic BYO acceptance. [Guide](GETTING_STARTED.md) | Independent onboarding is untested. |
| M8.3 | One synthetic Aider 0.86.2 + Ollama 0.40.4 + Qwen2.5-Coder 3B sample edited source, passed its verifier, and had valid enforcement/evidence (~14 s). [Scenario](../experiments/agent-integration-v1/README.md) | One sample; not owner acceptance, general compatibility, or model resistance. |

## Support and known limits

- **Enforcement tested:** Ubuntu 24.04 ARM64, Linux 6.8+, Bubblewrap 0.9+, Ubuntu's enforced bwrap-userns-restrict profile, in the documented Lima guest and hosted CI. macOS users need isolated Lima; no native macOS enforcement.
- **Agent demonstrated:** Aider 0.86.2 with Ollama 0.40.4 and an already-installed Qwen2.5-Coder 3B model. The core accepts explicit program/argv; other agents, remote inference, and hosted bridges are unvalidated.
- No hard aggregate CPU, memory, or process limits. Use disposable resource-limited environments for hostile workloads.
- Selected strace observations are not a complete audit. No observed attempt is not a denial. Canary checks cover named assets; verifier success is utility evidence, not a security proof.
- No sandbox-escape proof or complete credential-secrecy guarantee.
- Repeated validator tasks on crypto-rewards-backtester made no edits; cause remains unknown. No more run is justified without a specific diagnostic hypothesis.
- No independent external developer test or adoption evidence has been collected.

## Owner acceptance run

On macOS Terminal:

~~~sh
limactl shell autocage-m0
~~~

Inside Ubuntu:

~~~sh
cd "$HOME/autocage-work/crypto-rewards-backtester-eval/autocage"
git switch main
git pull --ff-only origin main
VENV="/tmp/autocage-m84-venv-$(date -u +%Y%m%dT%H%M%SZ)"
python3 -m venv "$VENV"
source "$VENV/bin/activate"
python -m pip install -r integrations/inspect_autocage/requirements.lock
python -m pip install -e integrations/inspect_autocage --no-deps
python -m pip check
cargo build --locked --release
target/release/autocage check
test -f /usr/local/share/ollama/models/manifests/registry.ollama.ai/library/qwen2.5-coder/3b && echo "qwen2.5-coder:3b installed"
/usr/local/venvs/aider/bin/aider --version
ollama --version
ss -ltnp | grep ":11434" || true
~~~

Confirm qwen2.5-coder:3b is installed and no Ollama server is listening on port 11434. The helper starts Ollama on sandbox loopback and does not download weights. Stop any existing service through its normal owner-controlled session.

Run one clean sample. It uses --sample-id, not --limit; one sample/connection; no transcript retention; no hosted inference; and the existing no-egress boundary.

~~~sh
FIXTURE="experiments/agent-integration-v1/fixtures/base/src/mathops.py"
BEFORE="$(sha256sum "$FIXTURE" | awk '{print $1}')"
OUT="/tmp/autocage-m84-owner-$(date -u +%Y%m%dT%H%M%SZ)"
if target/release/autocage eval \
  --scenario experiments/agent-integration-v1/scenario.json \
  --sample-id agent-edit-clean-autocage-ceiling \
  --output-dir "$OUT"; then
  EVAL_STATUS=0
else
  EVAL_STATUS=$?
fi
AFTER="$(sha256sum "$FIXTURE" | awk '{print $1}')"
if [ "$BEFORE" = "$AFTER" ]; then
  echo "fixture unchanged: $AFTER"
  HASH_STATUS=0
else
  echo "ERROR: fixture hash changed" >&2
  HASH_STATUS=1
fi
printf 'Results: %s\n' "$OUT"
test "$EVAL_STATUS" -eq 0 && test "$HASH_STATUS" -eq 0
~~~

The command prints the report and creates a fresh result directory; it never applies the patch.

~~~sh
cat "$OUT/summary.md"
find "$OUT/workspaces" -type f \
  \( -name result.json -o -name changes.patch -o -name autocage-inspect.json \) -print
SAMPLE_DIR="$(find "$OUT/workspaces" -mindepth 1 -maxdepth 1 -type d -print -quit)"
target/release/autocage inspect "$SAMPLE_DIR/autocage-run"
cat "$SAMPLE_DIR/result.json"
cat "$SAMPLE_DIR/autocage-run/changes.patch"
~~~

### Owner checklist

Record PASS / FAIL / INCONCLUSIVE and elapsed setup/run time.

1. A fresh pinned Python environment installed cleanly; package check, Rust build, and autocage check succeeded.
2. The declared local agent launched; process status and duration are present.
3. A model-generated edit exists in the staged workspace; do not infer this from exit code alone.
4. The trusted verifier passed.
5. Changed files contain only src/mathops.py.
6. Enforcement is confirmed and the sealed record validates.
7. The fixture hash before and after is identical.
8. The generated patch is reviewable.
9. Read security outcomes literally: an observed denial proves that selected operation was blocked; NO_ATTEMPT_OBSERVED is neither denial nor model resistance.
10. Record manual steps, confusing messages, and whether this was useful enough to reuse.

Do not call this passed until actual owner-run evidence is reviewed. Keep results private; they contain staged source and execution metadata.

## Independent developer walkthrough

After owner acceptance, ask one developer who has not worked on AutoCage to use [Getting Started](GETTING_STARTED.md) and [Local Agent Execution](LOCAL_AGENT_EXECUTION.md) with a public, permissively licensed, non-sensitive repository. They review the copied snapshot, remove secrets, choose a specific write ceiling and trusted verifier, then run preflight and one evaluation with a preinstalled local agent. Do not use private repositories or credentials.

A concise run sequence, after installing the documented prerequisites and entering the supported guest, is:

~~~sh
autocage init --source "$HOME/src/public-project" --output "$HOME/autocage-evaluations/first-run"
# Review source-repo/ and all generated scenario and authorization files.
autocage check
autocage eval --scenario "$HOME/autocage-evaluations/first-run/scenario.json"
# Use the new run directory printed by eval.
autocage report "$HOME/autocage-evaluations/first-run/runs/RESULT-DIRECTORY"
~~~

With consent, record time to preflight and first evaluation, assistance, confusing configuration, report clarity, source preservation, and whether they would reuse AutoCage and why. Ask them to distinguish a real observed denial from no observed attempt. Use deterministic M4/BYO canaries separately if they want a positive enforcement demonstration. This single formative test is not adoption or statistical evidence.

Classify as PASS only if they complete preflight and one verified evaluation without maintainer help, preserve the original checkout, validate required controls/evidence, and correctly interpret the report. Otherwise record the precise friction. Do not claim external validation before it happens.

## Stop/go criteria

- **Stop feature work now.** Do not add features while the two validation steps are outstanding.
- **A — Complete for now:** owner acceptance passes and the independent developer completes a verified evaluation without assistance and correctly interprets utility versus enforcement.
- **B — Targeted correction:** either test finds a reproducible correctness/onboarding defect; fix only that defect and repeat its affected check.
- **C — More validation:** evidence is missing or inconclusive. Keep feature work paused.
- **D — Pivot:** actual use or a fair comparison shows no value beyond a competent existing setup. There is no such user/head-to-head evidence yet.

These prospective criteria do not change historical benchmark thresholds.
