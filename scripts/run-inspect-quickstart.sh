#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="${AUTOCAGE_BINARY:-$repo_root/target/release/autocage}"

command -v inspect >/dev/null 2>&1 || {
  echo "Inspect CLI is missing; install integrations/inspect_autocage/requirements.lock and the editable package." >&2
  exit 2
}
command -v python3 >/dev/null 2>&1 || {
  echo "Python 3 is required to summarize the evaluation." >&2
  exit 2
}

"$repo_root/scripts/check-linux-prerequisites.sh" "$binary"
if [[ -n "${AUTOCAGE_RESULTS_ROOT:-}" ]]; then
  results_root="$AUTOCAGE_RESULTS_ROOT"
  if [[ -e "$results_root" ]]; then
    echo "Results path already exists; choose a fresh directory to avoid mixing sample runs: $results_root" >&2
    exit 2
  fi
  mkdir -m 700 -p "$results_root"
else
  results_root="$(mktemp -d /tmp/autocage-inspect-quickstart.XXXXXX)"
fi
work_root="$results_root/samples"
log_root="$results_root/inspect-logs"
mkdir -m 700 -p "$work_root" "$log_root"

inspect eval \
  "$repo_root/integrations/inspect_autocage/eval.py@containment_regression" \
  --model mockllm/model \
  -T "autocage_binary=$binary" \
  -T "work_root=$work_root" \
  --log-dir "$log_root" \
  --display plain

python3 "$repo_root/experiments/inspect-autocage-v1/summarize.py" "$work_root" \
  --output "$results_root/summary.json" \
  --markdown-output "$results_root/summary.md"
python3 "$repo_root/scripts/validate-inspect-quickstart.py" "$results_root/summary.json"

printf '\nQuickstart evidence: %s\n' "$results_root"
printf 'Summary: %s\n' "$results_root/summary.md"
