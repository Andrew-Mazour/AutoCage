#!/usr/bin/env bash
set -euo pipefail

binary="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/target/release/autocage}"

fail() {
  printf 'UNSUPPORTED: %s\n' "$1" >&2
  exit 2
}

[[ "$(uname -s)" == Linux ]] || fail "AutoCage enforcement requires Linux; use the isolated Lima guest on macOS."
[[ "$(uname -m)" == aarch64 ]] || fail "Only ARM64 Linux has been validated."

if [[ ! -r /etc/os-release ]]; then
  fail "Cannot identify the Linux distribution."
fi
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]] || \
  fail "The validated distribution is Ubuntu 24.04 (found ${PRETTY_NAME:-unknown})."

kernel="$(uname -r | cut -d- -f1)"
IFS=. read -r kernel_major kernel_minor _ <<<"$kernel"
if ((kernel_major < 6 || (kernel_major == 6 && kernel_minor < 8))); then
  fail "Linux 6.8 or later is required (found $(uname -r))."
fi

command -v bwrap >/dev/null 2>&1 || fail "bubblewrap is missing."
bwrap_version="$(bwrap --version | awk '{print $2}')"
IFS=. read -r bwrap_major bwrap_minor _ <<<"$bwrap_version"
if ((bwrap_major == 0 && bwrap_minor < 9)); then
  fail "Bubblewrap 0.9 or later is required (found $bwrap_version)."
fi

restriction=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
[[ -r "$restriction" && "$(cat "$restriction")" == 1 ]] || \
  fail "AppArmor's unprivileged-user-namespace restriction must remain enabled (value 1)."
[[ -x "$binary" ]] || fail "AutoCage executable not found or not executable: $binary"
printf 'Environment: %s, %s, kernel %s, Bubblewrap %s\n' \
  "$PRETTY_NAME" "$(uname -m)" "$(uname -r)" "$bwrap_version"
printf 'AppArmor: global user-namespace restriction enabled; active child profile is checked by autocage.\n'
exec "$binary" check
