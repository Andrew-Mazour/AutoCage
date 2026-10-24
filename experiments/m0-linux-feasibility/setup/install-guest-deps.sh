#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Run this script inside the disposable Lima guest, not on macOS." >&2
  exit 2
fi

if [[ "$(id -u)" == "0" ]]; then
  echo "Run as the ordinary Lima user; only package/profile administration uses sudo." >&2
  exit 2
fi

restriction=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
if [[ ! -r "$restriction" || "$(cat "$restriction")" != "1" ]]; then
  echo "AppArmor's global unprivileged-userns restriction must remain enabled (value 1)." >&2
  exit 2
fi

# Inspect before package installation/profile loading. Do not replace or stack
# an existing Bubblewrap profile whose source and policy have not been audited.
loaded_profiles="$(sudo cat /sys/kernel/security/apparmor/profiles)"
if grep -Eq '(^|[ /])(bwrap|unpriv_bwrap)(//|[[:space:](])' <<<"$loaded_profiles"; then
  echo "A Bubblewrap AppArmor profile is already loaded; inspect it for conflicts before continuing." >&2
  grep -E '(^|[ /])(bwrap|unpriv_bwrap)(//|[[:space:](])' <<<"$loaded_profiles" >&2
  exit 2
fi

sudo apt-get update
sudo apt-get install --yes bubblewrap diffutils git python3 python3-pip python3-venv python3-pytest util-linux procps iproute2 apparmor-profiles apparmor-utils rustc cargo rustfmt rust-clippy

profile=/usr/share/apparmor/extra-profiles/bwrap-userns-restrict
if [[ ! -r "$profile" ]]; then
  echo "The official Ubuntu bwrap-userns-restrict profile is missing: $profile" >&2
  exit 2
fi

# The package profile is tied to /usr/bin/bwrap. Its bwrap setup profile may
# use namespace-local capabilities; its stacked unpriv_bwrap child profile
# explicitly denies capabilities. Never disable the kernel-wide restriction.
sudo apparmor_parser -r "$profile"
loaded_profiles="$(sudo cat /sys/kernel/security/apparmor/profiles)"
if ! grep -Fq 'bwrap (enforce)' <<<"$loaded_profiles" || ! grep -Fq 'unpriv_bwrap (enforce)' <<<"$loaded_profiles"; then
  echo "The official Bubblewrap and child AppArmor profiles did not load in enforce mode." >&2
  exit 2
fi
if [[ "$(cat "$restriction")" != "1" ]]; then
  echo "AppArmor's global user-namespace restriction changed unexpectedly; refusing to continue." >&2
  exit 2
fi

# This is an ordinary-user test (never sudo). It checks the full namespace set,
# nested-userns denial, the enforced child profile, and empty capability sets.
bwrap \
  --die-with-parent --new-session \
  --unshare-user --unshare-pid --unshare-ipc --unshare-uts --unshare-net \
  --disable-userns --assert-userns-disabled \
  --ro-bind /usr /usr \
  --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
  --dev /dev --proc /proc --tmpfs /tmp \
  --clearenv --setenv PATH /usr/bin:/bin \
  -- /usr/bin/python3 -c 'import pathlib,sys; p=pathlib.Path; profile=p("/proc/self/attr/current").read_text().strip(); status={line.split(":",1)[0]:line.split(":",1)[1].strip() for line in p("/proc/self/status").read_text().splitlines() if line.startswith(("CapEff:","CapPrm:","CapBnd:","CapInh:","CapAmb:","NoNewPrivs:"))}; assert profile.startswith("bwrap//&unpriv_bwrap (enforce)"), profile; assert all(status.get(k)=="0000000000000000" for k in ("CapEff","CapPrm","CapBnd","CapInh","CapAmb")), status; assert status.get("NoNewPrivs")=="1", status; print("Bubblewrap namespace/profile smoke: PASS", profile, status)'
