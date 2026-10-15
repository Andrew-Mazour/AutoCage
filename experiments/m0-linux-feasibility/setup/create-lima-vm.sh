#!/usr/bin/env bash
set -euo pipefail

instance="autocage-m0"

if ! command -v limactl >/dev/null 2>&1; then
  echo "limactl is required; install Lima with: brew install lima" >&2
  exit 2
fi

if limactl list --format '{{.Name}}' 2>/dev/null | grep -Fxq "$instance"; then
  echo "Lima instance '$instance' already exists; inspect it before reusing it." >&2
  exit 2
fi

# --mount-none is intentional: no host home, checkout, credentials, or sockets
# are shared into the VM. Transfer only this synthetic experiment directory
# later with `limactl copy`.
limactl create \
  --name="$instance" \
  --vm-type=vz \
  --arch=aarch64 \
  --mount-none \
  --cpus=4 \
  --memory=8 \
  --disk=40 \
  --containerd=none \
  template:ubuntu-24.04 \
  -y

limactl start "$instance" -y

echo "Created $instance. Verify its generated Lima config has no mounts before copying fixtures."
