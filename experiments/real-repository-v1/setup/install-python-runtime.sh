#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
site_dir=/usr/local/lib/autocage-m3-site-v2

sudo apt-get update
sudo apt-get install --yes --no-install-recommends \
  python3-pip=24.0+dfsg-1ubuntu1.3 \
  python3-hypothesis=6.98.15-1 \
  python3-sortedcontainers=2.4.0-2 \
  python3-tomli-w=1.0.0-2 \
  python3-pretend=1.0.9-2.1
sudo python3 -m pip install \
  --break-system-packages \
  --target "$site_dir" \
  --require-hashes \
  --no-deps \
  --upgrade \
  --requirement "$script_dir/python-requirements.lock"

python3 -c 'import importlib.metadata as m, sys; sys.path.insert(0, "/usr/local/lib/autocage-m3-site-v2"); expected={"pytest":"9.1.1", "pytest-asyncio":"1.3.0", "pytest-mock":"3.15.1", "pytest-timeout":"2.4.0"}; actual={name:m.version(name) for name in expected}; assert actual == expected, (actual, expected); print(actual)'
