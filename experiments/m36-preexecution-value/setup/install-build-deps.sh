#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 WHEELHOUSE GUEST_SITE" >&2
    exit 2
fi

wheelhouse_dir=$1
guest_site=$2
mkdir -p "$guest_site"
python3 -m pip install \
    --no-index \
    --no-deps \
    --find-links "$wheelhouse_dir" \
    --target "$guest_site" \
    -r "$(dirname "$0")/python-build-requirements.lock"
