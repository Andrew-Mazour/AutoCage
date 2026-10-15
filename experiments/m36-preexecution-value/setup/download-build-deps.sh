#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 WHEELHOUSE" >&2
    exit 2
fi

wheelhouse_dir=$1
mkdir -p "$wheelhouse_dir"
python3 -m pip download \
    --require-hashes \
    --only-binary=:all: \
    --no-deps \
    --dest "$wheelhouse_dir" \
    -r "$(dirname "$0")/python-build-requirements.lock"
(
    cd "$wheelhouse_dir"
    sha256sum --check "$(dirname "$0")/python-build-requirements.lock"
)
