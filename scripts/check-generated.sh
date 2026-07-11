#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

GOWORK=off go run ./cmd/mc-schema --output "$tmpdir"
diff -ruN schema "$tmpdir"
