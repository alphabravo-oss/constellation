#!/usr/bin/env bash
# Verify the Go FIPS build/runtime contract; this is not whole-product certification.
set -euo pipefail
cd "$(dirname "$0")/.."
export GOWORK=off GOFIPS140=v1.0.0 GODEBUG=fips140=on CGO_ENABLED=0
artifact_dir="${ARTIFACT_DIR:-artifacts}/fips"
mkdir -p "$artifact_dir"
build_dir="$(mktemp -d "${TMPDIR:-/tmp}/constellation-fips.XXXXXX")"
trap 'rm -rf "$build_dir"' EXIT
for role in api scanner operator runtime-agent; do
  go build -trimpath -tags fips -o "$build_dir/constellation-$role" "./cmd/constellation-$role"
  go version -m "$build_dir/constellation-$role" > "$artifact_dir/$role-build.txt"
  grep -q 'GOFIPS140=v1.0.0' "$artifact_dir/$role-build.txt"
  grep -q -- '-tags=fips' "$artifact_dir/$role-build.txt"
done
# This test executable exercises the same package-init guard as the four roles.
go test -c -tags fips -o "$build_dir/runtime-check" ./pkg/version
"$build_dir/runtime-check" -test.v -test.run '^TestFIPSRuntime$' > "$artifact_dir/runtime-enabled.txt" 2>&1
if GODEBUG=fips140=off "$build_dir/runtime-check" -test.run '^TestFIPSRuntime$' > "$artifact_dir/runtime-disabled.txt" 2>&1; then
  echo 'FIPS-tagged executable incorrectly accepted a disabled runtime' >&2
  exit 1
fi
grep -q 'FIPS build requires enabled Go Cryptographic Module v1.0.0' "$artifact_dir/runtime-disabled.txt"
# A tag alone must not pass by enabling the toolchain's unpinned crypto module.
GOFIPS140=off go test -c -tags fips -o "$build_dir/unpinned-check" ./pkg/version
if "$build_dir/unpinned-check" -test.run '^TestFIPSRuntime$' > "$artifact_dir/runtime-unpinned.txt" 2>&1; then
  echo 'FIPS-tagged executable incorrectly accepted an unpinned module' >&2
  exit 1
fi
grep -q 'FIPS build requires enabled Go Cryptographic Module v1.0.0' "$artifact_dir/runtime-unpinned.txt"
echo 'FIPS: four Go roles built; pinned runtime accepted; disabled/unpinned runtimes rejected'
