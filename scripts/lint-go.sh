#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export GOWORK=off
linter="${GOLANGCI_LINT:-golangci-lint}"
command -v "$linter" >/dev/null || {
  echo "golangci-lint is required; run make tools" >&2
  exit 1
}
artifacts="${ARTIFACT_DIR:-test-results/tooling}"
mkdir -p "$artifacts"
# Match Go's package discovery, including every module-owned package and test.
# Recursive filesystem scanning also finds unrelated downloaded JS fixtures.
package_dirs="$(go list -f '{{.Dir}}' ./...)"
if [[ -z "$package_dirs" ]]; then
  echo "lint: no Go packages discovered; refusing an empty check" >&2
  exit 1
fi
mapfile -t packages <<< "$package_dirs"
exec "$linter" run --output.json.path="$artifacts/golangci-lint.json" "${packages[@]}"
