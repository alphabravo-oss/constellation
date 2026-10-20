#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export GOWORK=off
formatter="${GOLANGCI_LINT:-golangci-lint}"
artifacts="${ARTIFACT_DIR:-test-results/tooling}"
mkdir -p "$artifacts"
# Match the module's packages, without formatting ignored reference checkouts.
package_dirs="$(go list -f '{{.Dir}}' ./...)"
if [[ -z "$package_dirs" ]]; then
  echo "format: no Go packages discovered; refusing an empty check" >&2
  exit 1
fi
mapfile -t packages <<< "$package_dirs"
"$formatter" fmt --diff "${packages[@]}" > "$artifacts/format.diff"
if [[ -s "$artifacts/format.diff" ]]; then
  cat "$artifacts/format.diff"
  exit 1
fi
