#!/usr/bin/env bash
# Usage: bash scripts/test-go.sh unit|integration [package patterns]
# GOTESTSUM_BIN selects the executable. ARTIFACT_DIR defaults to artifacts,
# relative to the repository root; each mode writes <mode>.xml and <mode>.json.
set -euo pipefail

case "${1:-}" in
  unit|integration) mode="$1"; shift ;;
  *) echo "Usage: bash scripts/test-go.sh unit|integration [package patterns]" >&2; exit 2 ;;
esac

cd "$(dirname "$0")/.."
export GOWORK=off
if [[ $# == 0 ]]; then
  set -- ./...
fi
if [[ "$mode" == integration ]]; then
  export TEST_GO_USE_GOTESTSUM=1
  exec bash scripts/test-clean-database.sh "$@"
fi

gotestsum_bin="${GOTESTSUM_BIN:-gotestsum}"
command -v "$gotestsum_bin" >/dev/null || {
  echo "gotestsum executable not found: $gotestsum_bin (set GOTESTSUM_BIN)" >&2
  exit 127
}
artifact_dir="${ARTIFACT_DIR:-artifacts}"
mkdir -p "$artifact_dir"
exec "$gotestsum_bin" --junitfile "$artifact_dir/unit.xml" \
  --jsonfile "$artifact_dir/unit.json" -- -race -shuffle=on -count=1 "$@"
