#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
command -v shellcheck >/dev/null || { echo "shellcheck is required; run make tools" >&2; exit 1; }
artifacts="${ARTIFACT_DIR:-test-results/tooling}"
mkdir -p "$artifacts"
mapfile -d '' scripts < <(git ls-files -z --cached --others --exclude-standard -- '*.sh' ':!:third_party/**')
shellcheck --format=json "${scripts[@]}" > "$artifacts/shellcheck.json"
