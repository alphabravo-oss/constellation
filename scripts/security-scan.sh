#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
export GOWORK=off
artifacts="${ARTIFACT_DIR:-test-results/security}"
mkdir -p "$artifacts"
case "${1:-}" in
  gosec)
    gosec -fmt sarif -out "$artifacts/gosec.sarif" ./...
    ;;
  govulncheck)
    govulncheck -json ./... > "$artifacts/govulncheck.json"
    govulncheck -mode convert -format sarif < "$artifacts/govulncheck.json" > "$artifacts/govulncheck.sarif"
    govulncheck -mode convert -format text < "$artifacts/govulncheck.json" | tee "$artifacts/govulncheck.txt"
    ;;
  gitleaks)
    if [[ "$(git rev-parse --is-shallow-repository)" != false ]]; then
      echo "Full-history scanning requires git fetch --unshallow (CI checkout fetch-depth: 0)." >&2
      exit 1
    fi
    gitleaks git --redact=100 --log-opts=--all --report-format sarif --report-path "$artifacts/gitleaks.sarif" .
    ;;
  *) echo "Usage: bash scripts/security-scan.sh gosec|govulncheck|gitleaks" >&2; exit 2 ;;
esac
