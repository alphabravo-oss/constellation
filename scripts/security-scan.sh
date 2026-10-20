#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
export GOWORK=off
artifacts="${ARTIFACT_DIR:-artifacts}"
mkdir -p "$artifacts"
case "${1:-}" in
  gosec)
    # Enumerate this module as Go does so gosec never walks node_modules or tmp/.
    export GOMEMLIMIT="${GOSEC_GOMEMLIMIT:-2GiB}" GOMAXPROCS="${GOSEC_GOMAXPROCS:-2}"
    if [[ -z "${GOTMPDIR:-}" ]]; then
      scratch_root="${XDG_CACHE_HOME:-$HOME/.cache}/constellation"
      mkdir -p "$scratch_root"
      GOTMPDIR="$(mktemp -d "$scratch_root/gosec.XXXXXX")"
      export GOTMPDIR
      trap 'rm -rf -- "$GOTMPDIR"' EXIT
    fi
    package_dirs="$(go list ./...)"
    if [[ -z "$package_dirs" ]]; then
      echo "gosec: no Go packages discovered; refusing an empty scan" >&2
      exit 1
    fi
    mapfile -t packages <<< "$package_dirs"
    # GOMEMLIMIT is a runtime soft budget, not an OS-enforced RSS ceiling.
    scan_status=0
    # Gate on HIGH severity at HIGH confidence (guide ch.06); every finding is still written to
    # the SARIF/JSON for review. G115 (int conversion) and G304 (operator-supplied paths) match
    # the golangci-lint policy in .golangci.yml.
    gosec -concurrency "${GOSEC_CONCURRENCY:-2}" -severity high -confidence high -exclude G115,G304 \
      -fmt sarif -out "$artifacts/gosec.sarif" \
      -stdout -verbose json "${packages[@]}" > "$artifacts/gosec.json" || scan_status=$?
    if [[ -s "$artifacts/gosec.sarif" && -s "$artifacts/gosec.json" ]]; then
      go run ./cmd/tools/sarif-tool rebase-gosec "$artifacts/gosec.sarif" "$artifacts/gosec.json"
    elif [[ "$scan_status" == 0 ]]; then
      echo "gosec: successful scan did not produce both reports" >&2
      exit 1
    fi
    exit "$scan_status"
    ;;
  govulncheck)
    govulncheck -json ./... > "$artifacts/govulncheck.json"
    govulncheck -mode convert -format sarif < "$artifacts/govulncheck.json" > "$artifacts/govulncheck.sarif"
    go run ./cmd/tools/sarif-tool normalize "$artifacts/govulncheck.sarif"
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
