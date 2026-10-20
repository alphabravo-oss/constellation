#!/usr/bin/env bash
# Security scanners for CI and `make security`: gosec, govulncheck, gitleaks. Every scanner
# writes SARIF (plus its native output) under ${ARTIFACT_DIR:-artifacts}.
set -euo pipefail

cd "$(dirname "$0")/.."
export GOWORK=off
artifacts="${ARTIFACT_DIR:-artifacts}"
mkdir -p "$artifacts"
case "${1:-}" in
  gosec)
    export GOMEMLIMIT="${GOSEC_GOMEMLIMIT:-2GiB}" GOMAXPROCS="${GOSEC_GOMAXPROCS:-2}"
    if [[ -z "${GOTMPDIR:-}" ]]; then
      scratch_root="${XDG_CACHE_HOME:-$HOME/.cache}/constellation"
      mkdir -p "$scratch_root"
      GOTMPDIR="$(mktemp -d "$scratch_root/gosec.XXXXXX")"
      export GOTMPDIR
      trap 'rm -rf -- "$GOTMPDIR"' EXIT
    fi
    # Relative package directories, enumerated as Go does: absolute paths make gosec's loader
    # report type errors, import paths make it scan nothing, and ./... walks node_modules.
    package_dirs="$(go list -f '{{.Dir}}' ./... | sed "s#^$PWD/#./#")"
    if [[ -z "$package_dirs" ]]; then
      echo "gosec: no Go packages discovered; refusing an empty scan" >&2
      exit 1
    fi
    mapfile -t packages <<< "$package_dirs"
    # Gate on HIGH severity at HIGH confidence (guide ch.06); every finding is still written to
    # the SARIF/JSON for review. G115 (int conversion) and G304 (operator-supplied paths) match
    # the golangci-lint policy in .golangci.yml.
    # -no-fail: gosec's exit code also flips on loader "type errors" it reports for a whole-module
    # load while finding nothing; the gate below is the finding count from the JSON report.
    gosec -no-fail -concurrency "${GOSEC_CONCURRENCY:-2}" -severity high -confidence high -exclude G115,G304 \
      -fmt sarif -out "$artifacts/gosec.sarif" \
      -stdout -verbose json "${packages[@]}" > "$artifacts/gosec.json"
    if [[ ! -s "$artifacts/gosec.sarif" || ! -s "$artifacts/gosec.json" ]]; then
      echo "gosec: scan did not produce both reports" >&2
      exit 1
    fi
    go run ./cmd/tools/sarif-tool rebase-gosec "$artifacts/gosec.sarif" "$artifacts/gosec.json"
    files="$(jq -r '.Stats.files' "$artifacts/gosec.json")"
    found="$(jq -r '.Stats.found' "$artifacts/gosec.json")"
    echo "gosec: scanned $files files, $found HIGH/HIGH findings (see $artifacts/gosec.sarif)"
    [[ "$files" -gt 0 && "$found" == 0 ]]
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
    # .gitleaks.toml carries the reviewed allow-list (test fixtures, scan artefacts, paths from
    # a Rancher reference checkout that was once committed). Every commit is still scanned.
    gitleaks git --no-banner --config .gitleaks.toml --redact=100 --log-opts=--all \
      --report-format sarif --report-path "$artifacts/gitleaks.sarif" .
    ;;
  *) echo "Usage: bash scripts/security-scan.sh gosec|govulncheck|gitleaks" >&2; exit 2 ;;
esac
