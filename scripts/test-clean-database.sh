#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
export GOWORK=off
goose_bin="${GOOSE_BIN:-goose}"
# Opt in through scripts/test-go.sh integration, or TEST_GO_USE_GOTESTSUM=1.
if [[ "${TEST_GO_USE_GOTESTSUM:-0}" == 1 ]]; then
  gotestsum_bin="${GOTESTSUM_BIN:-gotestsum}"
  command -v "$gotestsum_bin" >/dev/null || {
    echo "gotestsum executable not found: $gotestsum_bin (set GOTESTSUM_BIN)" >&2
    exit 127
  }
  artifact_dir="${ARTIFACT_DIR:-artifacts}"
  mkdir -p "$artifact_dir"
fi
command -v docker >/dev/null
command -v "$goose_bin" >/dev/null
container=""
cleanup() {
  local status=$?
  local cleanup_status=0
  if [[ -n "$container" ]]; then
    docker rm -f "$container" >/dev/null || cleanup_status=$?
    if [[ "$cleanup_status" != 0 ]]; then
      echo "Failed to remove test database container: $container" >&2
      if [[ "$status" == 0 ]]; then
        status=$cleanup_status
      fi
    fi
  fi
  return "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
container="$(docker run -d --rm \
  -e POSTGRES_USER=test -e POSTGRES_PASSWORD=test -e POSTGRES_DB=constellation_test \
  -p 127.0.0.1::5432 "${PARITY_POSTGRES_IMAGE:-pgvector/pgvector:pg16}")"
ready=0
for ((attempt = 1; attempt <= 60; attempt++)); do
  if docker exec "$container" pg_isready -h 127.0.0.1 -U test -d constellation_test >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then
  docker logs "$container" >&2
  exit 1
fi
port="$(docker port "$container" 5432/tcp | sed 's/.*://')"
export DATABASE_URL="postgres://test:test@127.0.0.1:${port}/constellation_test?sslmode=disable"
export CONSTELLATION_TEST_DATABASE_URL="$DATABASE_URL"
export GOOSE_DRIVER=postgres GOOSE_DBSTRING="$DATABASE_URL" GOOSE_MIGRATION_DIR=db/migrations
"$goose_bin" up
"$goose_bin" up
if [[ $# == 0 ]]; then
  set -- ./...
fi
if [[ "${TEST_GO_USE_GOTESTSUM:-0}" == 1 ]]; then
  "$gotestsum_bin" --junitfile "$artifact_dir/integration.xml" \
    --jsonfile "$artifact_dir/integration.json" -- \
    -tags=integration -p 1 -count=2 -race -shuffle=on "$@"
else
  go test -tags=integration -p 1 -count=2 "$@"
fi
