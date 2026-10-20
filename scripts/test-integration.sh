#!/usr/bin/env bash
# Integration suite against a disposable, migrated Postgres.
# Honours CONSTELLATION_TEST_DATABASE_URL when set (bring-your-own DB); otherwise starts a
# throwaway pgvector container, runs `goose up` as the smoke test, then the -tags=integration suite.
set -euo pipefail
cd "$(dirname "$0")/.."
export GOWORK=off
ARTIFACT_DIR="${ARTIFACT_DIR:-artifacts}"
GOTESTSUM="${GOTESTSUM:-gotestsum}"
mkdir -p "$ARTIFACT_DIR"
for tool in "$GOTESTSUM" goose; do
  command -v "$tool" >/dev/null || { echo "$tool not found; run: make tools" >&2; exit 127; }
done

cleanup() { :; }
if [[ -z "${CONSTELLATION_TEST_DATABASE_URL:-}" ]]; then
  command -v docker >/dev/null || { echo "docker is required to start the disposable test database" >&2; exit 127; }
  name="constellation-it-$$"
  port="${TEST_PG_PORT:-15499}"
  # A previous run that was interrupted leaves its container holding the port; reclaim it.
  docker ps -aq --filter "name=^constellation-it-" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker run -d --rm --name "$name" -e POSTGRES_USER=test -e POSTGRES_PASSWORD=test -e POSTGRES_DB=constellation_test \
    -p "127.0.0.1:${port}:5432" pgvector/pgvector:pg16 >/dev/null
  cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
  trap cleanup EXIT
  export CONSTELLATION_TEST_DATABASE_URL="postgres://test:test@127.0.0.1:${port}/constellation_test?sslmode=disable"
  for _ in $(seq 1 60); do
    docker exec "$name" pg_isready -q -U test -d constellation_test 2>/dev/null && break
    sleep 1
  done
fi
export DATABASE_URL="$CONSTELLATION_TEST_DATABASE_URL"

echo ">> goose up (migration smoke)"
goose -dir db/migrations postgres "$DATABASE_URL" up
goose -dir db/migrations postgres "$DATABASE_URL" status 2>&1 | tail -3
echo ">> seed"
go run ./cmd/constellation-seed
echo ">> go test -tags=integration"
exec "$GOTESTSUM" --junitfile "$ARTIFACT_DIR/integration.xml" --jsonfile "$ARTIFACT_DIR/integration.json" \
  -- -tags=integration -race -shuffle=on -count=1 -p 1 "${@:-./...}"
