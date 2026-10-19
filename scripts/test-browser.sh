#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
export GOWORK=off
goose_bin="${GOOSE_BIN:-goose}"
for executable in docker go npm curl openssl python3 "$goose_bin"; do
  command -v "$executable" >/dev/null
done
artifact_dir="${ARTIFACT_DIR:-artifacts/browser}"
mkdir -p "$artifact_dir"
artifact_dir="$(cd "$artifact_dir" && pwd)"
run_id="constellation-browser-$(openssl rand -hex 6)"
network=""
database=""
api=""
frontend=""
cleanup() {
  local result=$?
  local container
  for container in "$frontend" "$api" "$database"; do
    if [[ -n "$container" ]]; then
      docker logs "$container" >"$artifact_dir/$container.log" 2>&1 || result=1
      docker rm -f "$container" >/dev/null || result=1
    fi
  done
  if [[ -n "$network" ]]; then
    docker network rm "$network" >/dev/null || result=1
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker build -f deploy/docker/Dockerfile.api -t "$run_id-api" . >"$artifact_dir/api-build.log" 2>&1
bash scripts/test-api-runtime.sh "$run_id-api" >"$artifact_dir/api-runtime-check.log" 2>&1
docker build -f deploy/docker/Dockerfile.frontend --build-arg "NODE_VERSION=$(cat .node-version)" -t "$run_id-frontend" . >"$artifact_dir/frontend-build.log" 2>&1
docker image inspect --format '{{.RepoTags}} {{.Id}}' "$run_id-api" "$run_id-frontend" >"$artifact_dir/images.txt"
network="$(docker network create "$run_id")"
database="$(docker run -d --rm --network "$network" --network-alias database \
  -e POSTGRES_USER=test -e POSTGRES_PASSWORD=test -e POSTGRES_DB=constellation_test \
  -p 127.0.0.1::5432 "${PARITY_POSTGRES_IMAGE:-pgvector/pgvector:pg16}")"
ready=0
for ((attempt=1; attempt<=60; attempt++)); do
  if docker exec "$database" pg_isready -h 127.0.0.1 -U test -d constellation_test >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
[[ "$ready" == 1 ]]
port="$(docker port "$database" 5432/tcp | sed 's/.*://')"
export DATABASE_URL="postgres://test:test@127.0.0.1:$port/constellation_test?sslmode=disable"
"$goose_bin" -dir db/migrations postgres "$DATABASE_URL" up >"$artifact_dir/migrations.log" 2>&1
go run ./cmd/constellation-seed >"$artifact_dir/seed.log" 2>&1
export CONSTELLATION_KEK
CONSTELLATION_KEK="$(openssl rand -hex 32)"
api="$(docker run -d --rm --network "$network" --network-alias constellation-api \
  -e DATABASE_URL='postgres://test:test@database:5432/constellation_test?sslmode=disable' \
  -e CONSTELLATION_KEK -e CORS_ORIGINS= -e MAX_CONCURRENT_SESSIONS=32 "$run_id-api")"
frontend="$(docker run -d --rm --network "$network" -p 127.0.0.1::8080 "$run_id-frontend")"
port="$(docker port "$frontend" 8080/tcp | sed 's/.*://')"
export PLAYWRIGHT_BASE_URL="http://localhost:$port"
export VITE_API_URL="$PLAYWRIGHT_BASE_URL"
export CONSTELLATION_SEED_DB=0
export PLAYWRIGHT_AUTH_SETUP=1
ready=0
for ((attempt=1; attempt<=60; attempt++)); do
  code="$(curl --silent --output /dev/null --write-out '%{http_code}' "$PLAYWRIGHT_BASE_URL/api/v1/auth/me" || true)"
  if [[ "$code" == 401 ]]; then
    ready=1
    break
  fi
  sleep 1
done
[[ "$ready" == 1 ]]
CONSTELLATION="http://127.0.0.1:$port" FRONTEND_CONTAINER="$frontend" DATABASE_CONTAINER="$database" \
  LIFECYCLE_METRICS_PATH="$artifact_dir/lifecycle-metrics.txt" \
  python3 -B - >"$artifact_dir/api-recipes-smoke.log" 2>&1 <<'PY'
import json
import os
import subprocess
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.request import ProxyHandler, Request, build_opener

from scripts.smoke_api_recipes import run


origin = os.environ["CONSTELLATION"]
opener = build_opener(ProxyHandler({}))

# Exercise the production workers, not just collector registration. The frontend
# container reaches the API on the private Docker network on Linux and Desktop.
# A busy parent is deliberately skipped and retried on the five-minute worker
# cadence. Allow that next pass; requiring success in 30s races startup DDL.
deadline = time.monotonic() + 360
while time.monotonic() < deadline:
    sample = subprocess.run([
        "docker", "exec", os.environ["FRONTEND_CONTAINER"], "wget", "-qO-",
        "http://constellation-api:8080/metrics",
    ], capture_output=True, text=True, timeout=5, check=True)
    lines = [line for line in sample.stdout.splitlines() if line.startswith((
        "constellation_partition_statistics_", "constellation_session_cleanup_",
    ))]
    analyzed = any(line.startswith("constellation_partition_statistics_completed_total{")
                   and float(line.rsplit(" ", 1)[1]) >= 1 for line in lines)
    reaped = any(line.startswith("constellation_session_cleanup_last_success_timestamp_seconds ")
                 and float(line.rsplit(" ", 1)[1]) > 0 for line in lines)
    parents = subprocess.run([
        "docker", "exec", os.environ["DATABASE_CONTAINER"], "psql", "-XAt",
        "-U", "test", "-d", "constellation_test", "-c",
        "SELECT count(*) FROM pg_stat_all_tables WHERE schemaname='public' "
        "AND relname IN ('network_flows','events','findings') AND last_analyze IS NOT NULL",
    ], capture_output=True, text=True, timeout=5, check=True)
    if analyzed and reaped and int(parents.stdout.strip()) > 0:
        Path(os.environ["LIFECYCLE_METRICS_PATH"]).write_text("\n".join(lines) + "\n")
        print("Production parent statistics and session cleanup workers passed")
        break
    time.sleep(2)
else:
    Path(os.environ["LIFECYCLE_METRICS_PATH"]).write_text("\n".join(lines) + "\n")
    raise RuntimeError("production lifecycle workers did not complete within the smoke budget")


def fetch(path, token=None, body=None):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = Request(origin + path, data=body, headers=headers)
    with opener.open(request, timeout=5) as response:
        return json.load(response)


login = fetch("/api/v1/auth/login", body=json.dumps({
    "email": "admin@demo.test", "password": "Constellation!1",
}).encode("utf-8"))
token = login["token"]
cluster = fetch("/api/v1/clusters", token)["clusters"][0]["id"]
with TemporaryDirectory() as directory:
    preview_file = Path(directory) / "nv-export.json"
    preview_file.write_text(json.dumps({
        "vulnerability_profiles": [{
            "name": "browser-smoke-profile",
            "entries": [{"name": "CVE-2026-1234"}],
        }],
    }), encoding="utf-8")
    preview = run({"CONSTELLATION": origin, "TOKEN": token, "CLUSTER": cluster}, preview_file)
    if preview["summary"]["vulnerability_profiles"] != 1 or len(preview["vulnerability_profiles"]) != 1:
        raise RuntimeError("migration preview did not convert the fixed vulnerability profile")
    profiles = fetch("/api/v1/vuln-profiles", token)["profiles"]
    if any(profile["name"] == "browser-smoke-profile" for profile in profiles):
        raise RuntimeError("migration preview applied the fixed vulnerability profile")
    if os.environ.get("API_RECIPES_APPLY_ROLLBACK_FIXTURE") == "1":
        run({"CONSTELLATION": origin, "TOKEN": token, "CLUSTER": cluster},
            apply_rollback_fixture=True)
PY
if [[ $# == 0 ]]; then
  set -- .
fi
cd frontend
npx playwright test "$@"
