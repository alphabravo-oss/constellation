#!/usr/bin/env bash
# scanner-driver-loop.sh — outer loop wrapping the one-shot
# `constellation-scanner-driver` so it polls pending scan_jobs every SCAN_INTERVAL.
#
# The Go program itself drains the pending queue once and exits (suitable for CI). In
# a long-running container we want a sleep-and-retry loop, which is what this wrapper
# adds. Exit code from the inner program is intentionally ignored: an exit-1 means
# "had failures last round" — we still want to retry on the next tick.
set -uo pipefail

: "${SCAN_INTERVAL:=30s}"
: "${API_URL:=http://api:8080}"

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "scanner-driver-loop: DATABASE_URL is required" >&2
  exit 2
fi

echo "scanner-driver-loop: api=${API_URL} interval=${SCAN_INTERVAL}"
echo "scanner-driver-loop: docker socket=$(ls -l /var/run/docker.sock 2>/dev/null || echo 'NOT MOUNTED')"

# Graceful SIGTERM handling — sleeping shells eat signals if we just `sleep` directly.
_term_pid=0
_term() {
  if [[ "${_term_pid}" -ne 0 ]]; then
    kill -TERM "${_term_pid}" 2>/dev/null || true
  fi
  exit 0
}
trap _term TERM INT

while true; do
  /usr/local/bin/constellation-scanner-driver --api "${API_URL}" --db "${DATABASE_URL}" &
  _term_pid=$!
  wait "${_term_pid}" || true
  _term_pid=0
  sleep "${SCAN_INTERVAL}" &
  _term_pid=$!
  wait "${_term_pid}" || true
  _term_pid=0
done
