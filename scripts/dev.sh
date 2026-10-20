#!/usr/bin/env bash
# Constellation dev loop: Postgres + observability (compose), Air x3 (api/operator/scanner), Vite.
# Usage: scripts/dev.sh up|down|status|logs [name]|migrate|migrate-down|seed
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
RUN_DIR="$ROOT/tmp/dev"
LOG_DIR="$RUN_DIR/logs"
PID_FILE="$RUN_DIR/pids"
COMPOSE=(docker compose -f deploy/dev/compose.yaml)

usage() { echo "usage: $0 up|down|status|logs [api|operator|scanner|web|compose]|migrate|migrate-down|seed" >&2; exit 2; }

require_dev_tools() {
  local missing=0 tool hint
  for tool in docker go air node npx goose; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      case $tool in
        air) hint="go install github.com/air-verse/air@latest" ;;
        goose) hint="go install github.com/pressly/goose/v3/cmd/goose@latest" ;;
        docker) hint="https://docs.docker.com/engine/install/" ;;
        node|npx) hint="https://nodejs.org (24 LTS, see .node-version)" ;;
        *) hint="https://go.dev/dl" ;;
      esac
      echo "missing tool: $tool  ($hint)" >&2; missing=1
    fi
  done
  [ "$missing" = 0 ] || exit 1
}

load_env() {
  [ -f .env.dev.local ] || { cp .env.dev .env.dev.local; echo "created .env.dev.local from .env.dev"; }
  set -a
  # shellcheck disable=SC1091
  . ./.env.dev
  # shellcheck disable=SC1091
  . ./.env.dev.local
  set +a
}

rotate_log() {
  local f="$LOG_DIR/$1.log"
  [ -s "$f" ] && mv "$f" "$f.$(date -u +%Y%m%dT%H%M%SZ)"
  : > "$f"
}

start_bg() { # name, command...
  local name=$1; shift
  rotate_log "$name"
  nohup "$@" >> "$LOG_DIR/$name.log" 2>&1 &
  echo "$name=$!" >> "$PID_FILE"
  echo "started $name (pid $!) -> $LOG_DIR/$name.log"
}

wait_for_pg() {
  for _ in $(seq 1 60); do
    if "${COMPOSE[@]}" exec -T postgres pg_isready -q -U "$DEV_PG_USER" -d "$DEV_PG_DB" 2>/dev/null; then return 0; fi
    sleep 1
  done
  echo "postgres did not become ready" >&2; return 1
}

migrate_db() { goose -dir db/migrations postgres "$DATABASE_URL" "${1:-up}"; }

seed_admin() {
  # Known credentials for the dev loop and the Playwright live spec (DEV_ADMIN_* in .env.dev).
  go run ./cmd/constellation-seed -password "$DEV_ADMIN_PASSWORD" >> "$LOG_DIR/seed.log" 2>&1 \
    && echo "seeded $DEV_ADMIN_EMAIL (see $LOG_DIR/seed.log)"
}

ensure_kubeconfig_readable() {
  if [ -n "${KUBECONFIG:-}" ] && [ -f "$KUBECONFIG" ] && [ ! -r "$KUBECONFIG" ]; then
    echo "KUBECONFIG=$KUBECONFIG is not readable; run: sudo chmod 644 $KUBECONFIG" >&2
  fi
}

cmd_up() {
  require_dev_tools; load_env
  mkdir -p "$RUN_DIR" "$LOG_DIR"
  if [ -s "$PID_FILE" ]; then echo "stack already running (see status); run '$0 down' first" >&2; exit 1; fi
  : > "$PID_FILE"
  trap 'echo "interrupted; stopping"; cmd_down' INT TERM
  "${COMPOSE[@]}" up -d --wait
  wait_for_pg
  migrate_db up
  seed_admin || echo "seed failed (non-fatal); see $LOG_DIR/seed.log"
  ensure_kubeconfig_readable
  start_bg api air -c .air.api.toml
  start_bg operator air -c .air.operator.toml
  start_bg scanner air -c .air.scanner.toml
  (cd frontend && [ -d node_modules ] || npm ci --silent)
  rotate_log web
  (cd frontend && nohup npx vite --host 0.0.0.0 --port "$VITE_PORT" --strictPort >> "$LOG_DIR/web.log" 2>&1 & echo "web=$!" >> "$PID_FILE")
  trap - INT TERM
  cat <<MSG

Constellation dev stack is up:
  web        http://localhost:$VITE_PORT          (Vite, proxies /api + /ws to the API)
  api        http://localhost:${LISTEN_ADDR#:}      admin/metrics http://localhost:${ADMIN_LISTEN_ADDR#:}/metrics
  operator   metrics :18082  probes :18083   (watching namespace $WATCH_NAMESPACE)
  scanner    http://localhost:${SCANNER_LISTEN_ADDR#:}/healthz
  postgres   $DATABASE_URL
  grafana    http://localhost:3000   prometheus http://localhost:9090   tempo :3200   loki :3100
  login      $DEV_ADMIN_EMAIL / $DEV_ADMIN_PASSWORD
Logs: $0 logs [api|operator|scanner|web]
MSG
}

cmd_down() {
  load_env
  if [ -f "$PID_FILE" ]; then
    while IFS='=' read -r name pid; do
      [ -n "${pid:-}" ] || continue
      if kill -0 "$pid" 2>/dev/null; then
        kill -INT "$pid" 2>/dev/null || true
        pkill -INT -P "$pid" 2>/dev/null || true
        echo "stopped $name ($pid)"
      fi
    done < "$PID_FILE"
    sleep 2
    while IFS='=' read -r _ pid; do [ -n "${pid:-}" ] && kill -KILL "$pid" 2>/dev/null || true; done < "$PID_FILE"
    rm -f "$PID_FILE"
  fi
  pkill -f 'tmp/(api|operator|scanner)/constellation-' 2>/dev/null || true
  "${COMPOSE[@]}" down
}

cmd_status() {
  load_env
  "${COMPOSE[@]}" ps
  if [ -f "$PID_FILE" ]; then
    while IFS='=' read -r name pid; do
      if kill -0 "$pid" 2>/dev/null; then echo "$name: running (pid $pid)"; else echo "$name: not running"; fi
    done < "$PID_FILE"
  else
    echo "no host processes recorded"
  fi
}

cmd_logs() {
  local which=${1:-}
  case "$which" in
    compose) exec "${COMPOSE[@]}" logs -f ;;
    "") exec tail -n 50 -F "$LOG_DIR"/*.log ;;
    *) exec tail -n 100 -F "$LOG_DIR/$which.log" ;;
  esac
}

case "${1:-}" in
  up) cmd_up ;;
  down) cmd_down ;;
  status) cmd_status ;;
  logs) cmd_logs "${2:-}" ;;
  migrate) load_env; migrate_db up ;;
  migrate-down) echo "migrations are forward-only (db/migrations/README.md); drop and recreate the dev database instead:" >&2
                echo "  $0 down && docker volume rm constellation-dev_pgdata && $0 up" >&2; exit 1 ;;
  seed) load_env; mkdir -p "$LOG_DIR"; seed_admin ;;
  *) usage ;;
esac
