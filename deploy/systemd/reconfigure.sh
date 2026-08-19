#!/usr/bin/env bash
# Open an env file for a role in $EDITOR and restart the corresponding unit.
#
#   sudo bash reconfigure.sh api
#   sudo bash reconfigure.sh scanner
#   bash reconfigure.sh --user discoverer

set -euo pipefail

USER_MODE=0
SYSTEMCTL="systemctl"
ETC_DIR="/etc/constellation"

if [[ "${1:-}" == "--user" ]]; then
  USER_MODE=1
  SYSTEMCTL="systemctl --user"
  ETC_DIR="$HOME/.config/constellation"
  shift
fi

ROLE="${1:-}"
if [[ -z "$ROLE" ]]; then
  cat <<EOF
usage: $0 [--user] <role>
  roles: api scanner operator runtime-agent discoverer audit-archiver scanner-driver
EOF
  exit 2
fi

declare -A ROLE_UNITS=(
  [api]=constellation-api.service
  [scanner]=constellation-scanner.service
  [operator]=constellation-operator.service
  [runtime-agent]=constellation-runtime-agent.service
  [discoverer]=constellation-discoverer.service
  [audit-archiver]=constellation-audit-archiver.service
  [scanner-driver]=constellation-scanner-driver.service
)
declare -A ROLE_ENVS=(
  [api]=api.env
  [scanner]=scanner.env
  [operator]=operator.env
  [runtime-agent]=runtime-agent.env
  [discoverer]=discoverer.env
  [audit-archiver]=audit-archiver.env
  [scanner-driver]=scanner-driver.env
)

UNIT="${ROLE_UNITS[$ROLE]:-}"
ENVF="${ROLE_ENVS[$ROLE]:-}"
[[ -n "$UNIT" && -n "$ENVF" ]] || { echo "unknown role: $ROLE" >&2; exit 2; }

ENV_PATH="$ETC_DIR/$ENVF"
[[ -f "$ENV_PATH" ]] || { echo "env file not found: $ENV_PATH (run install.sh first)" >&2; exit 2; }

EDITOR="${EDITOR:-${VISUAL:-vi}}"
echo "==> editing $ENV_PATH with $EDITOR"
"$EDITOR" "$ENV_PATH"

echo "==> restarting $UNIT"
$SYSTEMCTL daemon-reload
$SYSTEMCTL restart "$UNIT"
$SYSTEMCTL status --no-pager --lines=5 "$UNIT" || true
