#!/usr/bin/env bash
# Uninstall Constellation systemd units.
#
#   sudo bash uninstall.sh           # stop+disable+remove units; keep env + data
#   sudo bash uninstall.sh --purge   # also remove env files, /var/lib, user, binaries
#   sudo bash uninstall.sh --user    # systemd --user variant

set -euo pipefail

USER_MODE=0
PURGE=0
SYSTEMCTL="systemctl"

SYSTEMD_DIR="/etc/systemd/system"
ETC_DIR="/etc/constellation"
LIB_DIR="/var/lib/constellation"
LOG_DIR="/var/log/constellation"
BIN_DIR="/usr/local/bin"
SVC_USER="constellation"
SVC_GROUP="constellation"

UNITS=(
  constellation-api.service
  constellation-scanner.service
  'constellation-scanner@*.service'
  constellation-operator.service
  constellation-runtime-agent.service
  constellation-discoverer.service
  'constellation-discoverer@*.service'
  constellation-scanner-driver.service
  constellation-audit-archiver.service
  constellation-audit-archiver.timer
)

BINARIES=(
  constellation-api constellation-scanner constellation-operator
  constellation-runtime-agent constellation-discoverer audit-archiver
  constellationctl constellation-scanner-driver
)

for a in "$@"; do
  case "$a" in
    --user)  USER_MODE=1 ;;
    --purge) PURGE=1 ;;
    -h|--help)
      sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown: $a" >&2; exit 2 ;;
  esac
done

if [[ $USER_MODE -eq 1 ]]; then
  SYSTEMD_DIR="$HOME/.config/systemd/user"
  ETC_DIR="$HOME/.config/constellation"
  LIB_DIR="$HOME/.local/share/constellation"
  LOG_DIR="$HOME/.local/share/constellation/log"
  BIN_DIR="$HOME/.local/bin"
  SYSTEMCTL="systemctl --user"
fi

if [[ $USER_MODE -eq 0 && $EUID -ne 0 ]]; then
  echo "re-run with sudo (or pass --user)" >&2; exit 2
fi

echo "==> stopping + disabling units"
for u in "${UNITS[@]}"; do
  # expand globs against actually-installed units
  for inst in $($SYSTEMCTL list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -E "^${u//\*/[^ ]*}$" || true); do
    $SYSTEMCTL disable --now "$inst" 2>/dev/null || true
    rm -f "$SYSTEMD_DIR/$inst"
    echo "  removed $inst"
  done
  # also nuke literal file if it sits in $SYSTEMD_DIR even when systemctl never saw it
  for f in $SYSTEMD_DIR/$u; do
    [[ -e "$f" ]] && rm -f "$f" && echo "  removed $f"
  done
done

$SYSTEMCTL daemon-reload || true

if [[ $PURGE -eq 1 ]]; then
  echo "==> --purge: removing binaries, env files, data"
  for b in "${BINARIES[@]}"; do
    rm -f "$BIN_DIR/$b" && echo "  rm $BIN_DIR/$b" || true
  done
  rm -rf "$ETC_DIR" "$LIB_DIR" "$LOG_DIR"
  if [[ $USER_MODE -eq 0 ]] && getent passwd "$SVC_USER" >/dev/null; then
    userdel "$SVC_USER" 2>/dev/null || true
    groupdel "$SVC_GROUP" 2>/dev/null || true
    echo "  removed user $SVC_USER"
  fi
fi

echo "==> done"
