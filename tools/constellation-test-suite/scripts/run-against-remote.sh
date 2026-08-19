#!/usr/bin/env bash
# Convenience wrapper: run the suite against a remote node with a chosen
# cluster type. Builds + loads images, runs all tests, tears down.
#
# Usage:
#   ./scripts/run-against-remote.sh root@host ~/.ssh/key k3s
#   ./scripts/run-against-remote.sh root@host ~/.ssh/key k3d
set -euo pipefail
HOST="${1:?usage: $0 <user@host> <ssh-key-path> <cluster-kind>}"
KEY="${2:?missing ssh key path}"
KIND="${3:?missing cluster kind (k3s|k3d|kind)}"
# Always run from the suite directory so pytest finds conftest.py without
# walking up into the constellation/ rootdir (which has its own pytest config
# scope and would reject our --remote / --cluster CLI options).
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$SUITE_DIR/../.." && pwd)"
cd "$SUITE_DIR"

# Sync the entire constellation source tree (not just the suite) so the
# deployer's `make images` on the remote finds the chart, Dockerfiles, and
# Go source.
echo ">> rsync source to $HOST:/root/constellation/"
rsync -az --delete \
  --exclude='.git' --exclude='node_modules' --exclude='frontend/.next' \
  --exclude='frontend/node_modules' --exclude='.objs' --exclude='.deps' \
  --exclude='*.o' --exclude='*.d' --exclude='dist' --exclude='build' \
  --exclude='third_party/neuvector/dp/dp' \
  -e "ssh -i $KEY -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null" \
  "$REPO_ROOT/" "$HOST":/root/constellation/

# Drop --teardown when re-running quickly — the user can still pass it
# explicitly via "$@" for full cleanup.
echo ">> running pytest from $SUITE_DIR"
shift 3 2>/dev/null || true
exec pytest -v \
  --remote="$HOST" \
  --ssh-key="$KEY" \
  --cluster="$KIND" \
  "$@"
