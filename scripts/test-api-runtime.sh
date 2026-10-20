#!/usr/bin/env bash
# Check a built API image without relying on a shell inside the runtime.
set -euo pipefail
cd "$(dirname "$0")/.."
image="${1:?usage: scripts/test-api-runtime.sh IMAGE}"
probe_dir="$(mktemp -d)"
trap 'rm -rf -- "$probe_dir"' EXIT
CGO_ENABLED=0 GOWORK=off go build -trimpath -o "$probe_dir/probe" ./scripts/testdata/api-runtime-probe
chmod 755 "$probe_dir" "$probe_dir/probe"
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --mount "type=bind,src=$probe_dir/probe,dst=/runtime-probe,readonly" \
  --entrypoint /runtime-probe "$image"
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --entrypoint /usr/local/bin/constellationctl "$image" --help >/dev/null
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  "$image" -h >/dev/null
