#!/usr/bin/env bash
# Fixed test runner: select only the immutable locally inspected image ID.
set -euo pipefail
image_id="${CONSTELLATION_NATIVE_POLICY_IMAGE_ID:-}"
if [[ ! "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo 'Native policy acceptance requires an immutable local image ID.' >&2
  exit 2
fi
case "${1:-matcher}" in
  matcher) binary=/native-policy-matcher ;;
  connect) binary=/native-connect-report-standard ;;
  connect-pattern) binary=/native-connect-report-pattern ;;
  connect-unpatched) binary=/native-connect-report-unpatched ;;
  connect-wall-unpatched) binary=/native-connect-report-wall-unpatched ;;
  *) echo 'Unknown native acceptance entry point.' >&2; exit 2 ;;
esac
exec env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host unix:///var/run/docker.sock run --rm -i --network none --cap-drop ALL \
  --security-opt no-new-privileges --read-only --user 65534:65534 \
  --pids-limit 64 --memory 256m --entrypoint "$binary" "$image_id"
