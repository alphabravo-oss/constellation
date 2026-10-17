#!/usr/bin/env bash
# Actual native parser/staging/matcher and connection-reporter acceptance; no CNI effects.
set -euo pipefail
cd "$(dirname "$0")/.."
export GOWORK=off
export GOMAXPROCS="${GOMAXPROCS:-2}"
artifact_dir="${ARTIFACT_DIR:-/tmp/constellation-native-policy-acceptance}"
mkdir -p "$artifact_dir"
artifact_dir="$(realpath "$artifact_dir")"
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/constellation-native-policy.XXXXXXXX")"
trap 'rm -rf "$fixture_dir"' EXIT
image="${CONSTELLATION_NATIVE_POLICY_IMAGE:-constellation/native-policy-test:$(git rev-parse --short=12 HEAD)}"
docker_local() {
  env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
    docker --host unix:///var/run/docker.sock "$@"
}
if [[ "${NATIVE_POLICY_SKIP_BUILD:-0}" != 1 ]]; then
  docker_root="$(docker_local info --format '{{.DockerRootDir}}')"
  if [[ -z "$docker_root" || ! -d "$docker_root" ]]; then
    echo 'Native test build requires an existing local DockerRootDir.' >&2
    exit 1
  fi
  free_kib="$(df --output=avail "$docker_root" | tail -1 | tr -d ' ')"
  if [[ ! "$free_kib" =~ ^[0-9]+$ ]]; then
    echo 'Could not determine available local Docker storage.' >&2
    exit 1
  fi
  if (( free_kib < 40 * 1024 * 1024 )); then
    echo 'Native test build requires at least 40 GiB available to avoid node disk pressure.' >&2
    exit 1
  fi
  docker_local build --progress=plain -f tests/native-policy/Dockerfile -t "$image" . \
    >"$artifact_dir/build.log" 2>&1
fi
git rev-parse HEAD >"$artifact_dir/source-revision.txt"
sha256sum tests/native-policy/{Dockerfile,matcher.c,connect_report.c,connect-report-build.sh,run.sh} scripts/test-native-policy.sh \
  cmd/constellation-runtime-agent/{native_policy_acceptance_test.go,runtime_policy_scope.go,runtime_policy_sync.go} \
  internal/runtime/dp/{native_policy_acceptance_test.go,policy.go,client.go} >"$artifact_dir/fixture-source.sha256"
docker_local image inspect "$image" --format '{{.Id}}' >"$artifact_dir/image-id.txt"
image_id="$(cat "$artifact_dir/image-id.txt")"
docker_local run --rm --network none --cap-drop ALL --read-only --entrypoint /bin/cat "$image_id" \
  /native-source.sha256 >"$artifact_dir/vendor-source.sha256"
docker_local run --rm --network none --cap-drop ALL --read-only --entrypoint /bin/cat "$image_id" \
  /native-harness-source.sha256 >"$artifact_dir/harness-source.sha256"
find third_party/neuvector -type f ! -path '*/.objs/*' ! -path '*/.deps/*' \
  ! -path third_party/neuvector/dp/dp -print0 | sort -z | xargs -0 sha256sum >"$artifact_dir/expected-vendor-source.sha256"
sha256sum tests/native-policy/{matcher.c,connect_report.c,connect-report-build.sh,Dockerfile,run.sh} >"$artifact_dir/expected-harness-source.sha256"
if ! cmp -s "$artifact_dir/vendor-source.sha256" "$artifact_dir/expected-vendor-source.sha256" || \
   ! cmp -s "$artifact_dir/harness-source.sha256" "$artifact_dir/expected-harness-source.sha256"; then
  echo 'Native test image source differs from this checkout; rebuild without NATIVE_POLICY_SKIP_BUILD.' >&2
  exit 1
fi
docker_local run --rm --network none --cap-drop ALL --read-only --entrypoint /bin/cat "$image_id" \
  /native-source.sha256 /native-original-objects.sha256 /native-harness.sha256 /native-harness-source.sha256 >"$artifact_dir/native-provenance.sha256"
docker_local run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --read-only --user 65534:65534 --entrypoint /usr/bin/sha256sum "$image_id" \
  -c /native-harness.sha256 >"$artifact_dir/harness-binary-verification.txt"
export CONSTELLATION_NATIVE_POLICY_IMAGE_ID="$image_id"
for variant in connect connect-pattern; do
  bash tests/native-policy/run.sh "$variant" >"$artifact_dir/$variant.log" 2>&1
  grep -Fx 'PASS 97 actual dp_ctrl_connect_report assertions' "$artifact_dir/$variant.log" >/dev/null
done
if bash tests/native-policy/run.sh connect-unpatched >"$artifact_dir/connect-unpatched.log" 2>&1; then
  echo 'Unpatched native reporter unexpectedly passed its deterministic negative control.' >&2
  exit 1
else
  negative_status=$?
  if [[ "$negative_status" != 1 ]] || ! grep -Fx \
    'identical HTTP1001 expected buckets=1 actual=2' "$artifact_dir/connect-unpatched.log" >/dev/null; then
    echo 'Unpatched negative control failed for an unexpected reason.' >&2
    exit 1
  fi
fi
CONSTELLATION_NATIVE_POLICY_IMAGE_ID="$(cat "$artifact_dir/image-id.txt")"
export CONSTELLATION_NATIVE_POLICY_IMAGE_ID
export CONSTELLATION_NATIVE_POLICY_DIR="$fixture_dir"
go test -tags=integration -race -shuffle=on -count=1 ./cmd/constellation-runtime-agent \
  -run '^TestGenerateNativeRuntimePolicyFixture$' -json >"$artifact_dir/generator.json"
cp "$CONSTELLATION_NATIVE_POLICY_DIR/policies.json" "$artifact_dir/policies.json"
go test -tags=integration -race -shuffle=on -count=2 ./internal/runtime/dp \
  -run '^TestNativeRuntimePolicyAcceptance$' -json >"$artifact_dir/native.json"
printf 'Native parser/staging/matcher acceptance passed. Evidence: %s\n' "$artifact_dir"
