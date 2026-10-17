#!/usr/bin/env bash
# Only explicit 'run' creates isolated resources. Never uses the current context.
set -euo pipefail
cd "$(dirname "$0")/.."
export GOWORK=off GOMAXPROCS="${GOMAXPROCS:-4}"
umask 077
runtime_image='constellation/runtime-agent:scope-20261017-6c4a1cc'
runtime_id='sha256:58a1dfe1ce01f77007243106143edceb3db0071cbcbd2765b2be267679a0ff8e'
source_revision="$(git rev-parse '1cb1045^{commit}')"
mode="${1:-prepare}"
work="${FLANNEL_POLICY_ARTIFACT_DIR:-/tmp/constellation-flannel-policy-prepared}"
[[ "$work" =~ ^/tmp/constellation-flannel-policy-[a-zA-Z0-9-]+$ && ! -L "$work" ]] || { echo 'Use a dedicated nonsymlink /tmp/constellation-flannel-policy-* directory.' >&2; exit 1; }
mkdir -p "$work/build" "$work/driver-evidence"
work="$(realpath "$work")"
source_root="$work/source"
[[ "$work" == /tmp/constellation-flannel-policy-* ]] || { echo 'Evidence must use a dedicated /tmp/constellation-flannel-policy-* directory.' >&2; exit 1; }
docker_local() { env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host unix:///var/run/docker.sock "$@"; }
k3d_local() { env -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH DOCKER_HOST=unix:///var/run/docker.sock k3d "$@"; }
free_kib() { df --output=avail "$work" | tail -1 | tr -d ' '; }
[[ "$(docker_local image inspect "$runtime_image" --format '{{.Id}}')" == "$runtime_id" ]] || { echo 'Qualified native image identity changed.' >&2; exit 1; }
prepare() {
  [[ ! -e "$source_root" ]] || { echo 'Use a fresh dedicated evidence directory for preparation.' >&2; exit 1; }
  mkdir -p "$source_root"
  git archive "$source_revision" | tar -x -C "$source_root"
  printf '%s\n' "$source_revision" > "$work/base-revision.txt"
  for file in cmd/constellation-runtime-agent/flannel_policy_{acceptance,fixture,probe}_test.go; do install -m 600 "$file" "$source_root/$file"; done
  install -D -m 600 tests/flannel-policy/fixture/main.go "$source_root/tests/flannel-policy/fixture/main.go"
  (cd "$source_root"; CGO_ENABLED=0 GOOS=linux go test -tags=integration -c -o "$work/build/driver" ./cmd/constellation-runtime-agent)
  (cd "$source_root"; CGO_ENABLED=0 GOOS=linux go build -trimpath -o "$work/build/fixture" ./tests/flannel-policy/fixture)
  install -m 600 tests/flannel-policy/Dockerfile "$work/build/Dockerfile"
  sha256sum "$work/build/driver" "$work/build/fixture" > "$work/binaries.sha256"
  sha256sum scripts/test-flannel-policy.sh tests/flannel-policy/{Dockerfile,pods.yaml,verify_evidence.py,README.md,fixture/main.go} cmd/constellation-runtime-agent/flannel_policy_{acceptance,fixture,probe}_test.go > "$work/source.sha256"
  printf '%s\n' "$runtime_id" > "$work/runtime-image-id.txt"
  echo "Prepared test binaries only: $work"
}
if [[ "$mode" == prepare ]]; then prepare; exit; fi
[[ "$mode" == run && "${CONSTELLATION_FLANNEL_POLICY_APPROVED_RUN:-0}" == 1 ]] || { echo 'Run requires a separate root-reviewed fixture execution signal.' >&2; exit 1; }
for executable in k3d kubectl docker python3; do command -v "$executable" >/dev/null; done
(( $(free_kib) >= 48 * 1024 * 1024 )) || { echo 'At least48GiB free required before isolated cluster creation.' >&2; exit 1; }
(cd /; sha256sum -c "$work/binaries.sha256")
sha256sum -c "$work/source.sha256"
nonce="$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
cluster="constellation-flannel-policy-$nonce"
namespace="packet-proof-$nonce"
node="k3d-$cluster-server-0"
driver="flannel-policy-driver-$nonce"
fixture_image="constellation/flannel-policy-fixture:$nonce"
base_tag="constellation/flannel-policy-base:$nonce"
network="flannel-policy-$nonce"
network_id=''
network_created=0
owned_volumes=()
volume_names=("flannel-policy-$nonce-cni" "flannel-policy-$nonce-kubelet" "flannel-policy-$nonce-k3s" "flannel-policy-$nonce-log")
created=0; monitor=''; driver_created=0; base_created=0; fixture_created=0
cleanup() {
  status=$?
  trap - EXIT INT TERM
  [[ -z "$monitor" ]] || kill "$monitor" 2>/dev/null || true
  if [[ "$driver_created" == 1 ]]; then
    if docker_local inspect "$driver" >/dev/null 2>&1; then
      if [[ "$(docker_local inspect "$driver" --format '{{index .Config.Labels "constellation.flannel-proof"}}')" == "$nonce" ]]; then
        docker_local logs "$driver" > "$work/driver.log" 2>&1 || status=1
        docker_local rm -f "$driver" >/dev/null || status=1
      else echo 'Driver ownership changed; refusing deletion.' >&2; status=1; fi
    fi
  fi
  if [[ "$created" == 1 ]]; then
    owned="$(docker_local inspect "$node" --format '{{index .Config.Labels "constellation.flannel-proof"}}' 2>/dev/null || true)"
    if [[ "$owned" == "$nonce" ]]; then
      k3d_local cluster delete "$cluster" > "$work/cleanup.log" 2>&1 || status=1
      # A failed k3d cleanup may leave its exact owned node. Never touch peers.
      if docker_local inspect "$node" >/dev/null 2>&1; then
        if [[ "$(docker_local inspect "$node" --format '{{index .Config.Labels "constellation.flannel-proof"}}')" == "$nonce" ]]; then docker_local rm -f -v "$node" >/dev/null || status=1
        else echo 'Node identity changed; refusing deletion.' >&2; status=1; fi
      fi
    elif docker_local inspect "$node" >/dev/null 2>&1; then
      echo 'Node ownership changed: refusing cluster deletion.' >&2; status=1
    fi
  fi
  for volume in "${owned_volumes[@]}"; do
    if docker_local volume inspect "$volume" >/dev/null 2>&1; then
      if [[ "$(docker_local volume inspect "$volume" --format '{{index .Labels "constellation.flannel-proof"}}')" == "$nonce" ]]; then docker_local volume rm "$volume" >/dev/null || status=1
      else echo 'Volume ownership changed: refusing deletion.' >&2; status=1; fi
    fi
  done
  if [[ "$network_created" == 1 ]] && docker_local network inspect "$network" >/dev/null 2>&1; then
    actual_network="$(docker_local network inspect "$network" --format '{{.Id}}')"
    owned="$(docker_local network inspect "$network" --format '{{index .Labels "constellation.flannel-proof"}}')"
    if [[ "$owned" == "$nonce" && ( -z "$network_id" || "$actual_network" == "$network_id" ) ]]; then docker_local network rm "$actual_network" >/dev/null || status=1
    else echo 'Network identity changed: refusing deletion.' >&2; status=1; fi
  fi
  if [[ "$fixture_created" == 1 ]] && docker_local image inspect "$fixture_image" >/dev/null 2>&1; then
    if [[ "$(docker_local image inspect "$fixture_image" --format '{{index .Config.Labels "constellation.flannel-proof"}}')" == "$nonce" ]]; then docker_local image rm "$fixture_image" >/dev/null || status=1
    else echo 'Fixture tag changed; refusing deletion.' >&2; status=1; fi
  fi
  if [[ "$base_created" == 1 ]] && docker_local image inspect "$base_tag" >/dev/null 2>&1; then
    if [[ "$(docker_local image inspect "$base_tag" --format '{{.Id}}')" == "$runtime_id" ]]; then docker_local image rm "$base_tag" >/dev/null || status=1
    else echo 'Base tag changed; refusing deletion.' >&2; status=1; fi
  fi
  echo "Isolated Flannel evidence: $work; result=$status"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# This check reads names only; never dump cluster tokens/configuration.
if k3d_local cluster list -o json | python3 -c 'import json,sys; raise SystemExit(0 if any(c["name"]==sys.argv[1] for c in json.load(sys.stdin)) else 1)' "$cluster"; then echo 'Generated cluster already exists; refusing reuse.' >&2; exit 1; fi
for tag in "$fixture_image" "$base_tag"; do
  if docker_local image inspect "$tag" >/dev/null 2>&1; then echo 'Generated image tag exists; refusing reuse.' >&2; exit 1; fi
done
if docker_local inspect "$driver" >/dev/null 2>&1; then echo 'Generated driver exists; refusing reuse.' >&2; exit 1; fi
script_pid=$$
(while true; do sleep 2; if (( $(free_kib) < 40 * 1024 * 1024 )); then echo 'Disk safety floor reached; stopping owned test.' > "$work/disk-stop.txt"; kill -TERM "$script_pid"; exit; fi; done) & monitor=$!
docker_local image inspect rancher/k3s:v1.35.5-k3s1 --format '{{.Id}}' > "$work/k3s-image-id.txt"
base_created=1; docker_local tag "$runtime_id" "$base_tag"
fixture_created=1
docker_local build --pull=false --network=none --build-arg "PROOF_NONCE=$nonce" --build-arg "RUNTIME_IMAGE=$base_tag" -t "$fixture_image" "$work/build" > "$work/build.log" 2>&1
docker_local image inspect "$fixture_image" --format '{{.Id}}' > "$work/fixture-image-id.txt"
docker_local run --rm -i --network none --cap-drop ALL --read-only --entrypoint /bin/sh "$runtime_id" -s > "$work/native-provenance.sha256" <<'PROVENANCE'
set -eu
sha256sum /usr/local/bin/dp
libraries="$(ldd /usr/local/bin/dp)"
case "$libraries" in *'not found'*) echo 'Unresolved native dependency' >&2; exit 1;; esac
paths="$(printf '%s\n' "$libraries" | sed -n 's/.*=> \(\/[^ ]*\) .*/\1/p; s/^[[:space:]]*\(\/[^ ]*\) .*/\1/p' | sort -u)"
[ -n "$paths" ] || { echo 'No native linked-library provenance' >&2; exit 1; }
printf '%s\n' "$paths" | while IFS= read -r library; do sha256sum "$library"; done
PROVENANCE


docker_local network inspect "$network" >/dev/null 2>&1 && { echo 'Generated network exists; refusing reuse.' >&2; exit 1; }
network_created=1
network_id="$(docker_local network create --driver bridge --label "constellation.flannel-proof=$nonce" "$network")"
printf '%s\n' "$network_id" > "$work/network-id.txt"
for volume in "${volume_names[@]}"; do
  if docker_local volume inspect "$volume" >/dev/null 2>&1; then echo 'Generated volume exists; refusing reuse.' >&2; exit 1; fi
  owned_volumes+=("$volume")
  docker_local volume create --label "constellation.flannel-proof=$nonce" "$volume" >> "$work/volume-names.txt"
done
created=1
k3d_local cluster create "$cluster" --servers 1 --agents 0 --no-lb --no-image-volume --network "$network" --runtime-label "constellation.flannel-proof=$nonce@server:0" --volume "${volume_names[0]}:/var/lib/cni@server:0" --volume "${volume_names[1]}:/var/lib/kubelet@server:0" --volume "${volume_names[2]}:/var/lib/rancher/k3s@server:0" --volume "${volume_names[3]}:/var/log@server:0" --api-port 127.0.0.1:0 --servers-memory 2g --image rancher/k3s:v1.35.5-k3s1 --kubeconfig-update-default=false --kubeconfig-switch-context=false --wait --timeout 180s --k3s-arg '--disable=traefik,servicelb,metrics-server,local-storage,coredns@server:0' --k3s-arg '--cluster-cidr=10.233.0.0/16@server:0' --k3s-arg '--service-cidr=10.234.0.0/16@server:0' > "$work/cluster.log" 2>&1
k3d_local kubeconfig get "$cluster" > "$work/kubeconfig"
k=(kubectl --kubeconfig "$work/kubeconfig")
[[ "$("${k[@]}" config current-context)" == "k3d-$cluster" ]]
[[ "$(docker_local inspect "$node" --format '{{.HostConfig.PidMode}}')" != host ]]
[[ "$(docker_local inspect "$node" --format '{{.HostConfig.NetworkMode}}')" != host ]]
[[ "$(docker_local inspect "$node" --format '{{index .Config.Labels "k3d.cluster"}}')" == "$cluster" ]]
docker_local inspect "$node" --format '{{json .Mounts}}' > "$work/node-mounts.json"
python3 - "$work/node-mounts.json" "${volume_names[@]}" <<'MOUNTS'
import json,sys
mounts=json.load(open(sys.argv[1]))
actual={m['Name'] for m in mounts if m['Type']=='volume'}
if actual!=set(sys.argv[2:]): raise SystemExit('Unexpected node volume identity; refusing driver start')
MOUNTS
k3d_local image import --mode direct "$fixture_image" -c "$cluster" > "$work/import.log" 2>&1
"${k[@]}" create namespace "$namespace" >/dev/null
sed "s|FIXTURE_IMAGE|$fixture_image|g" tests/flannel-policy/pods.yaml > "$work/pods.yaml"
"${k[@]}" -n "$namespace" apply -f "$work/pods.yaml" >/dev/null
"${k[@]}" -n "$namespace" wait --for=condition=Ready pod --all --timeout=180s
"${k[@]}" -n "$namespace" get pods -o json > "$work/pods.json"
docker_local exec "$node" cat /var/lib/rancher/k3s/agent/etc/cni/net.d/10-flannel.conflist > "$work/flannel.json"
for pod in server-a server-b client; do
  container="$(python3 -c 'import json,sys; p=next(p for p in json.load(open(sys.argv[1]))["items"] if p["metadata"]["name"]==sys.argv[2]); print(p["status"]["containerStatuses"][0]["containerID"].removeprefix("containerd://"))' "$work/pods.json" "$pod")"
  [[ "$container" =~ ^[0-9a-f]{64}$ ]]
  docker_local exec "$node" k3s crictl inspect "$container" > "$work/cri-$pod.json"
  pid="$(python3 -c 'import json,sys; p=int(json.load(open(sys.argv[1]))["info"]["pid"]); assert 1<p<=2147483647; print(p)' "$work/cri-$pod.json")"
  docker_local exec "$node" readlink "/proc/$pid/ns/net" > "$work/netns-$pod.txt"
done
python3 tests/flannel-policy/verify_evidence.py identity "$work" --cluster "$cluster" --namespace "$namespace" --node "$node" --node-pidns "$(docker_local exec "$node" readlink /proc/self/ns/pid)" --node-netns "$(docker_local exec "$node" readlink /proc/self/ns/net)" --host-pidns "$(readlink /proc/self/ns/pid)" --host-netns "$(readlink /proc/self/ns/net)" --runtime-image "$runtime_id" > "$work/driver-evidence/identity.json"
driver_created=1
docker_local create --name "$driver" --label "constellation.test.cluster=$cluster" --label "constellation.flannel-proof=$nonce" --pid="container:$node" --network="container:$node" --ipc=private --read-only --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN --cap-add SYS_PTRACE --security-opt no-new-privileges:true --pids-limit 128 --memory 1g --cpus 1.5 --tmpfs /tmp:rw,nosuid,noexec,size=64m --mount "type=bind,source=$work/driver-evidence,target=/evidence" --env CONSTELLATION_FLANNEL_POLICY_RUN=1 --env GOMAXPROCS=2 --entrypoint /usr/local/bin/flannel-policy-driver "$fixture_image" -test.run '^TestFlannelRuntimePolicyPacketAcceptance$' -test.v -test.timeout=8m > "$work/driver-container-id.txt"
docker_local start -a "$driver" > "$work/driver.log" 2>&1 || result=$?
result="${result:-0}"
container_exit="$(docker_local inspect "$driver" --format '{{.State.ExitCode}}')"
[[ "$container_exit" == 0 ]] || result="$container_exit"
for pod in server-a server-b; do "${k[@]}" -n "$namespace" logs "$pod" > "$work/$pod.log"; done
[[ "$result" == 0 ]] || exit "$result"
python3 tests/flannel-policy/verify_evidence.py verify "$work"
