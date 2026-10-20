#!/usr/bin/env bash
# Air-gap e2e on a live k3s node (guide ch.09): build a signed bundle, prove
# unsigned/tampered bundles are rejected, load it into containerd, install the
# chart into a scratch namespace whose pods can reach nothing outside the
# cluster, scan an image from a cluster-local registry with the baked
# vulnerability DBs, and prove the admission webhook rejects an unsigned image.
# Usage: SIGN_KEY=bundle.key TAG=<image tag> scripts/e2e-airgap.sh [run|prove|cleanup]
set -euo pipefail
cd "$(dirname "$0")/.."
NS=airgap-e2e WL=airgap-e2e-workloads REL=airgap
TAG="${TAG:?image tag of the locally built role images}"
REG="${REGISTRY:-ghcr.io/alphabravo-oss/constellation}"
OUT="${OUT:-$PWD/tmp/airgap-e2e}"
CTL="${CTL:-bin/constellationctl}"
SIGN_KEY="${SIGN_KEY:?ECDSA P-256 bundle signing key (PEM)}"
step() { printf '\n### %s (%s)\n' "$*" "$(date -u +%T)"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
  step "cleanup"
  helm uninstall "$REL" -n "$NS" --wait --timeout 5m 2>/dev/null || true
  kubectl delete ns "$NS" "$WL" --wait=true --timeout=5m --ignore-not-found
  pkill -f "kubectl -n $NS port-forward" 2>/dev/null || true
}

build_bundle() {
  step "bundle build (signed)"
  local images=() role
  for role in api admission bootstrap toolbox scanner; do images+=(--image "$REG/$role:$TAG"); done
  # CNPG requires the PostgreSQL version in the tag (release.yml tags it 16.14-<version>).
  images+=(--image "$REG/postgres:16.14-$TAG")
  rm -rf "$OUT" && mkdir -p "$OUT"
  "$CTL" bundle build --from-daemon --sign-key "$SIGN_KEY" --chart deploy/charts/constellation \
    --out "$OUT/bundle" --version "$TAG" "${images[@]}" --image docker.io/library/registry:2.8.3
  "$CTL" bundle build --from-daemon --sign-key "$SIGN_KEY" --out "$OUT/target" --version "$TAG" \
    --image docker.io/library/busybox:1.37.0
  step "bundle verify against the embedded vendor key"
  "$CTL" bundle verify "$OUT/bundle"
  step "negative: unsigned and tampered bundles are rejected before load"
  cp -r "$OUT/bundle" "$OUT/unsigned" && rm "$OUT/unsigned/bom.sig"
  if "$CTL" bundle load --containerd --dry-run "$OUT/unsigned" 2>"$OUT/unsigned.err"; then fail "unsigned bundle loaded"; fi
  grep -o 'unsigned bundle' "$OUT/unsigned.err" | head -1
  cp -r "$OUT/bundle" "$OUT/tampered" && echo "# tampered" >> "$OUT/tampered/chart/values.yaml"
  if "$CTL" bundle load --containerd --dry-run "$OUT/tampered" 2>"$OUT/tampered.err"; then fail "tampered bundle loaded"; fi
  grep -o 'payload digest mismatch: chart/values.yaml' "$OUT/tampered.err" | head -1
}

install() {
  step "bundle load into k3s containerd"
  "$CTL" bundle load --containerd --values-out "$OUT/values-bundle.yaml" "$OUT/bundle"
  cat "$OUT/values-bundle.yaml"
  kubectl create ns "$NS" --dry-run=client -o yaml | kubectl apply -f -
  kubectl create ns "$WL" --dry-run=client -o yaml | kubectl apply -f -
  kubectl label ns "$WL" constellation.alphabravo.io/enforce=true --overwrite
  step "cluster-local registry (scan source) inside the denied namespace"
  kubectl -n "$NS" apply -f deploy/e2e/airgap-registry.yaml
  step "helm install from the bundle's chart"
  # CRDs are cluster-scoped: next to an existing install they belong to that release.
  local crds=()
  kubectl get crd constellationresponserules.constellation.alphabravo.io >/dev/null 2>&1 && crds=(--skip-crds)
  helm install "$REL" "$OUT/bundle/chart" -n "$NS" "${crds[@]}" -f "$OUT/values-bundle.yaml" \
    -f deploy/e2e/values-airgap-e2e.yaml --wait --timeout 15m
  kubectl -n "$NS" get pods -o wide
  kubectl -n "$NS" get networkpolicy
}

prove_egress_denied() {
  step "egress denied: scanner pod cannot reach the internet"
  local pod; pod=$(kubectl -n "$NS" get pod -l app.kubernetes.io/component=scanner -o name | head -1)
  if kubectl -n "$NS" exec "$pod" -- timeout 5 bash -c '</dev/tcp/1.1.1.1/443' 2>/dev/null; then fail "scanner reached 1.1.1.1:443"; fi
  echo "scanner -> 1.1.1.1:443 blocked"
  if kubectl -n "$NS" exec "$pod" -- timeout 5 bash -c '</dev/tcp/140.82.112.34/443' 2>/dev/null; then fail "scanner reached github"; fi
  echo "scanner -> github (140.82.112.34:443) blocked"
  kubectl -n "$NS" logs "$pod" | grep -m1 '"egress endpoints"\|egress endpoints' || fail "no egress line"
}

api() { curl -sf -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }

prove_scan() {
  step "push the scan target into the cluster-local registry"
  kubectl -n "$NS" port-forward --address 127.0.0.1 svc/airgap-registry 25000:5000 >/dev/null 2>&1 &
  kubectl -n "$NS" port-forward --address 127.0.0.1 "svc/$REL-constellation-api" 28090:8080 >/dev/null 2>&1 &
  for _ in $(seq 1 30); do curl -sf -o /dev/null 127.0.0.1:25000/v2/ && curl -sf -o /dev/null 127.0.0.1:28090/healthz && break; sleep 1; done
  "$CTL" bundle load --registry 127.0.0.1:25000 --insecure "$OUT/target"
  TOKEN=$(curl -sf -X POST 127.0.0.1:28090/api/v1/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"admin@airgap.test","password":"Airgap-e2e-Passw0rd!"}' | jq -r '.token // .access_token')
  [ -n "$TOKEN" ] && [ "$TOKEN" != null ] || fail "login"
  step "scan an image from the cluster-local registry with baked DBs"
  local ref="airgap-registry.$NS.svc:5000/library/busybox:1.37.0" job status=""
  job=$(api -X POST 127.0.0.1:28090/api/v1/scan-jobs -d "{\"target_type\":\"image\",\"target_ref\":\"$ref\"}" | jq -r .id)
  echo "scan job $job -> $ref"
  for _ in $(seq 1 90); do
    status=$(api "127.0.0.1:28090/api/v1/scan-jobs?limit=50" | jq -r --arg id "$job" '.jobs[]? // .items[]? | select(.id==$id) | .status')
    case "$status" in completed|failed) break ;; esac; sleep 5
  done
  api "127.0.0.1:28090/api/v1/scan-jobs?limit=50" | jq --arg id "$job" '.jobs[]? // .items[]? | select(.id==$id) | {id,status,target_ref,last_error,attempt_count}'
  [ "$status" = completed ] || fail "scan job ended $status"
  api "127.0.0.1:28090/api/v1/image-scan-results?limit=5" | jq -c '.image_scan_results[0] | {image_ref, package_count, finding_count, signature_status, last_scan_job_id}' 
  kubectl -n "$NS" logs deploy/"$REL"-constellation-scanner --tail=200 | grep -iE 'offline|engine_db|scan (complete|completed)|job complete' | tail -5 || true
}

prove_admission() {
  step "admission: enforce image provenance, then create an unsigned pod"
  api -X POST 127.0.0.1:28090/api/v1/policies/admission-profiles:import -d '{"profile_id":"image-provenance-required"}' | jq -c '{imported: (.imported // .policies // .created // .)}' | cut -c1-300
  sleep 20
  local out
  if out=$(kubectl -n "$WL" run unsigned --image=docker.io/library/busybox:1.37.0 --image-pull-policy=Never --restart=Never -- sleep 60 2>&1); then
    kubectl -n "$WL" delete pod unsigned --wait=false >/dev/null 2>&1 || true
    fail "unsigned pod admitted: $out"
  fi
  echo "$out"
  echo "$out" | grep -q 'denied the request' || fail "rejection did not come from the webhook"
  step "admission: digest-pinned but unsigned image is rejected by the signature rule"
  local digest
  digest=$(jq -r '.images[0].digest' "$OUT/target/bom.json")
  if out=$(kubectl -n "$WL" run unsigned-pinned --image="docker.io/library/busybox@$digest" --image-pull-policy=Never --restart=Never -- sleep 60 2>&1); then
    kubectl -n "$WL" delete pod unsigned-pinned --wait=false >/dev/null 2>&1 || true
    fail "digest-pinned unsigned pod admitted: $out"
  fi
  echo "$out"
  echo "$out" | grep -qi 'signature\|image-signed' || fail "digest-pinned pod not rejected by the signature rule"
}

case "${1:-run}" in
  cleanup) cleanup ;;
  prove) trap 'pkill -f "kubectl -n $NS port-forward" 2>/dev/null || true' EXIT
         prove_egress_denied; prove_scan; prove_admission; step "air-gap e2e (prove): PASS" ;;
  run) trap 'pkill -f "kubectl -n $NS port-forward" 2>/dev/null || true' EXIT
       build_bundle; install; prove_egress_denied; prove_scan; prove_admission
       [ "${KEEP:-0}" = 1 ] || cleanup; step "air-gap e2e: PASS" ;;
  *) echo "usage: $0 [run|prove|cleanup]" >&2; exit 2 ;;
esac
