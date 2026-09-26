#!/usr/bin/env bash
set -euo pipefail

chart="deploy/charts/constellation"
profile="$chart/examples/values-k3s-ha.yaml"
rendered="$(mktemp)"
error_output="$(mktemp)"
trap 'rm -f "$rendered" "$error_output"' EXIT

helm template constellation "$chart" --kube-version 1.35.0 -f "$profile" >"$rendered"

[[ "$(grep -c '^kind: PodDisruptionBudget$' "$rendered")" -eq 8 ]]
[[ "$(grep -c '^[[:space:]]*matchLabelKeys:$' "$rendered")" -eq 7 ]]
grep -q '^kind: HTTPRoute$' "$rendered"
grep -q 'sectionName: constellation-https' "$rendered"
grep -q 'constellation.dev.alphabravo.io' "$rendered"
grep -q '^kind: Cluster$' "$rendered"
grep -q 'instances: 3' "$rendered"
grep -q 'storageClass: longhorn' "$rendered"
grep -q 'imageName: ghcr.io/alphabravo-oss/constellation/postgres:16.10-v0.2.0' "$rendered"
grep -q 'CREATE EXTENSION IF NOT EXISTS vector' "$rendered"
grep -q 'port: 8000' "$rendered"
grep -q 'name: constellation-migrate-1' "$rendered"
grep -q 'name: wait-for-migrations' "$rendered"
grep -q 'name: constellation-bootstrap-1' "$rendered"
grep -A5 'name: CONSTELLATION_SCANNER_TOKEN$' "$rendered" | grep -q 'secretKeyRef:'
if grep -A8 'name: CONSTELLATION_SCANNER_TOKEN$' "$rendered" | grep -q 'optional: true'; then
  echo "scanner token must block startup until bootstrap creates the Secret" >&2
  exit 1
fi
if grep -Eqi 'vulndb|constellation-vulndb' "$rendered"; then
  echo "removed VulnDB subsystem unexpectedly rendered" >&2
  exit 1
fi
grep -A2 'name: BOOTSTRAP_FORCE_PASSWORD_CHANGE' "$rendered" | grep -q 'value: "false"'
helm template constellation "$chart" --kube-version 1.35.0 -f "$profile" \
  --set bootstrap.admin.forcePasswordChange=true >"$rendered"
grep -A2 'name: BOOTSTRAP_FORCE_PASSWORD_CHANGE' "$rendered" | grep -q 'value: "true"'
grep -A12 'app.kubernetes.io/component: network-policy-applier' "$rendered" | grep -q 'port: 5432'
# HA API replicas must reach the Lease API or none of the leader-only passive
# workers (including network-flow rollups) will start.
api_policy="$(sed -n '/name: constellation-api-egress$/,/^---$/p' "$rendered")"
grep -q 'port: 443' <<<"$api_policy"
grep -q 'port: 6443' <<<"$api_policy"

if helm template constellation "$chart" --set highAvailability.enabled=true >"$error_output" 2>&1; then
  echo "unsafe HA values unexpectedly rendered" >&2
  exit 1
fi
grep -q 'requires postgres.mode=cnpg or postgres.mode=external' "$error_output"

if helm template constellation "$chart" --set gateway.enabled=true --set ingress.enabled=true >"$error_output" 2>&1; then
  echo "simultaneous Gateway and Ingress unexpectedly rendered" >&2
  exit 1
fi
grep -q 'enable only one of gateway.enabled or ingress.enabled' "$error_output"

echo "helm-ha: ok"
