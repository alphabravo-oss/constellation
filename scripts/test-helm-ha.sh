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
grep -q 'port: 8000' "$rendered"

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
