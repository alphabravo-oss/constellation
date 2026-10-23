#!/usr/bin/env bash
set -euo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
chart=deploy/charts/constellation
helm template constellation "$chart" --namespace cache-tests > "$work/default.yaml"
helm template constellation "$chart" --namespace cache-tests \
  --set metrics.prometheusRule.enabled=true --set metrics.serviceMonitor.enabled=true > "$work/enabled.yaml"
helm template constellation "$chart" --namespace cache-tests \
  --set metrics.prometheusRule.enabled=true --set metrics.prometheusRule.scannerCache.enabled=false > "$work/disabled.yaml"
helm template constellation "$chart" --namespace cache-tests \
  --set metrics.prometheusRule.enabled=true --set scanner.enabled=false > "$work/no-scanner.yaml"
helm template constellation "$chart" --namespace cache-tests \
  --set metrics.prometheusRule.enabled=true --set metrics.prometheusRule.namespace=monitoring > "$work/other-namespace.yaml"
for setting in availableBytes=0 availableRatio=1 freeInodeRatio=-1; do
  if helm template constellation "$chart" --set metrics.prometheusRule.enabled=true \
    --set "metrics.prometheusRule.scannerCache.$setting" > /dev/null 2> "$work/error"; then
    echo "accepted invalid scanner-cache threshold $setting" >&2
    exit 1
  fi
  grep -q 'metrics.prometheusRule.scannerCache' "$work/error"
done
python3 scripts/test-scanner-cache-monitoring.py "$work"
if [[ -n "${PROMTOOL:-}" ]]; then
  "$PROMTOOL" check rules "$work/rules.yaml"
  "$PROMTOOL" test rules "$work/tests.yaml"
elif command -v promtool > /dev/null; then
  promtool check rules "$work/rules.yaml"
  promtool test rules "$work/tests.yaml"
else
  image=prom/prometheus:v3.15.0@sha256:efd719c99d83b060d9daefdcf00360461adf279f45ef5391f8d111892118753e
  if ! docker image inspect "$image" > /dev/null 2>&1; then
    echo 'Set PROMTOOL or preload the pinned dev Prometheus image' >&2
    exit 1
  fi
  docker run --rm --network none --user "$(id -u):$(id -g)" --entrypoint /bin/promtool \
    -v "$work:$work:ro" "$image" check rules "$work/rules.yaml"
  docker run --rm --network none --user "$(id -u):$(id -g)" --entrypoint /bin/promtool \
    -v "$work:$work:ro" "$image" test rules "$work/tests.yaml"
fi
if [[ -n "${SCANNER_CACHE_MONITORING_EVIDENCE_DIR:-}" ]]; then
  mkdir -p "$SCANNER_CACHE_MONITORING_EVIDENCE_DIR"
  cp "$work"/*.yaml "$SCANNER_CACHE_MONITORING_EVIDENCE_DIR/"
fi
