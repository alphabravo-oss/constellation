#!/usr/bin/env bash
# Render wiring and use actual PromQL evaluation for storage alert acceptance.
set -euo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
chart=deploy/charts/constellation
helm template constellation "$chart" --namespace storage-tests > "$work/default.yaml"
helm template constellation "$chart" --namespace storage-tests \
  --set metrics.prometheusRule.enabled=true --set metrics.storageDashboard.enabled=true > "$work/enabled.yaml"
helm template constellation "$chart" --namespace storage-tests \
  --set metrics.prometheusRule.enabled=true --set metrics.prometheusRule.storage.enabled=false > "$work/disabled.yaml"
helm template constellation "$chart" --namespace storage-tests \
  --set metrics.prometheusRule.enabled=true --set api.enabled=false > "$work/no-api.yaml"
for setting in databaseBytes=0 deadRowRatio=1; do
  if helm template constellation "$chart" --set metrics.prometheusRule.enabled=true \
    --set "metrics.prometheusRule.storage.$setting" > /dev/null 2> "$work/error"; then
    echo "accepted invalid storage threshold $setting" >&2
    exit 1
  fi
  grep -q 'metrics.prometheusRule.storage' "$work/error"
done
cat > "$work/archive.yaml" <<'YAML'
api:
  env:
    CONSTELLATION_STORAGE_K8S_AUDIT_SOURCES: '11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222'
    CONSTELLATION_STORAGE_K8S_AUDIT_MAX_GAP: '30m'
auditArchiver:
  enabled: true
  bucket: evidence
  prefix: /private/audit/
  sign: { keySecretName: signing }
  env:
    - name: AWS_ENDPOINT_URL
      value: https://generic.example
    - name: AWS_ENDPOINT_URL_S3
      valueFrom:
        secretKeyRef: { name: archive-endpoint, key: endpoint }
YAML
helm template constellation "$chart" --namespace storage-tests -f "$work/archive.yaml" > "$work/archive-secret.yaml"
helm template constellation "$chart" --namespace storage-tests -f "$work/archive.yaml" \
  --set auditArchiver.endpoint=https://explicit.example > "$work/archive-explicit.yaml"
python3 scripts/test-storage-monitoring.py "$work"
if [[ -n "${PROMTOOL:-}" ]]; then
  "$PROMTOOL" check rules "$work/rules.yaml" "$work/dashboard-rules.yaml"
  "$PROMTOOL" test rules "$work/tests.yaml"
elif command -v promtool > /dev/null; then
  promtool check rules "$work/rules.yaml" "$work/dashboard-rules.yaml"
  promtool test rules "$work/tests.yaml"
else
  # The existing dev stack pins this release; never pull during an air-gap test.
  image=prom/prometheus:v3.15.0@sha256:efd719c99d83b060d9daefdcf00360461adf279f45ef5391f8d111892118753e
  if ! docker image inspect "$image" > /dev/null 2>&1; then
    echo 'promtool is required: set PROMTOOL or preload the pinned dev Prometheus image' >&2
    exit 1
  fi
  docker run --rm --network none --user "$(id -u):$(id -g)" --entrypoint /bin/promtool \
    -v "$work:$work:ro" "$image" check rules "$work/rules.yaml" "$work/dashboard-rules.yaml"
  docker run --rm --network none --user "$(id -u):$(id -g)" --entrypoint /bin/promtool \
    -v "$work:$work:ro" "$image" test rules "$work/tests.yaml"
fi

if [[ -n "${STORAGE_MONITORING_EVIDENCE_DIR:-}" ]]; then
  mkdir -p "$STORAGE_MONITORING_EVIDENCE_DIR"
  cp "$work"/*.yaml "$STORAGE_MONITORING_EVIDENCE_DIR/"
fi
