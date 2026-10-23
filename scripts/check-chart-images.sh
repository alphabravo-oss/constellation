#!/usr/bin/env bash
# Image-tag contract: render the chart with every first-party role switched on
# and prove that each image it would pull exists in the registry. This is the
# check that would have caught the 0.2.0 chart rendering `api:0.2.0` while the
# release pipeline pushed `api:v0.2.0`.
#
# Usage: scripts/check-chart-images.sh <chart dir | .tgz | oci://ref> [extra helm template args...]
#   CHECK_IMAGES_LIST_ONLY=1  print the rendered refs, do not query the registry
#   REGISTRY                  first-party registry prefix (default ghcr.io/alphabravo-oss/constellation)
set -euo pipefail

chart="${1:?usage: check-chart-images.sh <chart dir|.tgz|oci://ref> [helm template args...]}"
shift
registry="${REGISTRY:-ghcr.io/alphabravo-oss/constellation}"

# Every optional role that renders a first-party image from the chart default
# (kube-bench-runner is excluded: the chart requires an explicit repository).
profile=(
  --set auditArchiver.enabled=true --set auditArchiver.bucket=contract-check --set auditArchiver.sign.keySecretName=contract-signing
  --set complianceScheduler.enabled=true
  --set complianceScheduler.storage.existingClaim=contract-check
  --set complianceScheduler.signingSecret=contract-check
  --set backup.objectStore.enabled=true
  --set backup.offhost.enabled=true --set backup.offhost.endpointURL=http://offhost.invalid:9000
  --set backup.offhost.credentialsSecret=contract-check
  --set backup.secrets.enabled=true --set backup.secrets.ageRecipient=age1contractcheck
  --set backup.secrets.remote.endpointURL=http://offhost.invalid:9000
  --set backup.secrets.remote.credentialsSecret=contract-check
  --set postgres.cloudnativepg.enabled=true
)

rendered="$(helm template constellation "$chart" "${profile[@]}" "$@")"
pattern="${registry//./\\.}/[a-z0-9-]+[:@][A-Za-z0-9_.:+-]+"
refs="$(grep -oE "$pattern" <<<"$rendered" | sort -u || true)"
if [[ -z "$refs" ]]; then
  echo "check-chart-images: no $registry images rendered" >&2
  exit 1
fi

if [[ "${CHECK_IMAGES_LIST_ONLY:-0}" == "1" ]]; then
  printf '%s\n' "$refs"
  exit 0
fi

missing=0
while read -r ref; do
  if docker buildx imagetools inspect "$ref" >/dev/null 2>&1; then
    echo "ok       $ref"
  else
    echo "MISSING  $ref" >&2
    missing=$((missing + 1))
  fi
done <<<"$refs"

if ((missing > 0)); then
  echo "check-chart-images: $missing rendered image(s) do not exist in the registry" >&2
  exit 1
fi
echo "check-chart-images: every rendered first-party image exists"
