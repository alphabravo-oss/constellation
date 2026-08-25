#!/usr/bin/env bash
set -euo pipefail

release_tag="${1:-}"
if [[ ! "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
  echo "release version must be a v-prefixed semantic tag (for example v0.2.0)" >&2
  exit 1
fi
release_version="${release_tag#v}"
chart_dir="deploy/charts/constellation"

chart_version="$(awk '$1 == "version:" { print $2; exit }' "$chart_dir/Chart.yaml")"
app_version="$(awk '$1 == "appVersion:" { gsub(/"/, "", $2); print $2; exit }' "$chart_dir/Chart.yaml")"
frontend_version="$(sed -n 's/^[[:space:]]*"version": "\([^"]*\)",/\1/p' frontend/package.json | head -1)"
openapi_version="$(sed -n 's/^[[:space:]]*"version": "\([^"]*\)",/\1/p' internal/handler/openapi.json | head -1)"

for surface in "$chart_version" "$app_version" "$frontend_version" "$openapi_version"; do
  if [[ "$surface" != "$release_version" ]]; then
    echo "release surface mismatch: expected $release_version, got $surface" >&2
    exit 1
  fi
done

helm lint "$chart_dir"
helm template constellation "$chart_dir" --kube-version 1.35.0 >/dev/null
helm template constellation "$chart_dir" --kube-version 1.35.0 \
  -f "$chart_dir/examples/values-k3s-ha.yaml" >/dev/null

if [[ "${VERIFY_PUBLISHED:-0}" != "1" ]]; then
  echo "release-check: source and Helm contracts passed for $release_tag"
  echo "set VERIFY_PUBLISHED=1 after publishing to verify signatures and SLSA provenance"
  exit 0
fi

command -v cosign >/dev/null
command -v jq >/dev/null
registry="${REGISTRY:-ghcr.io/alphabravo-oss/constellation}"
identity="${COSIGN_IDENTITY_REGEXP:-^https://github.com/alphabravo-oss/constellation/\.github/workflows/.*@refs/tags/${release_tag}$}"
issuer="${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
roles=(api scanner operator discoverer audit-archiver frontend runtime-agent admission migrate bootstrap postgres)

for role in "${roles[@]}"; do
  ref="$registry/$role:$release_tag"
  cosign verify "$ref" \
    --certificate-identity-regexp "$identity" \
    --certificate-oidc-issuer "$issuer" >/dev/null
  attestations="$(cosign verify-attestation "$ref" \
    --type slsaprovenance \
    --certificate-identity-regexp "$identity" \
    --certificate-oidc-issuer "$issuer")"
  jq -e --arg repository "https://github.com/alphabravo-oss/constellation" '
    map(.payload | @base64d | fromjson
      | ((.predicate.materials // []) +
         (.predicate.buildDefinition.resolvedDependencies // [])))
    | flatten
    | any(.uri | contains($repository))
  ' <<<"$attestations" >/dev/null
done

echo "release-check: signatures and source-bound SLSA provenance passed for $release_tag"
