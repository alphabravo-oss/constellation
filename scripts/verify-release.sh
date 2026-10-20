#!/usr/bin/env bash
# Release contract. Source mode: every version surface matches the tag, the chart
# lints/renders, and every first-party image the chart renders is built by
# release.yml. VERIFY_PUBLISHED=1: the published chart's rendered images exist,
# are cosign-signed by the release workflow and carry source-bound SLSA provenance.
#
# Pre-release tags (v0.3.0-rc.1) are cut from a tree whose surfaces say 0.3.0;
# release.yml packages the chart with --version/--app-version set to the full
# tag so the published chart renders exactly the image tags it pushed.
set -euo pipefail

release_tag="${1:-}"
if [[ ! "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
  echo "release version must be a v-prefixed semantic tag (for example v0.3.0)" >&2
  exit 1
fi
release_version="${release_tag#v}"
base_version="${release_version%%[-+]*}"
chart_dir="deploy/charts/constellation"

chart_version="$(awk '$1 == "version:" { print $2; exit }' "$chart_dir/Chart.yaml")"
app_version="$(awk '$1 == "appVersion:" { gsub(/"/, "", $2); print $2; exit }' "$chart_dir/Chart.yaml")"
frontend_version="$(sed -n 's/^[[:space:]]*"version": "\([^"]*\)",/\1/p' frontend/package.json | head -1)"
openapi_version="$(sed -n 's/^[[:space:]]*"version": "\([^"]*\)",/\1/p' internal/handler/openapi.json | head -1)"

for surface in "$chart_version" "$app_version" "$frontend_version" "$openapi_version"; do
  if [[ "$surface" != "$release_version" && "$surface" != "$base_version" ]]; then
    echo "release surface mismatch: expected $release_version (or $base_version), got $surface" >&2
    exit 1
  fi
done
if ! grep -qE "^## \[?${base_version//./\\.}\]? - [0-9]{4}-[0-9]{2}-[0-9]{2}" CHANGELOG.md; then
  echo "CHANGELOG.md has no '## ${base_version} - <date>' section" >&2
  exit 1
fi

helm lint "$chart_dir"
helm template constellation "$chart_dir" --kube-version 1.35.0 >/dev/null
helm template constellation "$chart_dir" --kube-version 1.35.0 \
  -f "$chart_dir/examples/values-k3s-ha.yaml" >/dev/null

# Every role the chart can render must be a release.yml matrix role.
roles=()
while read -r ref; do
  role="${ref#*/constellation/}"
  role="${role%%[:@]*}"
  roles+=("$role")
  if ! grep -qE "role: ${role}," .github/workflows/release.yml; then
    echo "chart renders $ref but release.yml does not build role $role" >&2
    exit 1
  fi
done < <(CHECK_IMAGES_LIST_ONLY=1 scripts/check-chart-images.sh "$chart_dir")

if [[ "${VERIFY_PUBLISHED:-0}" != "1" ]]; then
  echo "release-check: source and Helm contracts passed for $release_tag (roles: ${roles[*]})"
  echo "set VERIFY_PUBLISHED=1 after publishing to verify images, signatures and SLSA provenance"
  exit 0
fi

command -v cosign >/dev/null
[[ -n "${COSIGN_KEY:-}" ]] || command -v gh >/dev/null
registry="${REGISTRY:-ghcr.io/alphabravo-oss/constellation}"
chart_ref="${CHART_REF:-oci://ghcr.io/alphabravo-oss/charts/constellation}"
identity="${COSIGN_IDENTITY_REGEXP:-^https://github.com/alphabravo-oss/constellation/\.github/workflows/.*@refs/tags/${release_tag}$}"
issuer="${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
helm pull "$chart_ref" --version "$release_version" --destination "$work"
published_chart="$work/constellation-${release_version}.tgz"
verify_sig() {
  if [[ -n "${COSIGN_KEY:-}" ]]; then
    cosign verify --key "$COSIGN_KEY" --insecure-ignore-tlog=true "$1" >/dev/null 2>&1
  else
    cosign verify "$1" --certificate-identity-regexp "$identity" --certificate-oidc-issuer "$issuer" >/dev/null
  fi
}
verify_sig "${chart_ref#oci://}:${release_version}"
scripts/check-chart-images.sh "$published_chart"

mapfile -t refs < <(CHECK_IMAGES_LIST_ONLY=1 scripts/check-chart-images.sh "$published_chart")
refs+=("$registry/kube-bench-runner:$release_tag")
for ref in "${refs[@]}"; do
  verify_sig "$ref"
  if [[ -n "${COSIGN_KEY:-}" ]]; then
    docker buildx imagetools inspect "$ref" --format '{{json .Provenance}}' \
      | grep -q 'github.com/alphabravo-oss/constellation'
  else
    # actions/attest-build-provenance stores a Sigstore bundle as an OCI referrer;
    # gh verifies it is SLSA provenance from this repository's release workflow.
    gh attestation verify "oci://$ref" --repo alphabravo-oss/constellation \
      --signer-workflow alphabravo-oss/constellation/.github/workflows/release.yml >/dev/null
  fi
  echo "verified $ref"
done
scripts/check-image-go.sh "${refs[@]}"

echo "release-check: published chart, images, signatures and source-bound SLSA provenance passed for $release_tag"
