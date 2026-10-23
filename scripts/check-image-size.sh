#!/usr/bin/env bash
# Enforce compressed linux/amd64 registry layer bytes, before promotion/signing.
set -euo pipefail
role="${1:?usage: check-image-size.sh ROLE IMAGE}"
ref="${2:?usage: check-image-size.sh ROLE IMAGE}"
budgets="$(dirname "$0")/image-size-budgets.json"
limit="$(jq -er --arg role "$role" '.[$role].bytes' "$budgets")"
manifest="$(docker buildx imagetools inspect --raw "$ref")"
if jq -e '.manifests' >/dev/null <<< "$manifest"; then
  digest="$(jq -er '.manifests[] | select(.platform.os=="linux" and .platform.architecture=="amd64") | .digest' <<< "$manifest")"
  repository="${ref%@*}"
  if [[ "${repository##*/}" == *:* ]]; then repository="${repository%:*}"; fi
  manifest="$(docker buildx imagetools inspect --raw "$repository@$digest")"
fi
size="$(jq -er '[.layers[].size] | add' <<< "$manifest")"
printf '%s: %s compressed bytes / %s budget\n' "$role" "$size" "$limit"
if (( size > limit )); then
  echo "Image exceeds its release budget; review tools/layers before changing the documented exception." >&2
  exit 1
fi
