#!/usr/bin/env bash
# Rebuild the CloudNativePG operator and the Barman Cloud plugin + sidecar from
# their verified upstream tag commits on the repository Go toolchain (go.mod,
# golang:<go>-bookworm pinned by digest, GOTOOLCHAIN=local). Upstream images are
# built with Go < 1.27.3, which accepts the compromised eMudhra intermediate
# chain. Each image is pushed, gated (cmd/tools/release-gate), checked with
# scripts/check-image-go.sh, cosign-signed and recorded in deploy/cnpg/images.env.
#
# Usage: COSIGN_KEY=cosign.key COSIGN_PASSWORD=... deploy/cnpg/build-images.sh [operator|plugin|sidecar]...
set -euo pipefail
cd "$(dirname "$0")/../.."
REG="${REGISTRY:-ghcr.io/alphabravo-oss/constellation}"
GO_VERSION="$(awk '/^go /{print $2}' go.mod)"
GO_IMAGE="golang:${GO_VERSION}-bookworm@$(sed -n 's/^ARG GO_IMAGE_DIGEST=//p' deploy/docker/Dockerfile.api)"
DISTROLESS="$(grep -oE 'gcr.io/distroless/static-debian13:nonroot@sha256:[a-f0-9]{64}' deploy/docker/Dockerfile.api | head -1)"
CNPG_VERSION=1.30.1   CNPG_COMMIT=2a35abb4628f209d149825ef3c38011e0701ff2f
PLUGIN_VERSION=0.15.1 PLUGIN_COMMIT=6216b7dd552f389952d3de77712d9522a79d9548
# Reviewed dependency bumps applied on top of the tag (release gate: no fixable
# critical/high); keep in step with deploy/docker/go-tools/go.mod.
BUMPS="golang.org/x/net@v0.61.0 golang.org/x/crypto@v0.58.0"
WORK="${WORK:-$(mktemp -d)}"
OUT="${OUT:-$WORK/out}"
mkdir -p "$OUT"
: "${COSIGN_KEY:?cosign private key}"

clone() { # url tag commit dir
  [ -d "$4/.git" ] || git clone -q --depth 1 --branch "$2" "$1" "$4"
  [ "$(git -C "$4" rev-parse HEAD)" = "$3" ] || { echo "$1 $2 is not $3" >&2; exit 1; }
}

bump() { # dir
  # shellcheck disable=SC2086
  docker run --rm -v "$1:/src" -w /src -e GOTOOLCHAIN=local -e GOFLAGS=-mod=mod "$GO_IMAGE" \
    sh -c "go get $BUMPS && go mod tidy" > "$OUT/bump-$(basename "$1").log" 2>&1
  git -C "$1" diff --stat -- go.mod go.sum
}

publish() { # name tag build-args...
  local name=$1 tag=$2; shift 2
  local ref="$REG/$name:$tag"
  docker buildx build --platform linux/amd64 --provenance=mode=max --sbom=true \
    --metadata-file "$OUT/$name.meta.json" -t "$ref" --push "$@" > "$OUT/$name.build.log" 2>&1
  local digest img
  digest="$(jq -r '."containerimage.digest"' "$OUT/$name.meta.json")"
  img="$REG/$name@$digest"
  go run ./cmd/tools/release-gate gate --image "$img" --report "$OUT/$name.scan.json" --receipt "$OUT/$name.gate.json"
  scripts/check-image-go.sh "$img"
  cosign sign --yes --key "$COSIGN_KEY" --use-signing-config=false --tlog-upload=false "$img" > "$OUT/$name.sign.log" 2>&1
  printf '%s=%s\n' "$(tr a-z- A-Z_ <<<"$name")_IMAGE" "$ref@$digest" >> "$OUT/images.env"
  echo "published $ref@$digest"
}

build_operator() {
  local src="$WORK/cloudnative-pg"
  clone https://github.com/cloudnative-pg/cloudnative-pg "v$CNPG_VERSION" "$CNPG_COMMIT" "$src"
  bump "$src"
  mkdir -p "$src/dist/manager"
  docker run --rm -v "$src:/src" -w /src -e CGO_ENABLED=0 -e GOTOOLCHAIN=local -e GOFLAGS=-trimpath "$GO_IMAGE" \
    go build -ldflags "-s -w -X github.com/cloudnative-pg/cloudnative-pg/pkg/versions.buildVersion=$CNPG_VERSION -X github.com/cloudnative-pg/cloudnative-pg/pkg/versions.buildCommit=${CNPG_COMMIT:0:9}" \
    -o dist/manager/manager_amd64 ./cmd/manager
  publish cnpg-operator "$CNPG_VERSION-go$GO_VERSION" --build-arg BASE="$DISTROLESS" -f "$src/Dockerfile" "$src"
}

build_plugin_image() { # plugin|sidecar
  local src="$WORK/plugin-barman-cloud"
  clone https://github.com/cloudnative-pg/plugin-barman-cloud "v$PLUGIN_VERSION" "$PLUGIN_COMMIT" "$src"
  [ -n "$(git -C "$src" status --porcelain go.mod)" ] || bump "$src"
  publish "barman-$1" "$PLUGIN_VERSION-go$GO_VERSION" --build-arg GO_VERSION="${GO_IMAGE#golang:}" \
    -f "$src/containers/Dockerfile.$1" "$src"
}

targets=("$@"); [ ${#targets[@]} -gt 0 ] || targets=(operator plugin sidecar)
for t in "${targets[@]}"; do
  case $t in
    operator) build_operator ;;
    plugin|sidecar) build_plugin_image "$t" ;;
    *) echo "unknown target $t" >&2; exit 2 ;;
  esac
done
cat "$OUT/images.env"
