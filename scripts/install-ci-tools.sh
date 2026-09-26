#!/usr/bin/env bash
set -euo pipefail

bin_dir="${CI_TOOLS_BIN:-${HOME}/.local/bin}"
mkdir -p "$bin_dir"
bin_dir="$(cd "$bin_dir" && pwd)"
export GOBIN="$bin_dir"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT

install_archive() {
  local repository="$1" version="$2" archive="$3" checksums="$4" executable="$5"
  local destination="$temporary/$executable"
  mkdir -p "$destination"
  curl --fail --silent --show-error --location --retry 3 \
    "https://github.com/$repository/releases/download/$version/$archive" -o "$destination/$archive"
  curl --fail --silent --show-error --location --retry 3 \
    "https://github.com/$repository/releases/download/$version/$checksums" -o "$destination/checksums"
  (cd "$destination"; grep -E "[ *]${archive//./\\.}$" checksums | sha256sum --check --strict -)
  tar -xzf "$destination/$archive" -C "$destination"
  local binary
  binary="$(find "$destination" -type f -name "$executable" -print -quit)"
  test -n "$binary"
  install -m 0755 "$binary" "$bin_dir/$executable"
}

if [[ "$#" == 0 ]]; then
  set -- golangci-lint gosec govulncheck gitleaks gotestsum goose actionlint shellcheck
fi
for tool in "$@"; do
  case "$tool" in
    golangci-lint|gitleaks|shellcheck)
      if [[ "$(uname -s)/$(uname -m)" != Linux/x86_64 ]]; then
        echo "Archive installer requires Linux/x86_64; install the documented pins manually." >&2
        exit 1
      fi
      ;;
  esac
  case "$tool" in
    golangci-lint)
      install_archive golangci/golangci-lint v2.11.4 golangci-lint-2.11.4-linux-amd64.tar.gz golangci-lint-2.11.4-checksums.txt golangci-lint
      ;;
    gitleaks)
      install_archive gitleaks/gitleaks v8.30.0 gitleaks_8.30.0_linux_x64.tar.gz gitleaks_8.30.0_checksums.txt gitleaks
      ;;
    shellcheck)
      curl --fail --silent --show-error --location --retry 3 \
        https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.linux.x86_64.tar.xz \
        -o "$temporary/shellcheck.tar.xz"
      printf '%s  %s\n' 8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198 "$temporary/shellcheck.tar.xz" | sha256sum --check --strict -
      tar -xJf "$temporary/shellcheck.tar.xz" -C "$temporary"
      install -m 0755 "$temporary/shellcheck-v0.11.0/shellcheck" "$bin_dir/shellcheck"
      ;;
    gosec) go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0 ;;
    govulncheck) go install golang.org/x/vuln/cmd/govulncheck@v1.8.0 ;;
    gotestsum) go install gotest.tools/gotestsum@v1.13.0 ;;
    goose) go install github.com/pressly/goose/v3/cmd/goose@v3.27.1 ;;
    actionlint) go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.11 ;;
    *) echo "Unknown CI tool: $tool" >&2; exit 2 ;;
  esac
done
if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$bin_dir" >> "$GITHUB_PATH"
fi
printf 'Tools installed in %s; add this directory to PATH for local runs.\n' "$bin_dir"
