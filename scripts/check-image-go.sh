#!/usr/bin/env bash
# Every Go binary inside every release image must be built with go >= MIN_GO
# (eMudhra intermediate-CA compromise: go1.27.2 accepts the chain, go1.27.3 rejects it).
# Usage: scripts/check-image-go.sh <image-ref>...    MIN_GO (default 1.27.3)
set -euo pipefail
min="${MIN_GO:-1.27.3}"
command -v go >/dev/null
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }
fail=0
for ref in "$@"; do
  work="$(mktemp -d)"
  cid="$(docker create --platform linux/amd64 "$ref" /bin/true 2>/dev/null || docker create --platform linux/amd64 --entrypoint /bin/true "$ref")"
  docker export "$cid" | tar -x -C "$work" --exclude='dev/*' --exclude='proc/*' 2>/dev/null || true
  docker rm "$cid" >/dev/null
  while IFS= read -r bin; do
    line="$(go version "$bin" 2>/dev/null)" || continue
    case "$line" in *": go"[0-9]*) ;; *) continue ;; esac
    gv="${line##*: go}"; gv="${gv%% *}"; gv="${gv%%-*}"; gv="${gv%%+*}"
    status=ok
    if ! ver_ge "$gv" "$min"; then status=FAIL; fail=1; fi
    printf '%-4s %-62s %-44s go%s\n' "$status" "${ref##*/}" "${bin#"$work"}" "$gv"
  done < <(find "$work" -type f -perm -u+x -size +500k 2>/dev/null)
  rm -rf "$work"
done
if [ "$fail" -ne 0 ]; then echo "check-image-go: binaries older than go$min found" >&2; exit 1; fi
echo "check-image-go: every Go binary is built with go >= $min"
