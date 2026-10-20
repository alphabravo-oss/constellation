#!/usr/bin/env bash
# sync-neuvector.sh — refresh third_party/neuvector/ from upstream (ADR 0003).
# Procedure and rationale: third_party/neuvector/README.md ("Re-vendoring").
#   --diff                report drift of the vendored tree vs NOTICE's rev + local-patches/
#   --sync --rev <ref>    re-vendor <ref>: capture drift as a patch, apply local-patches/,
#                         gate on a build, restore the previous tree on any failure
#   --remote <url>        upstream repo (default github.com/neuvector/neuvector)
#   --upstream <path>     use a local checkout instead of the clone cache
#   --build image|dp|skip build gate (default dp)
# Exit: 0 ok, 1 usage, 2 drift (--diff), 3 patch failure, 4 build failure, 5 other.
set -euo pipefail
export LC_ALL=C
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR_DIR="${REPO_ROOT}/third_party/neuvector"
NOTICE_FILE="${VENDOR_DIR}/NOTICE"
LOCAL_PATCHES_DIR="${VENDOR_DIR}/local-patches"
mode="" rev="" remote="https://github.com/neuvector/neuvector.git" upstream="" build="dp"

die()  { echo "sync-neuvector: $1" >&2; exit "${2:-5}"; }
log()  { echo "sync-neuvector: $*" >&2; }
need() { command -v "$1" >/dev/null || die "missing required tool: $1" 1; }
usage() { sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while (( $# )); do
  case "$1" in
    --diff) mode="diff"; shift ;;
    --sync) mode="sync"; shift ;;
    --rev) rev="$2"; shift 2 ;;
    --remote) remote="$2"; shift 2 ;;
    --upstream) upstream="$2"; shift 2 ;;
    --build) build="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) die "unknown flag: $1" 1 ;;
  esac
done
[[ -n "${mode}" ]] || die "must specify --diff or --sync (try --help)" 1
for tool in git rsync diff sed patch; do need "$tool"; done

# NOTICE's "Source rev:" line is the source of truth for the vendored revision.
notice_rev() { awk '/^Source rev:/ { print $3 }' "${NOTICE_FILE}"; }

# fetch_upstream <rev>: path of an upstream checkout at <rev> (--upstream or the clone cache).
fetch_upstream() {
  local target_rev="$1" dir="${upstream}"
  if [[ -n "${dir}" ]]; then
    [[ -d "${dir}/.git" ]] || die "--upstream path is not a git repo: ${dir}" 1
    if [[ -n "${target_rev}" ]]; then
      git -C "${dir}" rev-parse --verify "${target_rev}^{commit}" >/dev/null || die "rev ${target_rev} not found in ${dir}" 1
    fi
  else
    dir="${TMPDIR:-/tmp}/constellation-neuvector-cache"
    if [[ -d "${dir}/.git" ]]; then
      log "refreshing ${dir}"; git -C "${dir}" fetch --quiet --tags origin
    else
      log "cloning ${remote} → ${dir} (one-time, ~200MB)"; git clone --quiet "${remote}" "${dir}"
    fi
  fi
  [[ -z "${target_rev}" ]] || git -C "${dir}" checkout --quiet "${target_rev}"
  echo "${dir}"
}

# vendor_one <src> <dst>: rsync one tree, dropping build artefacts.
vendor_one() {
  rsync -a --delete --exclude='.objs/' --exclude='.deps/' --exclude='*.o' --exclude='*.d' \
    --exclude='compile_commands.json' "$1" "$2"
}

# apply_local_patches [dir]: apply local-patches/*.patch in lexical order; abort on the first failure.
apply_local_patches() {
  [[ -d "${LOCAL_PATCHES_DIR}" ]] || return 0
  local destination="${1:-${VENDOR_DIR}}" applied=0 p
  for p in "${LOCAL_PATCHES_DIR}"/*.patch; do
    [[ -e "${p}" ]] || continue
    log "applying local patch: $(basename "${p}")"
    ( cd "${destination}" && patch -p1 --batch --forward --fuzz=0 --no-backup-if-mismatch --silent < "${p}" ) \
      || die "patch failed to apply: $(basename "${p}")" 3
    applied=$((applied + 1))
  done
  log "applied ${applied} local patch(es)"
}

# compute_drift <rev> <upstream>: unified diff (patch -p1 paths) of the vendored tree vs
# upstream@<rev> plus declared patches. Empty output = no undeclared drift.
compute_drift() (
  local recorded="$1" upstream_dir="$2" tmp compare_status=0
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/constellation-neuvector-clean.${recorded:0:12}.XXXXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "${tmp}/a/dp" "${tmp}/b"
  vendor_one "${upstream_dir}/dp/" "${tmp}/a/dp/"
  cp "${upstream_dir}/base.h" "${upstream_dir}/defs.h" "${tmp}/a/"
  apply_local_patches "${tmp}/a"
  vendor_one "${VENDOR_DIR}/" "${tmp}/b/"
  ( cd "${tmp}" && diff -ruN --exclude='local-patches' --exclude='LICENSE' --exclude='NOTICE' \
      --exclude='README.md' --exclude='.objs' --exclude='.deps' --exclude='*.o' --exclude='*.d' \
      --exclude='compile_commands.json' a b ) || compare_status=$?
  (( compare_status <= 1 )) || die "could not compare expected vendor source" 5
)

# update_notice <rev> <tag>: rewrite NOTICE provenance (portable, no sed -i).
update_notice() {
  local tmp; tmp="$(mktemp)"
  sed -e "s|^Source rev:.*|Source rev:   $1|" -e "s|^Source tag:.*|Source tag:   $2|" \
      -e "s|^Vendored at:.*|Vendored at:  $(date -u +%F)|" "${NOTICE_FILE}" > "${tmp}"
  mv "${tmp}" "${NOTICE_FILE}"
}

run_build() {
  case "${build}" in
    skip) log "build validation: skipped" ;;
    dp) log "build validation: make dp (host toolchain)"; ( cd "${REPO_ROOT}" && make dp ) ;;
    image) log "build validation: make image-runtime-agent"; ( cd "${REPO_ROOT}" && make image-runtime-agent ) ;;
    *) die "invalid --build value: ${build} (want image|dp|skip)" 1 ;;
  esac
}

cmd_diff() {
  local recorded upstream_dir drift
  recorded="$(notice_rev)"
  [[ -n "${recorded}" ]] || die "could not read Source rev from NOTICE" 5
  log "vendored revision recorded in NOTICE: ${recorded}"
  upstream_dir="$(fetch_upstream "${recorded}")"
  log "comparing vendored tree vs. upstream@${recorded} plus declared patches"
  drift="$(compute_drift "${recorded}" "${upstream_dir}")"
  if [[ -z "${drift}" ]]; then
    log "no drift: vendored tree matches upstream@${recorded} plus declared patches"; exit 0
  fi
  echo "${drift}"
  log "drift detected; pipe this output to a file under local-patches/ if intentional"
  exit 2
}

# capture_drift <recorded>: persist undeclared drift as the next local patch before a re-vendor.
capture_drift() {
  local drift last_patch="000" p drift_file
  drift="$(compute_drift "$1" "$(fetch_upstream "$1")")"
  [[ -n "${drift}" ]] || return 0
  mkdir -p "${LOCAL_PATCHES_DIR}"
  for p in "${LOCAL_PATCHES_DIR}"/*.patch; do [[ -e "$p" ]] && last_patch="$(basename "$p")"; done
  drift_file="${LOCAL_PATCHES_DIR}/${last_patch}.post-sync-drift-$(date -u +%Y%m%d%H%M%S)-$$.patch"
  echo "${drift}" > "${drift_file}"
  log "captured pre-sync drift → $(realpath --relative-to="${REPO_ROOT}" "${drift_file}")"
}

cmd_sync() (
  [[ -n "${rev}" ]] || die "--sync requires --rev <upstream-ref>" 1
  local recorded upstream_dir new_rev new_tag staging source_replaced=0 sync_status=0
  recorded="$(notice_rev)"
  log "current vendored rev:  ${recorded}"; log "target  vendored rev:  ${rev}"
  capture_drift "${recorded}"
  upstream_dir="$(fetch_upstream "${rev}")"
  new_rev="$(git -C "${upstream_dir}" rev-parse HEAD)"
  new_tag="$(git -C "${upstream_dir}" describe --tags --always)"
  # Validate the complete candidate before replacing current source; restore it on any failure.
  staging="$(mktemp -d "${TMPDIR:-/tmp}/constellation-neuvector-sync.XXXXXXXX")"
  trap 'sync_status=$?; if [[ "$sync_status" != 0 && "$source_replaced" == 1 ]]; then
    log "restoring prior vendor source after failed sync"
    vendor_one "$staging/previous/dp/" "$VENDOR_DIR/dp/"
    cp "$staging/previous/base.h" "$staging/previous/defs.h" "$staging/previous/LICENSE" "$staging/previous/NOTICE" "$VENDOR_DIR/"
  fi; rm -rf "$staging"; exit "$sync_status"' EXIT
  mkdir -p "${staging}/candidate/dp" "${staging}/previous"
  vendor_one "${upstream_dir}/dp/" "${staging}/candidate/dp/"
  cp "${upstream_dir}/base.h" "${upstream_dir}/defs.h" "${upstream_dir}/LICENSE" "${staging}/candidate/"
  apply_local_patches "${staging}/candidate"
  vendor_one "${VENDOR_DIR}/" "${staging}/previous/"
  log "vendoring ${new_tag} (${new_rev:0:12}) → third_party/neuvector/"
  source_replaced=1
  vendor_one "${staging}/candidate/dp/" "${VENDOR_DIR}/dp/"
  cp "${staging}/candidate/base.h" "${staging}/candidate/defs.h" "${staging}/candidate/LICENSE" "${VENDOR_DIR}/"
  update_notice "${new_rev}" "${new_tag}"
  log "updated NOTICE: rev=${new_rev:0:12} tag=${new_tag} date=$(date -u +%F)"
  run_build || die "build validation failed; restoring prior vendor source (captured drift patches are preserved)" 4
  log "sync complete: review git status third_party/neuvector/, run go test ./internal/runtime/dp/..., commit 'vendor: bump neuvector to ${new_tag}'"
)

case "${mode}" in
  diff) cmd_diff ;;
  sync) cmd_sync ;;
esac
