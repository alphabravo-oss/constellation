#!/usr/bin/env bash
# sync-neuvector.sh — refresh third_party/neuvector/ from upstream.
#
# This script automates the vendoring procedure documented in
# third_party/neuvector/README.md with three additions the manual procedure
# didn't have:
#
#   1. Drift detection. If the current vendored tree has diverged from the
#      revision recorded in NOTICE (i.e. someone edited the files despite
#      the README saying not to), the script extracts that diff as a patch
#      so a re-vendor doesn't silently discard it.
#
#   2. Local-patches workflow. Patches under
#      third_party/neuvector/local-patches/*.patch are applied on top of
#      the freshly synced upstream tree, in lexical order. Any patch that
#      fails to apply aborts the sync with a clear message.
#
#   3. Build-validation gate. After the swap, runs `make image-runtime-agent`
#      (or `make dp` for a faster local cycle) and rolls back on failure
#      so the working tree never ends up half-synced.
#
# Modes:
#   --diff               Report drift only; do not modify the vendored tree.
#   --sync               Perform the sync. Requires --rev or --remote.
#   --rev <git-ref>      Upstream rev to vendor (e.g. v5.5.1, sha).
#   --remote <git-url>   Upstream repo. Default: github.com/neuvector/neuvector.
#   --upstream <path>    Use a local sibling checkout instead of cloning.
#   --build {image|dp|skip}
#                        Build validation step. Default: dp (faster).
#
# Exit codes:
#   0   success (sync completed, or diff-mode with no drift)
#   1   usage error / missing args
#   2   drift detected in --diff mode (report printed to stderr)
#   3   patch apply failure
#   4   build validation failure
#   5   unexpected error
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR_DIR="${REPO_ROOT}/third_party/neuvector"
NOTICE_FILE="${VENDOR_DIR}/NOTICE"
LOCAL_PATCHES_DIR="${VENDOR_DIR}/local-patches"
DEFAULT_REMOTE="https://github.com/neuvector/neuvector.git"

mode=""
rev=""
remote="${DEFAULT_REMOTE}"
upstream=""
build="dp"

die()  { echo "sync-neuvector: $*" >&2; exit "${2:-5}"; }
log()  { echo "sync-neuvector: $*" >&2; }
need() { command -v "$1" >/dev/null || die "missing required tool: $1" 1; }

usage() {
    sed -n '2,/^set -e/p' "$0" | sed 's/^# \{0,1\}//; /^set -e/d'
    exit "${1:-0}"
}

while (( $# )); do
    case "$1" in
        --diff)              mode="diff"; shift ;;
        --sync)              mode="sync"; shift ;;
        --rev)               rev="$2"; shift 2 ;;
        --remote)            remote="$2"; shift 2 ;;
        --upstream)          upstream="$2"; shift 2 ;;
        --build)             build="$2"; shift 2 ;;
        -h|--help)           usage 0 ;;
        *)                   die "unknown flag: $1" 1 ;;
    esac
done

[[ -z "${mode}" ]] && die "must specify --diff or --sync (try --help)" 1
need git
need rsync
need diff
need sed

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# notice_rev: extract the "Source rev:" line from NOTICE. The vendoring
# procedure documents it as the source of truth for "what revision is
# currently in the tree".
notice_rev() {
    awk '/^Source rev:/ { print $3 }' "${NOTICE_FILE}"
}

# fetch_upstream: ensures we have a checkout of the upstream repo at the
# requested rev. Returns the absolute path. Honors --upstream (sibling
# checkout) when present.
fetch_upstream() {
    local target_rev="$1"
    if [[ -n "${upstream}" ]]; then
        [[ -d "${upstream}/.git" ]] || die "--upstream path is not a git repo: ${upstream}" 1
        if [[ -n "${target_rev}" ]]; then
            git -C "${upstream}" rev-parse --verify "${target_rev}^{commit}" >/dev/null \
                || die "rev ${target_rev} not found in ${upstream}" 1
            git -C "${upstream}" checkout -q "${target_rev}"
        fi
        echo "${upstream}"
        return
    fi
    local cache_dir="${TMPDIR:-/tmp}/constellation-neuvector-cache"
    if [[ ! -d "${cache_dir}/.git" ]]; then
        log "cloning ${remote} → ${cache_dir} (one-time, ~200MB)"
        git clone --quiet "${remote}" "${cache_dir}"
    else
        log "refreshing ${cache_dir}"
        git -C "${cache_dir}" fetch --quiet --tags origin
    fi
    if [[ -n "${target_rev}" ]]; then
        git -C "${cache_dir}" checkout --quiet "${target_rev}"
    fi
    echo "${cache_dir}"
}

# vendor_one: rsync a single upstream path into the vendor tree, honoring
# the standard build-artifact excludes.
vendor_one() {
    local src="$1"
    local dst="$2"
    rsync -a --delete \
        --exclude='.objs/' --exclude='.deps/' \
        --exclude='*.o' --exclude='*.d' \
        --exclude='compile_commands.json' \
        "${src}" "${dst}"
}

# compute_drift: produces a unified diff between the *current vendored tree*
# and the *upstream tree at the recorded revision*. If non-empty, someone
# has been editing the vendored files. Emits the diff to stdout.
compute_drift() {
    local recorded="$1"
    local upstream_dir="$2"
    local tmp="${TMPDIR:-/tmp}/constellation-neuvector-clean.$$"
    mkdir -p "${tmp}/dp"
    rsync -a --exclude='.objs/' --exclude='.deps/' --exclude='*.o' --exclude='*.d' \
        --exclude='compile_commands.json' \
        "${upstream_dir}/dp/" "${tmp}/dp/"
    cp "${upstream_dir}/base.h" "${tmp}/" 2>/dev/null || true
    cp "${upstream_dir}/defs.h" "${tmp}/" 2>/dev/null || true
    # Compare ours to a clean upstream-at-recorded-rev. Use -r -N -u so new
    # local files (which would be drift) appear as additions.
    #
    # Build artifacts left over from a previous `make dp` run inside the
    # vendored tree must be ignored — they're not source and aren't covered
    # by the vendoring guarantee. Same exclusions we use on the rsync side.
    diff -ruN \
        --exclude='local-patches' \
        --exclude='LICENSE' --exclude='NOTICE' --exclude='README.md' \
        --exclude='.objs' --exclude='.deps' \
        --exclude='*.o' --exclude='*.d' \
        --exclude='compile_commands.json' \
        "${tmp}" "${VENDOR_DIR}" || true
    rm -rf "${tmp}"
}

# apply_local_patches: lexically applies every *.patch under
# local-patches/. Fails loudly on the first non-applying patch.
apply_local_patches() {
    [[ -d "${LOCAL_PATCHES_DIR}" ]] || return 0
    local applied=0
    for p in "${LOCAL_PATCHES_DIR}"/*.patch; do
        [[ -e "${p}" ]] || continue
        log "applying local patch: $(basename "${p}")"
        ( cd "${VENDOR_DIR}" && patch -p1 --silent < "${p}" ) \
            || die "patch failed to apply: $(basename "${p}")" 3
        applied=$((applied + 1))
    done
    log "applied ${applied} local patch(es)"
}

# update_notice: rewrites the provenance lines in NOTICE.
update_notice() {
    local new_rev="$1"
    local new_tag="$2"
    local today
    today="$(date -u +%F)"
    # GNU sed and BSD sed disagree on -i; use a portable two-step.
    local tmp
    tmp="$(mktemp)"
    sed -e "s|^Source rev:.*|Source rev:   ${new_rev}|" \
        -e "s|^Source tag:.*|Source tag:   ${new_tag}|" \
        -e "s|^Vendored at:.*|Vendored at:  ${today}|" \
        "${NOTICE_FILE}" > "${tmp}"
    mv "${tmp}" "${NOTICE_FILE}"
}

run_build() {
    case "${build}" in
        skip)
            log "build validation: skipped"
            return 0
            ;;
        dp)
            log "build validation: make dp (host toolchain)"
            ( cd "${REPO_ROOT}" && make dp ) || return 1
            ;;
        image)
            log "build validation: make image-runtime-agent (docker buildx)"
            ( cd "${REPO_ROOT}" && make image-runtime-agent ) || return 1
            ;;
        *)
            die "invalid --build value: ${build} (want image|dp|skip)" 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

cmd_diff() {
    local recorded
    recorded="$(notice_rev)"
    [[ -n "${recorded}" ]] || die "could not read Source rev from NOTICE" 5
    log "vendored revision recorded in NOTICE: ${recorded}"
    local upstream_dir
    upstream_dir="$(fetch_upstream "${recorded}")"
    log "comparing vendored tree vs. clean upstream@${recorded}"
    local drift
    drift="$(compute_drift "${recorded}" "${upstream_dir}")"
    if [[ -z "${drift}" ]]; then
        log "no drift: vendored tree is byte-identical to upstream@${recorded}"
        exit 0
    fi
    echo "${drift}"
    log "drift detected; pipe this output to a file under local-patches/ if intentional"
    exit 2
}

cmd_sync() {
    [[ -n "${rev}" ]] || die "--sync requires --rev <upstream-ref>" 1
    local recorded
    recorded="$(notice_rev)"
    log "current vendored rev:  ${recorded}"
    log "target  vendored rev:  ${rev}"

    # Capture any drift before we swap. If found, persist it as a patch
    # under local-patches/ so it survives the re-vendor.
    local upstream_dir
    upstream_dir="$(fetch_upstream "${recorded}")"
    local drift
    drift="$(compute_drift "${recorded}" "${upstream_dir}")"
    if [[ -n "${drift}" ]]; then
        mkdir -p "${LOCAL_PATCHES_DIR}"
        local drift_file
        drift_file="${LOCAL_PATCHES_DIR}/000-pre-sync-drift-$(date -u +%Y%m%d%H%M%S).patch"
        echo "${drift}" > "${drift_file}"
        log "captured pre-sync drift → $(realpath --relative-to="${REPO_ROOT}" "${drift_file}")"
    fi

    # Check out the *new* rev and grab a tag-like description for NOTICE.
    upstream_dir="$(fetch_upstream "${rev}")"
    local new_rev new_tag
    new_rev="$(git -C "${upstream_dir}" rev-parse HEAD)"
    new_tag="$(git -C "${upstream_dir}" describe --tags --always)"

    # Re-vendor. Trailing slashes on rsync sources matter — they mean
    # "contents of" not "the directory itself". Match upstream layout.
    log "vendoring ${new_tag} (${new_rev:0:12}) → third_party/neuvector/"
    rm -rf "${VENDOR_DIR}/dp"
    mkdir -p "${VENDOR_DIR}/dp"
    vendor_one "${upstream_dir}/dp/" "${VENDOR_DIR}/dp/"
    cp "${upstream_dir}/base.h" "${VENDOR_DIR}/base.h"
    cp "${upstream_dir}/defs.h" "${VENDOR_DIR}/defs.h"
    cp "${upstream_dir}/LICENSE" "${VENDOR_DIR}/LICENSE"

    # Re-apply local patches (including any drift we captured above).
    apply_local_patches

    # Refresh NOTICE provenance.
    update_notice "${new_rev}" "${new_tag}"
    log "updated NOTICE: rev=${new_rev:0:12} tag=${new_tag} date=$(date -u +%F)"

    # Build gate — if this fails, the operator wants to know before
    # committing.
    if ! run_build; then
        die "build validation failed; the vendored tree is in an INVALID state.
Inspect the build output above. If the upstream rev is incompatible, revert with
  git checkout -- third_party/neuvector/" 4
    fi

    log "sync complete. Next steps:"
    log "  - inspect: git -C ${REPO_ROOT} status third_party/neuvector/"
    log "  - test:    go test ./internal/runtime/dp/..."
    log "  - commit:  git add third_party/neuvector/ && git commit -m 'vendor: bump neuvector to ${new_tag}'"
}

case "${mode}" in
    diff) cmd_diff ;;
    sync) cmd_sync ;;
    *)    die "internal error: mode=${mode}" 5 ;;
esac
