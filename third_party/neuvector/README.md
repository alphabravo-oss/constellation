# third_party/neuvector — vendored NeuVector data-plane

This directory holds a verbatim copy of the NeuVector C data-plane (`dp/`)
together with the two top-level NeuVector headers it depends on
(`base.h`, `defs.h`). It exists so the constellation runtime-agent can run
the NeuVector enforcer's wire-level inspection (NFQUEUE / AF_PACKET
packet tap + DPI parsers + per-session byte/packet counters) without us
re-implementing 30k LOC of C.

Upstream rev vendored: `4247e24561a9cd225db73a7cfaf5c7b2c99ba0a5`
(`v5.5.1-rc4-33-g4247e245`, vendored 2026-05-12).

## Layout

```
third_party/neuvector/
├── LICENSE      Apache 2.0 (upstream)
├── NOTICE       Attribution + provenance
├── README.md    This file
├── base.h       Shared macros (FLAGS_*, byte-order helpers).
├── defs.h       Wire-format types for agent↔dp IPC (DPMsgConnect, …).
└── dp/          C data-plane daemon source.
```

The `dp/` Makefile expects `base.h` and `defs.h` to live one directory
above it (`-include $(TOPDIR)/../base.h`), which is satisfied by this
layout.

## How it's consumed

- The Dockerfile.runtime-agent has a dedicated `dp-build` stage that
  installs the C toolchain + libnetfilter_queue / libpcap / libpcre2 /
  hyperscan / jansson / jemalloc / urcu and runs `make -C
  third_party/neuvector/dp`. The output binary is COPYed into the final
  runtime image at `/usr/local/bin/dp`.
- The Go runtime-agent supervises the `dp` process: forks it,
  communicates over a Unix socket at `/tmp/dp_client.<pid>` ↔
  `/tmp/ctrl_listen.sock`, decodes `DPMsgConnect` and `DPMsgThreatLog`
  records, and forwards them as `flowIngestRow` / threat rows to the
  control plane. (Supervisor and IPC consumer live under
  `internal/runtime/dp/` — see Wave 2.)
- Capture mechanism (NFQUEUE inline vs AF_PACKET TAP) is selected at
  runtime-agent startup. The CNI integration that installs TC qdisc
  redirects per pod is Wave 3.

## Modifications

**Do not edit the files in this directory.** Treat them as read-only
upstream code. Behavior changes belong on our side of the IPC boundary
(`internal/runtime/dp/`).

The only exception is build-glue (e.g. tweaking `dp/Makefile` to honor
`$(CC)` from the environment). If such a tweak is needed, document it in
the "Local patches" section below so the next sync knows to re-apply.

## Local patches

Patches we *intentionally* keep on top of the upstream sources live under
`local-patches/*.patch` and are re-applied by the sync tooling after each
upstream refresh, in lexical order.

When that directory is empty (current state — NOTICE confirms byte-for-byte
identical to upstream), the vendored tree is a clean mirror. The sync
tool's `--diff` mode (run by CI) will fail the build the moment that
invariant is broken.

To add a local patch (only for things like a CVE backport we genuinely need
ahead of upstream):

```bash
# Edit directly in third_party/neuvector/dp/, then:
git diff --no-color third_party/neuvector/dp/ > \
    third_party/neuvector/local-patches/010-cve-XXXX-backport.patch
git checkout -- third_party/neuvector/dp/
make vendor-neuvector-sync REV=$(awk '/^Source rev:/{print $3}' \
    third_party/neuvector/NOTICE)
# Round-trip succeeds = patch applies cleanly at the current rev.
```

Then explain *why* the patch exists in this section.

## Syncing from upstream

The canonical procedure is `scripts/sync-neuvector.sh`, fronted by two
Makefile targets:

```bash
# Read-only report — does the current vendored tree match the rev in NOTICE?
make vendor-neuvector-diff

# Bump to a new upstream rev. The script clones
# github.com/neuvector/neuvector into a temp cache on first run; cached
# thereafter. Build-validation gate defaults to `make dp` (host toolchain);
# pass BUILD=image for a full `make image-runtime-agent` build.
make vendor-neuvector-sync REV=v5.6.0
make vendor-neuvector-sync REV=v5.6.0 BUILD=image

# Use a sibling checkout instead of cloning (faster iteration):
make vendor-neuvector-sync REV=main UPSTREAM=../neuvector
```

The script:

1. Captures any pre-existing drift in the vendored tree as a patch at
   `local-patches/000-pre-sync-drift-<timestamp>.patch` (so a re-vendor
   doesn't silently discard hand-edits).
2. Replaces `dp/`, `base.h`, `defs.h`, `LICENSE` with the upstream rev.
3. Re-applies every `local-patches/*.patch` in lexical order. Aborts on
   the first failure with exit code 3.
4. Rewrites the provenance lines in NOTICE.
5. Runs the build-validation gate. If it fails (exit 4), the working tree
   is left in place — inspect, then revert with
   `git checkout -- third_party/neuvector/`.

Exit codes: 0 success / clean, 1 usage, 2 drift detected (`--diff` mode),
3 patch apply failure, 4 build failure, 5 unexpected.

## License

Apache License 2.0. See `./LICENSE` and `./NOTICE`.
