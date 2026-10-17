# third_party/neuvector — vendored NeuVector data-plane

This directory holds a copy of the NeuVector C data-plane (`dp/`)
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
├── local-patches/ Documented, ordered upstream correctness patches.
└── dp/          C data-plane daemon source plus those patches.
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

Build glue and explicitly reviewed correctness/security backports may be
maintained as documented local patches. Keep the upstream revision unchanged,
record attribution in NOTICE, and test the patch roundtrip before syncing.

## Local patches

Patches under `local-patches/*.patch` apply to this vendor directory with
`patch -p1` in lexical order. `--diff` compares the current source to the
recorded upstream revision **plus these declared patches**; undeclared drift
still fails. Sync validates all patches on a temporary candidate before
replacing source. It preserves undeclared drift as an ordered patch and restores
the prior source if the build gate fails.

- `000-existing-threat-controls.patch` (recorded 2026-10-17): provenance-only
  capture of behavior already present in snapshot `6a8057c`: the threat-toggle
  control IPC and disabled TCP_SMALL_MSS/SSL_VER_2OR3 defaults. No behavior change
  is introduced by declaring these existing differences; the prior pristine
  mirror claim was stale.
- `010-connection-lookup-application.patch` (2026-10-17): initialize the IPv4
  connection lookup key and populate Application before `conn4_match`. The
  upstream comparator already compares Application, so reading the uninitialized
  key could split identical reports. This aggregation occurs before IPC and
  cannot be corrected in the Go consumer. The actual `dp_ctrl_connect_report`
  regression lives in `tests/native-policy/connect_report.c`; it preserves
  existing tuple identity, counters, timestamps and selected-map semantics.
  This is a narrow downstream correctness backport, not a claim of upstream
  acceptance or a diagnosis of the separate Protect packet-evidence gap.

- `011-connection-report-wall-time.patch` (2026-10-17): derive connection
  observation timestamps from checked wall time minus the existing coarse Idle
  duration. A native packet diagnostic observed a fresh matching allow report
  whose startup-relative timestamp trailed the probe's wall second. Only the
  two report timestamp paths change; timeout/Idle processing, debug/rate clocks,
  aggregate keys/counters, preserved FirstSeenAt and latest-action selection stay
  unchanged. Nonzero Idle still gives an approximate last-activity time, not an
  exact historical packet timestamp. Invalid or unrepresentable wall time fails
  before any aggregate or rate-counter mutation. Actual reporter boundary and
  negative-control tests live in `tests/native-policy/connect_report.c`.

New patches must use vendor-relative `a/` and `b/` paths (for example
`a/dp/ctrl.c`). Verify forward/reverse/forward application, declared-patch clean
`--diff`, undeclared drift detection, and repeated sync before review.

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

1. Captures undeclared drift relative to the declared stack as an ordered
   `local-patches/*.post-sync-drift-<timestamp>.patch` (so a re-vendor
   doesn't silently discard hand-edits).
2. Stages `dp/`, `base.h`, `defs.h`, `LICENSE` from the upstream rev.
3. Applies every `local-patches/*.patch` in lexical order to the staged tree.
   Aborts on the first failure with exit code 3 before replacing source; only a
   completely patched candidate replaces the existing source.
4. Rewrites the provenance lines in NOTICE.
5. Runs the build-validation gate. If it fails (exit 4), the previous source
   is restored and any captured drift patch remains available for inspection.

Exit codes: 0 success / clean, 1 usage, 2 drift detected (`--diff` mode),
3 patch apply failure, 4 build failure, 5 unexpected.

## License

Apache License 2.0. See `./LICENSE` and `./NOTICE`.
