# Storage lifecycle review (2026-09-27)

This review compares the checked-in `../neuvector` source with Constellation's
current k3s database and scanner deployment. It corrects the earlier mistaken
assumption that `../constellation-vulndb` is still the active producer. It is a
design recommendation, not evidence that a new retention or archival path is
deployed.

## What NeuVector actually stores

- `../neuvector/controller/cache/log.go` keeps activity, event, threat,
  violation, incident, and audit display lists in separate 4,096-entry rolling
  slices. `../neuvector/share/cluster/eventqueue.go` bounds the producer queue
  at 4,096 entries, gzip-flushes it to cluster KV, and the controller uses a
  smaller 128-entry queue for its audit category. These are bounded console
  histories, not a durable, hash-chained audit ledger.
- `../neuvector/db/models.go` creates a dedicated, replaceable `/tmp/cve.db`
  SQLite file, separate from `vulasset.db`. `../neuvector/db/cvedb.go` replaces
  its CVE contents in a transaction; `../neuvector/db/cvedb_cache.go` lazily
  loads prefix groups and invalidates them after replacement. The controller
  rebuilds that store from versioned cluster slots in
  `../neuvector/controller/cache/scan.go`. Separation avoids local SQLite
  write-lock contention and makes CVE data replaceable; it does not imply a
  second PostgreSQL service is necessary here.

## Current Constellation state

On the existing k3s instance, PostgreSQL was about 6.8 GB after the event and raw
flow partition cleanup. Events retain seven days and raw flows three days.
Approximate relation sizes were: `audit_events` 1.6 GiB, `cve_records` 1.1 GiB,
and `network_flow_rollups` 79 MiB. The CVE table had about 398,000 live rows,
negligible reported dead tuples, and consists of roughly 504 MiB heap,
397 MiB TOAST, and 158 MiB indexes. It is a catalog-size cost, not the recent
telemetry-bloat failure.

`audit_events` contained about 1.76 million rows. Of the roughly 77,885 rows
from the last seven days, 51,306 were `runtime.alert.exec` and 26,494 were
`scan-job.complete`; nearly all recent growth is operational/security telemetry,
not human control-plane changes. The runtime path deliberately promotes high
severity `events` into the audit chain (`internal/handler/runtime/events_ingest.go`),
and scan completion writes a receipt (`internal/handler/scanning/scanjobs.go`).
Compliance mappings and tests currently depend on these actions, so they cannot
simply be disabled.

`pkg/audit/audit.go` writes the global hash chain inside PostgreSQL transactions,
including caller-owned mutation transactions. Keep that atomic control-plane
ledger in PostgreSQL. `cmd/audit-archiver/main.go` already exports a verified,
gzip-compressed JSONL window and a manifest that can be signed, but it only
selects the last configured time window; it has no durable catch-up cursor or
prune operation.
The Helm CronJob is disabled by default and not installed on this k3s release.
The current full-chain verifier starts at genesis, and the table's triggers
forbid DELETE, so enabling a TTL without a chain-anchor design would break
verification and evidence guarantees.

The sibling `../constellation-vulndb` repository is a retired producer, not the
active scanning source. The current `internal/scanner/aggregator.go` attaches
Syft for package inventory and Trivy plus Grype for vulnerability matching;
`internal/scanner/grype_matcher.go` fills the package-matcher slot formerly
owned by the bundle. The running k3s scanner has all three engines enabled,
refreshed Trivy and Grype on 2026-09-27, and has a separate scanner-cache PVC.
There is no active VulnDB importer CronJob or bundle requirement in the chart.
Constellation's `cve_records` API catalog is fed directly by KEV/EPSS and
optionally NVD, rather than the retired bundle;
`internal/handler/findings/cve.go` and `internal/handler/clusters_search.go`
depend on its SQL filters, statistics, detail, and free-text lookup. The local
table's `sources` include about 378,000 EPSS, 17,000 NVD, and 1,700 KEV
memberships; these are source labels, not a count of currently enabled feeds.

## Decision

1. **Do not move CVEs to another PostgreSQL database solely to reduce disk.**
   That changes backup and query topology without reducing bytes. Keep the
   existing `cve_records` table as the API catalog while Syft/Trivy/Grype use
   their own replaceable scanner caches. If CVE storage becomes a real limit,
   profile the wide columns and indexes, then test a compact, rebuildable
   read model sourced from the active KEV/EPSS/NVD pipeline. Preserve detail,
   search, statistics, freshness, and offline behavior. Do not restore the old
   `constellation-vulndb` bundle merely as a storage workaround.
2. **Keep control-plane audit writes in PostgreSQL, but separate their lifecycle
   from high-rate detection and job telemetry.** Preserve critical alert/job
   evidence and existing compliance links through a tested replacement receipt
   and SIEM/archive path before removing any `runtime.alert.*` or
   `scan-job.complete` chain writes. Do not adopt NeuVector's 4,096-entry limit
   for Constellation's tamper-evident control audit.
3. **Make cold audit storage verified and catch-up capable.** Archive contiguous
   ID ranges with durable progress, signed checksums, first previous hash and
   last chain hash, restore/replay tests, and gap detection. Only after an
   independently verified immutable copy exists should a reviewed hot-window
   policy prune PostgreSQL segments. Extend `VerifyChain` to trust a recorded
   archive checkpoint before changing append-only triggers or partition keys.
   Object storage is the evidence copy; a SIEM can be the search copy.
4. **Bound the other stores.** Define a reviewed rollup horizon, track per-table
   growth and partition-drop lag, alert on PVC free space, and periodically test
   archive restoration. Raw event/flow retention is already active locally,
   but its seven-/three-day values are development policy, not fleet policy.

No audit rows or CVE records were deleted for this review. The existing URL,
certificate, and login configuration were not changed.
