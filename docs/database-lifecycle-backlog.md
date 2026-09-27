# Database and storage lifecycle backlog

Reviewed 2026-09-27 against the checked-in code and the existing local k3s
release. This is the detailed open-item register for the OPS-2 storage item in
`NEUVECTOR-PARITY-PLAN.md`; it does not mark the parent item complete. The
retired `constellation-vulndb` integration is tracked separately and is not a
proposed destination for current CVE data.

## Live baseline

- PostgreSQL database: about 6.8 GB. `audit_events` 1.6 GB, `cve_records`
  1.1 GB, recent event partitions about 2.3 GB, recent raw-flow partitions
  about 1.5 GB, `k8s_audit_events` 174 MB, and `network_flow_rollups` 79 MB.
- Local retention config: events 7 days, raw flows 3 days, terminal scan jobs
  7 days. The partition manager has dropped expired daily partitions and now
  reclaims an empty, bloated DEFAULT partition. These local values are not a
  reviewed fleet-wide policy and do not make the current row-level pruners safe.
- The last seven days contributed about 51,306 `runtime.alert.exec` and 26,494
  `scan-job.complete` rows to the audit chain. `k8s_audit_events` has 81,695
  rows, with its newest row dated 2026-08-18.
- The scanner's separate cache uses about 5.7 GB (Trivy 2.8 GB, Grype 3.0 GB)
  against an 8 GiB cache claim. PostgreSQL WAL occupied about 960 MB. The
  PostgreSQL data filesystem reported 73 GB available on a 338 GB filesystem;
  the PostgreSQL PVC requests 60 GiB, but this observation does not prove a
  hard quota or recoverable capacity.
- The application backup catalog has zero schedules and zero backup rows, and
  no database-backup CronJob was visible in this namespace. External/node-level
  snapshots were not verified. A one-time pre-upgrade non-telemetry dump is not
  a full database backup or point-in-time recovery plan.

## P0: correctness and recoverability

| ID | Status | Required fix or decision | Acceptance gate |
| --- | --- | --- | --- |
| DB-01 | **Open — urgent fix** | Replace `ctid`-only DELETEs from partitioned `events` and `network_flows` (`internal/handler/events_retention.go`, `internal/handler/network/rollup.go`). `ctid` is only unique within a child; a disposable PostgreSQL reproduction selected one expired row and deleted it **and a current row** with the same `ctid` in another partition. | Partitioned two-child test proves an expired row is removed and a current row survives; deploy the fix before relying on pruning. Treat historical event/flow completeness as unverified. |
| DB-02 | **Open — urgent fix** | Never prune or drop raw flows until the rollup watermark and a successful fold cover them. The current refresh loop prunes even after a refresh failure, while the partition manager drops by age alone; late-arriving timestamps and `RefoldWindow` need a defined grace/replay contract (`internal/handler/network/rollup.go`, `internal/handler/partition_manager.go`). | Failure, lag, late-arrival, and refold-after-prune tests preserve counts; a visible fold-lag alarm blocks unsafe expiry. |
| DB-03 | **Open — fix** | Make new installations bounded by default. Migration 137 updates only pre-existing `system_config` rows; `syscfg.Default()` and first-boot seeding otherwise leave retention at zero, meaning never prune (`db/migrations/137_retention_defaults.sql`, `internal/syscfg/syscfg.go`, `internal/server/server.go`). | Fresh database install has explicit reviewed nonzero defaults; existing operator choices, including an explicit zero if allowed, are not silently overwritten. |
| DB-04 | **Open — decision + fix** | Choose installation-wide versus per-org retention. The leader currently reads the earliest org's settings for every org (`internal/server/leaderelection.go`). | Config API/UI, partition drops, row pruners, and tenant tests enforce one documented scope consistently. |
| DB-05 | **Open — fix** | Establish real PostgreSQL backup/PITR and offsite copies before more destructive cleanup. The local deployment has no app backup schedule/catalog entries; org backups are not equivalent to a database restore and omit audit replay (`pkg/backup/restorer.go`, `deploy/charts/constellation/values.yaml`). | Scheduled backup, retained WAL or equivalent recovery points, independent restore drill, RPO/RTO evidence, and alerts on missed backups. |

## P1: evidence-preserving retention

| ID | Status | Required fix or decision | Acceptance gate |
| --- | --- | --- | --- |
| DB-06 | **Open — decision** | Classify control-plane audit separately from high-rate detection and job telemetry. Recent `runtime.alert.exec` and `scan-job.complete` dominate `audit_events`, but compliance mappings and APIs cite them (`internal/handler/runtime/events_ingest.go`, `internal/handler/scanning/scanjobs.go`, `pkg/audit/compliance.go`). | Document which receipts stay in the permanent chain and which move to a bounded evidence stream; migrate consumers and prove no evidence or authorization regression before suppressing old writes. |
| DB-07 | **Open — fix** | Replace the optional archiver's last-window export with contiguous ID-range catch-up, durable cursor, gap detection, first `prev_hash`, last `chain_hash`, counts, and signed checksums (`cmd/audit-archiver/main.go`). Event timestamps can be backdated. | Missed runs and backdated rows are exported exactly once or safely replayed; archive progress advances only after durable verification. |
| DB-08 | **Open — decision + fix** | Choose immutable archive destination, signing/key rotation, access controls, legal hold, and hot/search/archive periods. Implement independent download, signature/hash-chain validation, and restore replay. Current SIEM dispatch is best-effort, not the evidence copy (`pkg/notify/dispatcher.go`). | A fresh environment verifies archived ranges and restores audit evidence without the source database; failure injection cannot advance the checkpoint. |
| DB-09 | **Open — fix** | Only after DB-07/08, design checkpoint-aware audit verification and safe PG pruning/partitioning. Current verifier starts at genesis, DELETE is forbidden, and the DELETE trigger does not protect against TRUNCATE (`pkg/audit/audit.go`, `db/migrations/007_audit_and_cve.sql`). | Trusted archive anchor spans the hot/cold boundary; unauthorized UPDATE/DELETE/TRUNCATE fail; archived evidence remains queryable for audit, timeline, support, exception history, and admission-hit consumers. |
| DB-10 | **Open — decision + fix** | Give `k8s_audit_events` its own raw/search/archive policy and ingestion-health alarm. It is unpartitioned, stores full JSON, and has no general prune path (`db/migrations/131_k8s_audit.sql`). | Reviewed window and verified export precede cleanup; freshness and gap tests catch a stopped audit webhook. |
| DB-11 | **Open — decision + fix** | Bound `runtime_threats` and packet bytes, PCAP files/rows, and `forensics_snapshots` separately from control audit. `SweepExpired` for PCAPs has no confirmed production caller (`db/migrations/041_runtime_threats.sql`, `internal/handler/runtime/runtime_pcap.go`, `db/migrations/013_forensics.sql`). | Expired files and rows disappear on schedule, while selected case evidence remains exportable and verifiable. |
| DB-12 | **Open — decision + fix** | Set raw-flow versus hourly-rollup windows and historical map/CSV behavior. `network_flow_rollups` is unbounded, and refolding can erase buckets whose raw rows have expired (`db/migrations/115_network_flow_rollups.sql`, `internal/handler/network/rollup.go`). | Rollup expiry is bounded, count-preserving, and respects DB-02; older UI ranges are explicitly unavailable or served from an archive. |
| DB-13 | **Open — decision + fix** | Define lifecycle-aware retention for `findings`. All current findings land in a DEFAULT child despite time partitioning; open findings and triage must not vanish by age alone (`db/migrations/004_findings_partitioned.sql`). | Resolved/orphaned findings archive by policy; open/suppressed/accepted decisions remain visible; partitions or another bounded layout avoid default-child bloat. |
| DB-14 | **Open — decision + fix** | Set separate policies for terminal versus stuck `scan_jobs`, attempts, named `image_scan_results`, registry results, and repository targets. Existing job TTL and orphan-digest cleanup do not bound all named results or verification history (`internal/handler/events_retention.go`, `internal/handler/repository_retention.go`). | Current/latest results and referenced attestations survive; stale jobs recover; historical results expire only after evidence and dependency checks. |
| DB-15 | **Open — decision + fix** | Classify large `scan_evidence`, SBOM documents, image artifacts, scan attestations and verification records as current cache or durable evidence (`db/migrations/063_scan_evidence.sql`, `db/migrations/003_assets_and_images.sql`, `db/migrations/084_scan_result_attestations.sql`). | A reference graph and restore test protect live decisions; size/age caps bound replaceable payloads. |
| DB-16 | **Open — fix** | Reap stale network sessions/kill requests, expired browser sessions and consumed refresh tokens, and other short operational histories without weakening reuse detection (`internal/handler/network/sessions.go`, `internal/auth/browser_sessions.go`). | Time-travel tests show stale rows are removed while active sessions and security evidence remain. |
| DB-17 | **Open — decision + fix** | Set retention for receiver deliveries, compliance runs, support-bundle job metadata, restart events, and admission dry-run history; distinguish operational logs from evidence (`db/migrations/020_settings_receivers_role_bindings.sql`, `db/migrations/039_compliance_schedules.sql`). | Every high-rate history table has an owner, window, cleanup job, and an evidence exception where needed. |

## P1/P2: CVE, cache, and operations

| ID | Status | Required fix or decision | Acceptance gate |
| --- | --- | --- | --- |
| DB-18 | **Open — fix** | Stop unnecessary `cve_records` rewrites. KEV/EPSS compares its process-local marker only after importing; the upsert updates conflicts even if values are unchanged (`internal/handler/findings/cve_intel_import.go`, `internal/handler/findings/cve_records_writer.go`). | Persist feed checkpoints, conditionally update changed rows, and measure lower WAL/dead-tuple growth across repeat imports and pod restarts. |
| DB-19 | **Open — decision + fix** | Define whether CVE `sources` and KEV flags are current membership or historical observations. The upsert can replace `sources` and only sets `kev_listed` true; NVD is opt-in and scans only a trailing 120-day modified window (`internal/handler/findings/cve_records_writer.go`, `internal/handler/findings/nvd_import.go`). | Feed withdrawal/update tests, full-bootstrap path, offline recovery, and published catalog-completeness/freshness semantics. |
| DB-20 | **Open — decision** | Keep the current PG `cve_records` API catalog unless a measured reason justifies a new format. Another PG database on the same storage does not save space; first profile wide descriptions/TOAST and index use, then evaluate a rebuildable compact projection (`internal/handler/findings/cve.go`). | Search, detail, CVSS/KEV/EPSS filters, stats, and restore behavior meet a size and latency budget without resurrecting retired VulnDB. |
| DB-21 | **Open — decision + fix** | Choose scanner-cache topology: one 8 GiB PVC-backed replica or multiple replicas with pod-local caches. Today's local cache uses about 5.7 GB; chart default multi-replica topology does not share the RWO cache (`deploy/charts/constellation/templates/scanner-cache-pvc.yaml`). | Cache free-space and DB-freshness alerts, restart/refresh/offline tests, and a capacity margin for both Trivy and Grype. |
| DB-22 | **Open — decision + fix** | Define backup-artifact retention separately from database PITR. Existing scheduled org-backup pruning is opt-in and only handles succeeded org backups/local files; scheduled S3 destination fields are not consumed by that executor (`pkg/backup/executor.go`). | Minimum recoverable copies, proven offsite upload, object lifecycle, failed/manual artifact cleanup, signature checks, and periodic restore evidence. |
| DB-23 | **Open — fix** | Export/alert on table and index bytes, dead tuples, DEFAULT partition occupancy, retention/drop lag, rollup watermark, archive backlog, WAL, DB and scanner-cache free space, backup age, and feed freshness. Avoid routine `VACUUM FULL` as a substitute for partition drops and healthy autovacuum. | Growth dashboard and alerts fire in disposable failure tests; operational runbook names safe reclaim actions and rollback points. |

## Policy decisions to record before deleting more data

1. Numeric database, WAL, scanner-cache, and node-disk budgets; alert and stop-work
   thresholds; RPO/RTO and restore-test cadence.
2. Whether retention is installation-wide or tenant-specific; whether zero means
   an explicit, approved hold rather than an accidental default.
3. Per-class hot/search/archive periods for raw events, flows, rollups,
   detections, Kubernetes audit, findings, scan evidence, control audit,
   sessions, captures, and operational history. The local 7-/3-day windows
   answer only the development raw-telemetry case.
4. Immutable audit/evidence store, signature trust, key custody, legal holds,
   older-history query path, and which high-rate actions remain in the global
   audit chain.
5. CVE catalog completeness, current-versus-historical feed membership,
   full-bootstrap/offline rebuild, and the scanner replica/cache topology.

No additional audit, CVE, scan, or evidence rows were deleted during this
review. DB-01 is a confirmed active correctness defect, not a hypothetical
storage optimization.
