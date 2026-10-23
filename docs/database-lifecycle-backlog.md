# Database and storage lifecycle backlog

**Latest source verification:** [2026-10-23 results for DB-01–04, DB-16 and DB-18](#october-23-source-reverification). Operational and deployment gates remain separate.

Reviewed 2026-09-27 against the checked-in code and the existing local k3s
release. This is the detailed open-item register for the OPS-2 storage item in
`NEUVECTOR-PARITY-PLAN.md`; it does not mark the parent item complete. The
retired `constellation-vulndb` integration is tracked separately and is not a
proposed destination for current CVE data.

**October 11 baseline recheck:** the `711a881` source still contains the DB-01
partition-ambiguous deletes and DB-02 prune-after-refresh-failure path. The
existing cluster has one node, a PostgreSQL StatefulSet, no CNPG CRDs/operator,
and no DB-backup CronJob in `constellation-system`. External backup coverage
has not been verified. The sizes and seven-day row counts below remain the
September 27 observations; they were not remeasured. The canonical parity
plan's October 11 packages A/B/J define the next implementation, recovery/CNPG
and lifecycle work. No item is closed by this source/infrastructure inspection.

**October 11 implementation:** DB-01–04 now have source fixes and actual
PostgreSQL tests. Deletes use `(id, at)`; folding and expiry share transactional
locks/watermarks; late rows update aggregates atomically; migration 168 prevents
rebuilding aggregates from already-pruned history. Fresh defaults are 14/30/7
days for flows/events/jobs. Existing zero/absent legacy values remain holds.
The installation-wide policy takes the maximum organization window, with any
zero holding deletion and read errors skipping maintenance. Race tests passed
twice. Deployment and operational acceptance remain open, especially the fold
lag alarm and measured lock contention. This does not repair historical loss.

DB-05 has chart plugin/recovery support and a local RustFS/CNPG rehearsal
([runbook](cnpg-recovery.md)). An independent full restore of the existing
database also passed migration 168 with unchanged raw-flow, rollup, event and
audit counts. The live StatefulSet remains unchanged; off-host copies, HA,
failure alerts and existing-history integrity remain unproved. The later local
rehearsal proves encrypted-credential recovery and the fresh fixture audit chain;
the existing database has the pre-existing row-53 discontinuity recorded below.
The table below retains the original failure/acceptance definitions so the
remaining deployment gates are not mistaken for new implementation work.

## October 12 recovery continuation

The owner deferred off-host recovery and real node-failure testing. CNPG cutover
and local recovery work remain authorized. The PostgreSQL 16.14 CNPG/RustFS
rehearsal now verifies an encrypted registry credential through the scanner API,
wrong-KEK rejection and recovery after the correct key returns, source audit-anchor
preservation, full fixture-chain verification and a database-pod restart. Local
pod deletion through authenticated recovery took 315 seconds. The
[recovery runbook](cnpg-recovery.md#october-12-credential-and-process-recovery-qualification)
records exact images and limits.

The existing-data restore fails chain verification at audit row 53. Read-only
inspection confirms the same June 14 `scan-job.complete` link mismatch on the live
source; it was not introduced by restoration. Historical hashes were preserved.
This is an additional concrete DB-07/08 acceptance blocker, not permission to
rewrite the evidence chain. The fresh fixture's passing chain does not clear it.

## October 12 session lifecycle implementation

Migration 171 adds explicit session expiry and cleanup indexes. The API leader
runs bounded, lock-skipping cleanup; browser-family expiry is recorded atomically
with refresh creation. New binaries reject schemas older than their required
migration before initializing services; Helm uses that same binary as its gate.
The guard reads Goose's latest up/down state per version, so a rolled-back
migration cannot satisfy startup with an old successful entry.

An independent restored-volume database applied migrations 169–171, then rolled
171 down and up. Counts remained 2,723,972 raw flows, 153,178 rollups, 3,020,985
events and 1,905,903 audit entries. This is migration preservation evidence, not
production tuning or a CNPG cutover. Logs:
`/tmp/constellation-session-restored-{before,migrations,after}.log`.
The live database remains on migration 167.

## October 11 live measurement and assessment

Read-only measurements at 23:42–23:46 UTC on the existing
`constellation-system/constellation-postgres-0`, not the disposable CNPG cluster.
The live server is PostgreSQL 16.14, schema migration **167**, with one
organization and one cluster. The migration-168/retention changes in PR #2 have
not been deployed here. No rows, settings, statistics or storage were changed
during this assessment.

**Assessment:** a reasonable PostgreSQL foundation at a manageable data volume,
but neither an optimized design nor demonstrated fleet-scale operation. Current
row count is not the limiting proof; lifecycle completeness, unnecessary writes,
query/lock latency and recovery under load remain unqualified.

| Data family | Exact rows in this snapshot | Physical size including indexes |
| --- | ---: | ---: |
| Runtime events | 2,928,117 | 3,783 MiB |
| Raw network flows | 2,777,455 | 1,622 MiB |
| Control/evidence audit | 1,906,845 | 1,700 MiB |
| CVE catalog | 403,690 | 1,060 MiB |
| Hourly flow aggregates | 153,235 | 91 MiB |
| Kubernetes audit | 81,695 | 174 MiB |
| Findings | 9,684 | 38 MiB |

Counts and sizes were sampled in adjacent read-only transactions while ingest
continued. They are observations, not consistency checks against each other.
`pg_stat_user_tables.n_live_tup` estimates were deliberately not used for the
exact count column: Kubernetes audit, for example, reported an estimated zero
despite containing 81,695 rows.

- **Database:** 8,992,160,791 bytes, approximately **8.37 GiB / 8.99 GB**, plus
  **160 MiB WAL** at a later snapshot. The database total includes table, TOAST
  and index storage; WAL, scanner caches, backups and other host workloads are
  additional. The PVC declares 60 GiB, but its backing filesystem is shared:
  `df` reported 338 GiB total, 265 GiB used, 60 GiB available and 82% utilization.
  PVC capacity is not proof of an enforced, exclusive 60-GiB quota. The older
  6.8-GB observation below is approximate; do not infer a precise growth rate or
  time-to-full from these two snapshots.
- **Cleanup is active, correctness remains open:** configured flow/event/job
  windows are 3/7/7 days. Only 2 raw flows and 386 events were older than their
  respective windows in the count query; 23 finished terminal jobs were older
  than seven days. These small boundary backlogs are consistent with periodic
  sweeps, not a large stuck queue. Daily partitions cover the expected windows,
  empty flow/event DEFAULT children occupy only 112/72 KiB, and autovacuum ran
  recently. The API also logged event pruning. These observations do not negate
  the known live partition-identity and rollup-expiry defects fixed in PR #2.
- **Aggregation is keeping up at this load:** the watermark trailed wall clock
  by about 78 seconds. There were no lock waiters at the later snapshot and ten
  idle application connections. This is a point-in-time health observation,
  not a latency SLO or a load test.
- **Avoidable write activity:** `cve_records` had about **110.8 million cumulative
  updates** against about 404,000 rows. The writer unconditionally updates
  conflicts; import checkpointing also needs DB-18. The statistics reset time
  was unavailable, so this is not a per-day rate or proof every update was
  unnecessary. Unchanged-feed tests and interval WAL/update deltas must quantify
  the fix. Small session/discovery tables also show substantial churn and need
  profiling before changing their correctness semantics.
- **Query/statistics work:** `shared_buffers` is 128 MiB in a pod limited to
  2 GiB RAM / two CPU cores. `work_mem` is 4 MiB, autovacuum uses global defaults,
  and there are no per-table storage overrides on the sampled hot tables.
  Partition parents have no recorded ANALYZE; `pg_stat_statements` and I/O timing
  are not enabled. The cumulative PostgreSQL buffer-hit ratio was 47.17%, with
  about 126 GiB of historical temporary-file writes. These counters include
  earlier workloads/restores, exclude the OS cache and have no known reset
  interval: they warrant measurement, not an asserted current bottleneck or
  blind memory/index tuning. Some large indexes have zero recorded scans, but
  uniqueness/constraint indexes must not be dropped on that basis.
- **Retention/data quality gaps:** audit and hourly rollups still retain June
  history without a completed archive/prune contract. Kubernetes audit's newest
  timestamp is **August 18**, so its freshness needs investigation separately
  from its size. Control audit writes serialize on a global hash-chain lock;
  changing that lock without a chain-format/migration design would break the
  integrity contract. The new conservative shared retention policy also means
  one tenant's zero/hold retains the corresponding history for every tenant;
  it is not evidence of bounded tenant-independent capacity.
- **Availability/recovery:** the live service is one StatefulSet on one node,
  with `archive_mode=off`. The verified logical restore and separate RustFS
  CNPG PITR rehearsal do not make this live database continuously archived or
  highly available.

### Ordered delivery and completion checks

This is the database detail of packages A/B/J and OPS-2, not a separate roadmap.
Owners below are responsibility areas, not assignments to named people.

| Order / owner | Existing items | Concrete delivery | Completion evidence |
| --- | --- | --- | --- |
| 1 — backend/release | DB-01–05; A/B | Resolve PR release-check failures, qualify the exact image, deploy retention safety/migration 168 through the existing upgrade/rollback contract; keep the independent recovery copy. | Hosted required checks green, deployed image/schema verified, concurrent ingest/prune/refold counts preserved, zero/hold policy preserved, rollback exercised. |
| 2 — data ingest | DB-18/19 | Persist feed checkpoints; update CVE rows only when the effective merged values change; preserve current source/KEV semantics until their separate decision is implemented. | Identical feed/restart is idempotent without row rewrites; changed rows update correctly; measure lower WAL/dead-tuple growth over the same replay workload. |
| 3 — storage/evidence | DB-06–17/22 | Complete the per-class hot/archive/delete matrix, contiguous signed audit archival and independent verification; bound rollups and operational histories; investigate stale Kubernetes audit. | Every growing family has an owner/window/hold exception; archive failures block deletion; restored evidence verifies; late/open/referenced security records survive; expiry and freshness alarms pass failure injection. |
| 4 — database/observability | DB-23; OPS-2 | Add interval growth, cleanup and fold-lag metrics; enable query-level profiling through a reviewed restart; maintain parent statistics; tune hot-table vacuum/index/memory settings against measured query plans. | Alerts tested for paused workers/full storage/backup gaps; representative foreground/background p95/p99 and WAL/IO/lock baselines recorded; before/after evidence for each tuning change. |
| 5 — performance/platform | OPS-2; B | Run simultaneous ingest, findings/search, audit/dashboard reads, pruning, scanner updates and backup at increasing cluster counts and dataset sizes; qualify live recovery and separate-node failover. | Measured sustainable rows/sec, active tenants/clusters, bytes/day and latency envelope; recover after overload; no count/isolation loss; RPO/RTO measured. A single healthy dev node or CNPG install cannot close this gate. |

For the first performance run, use the current dataset as the 1x profile and
10x as a **test profile, not a promised capacity**. Include skewed tenants,
late flows and an explicit retention hold. Record CPU/RAM/storage and query mix
with every result. Initial engineering budgets to validate are list/search
p95 <= 1 second, dashboard p95 <= 2 seconds, steady fold lag <= 2 minutes,
and raw-expiry backlog <= 2 maintenance intervals once aggregation permits
expiry. Run at least a 24-hour combined workload and a simulated full retention
cycle, then publish the actual supported envelope. These are qualification
targets, not customer SLAs; adjust with measured evidence and document changes.
Size reserves must cover WAL bursts, one failed cleanup interval, backup/restore
working space and other host consumers; set growth/free-space alerts before
expanding retention or onboarding larger fleets. Prefer partition expiry and
healthy routine vacuuming to routine `VACUUM FULL`, which requires an exclusive
lock and additional rewrite space ([PostgreSQL 16 maintenance guidance](https://www.postgresql.org/docs/16/routine-vacuuming.html)).

## October 12 partitioned-parent statistics maintenance

The API now periodically refreshes planner statistics for `network_flows`,
`events` and `findings`. PostgreSQL autovacuum analyzes their children but does
not maintain partitioned-parent statistics; see the
[PostgreSQL 16 maintenance guidance](https://www.postgresql.org/docs/16/routine-vacuuming.html#VACUUM-FOR-STATISTICS).
The worker runs under the API leader, with an additional transaction advisory
lock for installations without leader election. Every five minutes it selects
at most one parent whose PostgreSQL-reported last analysis is absent or older
than one hour. Targets resolve through the application connection's search path;
unrelated parents and non-partitioned tables are excluded.

Maintenance has a 30-second context budget, 25-second SQL statement limit,
one-second lock limit and 2 MiB ANALYZE buffer ring. It acquires the parent lock
without waiting, then uses `SKIP_LOCKED` for child analysis to avoid waiting on
busy child maintenance. It can still time out while sampling locked children;
failures are counted and retried on a later pass. Explicit ownership validation
prevents PostgreSQL's permission-skip warning from looking like success. A
skipped parent or failed transaction never increments the completed counter.
This updates statistics; it does not prune rows, rebuild indexes, vacuum tables
or change query-memory settings.

The Helm switch is `api.partitionStatisticsMaintenanceEnabled` (default `true`),
which sets `PARTITION_STATISTICS_MAINTENANCE_ENABLED`. Disable it when an external
maintenance service owns the same task. Metrics have only the three fixed table
labels: `constellation_partition_statistics_last_analyze_timestamp_seconds` and
`constellation_partition_statistics_completed_total`; failures and duration are
also exported. Last-analysis gauges include PostgreSQL-reported timestamps,
including analysis done outside this worker. Aggregate those gauges with `max`
across API replicas before computing age; followers initialize at zero. Alert
deployment and failure-injection qualification remain DB-23 work. A two-hour
age is an initial investigation threshold, not a query-latency guarantee.

On the independent restored copy, manual analysis with those SQL time/buffer
limits took **4.094 seconds for flows**, **5.141 seconds for events** and
**0.498 seconds for findings**. All three parents previously had unknown row
estimates (`reltuples=-1`). The distinct flow-organization estimate changed from
200 to 1, matching the measured single organization. These one-shot measurements
are not a concurrency or latency benchmark. Exact counts remained **2,723,972
flows, 153,178 rollups, 3,020,985 events and 1,905,903 audit entries**.

Validation: **342 repeated seeded race-test executions** passed, including
freshness, one-parent-per-pass, advisory-lock contention, conflicting parent
locks, cancellation, non-owner rejection and fixed metric labels. All **85
tooling tests**, ShellCheck and changed-code lint passed. A fresh production API
image completed one parent refresh and one session-cleanup pass, with matching
PostgreSQL statistics and exported metrics; six group/network browser cases
passed without retries. Evidence is in `/tmp/constellation-parent-stats-*.log`
and `/tmp/constellation-parent-stats-browser/`. No main-cluster database or
deployment was changed; DB-23 remains open for broader profiling and alarms.

## September 27 historical baseline

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

| ID | Status | Original failure / required work | Acceptance gate |
| --- | --- | --- | --- |
| DB-01 | **Implemented; live rollout open** | Replace `ctid`-only DELETEs from partitioned `events` and `network_flows` (`internal/handler/events_retention.go`, `internal/handler/network/rollup.go`). `ctid` is only unique within a child; a disposable PostgreSQL reproduction selected one expired row and deleted it **and a current row** with the same `ctid` in another partition. | Partitioned two-child test proves an expired row is removed and a current row survives; deploy the fix before relying on pruning. Treat historical event/flow completeness as unverified. |
| DB-02 | **Implemented; rollout/alarms open** | Never prune or drop raw flows until the rollup watermark and a successful fold cover them. The current refresh loop prunes even after a refresh failure, while the partition manager drops by age alone; late-arriving timestamps and `RefoldWindow` need a defined grace/replay contract (`internal/handler/network/rollup.go`, `internal/handler/partition_manager.go`). | Failure, lag, late-arrival, and refold-after-prune tests preserve counts; a visible fold-lag alarm blocks unsafe expiry. |
| DB-03 | **Implemented/tested; release acceptance open** | Make new installations bounded by default. Migration 137 updates only pre-existing `system_config` rows; `syscfg.Default()` and first-boot seeding otherwise leave retention at zero, meaning never prune (`internal/server/database/migrations/137_retention_defaults.sql`, `internal/syscfg/syscfg.go`, `internal/server/server.go`). | Fresh database install has explicit reviewed nonzero defaults; existing operator choices, including an explicit zero if allowed, are not silently overwritten. |
| DB-04 | **Conservative shared policy implemented; deployment open** | Choose installation-wide versus per-org retention. The leader currently reads the earliest org's settings for every org (`internal/server/leaderelection.go`). | Config API/UI, partition drops, row pruners, and tenant tests enforce one documented scope consistently. |
| DB-05 | **Local recovery passed; live/off-host gates open** | Establish real PostgreSQL backup/PITR and offsite copies before more destructive cleanup. The local deployment has no app backup schedule/catalog entries; org backups are not equivalent to a database restore and omit audit replay (`pkg/backup/restorer.go`, `deploy/charts/constellation/values.yaml`). | Scheduled backup, retained WAL or equivalent recovery points, independent restore drill, RPO/RTO evidence, and alerts on missed backups. |

## P1: evidence-preserving retention

| ID | Status | Required fix or decision | Acceptance gate |
| --- | --- | --- | --- |
| DB-06 | **Open — decision** | Classify control-plane audit separately from high-rate detection and job telemetry. Recent `runtime.alert.exec` and `scan-job.complete` dominate `audit_events`, but compliance mappings and APIs cite them (`internal/handler/runtime/events_ingest.go`, `internal/handler/scanning/scanjobs.go`, `pkg/audit/compliance.go`). | Document which receipts stay in the permanent chain and which move to a bounded evidence stream; migrate consumers and prove no evidence or authorization regression before suppressing old writes. |
| DB-07 | **Implemented/tested; deployment qualification open** | Version-2 archive segments use bounded ID catch-up, destination-specific locked progress, canonical row replay, signed boundary/checksum metadata and verified S3 read-back. See [archive contract](audit-archive.md). | Local PostgreSQL tests cover missed runs, backdated rows, rollback sequence gaps, replicas and safe replay after upload/read-back/commit failure. Actual destination capacity, compatibility and sustained catch-up remain deployment gates. |
| DB-08 | **Offline verification implemented; policy/off-host gates open** | Downloaded signed segments can be verified without PostgreSQL, including checksums, counts, ID order and every chain hash. Signing trust is required for durable cursor advancement. Immutable destination, access controls, rotation, legal hold and hot/search/archive periods still need operational decisions. | Local tamper and failure-injection tests pass. Complete multi-segment recovery on a fresh host, immutable retention and long-term availability remain unproven; individual segment replay does not implement historical query/restore services. |
| DB-09 | **TRUNCATE protected; hot/cold pruning design open** | Migration 191 closes the TRUNCATE gap; UPDATE/DELETE remain blocked, and demo seeding preserves audit rows. Full source verification still starts at genesis; no pruning or trusted hot/cold query anchor is introduced. | Local PostgreSQL rejects UPDATE/DELETE/TRUNCATE and preserves the chain. After DB-07/08 deployment acceptance, design trusted archive anchors and preserve audit, timeline, support, exception-history and admission-hit queries before pruning. |
| DB-10 | **Open — decision + fix** | Give `k8s_audit_events` its own raw/search/archive policy and ingestion-health alarm. It is unpartitioned, stores full JSON, and has no general prune path (`internal/server/database/migrations/131_k8s_audit.sql`). | Reviewed window and verified export precede cleanup; freshness and gap tests catch a stopped audit webhook. |
| DB-11 | **Open — decision + fix** | Bound `runtime_threats` and packet bytes, PCAP files/rows, and `forensics_snapshots` separately from control audit. `SweepExpired` for PCAPs has no confirmed production caller (`internal/server/database/migrations/041_runtime_threats.sql`, `internal/handler/runtime/runtime_pcap.go`, `internal/server/database/migrations/013_forensics.sql`). | Expired files and rows disappear on schedule, while selected case evidence remains exportable and verifiable. |
| DB-12 | **Open — decision + fix** | Set raw-flow versus hourly-rollup windows and historical map/CSV behavior. `network_flow_rollups` is unbounded, and refolding can erase buckets whose raw rows have expired (`internal/server/database/migrations/115_network_flow_rollups.sql`, `internal/handler/network/rollup.go`). | Rollup expiry is bounded, count-preserving, and respects DB-02; older UI ranges are explicitly unavailable or served from an archive. |
| DB-13 | **Open — decision + fix** | Define lifecycle-aware retention for `findings`. All current findings land in a DEFAULT child despite time partitioning; open findings and triage must not vanish by age alone (`internal/server/database/migrations/004_findings_partitioned.sql`). | Resolved/orphaned findings archive by policy; open/suppressed/accepted decisions remain visible; partitions or another bounded layout avoid default-child bloat. |
| DB-14 | **Open — decision + fix** | Set separate policies for terminal versus stuck `scan_jobs`, attempts, named `image_scan_results`, registry results, and repository targets. Existing job TTL and orphan-digest cleanup do not bound all named results or verification history (`internal/handler/events_retention.go`, `internal/handler/repository_retention.go`). | Current/latest results and referenced attestations survive; stale jobs recover; historical results expire only after evidence and dependency checks. |
| DB-15 | **Open — decision + fix** | Classify large `scan_evidence`, SBOM documents, image artifacts, scan attestations and verification records as current cache or durable evidence (`internal/server/database/migrations/063_scan_evidence.sql`, `internal/server/database/migrations/003_assets_and_images.sql`, `internal/server/database/migrations/084_scan_result_attestations.sql`). | A reference graph and restore test protect live decisions; size/age caps bound replaceable payloads. |
| DB-16 | **Current identity cleanup reverified; operational gates open** | After migration 187, the leader worker bounds expired OIDC login attempts and opaque identity sessions, plus five-minute network snapshots/kill requests. Current sessions and audit receipts survive. Cleanup metrics now name the current tables; other histories remain DB-17. | Real PostgreSQL batch/lock-skip/composite-key/partial-failure tests pass on the migrated schema. Live rollout, backlog/failure alarms and sustainable cleanup throughput remain open. |
| DB-17 | **Open — decision + fix** | Set retention for receiver deliveries, compliance runs, support-bundle job metadata, restart events, and admission dry-run history; distinguish operational logs from evidence (`internal/server/database/migrations/020_settings_receivers_role_bindings.sql`, `internal/server/database/migrations/039_compliance_schedules.sql`). | Every high-rate history table has an owner, window, cleanup job, and an evidence exception where needed. |

## P1/P2: CVE, cache, and operations

| ID | Status | Required fix or decision | Acceptance gate |
| --- | --- | --- | --- |
| DB-18 | **Implemented/tested; live qualification open** | Conditional merged-row updates skip identical/sparse repeats. Migration 170 adds bounded durable KEV/EPSS content hashes and NVD completed-window cursors; source changes, malformed/partial feeds, transaction failure, restart and replica overlap have real PostgreSQL regressions. See [checkpoint contract and evidence](cve-feed-checkpoints.md). | A 1,200-row unconditional replay rewrote 1,200 tuples/~1.35 MB WAL; three checkpointed repeats rewrote no tuples/checkpoints and measured zero extra WAL. Validate real-feed cadence and production WAL/dead-tuple growth after rollout; this local fixture is not fleet capacity proof. |
| DB-19 | **Open — decision + fix** | Define whether CVE `sources` and KEV flags are current membership or historical observations. The upsert can replace `sources` and only sets `kev_listed` true; NVD is opt-in and scans only a trailing 120-day modified window (`internal/handler/findings/cve_records_writer.go`, `internal/handler/findings/nvd_import.go`). | Feed withdrawal/update tests, full-bootstrap path, offline recovery, and published catalog-completeness/freshness semantics. |
| DB-20 | **Open — decision** | Keep the current PG `cve_records` API catalog unless a measured reason justifies a new format. Another PG database on the same storage does not save space; first profile wide descriptions/TOAST and index use, then evaluate a rebuildable compact projection (`internal/handler/findings/cve.go`). | Search, detail, CVSS/KEV/EPSS filters, stats, and restore behavior meet a size and latency budget without resurrecting retired VulnDB. |
| DB-21 | **Explicit cache topology/diagnostics/monitoring implemented; live qualification open** | Choose scanner-cache topology: one 8 GiB PVC-backed replica or multiple replicas with pod-local caches. Today's local cache uses about 5.7 GB; chart default multi-replica topology does not share the RWO cache (`deploy/charts/constellation/templates/scanner-cache-pvc.yaml`). | Cache free-space and DB-freshness alerts, restart/refresh/offline tests, and a capacity margin for both Trivy and Grype. |
| DB-22 | **Open — decision + fix** | Define backup-artifact retention separately from database PITR. Existing scheduled org-backup pruning is opt-in and only handles succeeded org backups/local files; scheduled S3 destination fields are not consumed by that executor (`pkg/backup/executor.go`). | Minimum recoverable copies, proven offsite upload, object lifecycle, failed/manual artifact cleanup, signature checks, and periodic restore evidence. |
| DB-23 | **Ten storage-observability items implemented/tested; remaining signals/live qualification open** | Bounded read-only metrics now cover database/relation allocation, dead/live estimates, DEFAULT branches, rollup watermark, active archive ID progress, per-schedule backup health and WAL generation. Failed snapshots invalidate data; release-scoped rules and an optional Grafana dashboard ship with executable PromQL fixtures. See [storage-health contract/runbook](storage-health.md). | Real PostgreSQL and 75 Prometheus scenarios cover failure/recovery, tenant scope, stale progress and alert suppression. Live scrape/notification/Grafana validation, capacity budgets, raw retention/drop lag, retained WAL occupancy and live scanner-cache headroom qualification remain open; existing CNPG/PVC/feed/engine rules are preserved. |

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

## October 12 implementation update

Migration 169 adds persistent ordered producer cursors. Event/flow agents now use
bounded node disk queues, matching durable acknowledgements and Retry-After;
ingestion batches PostgreSQL writes and commits flow rule hits with the raw rows.
See [telemetry delivery](telemetry-delivery.md) for exact guarantees and gaps.
Independent rollup progress, byte/rate quotas, durable side effects, 24-hour fleet
qualification and live rollout remain open. The separately requested
[ClickHouse plan](CLICKHOUSE-PLAN.md) specifies a measured analytical-store
evaluation, not an installed second database.


## October 23 source reverification

Source baseline `f63b06072f09424660f1a456f3adae3882cb4e9f` was reviewed alongside
H9–H12 in the [ten-item continuation](security-testing.md#ten-item-security-and-lifecycle-continuation-2026-10-23).
These are fresh source/database checks, not a new deployment or capacity claim.
They do not close rollout, alarms, recovery, off-host or load acceptance gates.

| Item | Verified behavior | Evidence |
| --- | --- | --- |
| DB-01 | Event and flow pruning preserves current rows with colliding partition-local tuple identities; batches and row locks are respected. | `TestEventsRetentionPartitionIdentityAndLocks`, `TestFlowRetentionPartitionIdentityAndBatch` |
| DB-02 | Failed/lagging folds prevent raw expiry; late arrivals and refolds retain counts after pruning. Partition drops wait for folded history and exclude active ingest. | `TestRollupFailureAndLagBlockRetention`, `TestRollupLateArrivalPruneAndRefoldPreserveHistory`, `TestFlowPartitionExpiryRequiresFoldedHistory` |
| DB-03 | Fresh persisted defaults are 30-day events, 14-day flows and 7-day jobs. Repeated bootstrap preserves explicit zero holds and custom windows. | `TestRetentionFirstBootSeedPreservesExistingPolicy`, `TestRetentionDefaultsPreserveStoredHolds` |
| DB-04 | Each family takes the longest organization window; a hold affects its family, and invalid/unreadable settings prevent expiry. The leader passes these resolvers to row and partition workers. | `TestEffectiveRetentionKeepsFamilyHoldsIndependent`, `TestEffectiveRetentionRespectsEveryOrgAndFailsClosed`, `TestRollupExplicitZeroRetentionOverridesEnvironment`; `internal/server/leaderelection.go` inspection |
| DB-16 | Current OIDC attempts/sessions and network snapshots/kill requests are reaped in bounded batches, skip locks, retain current records across reused IDs, and preserve audit evidence. Partial failures report completed work. | `TestSessionCleanupCurrentIdentityTablesAndCompositeKeys`, `TestSessionCleanupFailurePreservesPartialProgress` |
| DB-18 | Identical feeds avoid row/checkpoint rewrites; corrected content changes data; failures roll back data and cursors; replica locks, restart, catch-up and mirror changes preserve progress. | `TestCVEFeedCheckpointRestartCorrectionAndRollback`, `TestCVEFeedReplicaLockAndCancellation`, `TestNVDCheckpoint*` |

The DB-16 regression exposed outdated observability names after the identity
cutover. `constellation_session_cleanup_deleted_total` now uses family values
`oidc_login_attempts` and `identity_sessions` instead of `refresh_tokens` and
`user_sessions`; cleanup log fields use the same names. Custom queries using the
old label values must be updated. The deletion queries and retention windows did
not change. No database migration or live cleanup was performed for this follow-up.

## October 23 scanner-cache diagnostics continuation

Ten diagnostic implementation items now cover exclusive probes, probe cleanup
errors, path-state classification, filesystem byte capacity, inode headroom,
bounded directory enumeration, root confinement/special-file exclusion, explicit
partial usage, stable records/checked totals, and API propagation. See the
[contract and validation](scanner-cache-diagnostics.md). This supplies DB-21/23
prerequisites without selecting topology, deploying alerts, evicting caches or
claiming refresh/restart/offline capacity qualification.

## October 23 scanner-cache monitoring continuation

Ten [scanner-cache monitoring items](scanner-cache-monitoring.md) now supply
read-only byte/inode capacity, explicit path states, serialized TTL collection,
failed-sample invalidation, bounded private labels and scoped pressure,
configuration, collection and discovery alerts. The chart's existing scanner
ServiceMonitor discovers the metrics; eight alert rules have executable PromQL
fixtures. DB-21/23 topology, refresh/offline/restart qualification, capacity budgets
and live scrape/notification acceptance remain open. No live resources changed.

## October 23 storage-alert isolation continuation

Ten [storage-alert isolation fixes](storage-health.md#ten-storage-alert-isolation-fixes-2026-10-23)
now retain optional cluster/Prometheus labels across nine data-alert health joins,
suppress stale data after failed scrapes and expose missing/failed exporters per
discovered target. The rendered rules pass 75 executable PromQL scenarios; restoring
the old joins/absence behavior fails all ten selected negative controls. DB-23
live activation, capacity, profiling and recovery gates remain open. Collector
queries, retention policies and live deployments were not changed.

## October 23 scanner cache topology continuation

Ten [cache topology/lifecycle fixes](scanner-cache-topology.md) make pod-local
storage explicit, reject incompatible persistence, isolate managed claim identities
and scanner Service routing by release, support external claims/retained managed
claims and add optional cache/tmp limits. Existing persistent installations must
preserve mode and claim identity when upgrading. DB-21 remains open for live
attachment, offline replacement, refresh/restart capacity and alert qualification.
No cluster resources or cache contents were changed during this implementation.
