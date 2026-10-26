# Database and storage lifecycle backlog

**Latest local verification:** October 26 runtime-threat archive qualification, October 24 partitioned flow qualification and the reconciled register below; earlier [October 23 source results](#october-23-source-reverification) remain available. Operational and deployment gates remain separate.

## October 23 completion pass

Current conservative decisions are recorded in [the retention policy](storage-retention-policy.md). Merged implementation is distinct from deployed operational acceptance.

The owner requested completion of DB-01–23, including implementation and
qualification. Work is tracked by the original IDs below, not by counting small
fixes as completed backlog items. Earlier dated observations are historical.

The owner subsequently directed **code and local verification only**, with GitHub
Actions kept disabled. Release publishing, live rollout and live alert delivery
are deferred; off-host recovery and real node-failure deferrals remain in place.
These operational gates are not requests for further approval.

Independent complete-chain replay is now available through
`audit-archiver --verify-chain-dir`, with an independently trusted head digest.
Local PostgreSQL fixtures cover three signed segments, missing/corrupt segments,
truncated heads, stream/link changes and cancellation. This does not clear the
historical row-53 discontinuity or implement hot-chain deletion.

A fresh read-only cluster check at approximately 16:46 UTC found one healthy
CNPG instance (`constellation-cnpg-postgres`), database migration **190**, an
8,702 MiB database, `archive_mode=on`, a recent successful WAL archive and zero
reported archive failures. The scheduled October 23 02:00 backup is completed.
The old statements that the live database is still a StatefulSet at migration
167 with archiving off are superseded by this observation. This does not prove
independent recovery, immutable retention, or separate-node availability.
PCAP maintenance is already wired through `internal/server/runtime_maintenance.go`;
its opt-in durable-store guard still applies. The prior statement that it has no
production caller is superseded.

| IDs | Remaining completion work |
| --- | --- |
| DB-01–04 | Local [110,000-flow concurrent ingest/fold/raw-retention qualification](flow-rollup-retention.md#local-ingest-fold-and-raw-retention-qualification) preserves exact counts/bytes across separate partitions and late arrivals. Deployed behavior/policy and fold-lag notification remain deferred; historical loss is not repaired. |
| DB-05 | Verify current scheduled recovery points with a fresh isolated restore, record RPO/RTO, and qualify failure notification; off-host and real node-failure gates remain deferred unless explicitly resumed. |
| DB-06 | Decision complete: preserve all existing permanent audit receipts and consumers; no suppression or stream migration. See [retention decisions](storage-retention-policy.md). Archive capacity remains DB-07–09/23. |
| DB-07–09 | Qualify signed archive catch-up/read-back and independent verification; resolve the recorded historical chain discontinuity without rewriting hashes; design trusted query anchors before any hot-chain deletion. |
| DB-10 | Explicit per-source Kubernetes-audit freshness/gap metrics and alerts are implemented and locally tested; no global latest-event shortcut. [Signed paged export and independent recovery](k8s-audit-archive.md) are now implemented; scheduled archival and hold-aware source retention remain open. |
| DB-11 | [Signed runtime-threat export and independent packet recovery](runtime-threat-archives.md) are implemented and locally tested. Qualify existing PCAP maintenance; scheduled archival, case/forensics dependency recovery and hold-aware retention remain open. |
| DB-12 | [Hourly retention](flow-rollup-retention.md) is implemented with a separate policy, raw-boundary gate, monotonic unavailable-history boundary, late-ingest exclusion and HTTP 410 for expired map/CSV ranges. Existing settings remain holds; live qualification remains open. |
| DB-13 | Preserve open/triaged findings; implement eligible resolved/orphaned archival and bounded storage. |
| DB-14–15 | [Reference protections](scan-evidence-retention.md) now preserve newest/referenced jobs and results, all findings and inventory/attestation evidence; bounded cleanup rechecks references under locks. Signed single-inventory export, offline verification and explicit scoped recovery now pass independent-database tests. Named-history and complete payload/dependency archival/restoration remain open; no pruning is authorized. |
| DB-16 | Local 400,000-row cleanup/foreground-concurrency qualification passed with live state and audit preservation; active-worker stalled/failure rules are locally evaluated. Scheduled capacity is explicitly distinguished from burst SQL throughput. Live deployment/delivery remain deferred. |
| DB-17 | Per-family [retention classification](storage-retention-policy.md) is recorded. Existing support-bundle payload expiration is bounded; explicit admission-history clears now have row/time budgets and atomic audit receipts. Delivery/compliance/restart archives and bounded retained metadata remain open. |
| DB-18–20 | Real KEV/EPSS replay qualification passed (394,803 rows, no replay rewrites/WAL). Historical source/KEV semantics and opt-in resumable NVD backfill are implemented; measured catalog indexing keeps PostgreSQL. Source deployment and full NVD mirror traversal remain operational gates. See [catalog decision](cve-catalog-capacity.md) and [feed contract](cve-feed-checkpoints.md). |
| DB-21 | Real Trivy/Grype package matching passed across two network-isolated container starts using unchanged private DB copies; missing DBs fail closed. Live topology, refresh/extraction headroom and notifications remain separate gates. |
| DB-22 | Scheduled destinations upload/read-back and bounded local retention are implemented. The copy floor requires available files and keeps remote/failed receipts; manual successful local backups already share this policy. Independent signed local-file and local-object-store configuration restoration into a separate database now pass. Remote lifecycle/off-host durability remain open, separate from PostgreSQL PITR. |
| DB-23 | Complete remaining lag/WAL signals, activate/qualify monitoring, and measure supported workload/capacity with failure recovery. |

No new evidence deletion or live rollout has been performed in this completion
pass. Local code/test success alone does not close operational gates.

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
| DB-02 | **Implemented/local concurrency qualified; live gates deferred** | Refresh failure and watermark lag block raw expiry; late arrivals and refolding share the retention lock/boundary contract. The original prune-after-failure and age-only drop defects are fixed. | Failure/lag regressions and the 110,000-flow partitioned concurrency fixture preserve counts and bytes. Live fold-lag notification remains deferred; historical loss is not repaired. |
| DB-03 | **Implemented/tested; release acceptance deferred** | Fresh-install defaults and seeding now set reviewed nonzero retention. Existing operator choices, including explicit zero holds, remain unchanged. | Fresh/migrated configuration tests pass. Live 3/7/7 policies were preserved; release acceptance remains deferred. |
| DB-04 | **Conservative shared policy implemented; deployment deferred** | Shared retention uses the longest organization window and any zero holds cleanup. The original earliest-org shortcut is superseded. | Config, partition/row maintenance and tenant tests enforce the shared policy; deployment remains deferred. |
| DB-05 | **Local archive recovery/migrations qualified; off-host/failure gates deferred** | A fresh isolated CNPG restore from the local object-store archive reached database readiness in 10m17s; migrations 190–194 preserved recorded counts. Temporary resources were removed. | This is database readiness, not application RTO or marker-based RPO. Off-host recovery, real node failure and live failure notification remain deferred; the pre-existing audit break survived unchanged. |

## P1: evidence-preserving retention

| ID | Status | Required fix or decision | Acceptance gate |
| --- | --- | --- | --- |
| DB-06 | **Decision complete: retain all permanent receipts** | Runtime detection and scan completion receipts remain in the append-only audit chain with existing consumers. No suppression or stream migration is authorized by this retention policy. | The [classification decision](storage-retention-policy.md) preserves audit semantics. Archive capacity and query/pruning work remain DB-07–09/23. |
| DB-07 | **Implemented/tested; deployment qualification open** | Version-2 archive segments use bounded ID catch-up, destination-specific locked progress, canonical row replay, signed boundary/checksum metadata and verified S3 read-back. See [archive contract](audit-archive.md). | Local PostgreSQL tests cover missed runs, backdated rows, rollback sequence gaps, replicas and safe replay after upload/read-back/commit failure. Actual destination capacity, compatibility and sustained catch-up remain deployment gates. |
| DB-08 | **Offline complete-chain verification implemented; external durability gates open** | Downloaded segments and complete linked chains verify offline using an independently trusted key and head digest. Bounds, signatures, checksums, IDs, predecessor links and chain hashes are checked. | Local independent replay/tamper/missing-segment tests pass. The historical row-53 discontinuity is not bypassed. Fresh-host recovery, immutable object policy and long-term availability remain unproven. |
| DB-09 | **TRUNCATE protected; hot/cold pruning design open** | Migration 191 closes the TRUNCATE gap; UPDATE/DELETE remain blocked, and demo seeding preserves audit rows. Full source verification still starts at genesis; no pruning or trusted hot/cold query anchor is introduced. | Local PostgreSQL rejects UPDATE/DELETE/TRUNCATE and preserves the chain. After DB-07/08 deployment acceptance, design trusted archive anchors and preserve audit, timeline, support, exception-history and admission-hit queries before pruning. |
| DB-10 | **Per-source health and paged recovery implemented; retention open** | Explicit organization/cluster source configuration detects missing, stale, delayed and unknown-reported timestamps independently. No global latest-event shortcut or fabricated reported timestamp remains for new ingress. | PostgreSQL and PromQL failure/recovery tests pass. Signed export/offline verification and independent-database scoped restore pass local tests. Scheduled archival and hold-aware source retention remain open; live delivery is deferred. |
| DB-11 | **PCAP maintenance wired; broader evidence lifecycle open** | The runtime maintenance caller invokes bounded PCAP expiry only with a verified durable store. The earlier claim that it had no production caller is superseded. Threats, packet bytes and forensic snapshots need separate case-evidence/archive handling. | Existing file/receipt failure behavior is tested. No new age-only threat or forensic deletion is introduced; selected evidence restoration and broader lifecycle remain open. |
| DB-12 | **Implemented/local tests passed; live gates deferred** | Migration 196 and the [hourly retention contract](flow-rollup-retention.md) provide a separate window, bounded raw-boundary-gated cleanup, monotonic unavailable-history boundary and late-ingest exclusion. | Existing values remain holds; new defaults are 90 days. PostgreSQL and HTTP tests preserve counts and return 410 for expired map/conversation/CSV ranges. Live rollout remains deferred. |
| DB-13 | **Preservation policy set; archive/layout open** | Define lifecycle-aware retention for `findings`. All current findings land in a DEFAULT child despite time partitioning; open findings and triage must not vanish by age alone (`internal/server/database/migrations/004_findings_partitioned.sql`). | Resolved/orphaned findings archive by policy; open/suppressed/accepted decisions remain visible; partitions or another bounded layout avoid default-child bloat. |
| DB-14 | **Reference protection implemented; named-history archive open** | Bounded job/result/repository maintenance locks candidates and rechecks references under READ COMMITTED. Latest/live/referenced records and all findings survive. | Real reference-race and boundary tests pass. Full named-result/job-history archival and dependency-aware restoration remain open; age alone does not authorize evidence removal. |
| DB-15 | **Single-inventory recovery implemented; complete graph lifecycle open** | Signed package-inventory export/offline verification/scoped restore has an independent-database recovery test and atomic audit receipt. It neither deletes source evidence nor archives complete SBOM/result/attestation dependency graphs. | Size/signature/scope/conflict/rollback tests pass for the single-record primitive. Full dependency restoration, durable archive scheduling and payload cleanup remain open. |
| DB-16 | **Cleanup/load/alerts locally qualified; live gates deferred** | Bounded identity/login/network-session cleanup preserves live state and audit receipts. A 400,000-expired-row fixture measures foreground concurrency and WAL; active-worker stall/failure rules avoid idle-follower alarms. | PostgreSQL and PromQL tests pass. Immediate SQL drain is not scheduled capacity: 1,000 rows/family/minute remains the production budget. Live rollout/delivery and fleet sizing remain deferred. |
| DB-17 | **Classification and bounded manual clearing complete; broader lifecycle open** | Per-family ownership/holds are recorded. Existing support payload expiry is bounded; explicit admission-history clearing now has a 1,000-row/five-second budget and atomic audit receipt. | Batch, lock, tenant and commit-failure tests pass. Delivery/compliance/restart archives and bounded retained metadata remain open; no automatic evidence-history expiry was added. |

## P1/P2: CVE, cache, and operations

| ID | Status | Required fix or decision | Acceptance gate |
| --- | --- | --- | --- |
| DB-18 | **Implemented; real-feed replay locally qualified** | Conditional merged writes and durable checkpoints avoid identical/sparse rewrites. Real KEV/EPSS replay covered 394,803 rows with no replay rewrites or extra WAL; malformed/partial/restart/replica regressions pass. | Production cadence and fleet WAL/dead-tuple growth remain deferred. The local fixture is not fleet capacity proof; see the [feed contract](cve-feed-checkpoints.md). |
| DB-19 | **Historical semantics/backfill implemented; full traversal unqualified** | Sources, aliases and KEV preserve historical observations; EPSS freshness uses its score timestamp. Opt-in resumable NVD bootstrap covers historical modified windows while current updates retain priority. | Withdrawal/sparse-update/replay tests pass. Full real NVD mirror traversal and source deployment remain operational qualification work. |
| DB-20 | **Storage decision complete: retain PostgreSQL** | A restored 412,772-row catalog profile justified targeted indexing, not another database format. The measured default page improved from about 497 ms to 0.258 ms with about 26 MiB additional index allocation. | Local catalog/restore evidence supports the decision; broader workload/fleet capacity is DB-23. Retired VulnDB is not reintroduced. |
| DB-21 | **Topology/health and offline process recovery qualified; live capacity open** | Explicit pod-local/single-PVC topology and diagnostics are implemented. Real Trivy/Grype matching passed twice in fresh network-isolated containers with unchanged private copies of 4,954,046,907 DB bytes; missing databases fail closed. | This proves local package matching across process replacement, not live PVC attachment, full image extraction, refresh overlap headroom or notification delivery. No claim that 8 GiB is sufficient. |
| DB-22 | **Scheduled read-back/local recovery and retention implemented; remote lifecycle open** | Scheduled S3 destinations are consumed and verified by independent read-back. Local cleanup is bounded, locked and opt-in; the protected newest-copy floor requires available safe files. Signed local-file and local-object-store configuration restores into separate databases pass. | Organization backups remain distinct from PostgreSQL PITR and exclude operational evidence/secrets. Remote/failed receipts stay held; off-host recovery, object lifecycle and broader failed-artifact cleanup remain open. |
| DB-23 | **Storage signals and local qualification implemented; fleet/live gates open** | Read-only database/relation/WAL/partition/archive/backup/audit-source signals and active-worker cleanup alarms ship with 21 storage rules and 137 PromQL scenarios. Local catalog, session, scanner and flow concurrency fixtures record measured limits. | Live scrape/notification/Grafana validation, fleet budgets, full event/HTTP ingestion and scanner refresh/extraction headroom remain unqualified. Local burst SQL measurements do not establish production cadence or capacity. |

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

## October 24 next-ten code/local batch

These are ten concrete deliverables, not ten additional closed DB IDs. Actions,
release publishing and live rollout remain disabled/deferred as instructed.

1. Kubernetes-audit export explicitly scoped by organization, cluster and receipt-time window.
2. Exclusive `(at,id)` continuation with row/byte budgets and oversized-row holds.
3. Trusted signed-page verification independent of the source database or AWS.
4. Explicit destination recovery with atomic audit receipts, conflict rejection and idempotent replay.
5. Operator CLI export, verify and restore workflows with independent-database qualification.
6. Private archive publication with directory sync and exact-byte/signature read-back before success.
7. Strict archive JSON parsing: duplicate/escaped keys, unknown fields, invalid UTF-8 and depth/trailing guards.
8. Cancellation checks during archive reads, compressed hashing and decompression.
9. Inventory restore rejects and locks against cross-organization destination cluster bindings.
10. Support payload expiry holds pending/missing audit receipts while preserving bounded lock-skipping cleanup.

The Kubernetes-audit pages do not form a cross-request source snapshot or prove
that no backdated event can arrive later. They authorize no source pruning.
Findings/attestation dependency archives, trusted hot/cold query anchors and the
other explicitly open lifecycle work remain tracked above.


## October 26 next-ten runtime-evidence batch

Ten code/local deliverables advance DB-11; they do not close ten original DB IDs:

1. Shared bounded signed-page encoding with distinct threat/audit format identities.
2. Runtime-threat export scoped to organization, cluster and receipt-time window.
3. Timestamp-tie-safe continuation and a concurrent source/cursor index (migration 198).
4. Row and byte budgets, oversized-record holds and cancellation-aware archive I/O.
5. Exact packet preservation, including null versus empty and arbitrary binary bytes.
6. Lossless persisted metadata and full unsigned-32-bit threat identifiers.
7. Trusted offline verification and private CLI publication with verified disk read-back.
8. Explicit destination recovery with organization validation and cluster locking.
9. Atomic audit receipts, whole-page conflict rollback and concurrent idempotent replay.
10. Independent-database/CLI recovery and byte-budget qualification with source/quarantine preservation.

No source expiry is enabled. Quarantine/case/forensics dependency archives,
scheduled immutable storage, trusted historical queries and the other open work
remain tracked above. Actions, live migration/deployment, off-host recovery and
real node-failure tests remain disabled/deferred under the owner's instruction.
