# Storage health metrics, alerts and operating limits

The API exports storage-health metrics on its existing admin `/metrics` listener.
It registers a read-only collector after migrations and does not expose these
signals through tenant HTTP APIs. Migration 192 adds the partial backup-history
index used by the reader and advances the startup schema gate.

This implements ten concrete observability items under DB-23: relation sizes,
dead-row estimates, DEFAULT occupancy, rollup lag, active archive progress,
organization-backup health, WAL generation, collector failure visibility,
executable alert tests, and a dashboard/runbook. It does not change retention,
trigger cleanup, enable live alerts, or establish database recovery coverage.

## Collection contract

Each API replica collects at most one complete snapshot per minute, on demand
when scraped. Concurrent scrapes share that snapshot. Reads use a read-only
transaction with a three-second overall collection deadline, 2.5-second SQL
statement timeout and 250-millisecond lock timeout. PostgreSQL catalog estimates
replace full row counts on high-volume tables. The archive lookup uses primary
keys; each enabled backup schedule uses the latest-success partial index.
Collection cost still grows with the number of partitions and schedules, and the
deadline remains a hard failure boundary rather than a claim of constant cost.

If any query fails, the collector removes its cached storage values, emits
`constellation_storage_collector_up=0`, increments its error counter and retains
the previous last-success timestamp. It waits until the next one-minute refresh
before retrying, avoiding scrape-driven query storms. Missing monitored tables
are errors, not empty tables. Metrics from an old successful snapshot are never
re-emitted as healthy after a known failure. Between refreshes, observations can
be up to one minute old; progress metrics are timestamps so PromQL computes age
at evaluation time.

All metrics below have the `constellation_storage_` prefix. Only the 14 fixed
relation names and fixed `kind` values become application labels. Tenant IDs,
user-controlled partition names, stream hashes, endpoints, buckets, object keys
and backup paths are excluded. Prometheus supplies scrape target labels such as
`namespace`, `service`, `job` and `instance`.

| Signal | Metrics and interpretation |
| --- | --- |
| Database/relation allocation | `database_bytes`; `relation_bytes{table,kind="table\|indexes\|total"}`. Sizes sum physical leaves once; table bytes include TOAST. Database size excludes WAL and is not free space. |
| Row estimates | `relation_rows_estimate{table,kind="live\|dead"}`. PostgreSQL statistics, not exact current counts. Partition-parent estimates are excluded to avoid double-counting leaf rows. |
| DEFAULT occupancy | `default_partition_bytes{table}` and `default_partition_rows_estimate{table}`. Catalog ancestry identifies DEFAULT branches even after renaming or nested partitioning. Allocated bytes can remain after rows are removed. |
| Rollup progress | `rollup_watermark_timestamp_seconds`. `time() - watermark` measures lag; the epoch means the watermark has never advanced. Existing fold-gated expiry remains unchanged. |
| Archive progress | `archive_enabled`, `archive_checkpoint_present`, `archive_source_head_id`, `archive_last_id`, `archive_pending_id_distance`, `archive_updated_timestamp_seconds`. Only the configured destination is observed. ID distance includes rolled-back sequence gaps and is not a row count. Integer subtraction precedes Prometheus conversion, preserving a one-ID gap above 2^53. No checkpoint is represented explicitly, not hidden. |
| Organization backups | `backup_enabled_schedules`, `backup_schedules_without_success`, `backup_failed_schedules`, `backup_oldest_success_timestamp_seconds`, `backup_oldest_due_timestamp_seconds`. The oldest of each enabled organization's latest successes cannot be hidden by another organization's fresh backup. Disabled schedules are excluded. |
| WAL generation | `postgres_wal_generated_bytes_total`, `postgres_wal_stats_reset_timestamp_seconds`. Instance-wide cumulative generation, including other databases, not retained WAL files or disk occupancy. Use `rate`; resets are expected. |
| Collector health | `collector_up`, `collector_last_success_timestamp_seconds`, `collector_duration_seconds`, `collector_errors_total`, `collector_queries_total`. The query counter counts snapshot attempts, not individual SQL statements. |

The fixed relation roots are `events`, `network_flows`, `findings`, `audit_events`,
`cve_records`, `network_flow_rollups`, `k8s_audit_events`, `runtime_threats`,
`runtime_pcap_captures`, `forensics_snapshots`, `scan_jobs`, `image_scan_results`,
`scan_evidence` and `backups`.

An enabled backup schedule with no `next_run_at` uses its creation time for
initialization-lag detection. A weekly schedule is not judged by a hard-coded
daily backup-age limit: overdue alerts follow its actual next due time. The
oldest-success gauge excludes schedules with no success; inspect the separate
missing-success count as well. Catalog status does not prove that the artifact
still exists, is verified, is off-host, or can restore PostgreSQL/PITR.

Archive monitoring uses the same destination identity function as the publisher.
The chart passes bucket/prefix and explicit, S3-specific and generic endpoints to
the API. Runtime precedence is the same as publication, including empty values
resolved from Secrets. Disabled archiving produces `archive_enabled=0` and no
archive-progress gauges. An idle archive with no pending IDs does not fire a
stalled-progress warning. Retired destinations do not affect the active signal.
For non-chart deployments, set the `CONSTELLATION_STORAGE_ARCHIVE_ENABLED`,
`_BUCKET`, `_PREFIX`, `_ENDPOINT`, `_ENDPOINT_S3` and `_ENDPOINT_DEFAULT` environment
variables consistently with the publisher (`_` abbreviates the shared
`CONSTELLATION_STORAGE_ARCHIVE` prefix here). Avoid hidden SDK profile endpoint
changes that bypass explicit configuration.

## Enable monitoring through Helm

```yaml
api:
  metrics:
    serviceMonitor:
      enabled: true
      labels: { release: kube-prometheus-stack }
metrics:
  prometheusRule:
    enabled: true
    labels: { release: kube-prometheus-stack }
    storage:
      enabled: true
      # Review these warning budgets against the actual installation.
      databaseBytes: 12884901888
      relationBytes: 2147483648
      defaultPartitionBytes: 134217728
      deadRowRatio: 0.2
      deadRowsMinimum: 10000
      rollupLagSeconds: 600
      archiveStallSeconds: 3600
      archivePendingIDDistance: 10000
      backupOverdueSeconds: 3600
      walBytesPerSecond: 104857600
      walRetainedBytes: 4294967296
      rawRetentionLagSeconds: 3600
      partitionExpiryLagSeconds: 3600
  storageDashboard:
    enabled: true
    labels: { grafana_dashboard: "1" }
```

The parent PrometheusRule toggle and dashboard toggle remain off by default.
When rules are enabled, storage rules are included unless their own toggle is
false. Positive thresholds are validated; `deadRowRatio` must also be below one.
They are warning budgets, not deletion thresholds or approved retention windows.

Rules are scoped to this release's namespace and API Service. Standard
ServiceMonitor discovery supplies those labels; annotation-based scraping must
supply matching `namespace` and `service` labels. Each data alert joins the
collector-health and scrape-health signals for the same complete target label set,
ignoring only the application labels `table` and `kind` where needed. This retains
optional cluster/Prometheus labels, preventing a healthy target elsewhere from
validating a failed read at the same address. A failed scrape suppresses stale
capacity/progress warnings. The missing-metrics rule reports discovered targets
with failed scrapes or missing collectors, plus completely absent discovery. Existing DB-health collector query failures now have an alert
because its cached feed/component ages can otherwise look current during failure.

The optional ConfigMap contains a 18-panel Grafana dashboard, selected by the
usual dashboard-sidecar label. It does not install Grafana. Choose the Prometheus
data source, namespace and API service. Replica observations of the same database
are combined with max/min, not summed. The dashboard includes 19 checked PromQL
expressions; it can also be imported directly from
`deploy/charts/constellation/files/storage-dashboard.json`.

## Response and safe reclaim

- Collector failed/absent: check API admin scraping, target labels, database
  connectivity, migration level, grants and locks. Data panels are intentionally
  absent after query failure. Restore collection before treating missing data as
  zero storage usage.
- Database/relation/default growth: inspect the table and existing kubelet PVC
  free-space alerts. Check partition routing and retention-worker failures.
  Findings currently use a DEFAULT child, so an alert is not permission to drop
  it. Size forecasts and installation-specific capacity tests remain necessary.
- Dead-row estimates: inspect autovacuum, stale statistics, long transactions and
  replica/replication-slot pressure. Prefer healthy normal maintenance and safe
  existing partition expiry. Do not use routine `VACUUM FULL`, manual audit
  DELETE/TRUNCATE, or broad orphan cleanup as an automatic response.
- Rollup lag: inspect failed folds and preserve raw evidence. Do not bypass the
  existing watermark guard to force a partition drop.
- Archive stalled/behind: verify the current destination, CronJob, signing trust,
  object permissions and read-back errors. Follow [archive replay](audit-archive.md)
  before relying on copies. Never manually advance a cursor over missing evidence.
- Backup failed/overdue: inspect the organization's schedule and executor logs,
  signing and storage availability. Verify a retained artifact and rehearse
  recovery. Existing CNPG backup/WAL-archive alerts and independent PITR drills
  remain necessary; this dashboard does not replace them.
- High WAL generation: identify write amplification and failed archiving. Use the
  existing CNPG/PVC/node signals for disk risk. This counter does not authorize
  deleting WAL files. Take recovery points before any reviewed storage change.

Disable the storage rule group or dashboard through Helm if unsuitable for an
installation; existing generic monitoring is independent. Do not drop migration
192 or reset archive cursors as a monitoring rollback. No destructive action is
performed by these collectors, rules, or dashboard.

## Local acceptance and remaining DB-23 work

Real PostgreSQL tests cover physical/default partition accounting, dead-row
statistics, least-privilege reads, active/missing/invalid archive progress,
backup tenant aggregation, uninitialized schedules and the indexed lookup plan,
concurrent cache hits, failed-query invalidation/recovery, missing tables and
lock deadlines. `scripts/test-helm-storage.sh` renders chart wiring and evaluates
102 scenarios with Prometheus `promtool`, including failing and healthy conditions,
disabled/idle archives, absence and per-replica joins. It also parses all dashboard
queries. Set `PROMTOOL` to a local binary or preload the digest-pinned Prometheus
3.15.0 test image; tests do not pull images or use the network. The CI workflow
preloads that image when CI is enabled. GitHub Actions remains disabled here.

This closes the ten scoped implementation items, not all of DB-23: live scrape
and notification delivery, Grafana rendering, capacity qualification, exact raw-row
expiry backlog measurements and live scanner-cache filesystem headroom qualification
still require follow-up. Raw-flow progress, actual expired partition bounds and
retained WAL occupancy now have the signals described below. Scanner-local metrics and tested
alerts now ship under the [cache monitoring contract](scanner-cache-monitoring.md). Existing volume, scanner-engine and feed alerts
are retained rather than duplicated. No live cluster, database retention or
alerting configuration was changed for this work.

## Ten storage-alert isolation fixes (2026-10-23)

The following nine data alerts now require both a successful collector snapshot
and a healthy scrape from the same complete target. All target labels are
preserved; only the application's `table` and `kind` dimensions are excluded from
joins to target-level health. Thresholds, severities and hold periods are unchanged.

| Item | Alert | Preserved application dimensions |
| --- | --- | --- |
| 1 | `ConstellationDatabaseSizeHigh` | None |
| 2 | `ConstellationRelationSizeHigh` | Table and size kind |
| 3 | `ConstellationDeadRowsHigh` | Table and dead-row kind; live/dead arithmetic still matches the same table and target |
| 4 | `ConstellationDefaultPartitionLarge` | Table |
| 5 | `ConstellationFlowRollupLagging` | None |
| 6 | `ConstellationAuditArchiveLagging` | Archive-enabled and progress timestamps must also match the complete target |
| 7 | `ConstellationBackupScheduleOverdue` | None |
| 8 | `ConstellationBackupScheduleFailed` | None |
| 9 | `ConstellationWALGenerationHigh` | None |
| 10 | `ConstellationStorageMetricsAbsent` | Detects failed scrapes/missing collectors per discovered target; completely absent discovery produces a release-scoped alert |

Previously the health joins matched only namespace/service/job/instance, allowing
a healthy collector in another cluster or Prometheus source to validate stale
values at the same address. The missing-metrics rule previously used only global
`absent(collector_up)`, so one healthy replica could hide another missing exporter.
The rule name is retained, but its summary now says metrics are unavailable and
its per-target failures carry the target labels. A collector reporting zero is
present: its query failures remain covered by `ConstellationStorageCollectorFailed`.

Forward `up` alongside these metrics when using remote write/federation. Preserve
consistent target labels on all series; `table` and `kind` are reserved application
labels here. Annotation-based scraping must still supply the namespace/service
labels used by the rules. These rules do not infer desired replica counts: if one
target disappears from discovery while others remain, workload-availability alerts
must detect the missing desired replica.

For every data alert, executable fixtures prove positive behavior with matching
extra labels, suppression for mismatched cluster/Prometheus/instance health, and
suppression after failed scrapes. Additional archive fixtures isolate enabled and
progress values across clusters. The complete suite has 75 scenarios. An isolated
negative control restores the restricted health joins and global absence rule;
all ten corresponding regression cases fail as expected. This changes monitoring
correctness, not retention policy, deletion behavior, live alert routing or DB-23
capacity/recovery acceptance.

## Retained WAL and retention progress

The collector now distinguishes WAL generation from WAL directory allocation.
`postgres_wal_occupancy_known` is zero when the database role lacks EXECUTE on
`pg_catalog.pg_ls_waldir()`. In that case `postgres_wal_retained_bytes` is absent,
not a measured zero; all other snapshot values remain available. An administrator
can review a narrow EXECUTE grant or use CNPG disk metrics instead. No privilege
is granted by the collector. Occupancy includes retained and recycled WAL files;
it is not the replication-slot backlog alone.

`raw_flow_pruned_before_timestamp_seconds` is the committed raw-flow expiry
boundary. It is a progress signal, not a count of expired rows: a bounded sweep
can leave eligible rows behind. For the two fixed `table` labels `events` and
`network_flows`, `retention_enabled` and `retention_cutoff_timestamp_seconds`
reflect the same conservative organization policy as maintenance. Any tenant
hold suppresses expiry. The flow cutoff also respects the committed fold
watermark and one-hour safety boundary.

`expired_partitions` and `oldest_expired_partition_upper_timestamp_seconds`
inspect actual attached range bounds rather than date-shaped table names. They
exclude DEFAULT branches, which have separate metrics. Unexpected range bounds
or unreadable/invalid retention policy fail the snapshot. The reader now also
requires SELECT on `orgs` and `system_config`; it does not expose those values or
tenant identities as labels. These catalog/policy queries retain the existing
read-only transaction and query deadlines.

Four additional alert rules cover retained WAL pressure, unknown occupancy, raw
expiry progress and overdue attached partitions. Matching preserves all target
labels, tenant holds suppress expiry alarms, and failed scrapes/snapshots suppress
data alarms. Four dashboard panels expose the new signals. Thresholds are
warning budgets, configurable through `metrics.prometheusRule.storage`.

## Explicit Kubernetes audit source coverage

Configure expected webhook sources through the existing `api.env` map. Each
pair is an organization UUID and cluster UUID, separated by `/`; multiple pairs
are comma-separated. Empty configuration disables coverage inference. Registering
a cluster or having old audit rows does not mean a webhook is configured.

```yaml
api:
  env:
    CONSTELLATION_STORAGE_K8S_AUDIT_SOURCES: "11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222"
    CONSTELLATION_STORAGE_K8S_AUDIT_MAX_GAP: "15m"
```

The default maximum gap is 15 minutes; valid explicit gaps range from one second
to 30 days. Invalid UUID pairs, invalid durations and more than 1,000 entries fail
startup. Duplicate pairs are observed once. Configure every API replica alike.
The fixed-cardinality `constellation_storage_k8s_audit_*` gauges report expected,
missing (never seen), stale (receipt older than the maximum gap), delayed (latest
receipt minus reported event time exceeds the gap), unknown reported timestamp,
and future reported timestamp (over five minutes after receipt) source counts.
`oldest_receipt_timestamp_seconds` is the minimum latest receipt among sources
with data, excluding never-seen sources. Always inspect missing counts with it.
Tenant/cluster UUIDs, event JSON and usernames do not become metric labels.
New ingests preserve an absent source timestamp as NULL, and the list API returns
`reported_at: null` rather than substituting receipt time. Older binaries filled
missing timestamps with receipt time; those historical values remain unchanged
and cannot establish that the source supplied a timestamp.

Each expected pair gets an indexed latest-row lookup under the existing snapshot
query timeout. Sources are evaluated independently before aggregation, so a busy
cluster cannot hide a stopped source. No high-volume JSON scan, retention change,
implicit source enrollment or evidence deletion occurs. Failed queries invalidate
the snapshot and use the existing collection-failure alert, not healthy zeros.
Three alert rules cover delivery gaps, delayed events and unknown/future source
timestamps, gated by successful collection and the same scrape target. They hold
for five minutes. Source expectation zero means **unconfigured**, not verified
coverage; silence on an unconfigured installation is not a passing audit check.

An event silence interval is not proof of a lost event: quiet clusters may have no
eligible activity. Set expectations and the gap against audit policy and known
periodic audited traffic. These observations cannot prove completeness, detect
all intermediate gaps or distinguish filtering from lost delivery. They expose
current source gaps without asserting a continuity guarantee Kubernetes event IDs
do not provide. Export/hold-aware retention remains separate; keep all existing
Kubernetes audit JSON until that recovery contract is qualified.

Local migrated-PostgreSQL tests cover tenant/cluster isolation, simultaneous
healthy/stale/missing sources, delayed/unknown/future event time, recovery and
read-only evidence preservation. Promtool fixtures cover all three new alerts,
configuration holds, target isolation, hold periods and recovery. This does not
assert live scrape or notification delivery; those remain deferred by the owner.

## Session cleanup worker health

`constellation_session_cleanup_active_workers` counts cleanup loops active in an
API process. It is zero on idle replicas and after the worker stops, including
leadership-context cancellation. Overlapping loop lifetimes are counted so an
older loop stopping cannot hide a newer active loop. Existing deleted-row,
failure, duration and last-success metrics remain unchanged.

Two storage rules now observe only active workers on the same healthy target:
`ConstellationSessionCleanupStalled` fires after a five-minute hold when the last
complete pass is more than five minutes old; `ConstellationSessionCleanupFailing`
fires after a two-minute hold while the five-minute failure increase is positive.
Collection/scrape failure uses the existing separate alerts. Idle/follower replicas
must not alert merely because they have never run cleanup. These rules do not
establish that at least one API has acquired leadership; lease/workload monitoring
is still needed for total absence of background workers. Live notification routing
remains deferred.

## October 23 local session-maintenance load fixture

Run the opt-in real-PostgreSQL fixture separately:

```sh
CONSTELLATION_TEST_LIFECYCLE_LOAD=true go test -tags=integration -race \
  -run '^TestSessionCleanupLocalLoad$' -count=1 -v ./internal/lifecycle
```

It seeds 100,000 expired rows in each of OIDC login attempts, opaque identity
sessions, network-session snapshots and kill requests, plus one live row per
family and an audit receipt. One hundred 1,000-row-per-family cleanup calls run
alongside a foreground probe that reads the active identity and updates the live
network session by its full primary key. All 400,000 expired rows drained; all
four live rows and the verified audit chain survived.

The October 23 standalone local run measured 3.61 seconds for the 100 cleanup
passes, with pass p95/p99 56.32/62.27 ms. The 1,669 concurrent foreground probes
measured p95/p99 1.37/1.64 ms, versus 0.88/1.02 ms across 100 baseline probes.
Combined WAL insertion between the baseline marker and final validation was
46,884,848 bytes; it includes foreground work and PostgreSQL background activity,
not just deletion. These are a shared-host disposable PostgreSQL fixture with race
detection and a small indexed foreground operation, not application-login latency,
fleet-scale capacity, cold-host performance or a guaranteed production SLO.

The fixture intentionally drains without production timer waits. Production still
runs at most 1,000 rows per family per minute: approximately 16.7 rows/second per
family before failures/locks. A 100,000-row backlog in one family therefore needs
about 100 scheduled passes even though SQL execution is much faster. Do not use
the burst fixture's rows/second as the deployed sustainable cleanup budget. No
cadence or retention setting was changed. Compare measured arrival rates with
this scheduled budget before tuning batch size or frequency.
