# ClickHouse evaluation and delivery plan

Updated: 2026-10-12. Status: **design complete; implementation and adoption pending**.
This is the separately requested ClickHouse plan. The canonical release tracker
remains [NEUVECTOR-PARITY-PLAN.md](NEUVECTOR-PARITY-PLAN.md), especially OPS-2.
Writing this plan does not close the storage, fleet capacity, or recovery gates.

## Decision and boundaries

Keep PostgreSQL/CNPG as the authority for organizations, cluster ownership,
identity, credentials, policies, desired/applied configuration, workflow state,
scan findings, evidence manifests, and producer ingestion progress. Initially
keep raw events/flows there too. ClickHouse is a candidate for large telemetry
history and aggregate queries, not the authority for enforcement or a substitute
for durable delivery. Do not add Kafka merely to connect these two databases.

The measured development database was 8.37 GiB on October 11, with one organization
and one cluster. That alone does not justify another production database. The
current disk is shared and already 82% used, so a benchmark must have its own
bounded storage. PostgreSQL cleanup, ingestion reliability, feed rewrite reduction,
and capacity measurement precede an adoption decision.

## Storage and data contracts

| Class | Authority | Possible analytical copy | Required semantics |
|---|---|---|---|
| Policy, auth, secrets, ownership | PostgreSQL | None for secrets | Transactional, current, scoped |
| Raw runtime events and flows | PostgreSQL initially | ClickHouse | Stable identity, replay-safe, late arrival |
| Rule hits and hourly summaries | PostgreSQL initially | Reconciled ClickHouse projection | No additive replay inflation |
| Control audit chain | PostgreSQL + verified archive | Search projection only | Preserve chain/signatures and holds |
| Findings and scan jobs | PostgreSQL | Historical aggregate projection | Versioned lifecycle, tombstones |
| Captures, reports, cold raw evidence | S3-compatible object storage | Manifest/reference | Checksums, access control, lifecycle |
| Delivery queue | Node spool, then transactional outbox if adopted | None | ACK after durable commit; bounded backlog |

Use authenticated organization/cluster identity, never caller-supplied tenancy.
Each exported record carries a schema version, immutable observation ID,
organization ID, cluster ID, producer ID, stream, sequence, row ordinal,
event time, ingestion time, source, and payload hash. The current producer cursor
protects a batch; exporting a stable row identity and transactional outbox is
additional implementation. Do not infer IDs from timestamps or workload names.

Prototype separate `runtime_events` and `network_flows` tables with typed common
columns and a bounded JSON payload for less common fields. Candidate partitioning
is month or day based on measured volume; do not create one partition per node,
producer, or cluster. Compare sorting by `(org_id, cluster_id, event_time, event_id)`
against query-specific alternatives. Use an explicit time range in every query.
Test projections/indexes against the actual UI filters before adding them.

Prototype versioned replacement rows only where corrections require them.
ReplacingMergeTree deduplication happens during background merges; query correctness
cannot assume a merge has already occurred. Benchmark `FINAL`/explicit version
selection and duplicate-safe aggregates before accepting that engine. Do not feed
replayed replacement rows into a naive additive materialized view. Source:
[ReplacingMergeTree](https://clickhouse.com/docs/reference/engines/table-engines/mergetree-family/replacingmergetree).

## Ordered implementation

| Phase | Deliverables | Exit evidence |
|---|---|---|
| CH-0: baseline | Fixed replay/cleanup correctness; PostgreSQL statement and disk metrics; repeatable fleet workload; measured row widths/cardinality/skew | Passing current correctness suites and 1x/10x workload reports |
| CH-1: isolated prototype | Pinned server/client versions, reproducible disposable chart or compose fixture, scoped schemas, bounded CPU/RAM/disk, query adapter | Boot/migrate/rebuild/teardown smoke; no connection to live credentials/data |
| CH-2: delivery | PostgreSQL transactional outbox or verified snapshot+CDC design, batched exporter, checkpoints, retry, backpressure, schema versioning | Crash at every handoff; committed input recoverable; no duplicate counters |
| CH-3: shadow reads | Representative synthetic/sanitized history, dual query comparison, latency/bytes/CPU/merge statistics | Exact scoped totals and sampled records agree at common watermarks |
| CH-4: lifecycle/recovery | Retention classes, holds, cold manifests, backup/restore, credentials/TLS/RBAC, monitoring/runbooks | Expiry/hold/restore/failure tests; stated RPO/RTO met |
| CH-5: optional canary | Feature flag by organization/cluster and query family; bounded fallback; operator-visible freshness | Sustained canary with no security or count regressions |
| CH-6: adoption | Explicit cost/capacity decision, rollout/rollback artifacts, ownership/on-call, supported version matrix | All preceding gates pass; canonical OPS-2 evidence updated |

### CH-2 delivery details

1. Write normalized rows and export intent in the same PostgreSQL transaction as
   ingestion progress. ACK the node only after commit. A failed ClickHouse request
   must not block policy/authentication operations or erase acknowledged data.
2. Claim bounded outbox batches fairly across organizations/clusters; cap bytes,
   rows, outstanding requests, retry duration between attempts, and local buffers.
   Batch ClickHouse inserts; avoid one insert per observation. If asynchronous
   inserts are used, require acknowledgement of the durable flush and test that
   exact configuration. [Insert strategy](https://clickhouse.com/docs/concepts/best-practices/selecting-an-insert-strategy).
3. Persist checkpoint advancement only after successful delivery. A crash between
   insert and checkpoint will replay; correctness must hold beyond ClickHouse's
   finite insert deduplication window and through changed batch boundaries.
4. Keep payloads until the destination watermark is verified and the recovery
   window has elapsed. If backlog reaches its capacity budget, alert and throttle
   ingestion explicitly. Never silently expire unexported evidence.
5. Version exporter ownership by regional deployment. Transfer a cluster with a
   fenced epoch, resumable cursor, scoped historical query routing, and an explicit
   old-writer rejection. One global writer is not a fleet scaling design.
6. Add a broker only if measurements demonstrate required fan-out, independent
   consumers, or outage buffering beyond the outbox/spool budget. Evaluate it in a
   separate decision with operational cost and delivery semantics.

### CH-3 query and parity details

Serve analytics through the existing API authorization layer. Bind mandatory
organization and allowed-cluster predicates, use parameterized queries, cap time
range/result size/execution time/memory/concurrency, and test namespace scope.
Do not expose arbitrary ClickHouse SQL to the browser. Pagination uses a stable
cursor with a tie breaker; exports share the exact filter and watermark contract.

Expose ingestion/query freshness and partial regional results. Shadow-compare
counts, rule hits, bytes, packets, severities, protocol filters, time zones,
late arrivals, and retention boundaries. Permit no silent semantic changes from
exact to approximate counts. Live SSE is a bounded notification view; reconnect
must refetch durable state rather than claim the stream is an archive.

### CH-4 retention and recovery details

Define hot/search/archive windows per data class and approved hold semantics.
A tenant's hold must not silently retain every other tenant's telemetry. Test
changing a window, applying/removing a hold, old replay, late inserts, and erasure
across replicas, projections, archive copies, and backups. TTL cleanup runs during
background work; report observed deletion lag, not a promise of exact deletion at
the expiry instant. [TTL behavior](https://clickhouse.com/docs/concepts/features/operations/delete/ttl).

Use local RustFS for development, in a **separate bucket and prefix** from CNPG
WAL/base backups. Proposed test bucket: `constellation-clickhouse-test`, endpoint
`http://rustfs:9000`, signing region `us-east-1`; these are a plan, not a created
bucket or configured backup. Use generated test credentials, never checked-in
secrets. Test backup + restore to a fresh server, not just successful upload.
Native ClickHouse backups require their own configuration and restore rehearsal;
CNPG backup does not include ClickHouse. [Backup and restore](https://clickhouse.com/docs/concepts/features/backup-restore/overview).

For production, specify independent failure domains, encryption/key recovery,
object-store lifecycle, backup age/size alarms, replica/Keeper recovery where
applicable, and verified off-host copies. Replication is not a backup. Recover
PostgreSQL/outbox and analytical data to a common watermark and replay forward;
exercise destination loss, poisoned messages, old schema versions, and expired
source data. Record actual RPO/RTO and unrecoverable intervals.

## Benchmark and adoption gates

Run PostgreSQL-only and PostgreSQL+ClickHouse on the same workload distributions
and declared resource budgets. Report costs of both systems including outbox,
replicas, object storage, backups, network, and operations. Do not attribute all
performance improvement to ClickHouse if the hardware budget increased.

Workload matrix: 1/10/100 synthetic clusters, small/large nodes, 1x/10x measured
rates, a 10x noisy tenant, varied namespace/cardinality, late/out-of-order data,
agent/API/database restarts, 429/503/lost acknowledgements, destination outages,
concurrent dashboards/exports, retention, rollup and backup activity. The 100-cluster
profile is a test input, not an advertised support limit. Include a 24-hour soak
and accelerated full-retention-cycle scenario.

Initial evaluation targets: list p95 <=1s, dashboard p95 <=2s, committed-data
visibility/rollup lag <=2 minutes, and expiry lag <=2 maintenance intervals at the
specified workload. Require no cross-tenant results, missing acknowledged input,
or duplicate aggregates; bounded RSS/spool/outbox/parts; enough spare disk for
merges, replay and restore. Publish throughput, p50/p95/p99, query errors, rows and
bytes scanned, CPU/RSS/IO/WAL, compression, merge debt, backlog, and tested headroom.
These targets remain provisional until capacity tests establish a supported SLO.

Adopt only if the prototype meets correctness/recovery gates and demonstrates a
material workload-specific advantage that justifies a second operational system.
Otherwise retain PostgreSQL and record the limiting query or volume that would
reopen the decision. Regional deployment/sharding remains a separate requirement.

## Cutover and rollback

Backfill a consistent snapshot to watermark W, replay changes after W, then
reconcile before switching a canary query family. Retain PostgreSQL history for
the agreed rollback horizon and continue exporting during the canary. A feature
flag can return reads to PostgreSQL only while that required history still exists;
after its deletion, rollback requires archive restoration/replay and is not instant.
Fail explicitly on unavailable history instead of showing empty charts. Stop the
rollout on count divergence, scope failures, growing backlog, or missed recovery
targets. Never dual-write independently from the request handler.

## Completion checklist

- [x] Separate ClickHouse scope, architecture, dependencies, acceptance criteria,
  delivery, retention, recovery, benchmark, and rollback plan written.
- [ ] CH-0 PostgreSQL capacity baseline and release prerequisites pass.
- [ ] CH-1 through CH-4 implemented and verified in disposable infrastructure.
- [ ] Adoption decision records evidence and operational ownership.
- [ ] CH-5/CH-6 complete if adoption is selected; otherwise retain deferred status.
