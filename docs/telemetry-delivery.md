# Event and flow delivery

Updated 2026-10-12. Source implementation requires migration 169. Live rollout
and full fleet capacity qualification remain open under M3/M5 in the
[current readiness plan](readiness-and-parity-plan.md).

## Protocol and guarantees

Event and network-flow agents persist a batch to a private node-local directory
before delivery. File contents, rename, and directory metadata are synced. The
queue keeps a UUID producer identity and monotonically increasing sequence across
process restarts; one worker sends each stream in order. A file lock prevents two
processes from owning the same spool. Changed destinations and missing identity
with pending data fail closed instead of silently sending queued data elsewhere.

`X-Constellation-Producer` and `X-Constellation-Sequence` identify an upload. Scope
comes from the authenticated runtime-agent token and resolved cluster, not those
headers. PostgreSQL stores one cursor per `(org, cluster, stream, producer)` in
`telemetry_producers`; the cursor, event/flow rows, late-flow aggregation, and flow
rule-hit counters commit atomically. Receipt-aware transactions force local
`synchronous_commit=on`; replica/failover durability still depends on the CNPG
replication policy. Only then does the API acknowledge with
`X-Constellation-Ack`. A replay returns the stored response without inserting or
publishing again. Reusing the latest sequence with changed content returns 409.
Older sequences return 409 because they indicate out-of-order delivery or
cloned/rolled-back producer state whose historical payload hash cannot be verified.

The node removes a batch only after a matching acknowledgement. An old API that
returns 2xx without this header cannot drain the queue. HTTP/network failures
retain the batch; retry uses exponential backoff and jitter. Retry-After supports
seconds and HTTP dates, bounded to 24 hours, and cancellation interrupts waiting.
Permanent 4xx failures also retain the queue for diagnosis. Fix the identity,
credentials or payload issue before replay; do not blindly delete queued evidence.

Producer cursors are retained for the cluster lifetime and cascade on cluster/org
deletion. They do not expire with raw data: expiring a cursor would permit an old
replay to be accepted twice. A new producer per batch is invalid client behavior.
Registration quotas, fenced retirement, and node-replacement reconciliation remain
required before untrusted fleet-scale enrollment. Token rotation must preserve
cluster binding; changing cluster ownership requires an explicit queue migration.

## Bounds and operation

The chart mounts `/var/lib/constellation/telemetry` from the node, configurable via
`runtimeAgent.telemetrySpool.hostPath`. Each events/flows stream defaults to a
256 MiB payload-file budget and 4,096 batch files. The total default is therefore
up to 512 MiB plus filesystem metadata and at most a temporary batch per stream.
`CONSTELLATION_TELEMETRY_SPOOL_BYTES` sets the per-stream byte limit (1 MiB–16 GiB).
The batch-file cap may be reached first for sparse events. Measure the outage
window as `min(byte budget / encoded bytes per second, file cap / batches per
second)`; it is not a fixed number of hours.

At capacity, keep older queued data and reject new batches, incrementing existing
event/flow dropped counters and logging the reason. Disk write failures can leave
an ambiguously persisted batch recoverable after restart; a persistence-error
counter is not proof that every affected row was irretrievably lost. Batches are
split below the API's 1 MiB limit; a single oversized observation is counted as
dropped. Never raise raw retention to compensate for an unhealthy uploader.

Monitor `constellation_runtime_agent_spool_batches` and
`constellation_runtime_agent_spool_bytes` with `node` and fixed `stream` labels,
plus existing dropped and uploaded counters. Growing queue with no uploaded
progress indicates an outage, rate limit, bad credentials/payload, or unsupported
server. Alert on overflow and free disk independently. Queue age/oldest sequence
and full delivery-state health panels remain follow-up observability work.

For receipt-aware producers the API admits at most two concurrent event/flow
batches per cluster and 32 total per process, returning 429 with Retry-After when busy. It does not queue unbounded
requests behind PostgreSQL. These limits multiply with API replicas and are not
distributed rate/byte quotas or a fairness guarantee. Legacy agents are exempt
from this new budget because they discard 429 responses; closing that bypass
requires a completed fleet upgrade and protocol enforcement. Inserts use pgx batches to
avoid a database round trip per row; they are not COPY ingestion. Input remains
capped at 1,000 rows and 1 MiB per request.

## Upgrade and rollback

1. Back up PostgreSQL and credentials, qualify migration 169, and deploy the API
   first. Legacy agents without identity headers still work but are not deduped.
2. Deploy a single canary agent with a persistent node path. Interrupt delivery,
   restart the agent, and verify backlog drains without duplicate raw rows,
   rule-hit counts, or late-flow aggregates. Inspect overflow metrics.
3. Expand after capacity/recovery checks. Preserve spool storage and producer
   cursors across pod replacements. Do not clone a node's spool onto two nodes.
4. To downgrade the API, stop upgraded producers first. Keep queued data and the
   migration/receipts while restoring compatible service. Dropping the receipt
   table or recreating a producer identity discards the replay guarantee.

A node/disk loss can destroy unacknowledged local evidence. Kernel ring buffers,
agent channels, and the partial in-memory batch before enqueue remain volatile.
DPI threat uploads and other inventory/session lanes are still best effort.
Event response-rule callbacks, notifications, audit fan-out and live graph/SSE
are not a transactional delivery outbox: a process failure after raw-data commit
can lose those side effects; legacy pre-commit callbacks can repeat after a rolled
back request. Raw-data replay protection must not be advertised as exactly-once
external action delivery. Those gaps remain explicit parity acceptance gates.

## Verification

The focused race-enabled suites exercise queue restart and stable identity,
exclusive ownership, destination mismatch, crash between batch/state writes,
byte/file overflow retaining oldest data, receipt rollback, concurrent replay,
changed-payload rejection, independent streams, matching acknowledgement,
Retry-After and cancellation, and noisy-cluster concurrency isolation. The real
PostgreSQL flow-handler test replays an identified batch and verifies one raw row.

These are correctness tests, not the required 24-hour fleet soak. Run against a
disposable migrated/seeded PostgreSQL database with
`CONSTELLATION_TEST_DATABASE_URL` set; never target production test fixtures:

```sh
GOWORK=off go test -race ./internal/telemetryspool ./internal/telemetryingest
GOWORK=off go test -race ./cmd/constellation-runtime-agent
GOWORK=off go test -race ./internal/handler/runtime ./internal/handler/netpolicy
```
