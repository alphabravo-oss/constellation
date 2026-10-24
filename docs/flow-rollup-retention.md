# Hourly flow retention

`network_rollup_retention_days` controls hourly history independently of raw flows.
New organizations default to 90 days. Existing stored configurations without this
field retain a zero hold; migration 196 does not overwrite operator settings.
The data-retention settings page exposes the policy. For shared data, the longest
organization window wins and any zero holds cleanup. Invalid/read-failed policy
skips deletion.

The leader runs a five-second, 5,000-row pass each minute. It locks the existing
rollup state row exclusively, shared with ingest, incremental folding and rebuilds.
Its cutoff is the earlier of the configured hourly boundary and the known raw
pruning boundary. It cannot erase rollups ahead of raw-history expiration. The
bucket index supports oldest-first cleanup; `(tableoid,ctid)` identifies each
selected tuple within the statement, and locked rows are skipped.

A monotonic `rollups_pruned_before` boundary commits with each batch. Even a
partially expired window is unavailable; increasing retention later cannot make
already-deleted history available again. Forward and late folding ignore raw rows
older than this boundary, preventing delayed events from recreating expired
buckets. Rebuilds already respect the stricter raw pruning boundary.

Map, conversation inventory and CSV reads check availability after gathering
results but before emitting them. A concurrent prune therefore cannot silently
return a partial expired window as complete. Requests crossing the boundary get
HTTP 410 with a safe explanatory message and `X-History-Available-From`. The map
and conversation error views show that message. The explicitly incomplete live
conversation snapshot retains its existing semantics; it does not claim to serve
historical inventory.

Real PostgreSQL coverage exercises holds, invalid policy, the raw boundary,
bounded batches, retained counts/bytes, monotonic availability, late ingest,
existing fold/refold races and JSON/CSV expired-range responses. There is no
archive fallback for expired hourly ranges. Raw retention and the existing live
3/7/7 day policies were not changed during this work.

## Local ingest, fold and raw-retention qualification

The opt-in `TestFlowLifecycleLocalLoad` uses a migrated disposable PostgreSQL
instance with separate old/current daily flow partitions. It preloads 100,000
expired flows across 1,000 edges, performs initial folding and rebuilding, then
runs 100 transactions of 100 incoming flows concurrently with 40 immediate
refresh/prune/rebuild passes. Half of each incoming batch is late historical
traffic; half is current. Inserts acquire the production shared watermark lock
and call `FoldLate`, while maintenance uses the actual refresher and raw-prune
methods. Each prune is capped at 5,000 rows. The test requires temporal overlap,
drains remaining late expired arrivals, and verifies exact conservation:
110,000 aggregated flows / 1,100,000 bytes, 105,000 expired raw rows removed,
and all 5,000 current raw rows retained. Rebuilding a partly pruned hour cannot
erase its aggregate.

The October 24 final partitioned run with the race detector measured an initial fold
of 399 ms and 2.69 seconds for the concurrent phase plus final drain/checks.
Ingest batch p95/p99 were 72.7/98.1 ms; maintenance pass p95/p99 were
116.6/120.1 ms. WAL advanced 23,680,920 bytes after initial raw seeding, including
initial fold/refold, incoming writes, late aggregation and retention. These are
local fixture observations, not production cadence or fleet capacity guarantees.
There is one ingest writer, a fixed edge distribution and no HTTP/authentication,
external agents, event ingestion, partition dropping or hourly-expiry workload.
The forty passes run immediately rather than on the production one-minute tick.
The smaller default-partition exploratory run is superseded by this partitioned
fixture. Live throughput, lag notification and topology qualification remain
separate deferred gates; existing policies and deployment were unchanged.

```sh
CONSTELLATION_TEST_FLOW_LOAD=true go test -tags=integration -race -count=1 \
  -run '^TestFlowLifecycleLocalLoad$' -v ./internal/handler/network
```
