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
