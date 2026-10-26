# Runtime threat evidence archives

Runtime threats can be exported, verified offline, and restored independently with
`constellationctl evidence`. This implements a preservation/recovery portion of
DB-11. It does not expire threats, packets, quarantine history, forensic snapshots,
or case evidence. A verified page does not authorize deleting any source row.

## Export

Use operator database credentials, a dedicated private output directory, and an
Ed25519 key pair generated with `constellationctl backup gen-key`. The public key
must be trusted independently. A signature attests the export's contents and
scope; it does not establish that a sensor originally observed the event.

```sh
constellationctl evidence export-runtime-threat \
  --org-id "$SOURCE_ORG" --cluster-id "$SOURCE_CLUSTER" \
  --from 2026-10-01T00:00:00Z --through 2026-10-02T00:00:00Z \
  --sign-key /secure/private.pem --verify-key /secure/public.pem \
  --out-dir /secure/threat-archives
```

`DATABASE_URL` or `--database-url` selects the source. Both organization and cluster
are required. The half-open window uses server receipt time `at`, not sensor time
`reported_at`. Times must have microsecond precision or less. The default and
maximum page size is 1,000 rows; `--limit` can reduce it. Limits are 4 MiB per
serialized record, 32 MiB per raw page, and 48 MiB per artifact. Oversized records
fail without changing or skipping source evidence. Empty queries write no file.

If `archive.manifest.more` is true, repeat the window with `--after-at` and
`--after-id` from `archive.manifest.last`. The exclusive `(at,id)` cursor handles
timestamp ties. Migration 198 adds a concurrent `(org_id,cluster_id,at,id)` index;
existing UI indexes remain. An interrupted index build is rebuilt on retry.
This binary requires schema 198; it has only been exercised in disposable local
PostgreSQL databases for this batch.

Each page has its own statement snapshot. Concurrent backdated arrivals/edits can
fall behind a cursor. `more=false` is not proof that an active source is complete;
repeat a stable window from its beginning to capture later arrivals. There is no
cross-page completeness claim or source-pruning policy.

## Packet and metadata fidelity

The archive includes every persisted threat column. It preserves unsigned
32-bit threat IDs through 4,294,967,295, nullable application and workload fields,
64-bit DLP hashes, original timestamps, and packet direction/tap flags. This is a
storage representation rather than the live ingest DTO: it does not replace
historical nulls with defaults or reinterpret recorded severity/length claims.

Packets use PostgreSQL hex bytea notation inside the signed payload. A missing
packet is JSON null; an empty packet is `"\\x"`. Arbitrary bytes, including NUL and
non-UTF-8 bytes, round-trip exactly. Export explicitly encodes hex independently
of the connection's `bytea_output` setting. Reported packet/capture lengths are
preserved even when they differ from captured bytes; recovery does not rewrite
historical evidence to make it look consistent.

Files contain confidential messages, identities, addresses and packet contents.
They are unencrypted, mode 0600 in a mode-0700 directory. Publication syncs file and
directory, then checks exact bytes and signature from disk before returning a
path. JSON reports contain boundaries, counts and digests, not packet/message
content. A failed artifact may remain private for investigation.

## Verify and restore

```sh
constellationctl evidence verify-runtime-threat \
  --in /secure/threat-archives/ARCHIVE.runtime-threat.json \
  --verify-key /secure/public.pem

constellationctl evidence restore-runtime-threat \
  --in /secure/threat-archives/ARCHIVE.runtime-threat.json \
  --verify-key /secure/public.pem \
  --org-id "$DESTINATION_ORG" --cluster-id "$DESTINATION_CLUSTER"
```

Verification is offline and needs no database or AWS connection. Runtime-threat
and Kubernetes-audit pages share bounded signed-page machinery but have distinct
format identities and row validators; one family cannot be accepted as the other.
Signatures, compressed/raw checksums, bounds, scope, timestamps, order and packet
encoding are checked. Strict JSON parsing rejects duplicate/escaped aliases,
unknown fields, invalid UTF-8, excessive nesting and trailing values. Reads and
compression/decompression check cancellation between I/O operations.

Restore maps the signed source scope to an explicitly chosen existing cluster in
the destination organization. It locks that cluster against reassignment. All
other evidence values and UUIDs are preserved. An identical existing row is a
no-op; any UUID conflict rolls back the whole page. Concurrent identical replays
produce one inserted copy and one `runtime.threat.restore` receipt. Inserts and
that permanent audit receipt commit atomically, including deferred failures.
Queries/restore transactions have five-second budgets. Export closes the database
reader after a bounded fetch, then performs strict payload validation outside that
query deadline. Both fetched and normalized pages are byte bounded. CLI operations
have a one-minute outer deadline. Reduce page size if a destination cannot meet that budget.

Recovery does not invoke live ingest, notifications, response rules, or automatic
quarantine. It does not recreate clusters or restore quarantine/case/forensics
records. Those relationships are a separate dependency-recovery requirement;
source references remain held. It does not bypass the recorded control-audit
chain discontinuity or authorize deletion of permanent audit evidence.

## Local qualification

Real PostgreSQL tests export 1,005 timestamp-tied threats across two pages, close
the source, and restore/replay into an independently migrated database. They check
full-width threat IDs and binary packets, tenant/cluster/window exclusions,
nullable metadata, wrong keys/formats, conflicts, deferred audit failures,
concurrent replay, cancellation and a locked destination. A 36 MiB source fixture
exercises the byte budget before the row limit and preserves an active quarantine
reference. Oversized source records remain intact. The CLI test verifies a private
artifact with unusable database/AWS environment values and restores independently.
The existing Kubernetes-audit tests cover the shared-code refactor.

Actions remains disabled. No live migration, rollout, source deletion, off-host
recovery or real node-failure qualification is included.
