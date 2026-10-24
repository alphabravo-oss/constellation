# Kubernetes audit evidence archives

`constellationctl evidence` exports signed pages of `k8s_audit_events`, verifies
them offline, and restores them to an explicitly selected existing cluster.
The source rows remain untouched. This is preservation and recovery tooling;
it does not implement automatic archival, source pruning, immutable object
storage or a complete historical query service.

## Export and continue a page

Use a dedicated directory for confidential artifacts, an Ed25519 private key,
and an independently trusted matching public key. Generate a pair with
`constellationctl backup gen-key PRIVATE.pem PUBLIC.pem`. Archive signatures
bind exported content and scope to that key; they do not independently attest
that an API server originally emitted an event. The full raw event may contain
sensitive request/response content. Files are private, not encrypted by this tool.

```sh
constellationctl evidence export-k8s-audit \
  --org-id "$SOURCE_ORG" --cluster-id "$SOURCE_CLUSTER" \
  --from 2026-10-01T00:00:00Z --through 2026-10-02T00:00:00Z \
  --limit 1000 --sign-key /secure/archive-private.pem \
  --verify-key /secure/archive-public.pem --out-dir /secure/k8s-audit-archives
```

Export uses `DATABASE_URL` or `--database-url`. Both organization and cluster are
required. Receipt time `at`, not the optional API-server reported time, selects
the half-open `[from, through)` window. Timestamps must have at most microsecond
precision. The manifest signs scope, window, exclusive input cursor, first/last
record keys, row count, whether more rows were observed, both compressed/raw
SHA-256 digests, byte count and signer identity.

When `archive.manifest.more` is true, repeat the same scope/window with
`--after-at` and `--after-id` from `archive.manifest.last`. Ordering by `(at,id)`
keeps timestamp ties from skipping or repeating rows. Migration 197 replaces
the per-source timestamp index with `(org_id,cluster_id,at,id)` using a concurrent
build; the old index remains until the replacement succeeds. Interrupted builds
are recreated on migration retry. This build requires schema 197. The default/max page is
1,000 rows, with 4 MiB per serialized row, 32 MiB per uncompressed page and
48 MiB per artifact. A page can stop at the byte budget before the row budget.
An oversized individual record fails and remains in the source; it is never
silently skipped. An empty query returns an error and writes no artifact.
Each database operation has a five-second budget; use a smaller page if needed.

Each page is one database statement snapshot. Separate invocations do **not**
share a snapshot: concurrent backdated arrivals or edits can fall behind a cursor.
`more=false` means no later row was observed in that statement, not that an active
source is permanently complete. Re-export a stable window from its beginning to
capture later arrivals. This contract cannot authorize deletion of source rows.

Both inventory and Kubernetes-audit export write a unique mode-0600 file in a
mode-0700 directory, sync the file and directory, then reopen and verify exact
bytes and the signature before returning success. JSON output contains only
paths, digests and scope/boundary metadata; raw event fields are not printed.
Failed verification does not return a successful archive receipt. A failed local
artifact may remain for investigation; no source deletion follows a failure.

## Offline verification and recovery

```sh
constellationctl evidence verify-k8s-audit \
  --in /secure/k8s-audit-archives/ARCHIVE.k8s-audit.json \
  --verify-key /secure/archive-public.pem

constellationctl evidence restore-k8s-audit \
  --in /secure/k8s-audit-archives/ARCHIVE.k8s-audit.json \
  --verify-key /secure/archive-public.pem \
  --org-id "$DESTINATION_ORG" --cluster-id "$DESTINATION_CLUSTER"
```

Verification requires no database, AWS access or source connection. It checks
signature trust, checksums, byte/row bounds, scope, ordering and window boundaries.
Archive parsing rejects duplicate keys (including escaped aliases), unknown
fields, invalid UTF-8, excessive nesting and trailing values. Reads check
cancellation between I/O operations; local input must be a regular file.

Restore uses operator database credentials. Explicit destination IDs map the
signed source scope to an existing cluster in that organization. The cluster is
locked against reassignment while restoration runs. Original event UUIDs,
receipt/reported timestamps, null fields and raw JSON content are preserved in
the destination mapping. A matching existing record is a no-op. A conflicting
UUID fails the entire page without overwriting evidence. Newly inserted rows
and one `k8s.audit.restore` audit receipt commit together. Identical replay adds
neither rows nor duplicate restore receipts. Restoration does not replay live
notification or response actions, create a cluster, restore credentials, or
assert continuity with control-plane `audit_events`.

Real PostgreSQL qualification exports 1,005 timestamp-tied events in two pages,
checks tenant/cluster/window exclusions and source preservation, closes the
source, and restores twice into a separately migrated database. Conflict and
deferred audit-commit failures leave no partial page. CLI recovery separately
exercises private-file publication, offline verification with unusable database/
AWS environment values, and a fresh destination. Unknown reported timestamps
remain unknown. Existing control-audit integrity problems are not bypassed.
