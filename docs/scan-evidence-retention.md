# Scan evidence retention contract

Scan age alone is not sufficient reason to delete a security decision or its
inputs. The retention workers now use `internal/scanretention`; they do not add
SQL to the legacy HTTP handler layer.

| Parent | References / protected state | Cleanup behavior |
| --- | --- | --- |
| `scan_jobs` | `scan_result_attestations.scan_job_id`, `image_scan_results.last_scan_job_id`, newest terminal job per target | Keep referenced/latest/live jobs. Delete only older unreferenced terminal jobs after the existing configured window. Attempts cascade only with an eligible job. A zero window remains a hold. |
| `image_scan_results` | Attestations, image findings, target findings, running workload digest links, newest result per image/platform/profile and per target | Keep all named results and protected records. Remove at most one batch of superseded unnamed cache records older than six hours. Linked artifacts cascade only with an eligible parent. |
| `scan_targets` (repository) | Findings, inventory evidence, all attestations regardless of trust/expiry, image results, active jobs, references to descendant jobs | The existing opt-in repository policy can remove only empty, inactive history. It never deletes findings. Preserve inventory evidence pending a verified archive contract. |
| Repository `assets` | Any finding referencing the asset, even through another target | Lock before checking references; retain referenced assets. |
| `scan_evidence`, attestations and verification records | Current decisions and restore provenance | No age-only payload cleanup is introduced. These remain held until verified archival and dependency-aware restoration exist. |

Every pass has a five-second deadline, a row budget and transaction rollback on
failure. Repository cleanup caps targets at 5,000 and cascade parents at 20,000;
exceeding the cascade budget fails safely. Unnamed-result cleanup no longer drains
an arbitrarily large backlog in one invocation. Terminal job/result candidate
selection skips row locks.

Selection and deletion are separate READ COMMITTED statements. Candidate parent
rows are locked before deletion obtains a fresh snapshot and checks references
again. This matters because several evidence FKs use `ON DELETE SET NULL`: a
single-statement candidate/delete can otherwise erase a reference committed after
its snapshot. Foreign-key key-share locks serialize subsequent reference inserts.
Repository cleanup also locks descendant jobs and assets before rechecking them.
Migration 195 indexes job-reference and chronological cleanup lookups.

Real PostgreSQL tests exercise a reference committed after the candidate snapshot,
existing trusted/untrusted references, current results, finding preservation,
locked rows, bounded batches, holds, dry runs and eligible empty repository cleanup.
No source data was deleted while developing or testing this change.

This is protection for existing cleanup, not the missing archival implementation.
Named scan history, resolved findings, inventory payloads and attestations remain
held. Their storage is observable but not bounded by this worker; DB-13–15 retain
those explicit archive/restore acceptance gates. The documented audit-chain break
is never bypassed to authorize evidence deletion.

## Signed inventory export and recovery

`constellationctl evidence` can preserve one package-inventory record together
with its target identity. The artifact contains the full inventory payload and
source organization, target and evidence UUIDs. A signed manifest binds the raw
record and compressed payload SHA-256 digests, byte count and signing identity.
Verification requires an independently trusted Ed25519 public key; it never
trusts a key embedded in an archive. Protect these artifacts as sensitive data.

```sh
constellationctl evidence export-inventory \
  --org-id "$SOURCE_ORG" --evidence-id "$EVIDENCE_ID" \
  --sign-key /secure/archive-private.pem --verify-key /secure/archive-public.pem \
  --out-dir /secure/inventory-archives

constellationctl evidence verify-inventory \
  --in /secure/inventory-archives/ARCHIVE.inventory.json \
  --verify-key /secure/archive-public.pem

constellationctl evidence restore-inventory \
  --in /secure/inventory-archives/ARCHIVE.inventory.json \
  --verify-key /secure/archive-public.pem \
  --org-id "$DESTINATION_ORG" --target-id "$DESTINATION_TARGET"
```

Export and restore use `DATABASE_URL` or `--database-url`, with database credentials
that authorize the operation. Verification is offline and needs neither a database
nor object storage. Generate a key pair with `constellationctl backup gen-key`.
Export creates a unique file with mode 0600 in a dedicated private directory;
JSON command output contains identities/digests, never the inventory payload.
The record limit is 32 MiB, the artifact limit 48 MiB, and each database operation
has a five-second deadline. Oversized records fail without modifying the source.

Restoration requires an existing destination target whose type, reference and
source identity match the signed target. The operator explicitly chooses the
destination organization and target; cluster context comes from that target.
Evidence UUID and original timestamps, including expiration, are preserved.
An identical existing record is a no-op; a conflicting UUID or inventory identity
fails without overwriting evidence. New evidence and its `scan.evidence.restore`
audit receipt commit atomically. Real PostgreSQL tests close the source connection
and restore into a separately migrated database, check replay and rejected scopes,
and inject an audit failure to verify rollback. The CLI test verifies an exported
file while database and AWS environment settings point to unusable endpoints.

This is a single-record preservation primitive. It does not restore targets,
credentials, findings, scan results, attestations or their reference graph, upload
to durable storage, schedule exports, or authorize source pruning. Existing holds
remain in force. A verified inventory archive alone does not complete DB-14–15.
