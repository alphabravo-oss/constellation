# Audit archive catch-up and verification

The optional audit archiver exports the global audit chain in bounded ID order.
It includes old and backdated event timestamps. Migration 191 creates
`audit_archive_progress` and adds an audit-table TRUNCATE guard. UPDATE and DELETE
remain forbidden, and the demo seed command preserves the ledger.

Each destination has an independent cursor: a SHA-256 of the configured endpoint,
bucket and normalized prefix. Changing any of these starts a fresh catch-up from
genesis. Configure custom endpoints explicitly with `--endpoint`,
`AWS_ENDPOINT_URL_S3`, or `AWS_ENDPOINT_URL`; do not change a hidden SDK profile
endpoint while reusing an existing cursor. Existing version-1 time-window exports
do not initialize progress. Keep them as historical evidence; version 2 catches
up from the retained source chain.

## Publication contract

Each invocation exports at most `--batch-size` rows (default 1,000, maximum
10,000). Compressed and uncompressed artifacts are each limited to 256 MiB.
Oversized batches fail without advancing progress; reduce the batch size. A
single row exceeding the limit needs operator investigation and is not skipped.
The default chart schedule is every five minutes; size the cadence and batch for
the actual arrival rate and existing backlog. One successful run does not imply
that the whole backlog is caught up.

A database transaction locks the destination's progress row throughout export,
upload and read-back. Other archivers for that destination serialize, while
normal audit writers continue. The CLI has a 15-minute deadline. Timeout, local
verification failure, failed upload/read-back or a failed database commit leaves
progress unchanged. On retry, unique attempt IDs and `If-None-Match: *` writes
preserve already-written artifacts. A crash after upload can leave a duplicate
or partial orphan attempt; only the cursor's manifest and its linked predecessors
are the committed sequence. Do not automatically delete orphan attempts.

Each signed version-2 manifest records:

- destination stream ID, first and last row IDs, and record count;
- the first row's previous hash, first/last chain hashes, and predecessor manifest;
- separate compressed-file and uncompressed-JSONL SHA-256 checksums;
- artifact keys, signer identity, creation time and observed timestamp bounds.

Timestamp bounds describe exported rows and never select them. Sequence gaps
from rolled-back PostgreSQL transactions are valid. Missing chain links,
non-increasing IDs and changed row contents fail verification. Export and replay
use the existing audit writer's canonical hash algorithm, with `host(actor_ip)`
for address round-tripping. The new path verifies each newly exported segment
against its checkpoint; it does not rescan all previously archived source rows
on every run or repair historical corruption.

Before updating the cursor, the job verifies the signature locally, uploads all
artifacts, downloads and compares the manifest/signature/certificate, and
independently verifies the downloaded compressed file and every row. A successful
PUT or ETag alone is insufficient. The destination must support conditional S3
PUTs with SHA-256 checksums and immediate GET of the written objects; unsupported
operations fail closed. No source audit rows are deleted.

## Configure the optional CronJob

The chart remains disabled by default. Durable publication requires signing and
operator-supplied verification trust. Static signing uses a Secret containing
both the Ed25519 private key and its trusted public key:

```yaml
auditArchiver:
  enabled: true
  bucket: constellation-audit-prod
  prefix: constellation/audit
  schedule: '*/5 * * * *'
  batchSize: 1000
  sign:
    mode: static-key
    keySecretName: constellation-audit-signing
    keySecretKey: cosign.key
    verifySecretKey: cosign.pub
```

Generate keys with `constellationctl backup gen-key`. Keep a trusted copy of each
public key outside the source database, including keys retired during rotation.
The private key and public key must match before a new batch can be published.
Rotating the key does not reset the destination's cursor. Keyless mode requires
`auditArchiver.sign.verifyIdentity`, `cosign` and suitable ambient OIDC credentials;
its provider/trust availability needs separate deployment validation.

`auditArchiver.window` / `--window` have been replaced by `batchSize` /
`--batch-size`. Existing unsigned enabled configurations must supply signer and
verifier settings before upgrading. AWS credentials must allow object PUT and
GET. This change does not provision IAM, object lock, legal hold, lifecycle rules,
key rotation procedures or a workload-identity service account.

A local preview reads the current cursor but never creates or advances it:

```sh
audit-archiver --bucket constellation-audit-prod --prefix constellation/audit \
  --dry-run --out-dir /private/audit-preview --batch-size 1000 --sign-mode none
```

Unsigned previews are diagnostic output and are rejected by the evidence
verifier. To test signed replay locally, also supply `--sign-mode static-key`,
`--sign-key` and `--verify-key` to the dry run.

## Verify downloaded evidence without PostgreSQL

Download a committed `.jsonl.gz`, its `.manifest.json`, and the adjacent `.sig`
into a private directory. For keyless signatures also download `.cert`. Verify
with a public key obtained independently of the downloaded artifacts:

```sh
audit-archiver --verify-archive /private/evidence/range.jsonl.gz \
  --verify-manifest /private/evidence/range.manifest.json \
  --signature /private/evidence/range.manifest.json.sig \
  --sign-mode static-key --verify-key /trusted/archive-signing.pub
```

This mode does not open PostgreSQL or initialize an AWS client. Static-key replay
works offline. It verifies the signature, format version, both checksums, count,
ID order, hash-chain links and row content. A successful result prints the
verified manifest. Keyless replay uses `--certificate` and `--verify-identity`
and inherits cosign's trust/network requirements.

To verify completeness automatically, download the committed head and every
linked predecessor with its archive/signature (and keyless certificate), preserving
S3 key paths underneath a private directory. Obtain the committed head key and
SHA-256 of its exact manifest bytes through an independently trusted record.
Computing a digest from an untrusted download alone does not establish the head:
a valid old prefix could otherwise be substituted for the complete chain.

```sh
audit-archiver --verify-chain-dir /private/evidence \
  --trusted-head audit/COMMITTED.manifest.json \
  --trusted-head-sha256 "$TRUSTED_MANIFEST_SHA256" \
  --sign-mode static-key --verify-key /trusted/archive-signing.pub
```

This follows signed predecessor links to genesis, verifies every signature and
row, and requires matching stream IDs, increasing inter-segment IDs, and matching
chain boundaries. Sequence-number gaps from rollbacks are permitted. Missing,
corrupt, cyclic, mislinked, and path-escaping artifacts fail closed without
emitting a partial proof. Processing is bounded by the CLI deadline, 100,000
segments, and the existing per-artifact byte limits. The result reports the
verified head, final chain hash, segment count and row count. A proof covers only
the trusted head; it does not assert that no newer events exist. The selected
public key or keyless identity must verify every segment in this invocation;
chains spanning different signing identities require separately reviewed trust
rotation support before they can pass this complete-chain command.

Do not treat every object in a bucket listing as committed: retries leave orphan
attempts. The proof is independent of PostgreSQL and AWS with static-key trust.
It does not repair the historical source discontinuity at row 53 or authorize
source deletion. Trusted hot/cold query anchors and a historical-query service
remain separate work.

Replay validates portable evidence; it does not insert archived rows into the
append-only operational table or implement a historical-query service. Full
PostgreSQL/PITR recovery remains a separate backup requirement.

## Acceptance and remaining gates

The ten implementation items are durable catch-up, bounded batches, per-stream
concurrency, chain-boundary metadata, database-independent verification, required
signer trust, object read-back, safe retries, isolated dry runs, and TRUNCATE
protection. Real migrated PostgreSQL tests cover missed runs, backdated rows,
sequence rollback gaps, concurrent writers/archivers, destination changes, wrong
keys, cancellation, upload/read-back corruption, deferred commit failure, damaged
source chains, and all three forbidden mutation statements. Tamper tests re-sign
altered manifests to exercise replay beyond the signature check. A CLI test
verifies downloaded artifacts with an unusable DATABASE_URL and AWS endpoint.
Chart tests cover four rendered configurations and seven rejected trust/batch
configurations.

DB-07's code path is implemented and tested locally. DB-08 still needs the actual
immutable destination/access/hold/retention policy and a fresh-host recovery drill;
conditional writes and immediate read-back do not establish long-term durability.
DB-09's TRUNCATE gap is closed, but checkpoint-aware hot/cold queries and safe
pruning are not implemented. Database owners able to disable triggers can bypass
the guard; this is not a database-superuser security boundary. No live archive,
retention, recovery or cluster configuration was changed for this acceptance run.
