# CNPG backup, recovery and cutover

The chart supports CNPG-I Barman Cloud backups and recovery into a new cluster.
This is a deployment contract, not evidence that the existing development
StatefulSet has been migrated or that an off-host recovery target is configured.

Install a compatible CloudNativePG operator and Barman Cloud plugin separately.
Create an ObjectStore resource with externally managed credentials, trusted TLS,
WAL archival and a reviewed retention policy. Pin a CNPG-compatible PG16 image
containing pgvector, pgcrypto and pg_trgm. Qualify it with the full migration set.
Treat a PG major upgrade as a separate migration.

Enable backups with these non-secret values:

```yaml
postgres:
  mode: cnpg
  cloudnativepg:
    barmanCloud:
      enabled: true
      objectStoreName: constellation-archive
    scheduledBackup:
      enabled: true
      schedule: "0 0 2 * * *"
```

The chart renders `method: plugin` and the plugin's WAL-archiver configuration.
It rejects missing ObjectStore names, plugin configuration in another DB mode,
and simultaneous legacy/native and plugin backup configuration. ObjectStore
credentials and bucket lifecycle remain owned by the infrastructure operator.
See the [CNPG backup contract](https://cloudnative-pg.io/docs/1.28/backup/).

For recovery, use a new release/cluster identity and empty PVCs:

```yaml
postgres:
  mode: cnpg
  cloudnativepg:
    instances: 1 # development rehearsal; not HA
    barmanCloud:
      recovery:
        enabled: true
        objectStoreName: constellation-source-archive
        serverName: constellation-postgres
        targetTime: "" # or a timestamp covered by the WAL archive
```

Recovery renders the application's database, owner and Secret reference so the
recovered application user receives the intended connection password after
promotion. Application encryption and signing keys require their own protected
recovery path; PostgreSQL backup alone does not capture Kubernetes Secrets.
Choose a separate archive destination for the restored cluster. Never disable
CNPG's empty-archive safeguard. See [CNPG recovery](https://cloudnative-pg.io/docs/1.28/recovery/).

Before switching the existing StatefulSet:

1. Record source image digests, migration version, DB extensions, chart values,
   service/Secret identities, row counts and audit head. Keep secrets out of the
   evidence report. Establish disk headroom and a bounded maintenance window.
2. Take a full database backup with a matching PostgreSQL client. Preserve
   external decryption/signing material separately under restricted access.
   Verify the dump and independently restore into an isolated PG16/pgvector
   target. Compare counts, audit continuity and credential decryption.
3. Initialize the new CNPG cluster, import the validated logical backup for the
   first StatefulSet transition, and test the application's connection as its
   non-superuser. Plugin physical recovery requires an existing compatible base
   backup/WAL archive; it cannot consume a plain logical dump directly.
4. Freeze application writers for the final transfer, verify a final consistent
   copy, and change the owning deployment's DSN through reviewed Helm values.
   Do not perform an in-place mode flip that removes the source StatefulSet
   before the replacement has passed recovery and application checks. Retain
   the source PVC and rollback configuration until cutover is accepted.
5. Verify authenticated login, scans, flow ingestion/rollups, policy reads and
   writes, audit append/verification and key-dependent operations. If rollback
   occurs after new writes, reconcile those writes first; pointing back to an
   older source alone is data loss.
6. Produce a real scheduled backup and WAL archive; restore to a second fresh
   target and verify the recovery point. Measure RPO/RTO, missed-backup alerts,
   storage failures and credential/TLS rejection. Require separate nodes/storage
   failure domains for HA and an independent host/site for off-host recovery.

Keep package B and DB-05 open until their full restore/deployment acceptance exists.

## Local RustFS rehearsal (October 11, 2026)

The user selected local RustFS for initial testing. The non-secret contract is:

| Setting | Value |
| --- | --- |
| Bucket | `constellation-recovery` |
| ObjectStore | `rustfs-archive` (same namespace as CNPG) |
| Endpoint | `http://rustfs:9000` inside the isolated test namespace |
| Signing region | `us-east-1` |
| Retention / schedule | 7 days; daily at 02:00 UTC, plus immediate first backup |
| Tested versions | RustFS 1.0.1; CNPG 1.30.1; Barman plugin 0.15.1; cert-manager 1.21.2; PostgreSQL 16.10 with pgvector |

Credentials are generated randomly into Kubernetes Secrets and a restricted
temporary evidence directory. There is no public S3 ingress. Source and target
use different CNPG server prefixes in the same test bucket; recovery never
reuses the source archive identity. Plain HTTP is confined to this disposable
local test network. This single-host test does not establish off-host disaster
recovery, high availability or a production storage policy.

To reproduce, create an isolated k3d cluster without changing the default
kubeconfig, install the pinned operators, and import the repository images:

```sh
k3d cluster create constellation-recovery --image rancher/k3s:v1.35.5-k3s1 \
  --kubeconfig-update-default=false --kubeconfig-switch-context=false
export CNPG_TEST_KUBECONFIG="$(mktemp /tmp/constellation-recovery-kubeconfig.XXXXXX)"
k3d kubeconfig get constellation-recovery > "$CNPG_TEST_KUBECONFIG"
chmod 600 "$CNPG_TEST_KUBECONFIG"
kubectl --kubeconfig "$CNPG_TEST_KUBECONFIG" apply -f \
  https://github.com/cert-manager/cert-manager/releases/download/v1.21.2/cert-manager.yaml
kubectl --kubeconfig "$CNPG_TEST_KUBECONFIG" -n cert-manager rollout status deployment --timeout=300s
kubectl --kubeconfig "$CNPG_TEST_KUBECONFIG" apply --server-side -f \
  https://github.com/cloudnative-pg/cloudnative-pg/releases/download/v1.30.1/cnpg-1.30.1.yaml
kubectl --kubeconfig "$CNPG_TEST_KUBECONFIG" -n cnpg-system rollout status deployment --timeout=300s
kubectl --kubeconfig "$CNPG_TEST_KUBECONFIG" apply -f \
  https://github.com/cloudnative-pg/plugin-barman-cloud/releases/download/v0.15.1/manifest.yaml
kubectl --kubeconfig "$CNPG_TEST_KUBECONFIG" -n cnpg-system rollout status deployment --timeout=300s
docker build -f deploy/docker/Dockerfile.postgres -t constellation/postgres:16.10-convergence-20261011 .
docker build -f deploy/docker/Dockerfile.api -t constellation/api:convergence-20261011 .
k3d image import -c constellation-recovery constellation/postgres:16.10-convergence-20261011 constellation/api:convergence-20261011
CNPG_TEST_API_IMAGE=constellation/api:convergence-20261011 scripts/test-cnpg-rustfs.sh
```

The script requires Go, Goose, Python, Helm, kubectl, curl and ripgrep. It refuses
non-k3d contexts and creates a new namespace for each run. By default it deletes
only that namespace on exit; `KEEP_CLUSTER=1` retains the namespace for inspection.
The dedicated k3d cluster is always retained until explicitly deleted. Evidence
and credentials remain in the printed mode-700 temporary directory; handle that
directory as sensitive and never commit it. Ports default to 15435 and 18083 and
can be overridden with `CNPG_TEST_PG_PORT` / `CNPG_TEST_API_PORT`.

The test migrates and seeds the real application, waits for a ScheduledBackup
to complete, commits a post-backup marker and captures a recovery timestamp,
then commits a marker after that timestamp. It waits for the committed WAL to
archive before creating a separate recovery cluster. The restored database must
contain exactly markers 1 and 2, exclude marker 3, and contain all three required
extensions. Only the disposable API's DSN is switched. An existing signed
session, saved configuration and fresh authenticated login must all work after
the switch. The same application KEK Secret is retained; this test does not yet
assert decryption of an encrypted integration credential or audit-chain validity.

The manual run restored exactly markers 1 and 2. Its first recovery attempt
correctly refused to promote because the final transaction's commit WAL was not
yet archived. The reproducible script separates the final insert and WAL switch
into distinct transactions and explicitly waits for archival, preventing that
test sequencing error. A successful backup alone is not sufficient PITR proof.

The checked-in script subsequently passed end to end in namespace
`recovery-c4dc97f6` on the isolated `constellation-convergence` k3d cluster:
ScheduledBackup-created `recovery-source-postgres-20261011225145` completed;
`recovery-target-postgres` recovered markers 1 and 2 and all required extensions;
the test API rolled to the target DSN and passed both the pre-recovery session
continuity check (session created after the base backup, recovered through WAL)
and a fresh login/configuration check. Both CNPG clusters were healthy afterward.
The run finished with exit status 0. Protected evidence is retained locally in
`/tmp/constellation-cnpg-test.iSTzPK`; this directory contains secrets and is not
a repository artifact. No main-cluster resource was changed.

The recovery runner requires `CNPG_TEST_API_IMAGE` explicitly. Import that exact
fresh build into the isolated cluster first. Both the schema-check init container
and API use it on the source and recovered databases. An old cached fixture image
is not accepted as evidence for the current source. The API's schema requirement
is enforced before it initializes services.

The October 12 repeat passed at schema **171** in disposable namespace
`recovery-2e90a3cc`, including both schema-check init containers, scheduled backup
`recovery-source-postgres-20261012030452`, the WAL/PITR marker boundary, extensions,
existing session continuity, saved configuration and fresh login. The namespace
was deleted on exit. The selected API image was
`constellation-browser-24194cdf9ad0-api:latest`, image index
`sha256:2880f0aeaed7a5e27a3abf44aabaa1025cfb6e7eb9894aeb48c9c145c8e29ccd`,
built for the session/schema increment `103bf74`. This qualifies that build; it
does not qualify subsequent archive extraction or dead-code changes. The run log
is `/tmp/constellation-cnpg-171-rehearsal-fixed.log`; protected credentials and
evidence remain in `/tmp/constellation-cnpg-test.BTZyxA` and must not be committed.
The API manifest renderer handles both Kubernetes Lists and adjacent JSON
documents, requires exactly one API and schema-check container, and assigns the
explicitly selected image to both. Three tooling regression tests cover those
contracts and rejection of ambiguous manifests.

A later October 12 rehearsal passed with the native policy validation and DNS/CLI
changes in `constellation-browser-ec202b2c53f2-api:latest`, index
`sha256:85d14cbf5b7fb67f0ef3b6da4f8065df2c42fe5f89bdc90b8c57f1e87a8221e3`.
Namespace `recovery-94263fc4` completed scheduled backup
`recovery-source-postgres-20261012033238`, recovered exactly markers 1 and 2,
passed the extension/session/config/login checks, and was deleted on exit.
Schema 171 gates passed on source and target. This image precedes the small CLI
and group-edge error-handler cleanup, whose later image has separate browser
evidence; do not conflate the image digests. The successful run is recorded in
`/tmp/constellation-cnpg-current-rehearsal.log`; protected credentials/evidence
remain in `/tmp/constellation-cnpg-test.TEXvXJ` and must not be committed.
