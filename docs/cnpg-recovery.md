# CNPG backup, recovery and cutover

The chart supports CNPG-I Barman Cloud backups and recovery into a new cluster.
CloudNativePG is the only in-cluster Postgres the chart renders
(`postgres.mode=cnpg`, the default); `postgres.mode=external` points the
application at a DSN managed outside the release. The main development
deployment runs **PostgreSQL 16.14 on CNPG**; the October 12 cutover evidence is
kept below for the record. Local RustFS backup does not establish an off-host
recovery target or independent failure domains.

Install a compatible CloudNativePG operator and Barman Cloud plugin separately.
Pin a CNPG-compatible PG16 image containing pgvector, pgcrypto and pg_trgm
(the chart's default operand image does). Qualify it with the full migration
set. Treat a PG major upgrade as a separate migration.

There are two ways to provide the archive target:

**Production — externally managed ObjectStore.** Create an `ObjectStore`
resource with externally managed credentials, trusted TLS, WAL archival and a
reviewed retention policy, then reference it:

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

**Development / small installs — chart-rendered object store.** The chart can
render the whole target itself (this replaces the hand-applied manifests that
used to live in `deploy/dev/cnpg-rustfs/`): a single-replica RustFS StatefulSet
on one PVC, a `barmancloud.cnpg.io/v1 ObjectStore` named
`<release>-object-store-archive` (gzip WAL/data, `retentionPolicy`, SigV4
region `us-east-1`), random credentials in `<release>-object-store-credentials`
(re-used on upgrade), and a revision-scoped `aws-cli` Job that creates the
bucket idempotently. Leave `objectStoreName` empty and the Cluster archives to
the rendered store:

```yaml
backup:
  objectStore:
    enabled: true          # requires postgres.mode=cnpg
    storage: 8Gi
    bucket: constellation-recovery
    retentionPolicy: 7d
postgres:
  cloudnativepg:
    barmanCloud: { enabled: true }
    scheduledBackup: { enabled: true, schedule: "0 0 2 * * *" }
```

With NetworkPolicies enabled the chart also allows the Barman sidecar (in the
CNPG pods) and the bucket Job to reach the store on 9000, and nothing else.

The chart renders `method: plugin` and the plugin's WAL-archiver configuration.
It rejects a missing ObjectStore name (unless `backup.objectStore` supplies
one), plugin configuration in another DB mode, `backup.objectStore` outside
cnpg mode, and simultaneous legacy/native and plugin backup configuration.
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

Before moving an existing database (an external Postgres, or a CNPG cluster
managed outside the release) into a chart-managed CNPG cluster:

1. Record source image digests, migration version, DB extensions, chart values,
   service/Secret identities, row counts and audit head. Keep secrets out of the
   evidence report. Establish disk headroom and a bounded maintenance window.
2. Take a full database backup with a matching PostgreSQL client. Preserve
   external decryption/signing material separately under restricted access.
   Verify the dump and independently restore into an isolated PG16/pgvector
   target. Compare counts, audit continuity and credential decryption.
3. Initialize the new CNPG cluster, import the validated logical backup, and
   test the application's connection as its non-superuser. Plugin physical
   recovery requires an existing compatible base backup/WAL archive; it cannot
   consume a plain logical dump directly. When the target is rendered by a
   parallel release in the same namespace, set a distinct `nameOverride` as
   well as `fullnameOverride` so its pod labels and Services cannot be selected
   by the live release's policies and DSN.
4. Freeze application writers for the final transfer, verify a final consistent
   copy, and change the owning deployment's DSN through reviewed Helm values:
   keep the live release on `postgres.mode: external` with a new
   `postgres.existingSecret` containing the validated target DSN until the
   replacement has passed recovery and application checks, then flip the live
   release to `postgres.mode: cnpg` (or keep `external` if the CNPG cluster
   stays separately managed). Retain the source database and its credentials
   outside the release until cutover is accepted; the chart no longer keeps a
   stopped legacy workload around for rollback.
5. Verify authenticated login, scans, flow ingestion/rollups, policy reads and
   writes, audit append/verification and key-dependent operations. If rollback
   occurs after new writes, reconcile those writes first; pointing back to an
   older source alone is data loss.
6. Produce a real scheduled backup and WAL archive; restore to a second fresh
   target and verify the recovery point. Measure RPO/RTO, missed-backup alerts,
   storage failures and credential/TLS rejection. Require separate nodes/storage
   failure domains for HA and an independent host/site for off-host recovery.

Keep package B and DB-05 open until their full restore/deployment acceptance exists.

## Logical backup commands

`constellation-backup --mode=org-backup` and `constellationctl backup create`
export one organization's portable archive. Use `--out` for a local artifact,
`--s3=s3://bucket/prefix` for upload, or both. Generated filenames include the
organization name, time and job UUID; repeated jobs do not share an S3 object
name. Temporary workspaces use 0700 permissions and artifacts use 0600. Explicit
output directories must already exist; their permissions are not changed.

Choose either `--sign-key=/path/to/private.pem` or `--sign-keyless`.
`--verify-key=/path/to/public.pem` requires static-key signing and verifies the
completed archive before upload. An explicit empty key or conflicting signing
options fails before work begins. Omitting signing flags produces unsigned
output. Signature inspection allows up to 512 MiB of decompressed data, including
tar framing and trailing bytes, and checks the gzip trailer.

The standalone `--mode=pg-dump` exports the whole database through the matching
PostgreSQL client. It rejects signing/verification flags. Supply the connection
through `DATABASE_URL` to avoid putting credentials in the command invocation.
The child receives a temporary 0600 service profile and its password through
`PGPASSWORD`; this keeps the DSN out of child arguments, but does not hide the
child environment from the same user or privileged processes. Service-file
reads must complete within 1 MiB. Unsupported non-password values are rejected
instead of being trimmed or silently changing the database target.

Upload or catalog acknowledgement failures return an error. A completed local
artifact is retained for recovery, and a completed upload whose catalog write
fails reports its job UUID, object URI and retained local path. Check those
receipts before retrying; an error does not prove that no S3 object was created.
These commands do not replace the CNPG WAL/PITR recovery procedure above.

## Local RustFS rehearsal (October 11, 2026)

The user selected local RustFS for initial testing. The same contract is now
rendered by the chart's `backup.objectStore` values (defaults in brackets):

| Setting | Value |
| --- | --- |
| Bucket | `backup.objectStore.bucket` (`constellation-recovery`) |
| ObjectStore | `<release>-object-store-archive` (same namespace as CNPG) |
| Endpoint | `http://<release>-object-store:9000` inside the namespace |
| Signing region | `backup.objectStore.region` (`us-east-1`) |
| Retention / schedule | `backup.objectStore.retentionPolicy` (`7d`); `scheduledBackup.schedule` (`0 0 2 * * *`) plus immediate first backup |
| Images | `rustfs/rustfs:1.0.3` and `amazon/aws-cli:2.32.6`, both digest-pinned in values.yaml |
| Tested versions (manual rehearsal) | RustFS 1.0.1; CNPG 1.30.1; Barman plugin 0.15.1; cert-manager 1.21.2; PostgreSQL 16.14 with pgvector |

Credentials are generated randomly into the chart-managed Secret (or supplied
through `backup.objectStore.credentialsSecret`). There is no public S3 ingress.
Source and target use different CNPG server prefixes in the same test bucket;
recovery never reuses the source archive identity. Plain HTTP is confined to
the cluster network and, with NetworkPolicies, to the CNPG pods and the bucket
Job. This single-host setup does not establish off-host disaster recovery,
high availability or a production storage policy.

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
docker build -f deploy/docker/Dockerfile.postgres -t constellation/postgres:16.14-convergence-20261012 .
docker build -f deploy/docker/Dockerfile.api -t constellation/api:convergence-20261011 .
k3d image import -c constellation-recovery constellation/postgres:16.14-convergence-20261012 constellation/api:convergence-20261011
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
the switch. The current script also creates a random encrypted registry credential
through the production API, retrieves it through scanner-token authentication for an actively leased job,
and verifies its issuance receipt and the audit chain. The harness seeds only a
pending image target/job for the disposable registry; the production claim and
renew endpoints establish scanner ownership before credential release. The restored API must
return the original credential and retain the source audit anchor. A restart with
a different KEK must reject decryption; restoring the original key must restore
access. A recovered database-pod deletion must also recover authenticated access.
These checks use disposable identities and retain credential material only in the
restricted evidence directory. They do not invoke an external registry.

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

## October 12 credential and process-recovery qualification

The schema-172 continuation passed the complete script in
`recovery-bf8bf9af`, using API image
`constellation-browser-58c8017f4908-api:latest` with index
`sha256:8382addded7cd3d9d2e74410772f6b64342189a0f82e88ea74abe6e19ded867b`.
Scheduled backup `recovery-source-postgres-20261012050048` completed; PITR,
extensions, existing sessions, fresh login, saved configuration, encrypted
credentials, source audit anchor, wrong-key rejection and key restoration passed.
Database-pod restart through authenticated recovery took **199 seconds**.
The namespace was removed. The log is `/tmp/constellation-resume-cnpg.log`;
protected evidence is `/tmp/constellation-cnpg-test.ExEW6y` (never commit).

This run used locally rebuilt upstream operators: CNPG source
`2a35abb4628f209d149825ef3c38011e0701ff2f` and Barman source
`6216b7dd552f389952d3de77712d9522a79d9548`, rebuilt with Go 1.27.2 and updated
`golang.org/x` dependencies. The subsequent main-cluster operator index is
`sha256:cc61009ac3d2cdf0aa2ff7f44f85dbb7bdf85ab50425d41a71da2af6521cc1b9`,
plugin index
`sha256:de96d9e4bf0f2f69f8d2b3c1a8bc953ea8235d613901ae19754600b55cb07590`,
and sidecar index
`sha256:61b55f0807293213c68d3d7a5572c41d5b7fa164dba2f956d0c660952779f261`.
All have successful Trivy and Grype engine outcomes. The operator has no findings;
the plugin has 56 findings, none critical; the sidecar has 187 findings including
four critical Python findings without reported fixes. These are local development
artifacts, not a claim that upstream releases or the complete stack are clean.
The rehearsal controller ran the earlier operator image with runtime image ID
`sha256:3fd7acc3fa5923cf4b98d18abc88ba986a1f3ea3a959a6030e1c851ec778d110`;
the main controller uses
`sha256:7bd7c74ccdc103c7b6bbb2f28149d072ac0ee7c725bb4c65305f628a32af55b9`,
which also replaces the otherwise-unused arm64 binary. The amd64 operator binary
is the same build, but those container identities are not interchangeable evidence.

The live saved admission rule was explicitly converted from retired VulnDB
provenance to successful Trivy and Grype evidence through the authenticated policy
API. Its existing severity, fix-availability and exception requirements were
preserved. Actual local scan reports were uploaded through scanner claim/completion
endpoints, with imported image digests checked; findings were not filtered out.
Unknown-image admission still denies. The local-path provisioner helper was
scanned normally and pinned to the accepted digest
`rancher/mirrored-library-busybox:1.37.0@sha256:101b4afd76732482eff9b95cae5f94bcf295e521fbec4e01b69c5421f3f3f3e5`.
Mutable tag references were not recognized as equivalent to the scanner's pinned
reference; the digest pin avoids weakening admission or inventing tag evidence.

The main local-path provisioner also needed a patched build: upstream v0.0.36
(source `5d4bfc84b32cd9c5f56ed3aba921b1a3924ea2f0`) was rebuilt with Go 1.27.2,
`x/net v0.60.0` and `x/text v0.42.0`. Its static executable runs in pinned
`gcr.io/distroless/static-debian13:nonroot`, rather than the upstream runtime that
also carries an old Go toolchain. The imported local image
`constellation/local-path-provisioner:v0.0.36-go1.27.2` has image ID
`sha256:0cc6512f76e806dec03b7418d39ee953d75fc7f1b12df3aa9c32fc58ca2c35cb`.
Upstream tests passed; the real scan returned one finding, none critical, with
successful Trivy and Grype outcomes. Admission accepted the replacement. Setting
`CONFIG_MOUNT_PATH=/etc/config` enables the provisioner's helper-template reload;
its restart picked up the pinned helper and both new PVCs bound. These node-local
images and the k3s-managed provisioner override must be distributed/persisted
before adding nodes or replacing this host; they are not a portable release.

Staging initially crossed the node's image-GC threshold. Removing only Docker
build cache older than 24 hours reclaimed **26.9 GB**, reducing disk use to 79%
with approximately 72 GiB available before the new database copy. Existing
volumes and backup artifacts were retained. The protected cutover directory is
`/root/constellation-cutover-20261012-ec73Oq`; it contains database dumps, credentials,
prior resources/values, scan receipts and rollout configuration and must never be
committed. Helm release 19 reconciles the application values with the cutover
described below. The CNPG cluster, RustFS and operators were installed separately.

The stronger check passed first in namespace `recovery-224164bc` at schema 171,
with scheduled backup `recovery-source-postgres-20261012042414`. The API created
and recovered a randomly generated encrypted credential, rejected a wrong KEK,
resumed after restoring the correct key, and verified the audit chain and original
audit anchor. The log is `/tmp/constellation-cnpg-key-recovery.log`; protected
material is in `/tmp/constellation-cnpg-test.2I2GjA` (never commit).

The repeat in `recovery-09b1d9ba` passed on **PostgreSQL 16.14**, with backup
`recovery-source-postgres-20261012042922`. It additionally deleted the recovered
primary pod and passed session/config/credential/audit checks after recreation
on its existing PVC. Deletion through authenticated recovery took **315 seconds**.
This is a single-host, single-instance process/PVC recovery measurement, not HA,
node-loss or off-host recovery. The API image was
`constellation-browser-dd0f7f69b304-api:latest`, index
`sha256:3a6569c2c020c40fff1e5d143863c1ea3faa299a0df50341f4aa7d1a60b70d48`
(schema 171, before the later admission-engine evidence increment). The new
PostgreSQL image `constellation/postgres:16.14-convergence-20261012` has index
`sha256:98087f2e517416edda6e3649154c3be4a5a7b0ce2228c4fab3f4e2bed430d92a`.
Its upstream base is pinned by digest in `Dockerfile.postgres`.
Evidence: `/tmp/constellation-cnpg-pg1614-recovery.log`; protected material:
`/tmp/constellation-cnpg-test.PVcuhQ`. Both disposable namespaces were removed.

The owner explicitly **deferred off-host recovery and real node-failure testing**
on October 12. Those acceptance requirements remain deferred, not satisfied by
the local rehearsal. Main-cluster cutover is authorized, but image qualification,
consistent transfer and application checks still precede switching its DSN.

### Main development cutover

On October 12, the application moved from its legacy StatefulSet to
`constellation-cnpg-postgres-rw` on PostgreSQL **16.14**, schema **172**. Before
changing the DSN, the six application writer Deployments were stopped, remaining
source client connections checked, and a fresh custom-format dump restored into
the empty CNPG application database. All **138** public root-table counts matched,
including **2,992,972** flows, **3,095,974** runtime events and **1,909,943** audit
rows. The audit head at ID **1,909,970** matched; a second source check confirmed
that it had remained frozen. The successful dump/restore/comparison took
**208 seconds**; that is not an end-to-end outage or RTO measurement. An initial
attempt failed on a verification-script type error before switching connections;
its recovery path resumed the original writers, and a new dump was taken for the
successful attempt.

Helm release **19** used `postgres.mode=external` with the new Secret
`constellation-cnpg-database-url` and the (since removed)
`retainStatefulSetForRollback=true` flag, which kept the old StatefulSet at
zero replicas along with its original PVC and credentials. That rollback
scaffold no longer exists in the chart: the embedded StatefulSet mode was
deleted, so a future cutover retains the source database outside the release
(step 4 above). Do not simply point back at old data after writes reach CNPG;
rollback requires reconciliation.

All application roles returned ready. Fresh API and real-browser login passed;
clusters, scan status, organization settings and registries returned HTTP 200.
Existing Kubernetes Secret data was unchanged across the upgrade. The API and
frontend include the configured-provider-only SSO login fix; admission uses
successful Trivy/Grype evidence. Other runtime roles still use the earlier image
line, so this cutover does not qualify receipt-aware agent queues. The canonical
parity and fleet acceptance items remain open.

The verified final dump, row counts, audit anchor, Secret snapshots, exact values
and recovery receipts remain in the protected cutover directory. Continuous WAL
archiving is healthy. Daily scheduled backup is configured for **02:00 UTC** via
the Barman plugin and local RustFS. This single-node object store does not satisfy
the explicitly deferred off-host or node-loss recovery requirements.

The first main scheduled backup,
`constellation-cnpg-postgres-20261012053647`, completed successfully. A separate
`constellation-cnpg-restore-check` cluster recovered it through the Barman plugin.
An isolated API, with no service-account token and egress limited to that database
and DNS, verified the original session, fresh login, saved configuration and a
randomly generated encrypted registry credential. Schema 172, all three required
extensions and the original migrated audit anchor matched. This proves the
recorded backup plus archived WAL can recover the actual database and its key
material; it does not certify the pre-existing audit-chain break. Live ingestion
and retention had resumed before this backup, so its later row counts are not the
frozen transfer's counts. The temporary source credential fixture, validation API,
restored cluster and restored PVC were removed after passing. Logs are
`/tmp/constellation-main-restore-check.log` and
`/tmp/constellation-main-recovery-verification.log`; protected receipts are in the
cutover directory.

### Admission trust across the cutover upgrade

The final dry-run admission check detected that the revision-19 upgrade with
`--no-hooks` cleared the webhook CA bundle. TLS validation failed, and the existing
`failurePolicy=Ignore` allowed requests during that interval. The original CA was
restored from the unchanged admission TLS Secret; unknown-image denial resumed.
The chart now preserves the existing webhook CA during upgrade, falling back to
the configured TLS Secret's CA when necessary. Fresh installs still rely on
bootstrap or cert-manager injection. A server-side render matched the existing
bundle, and an actual revision-**20** upgrade with hooks disabled preserved it.
After that upgrade, server-side dry runs denied an unknown image and admitted the
scanned, digest-pinned helper. No test workload was created, and the failure policy
was not relaxed. Receipt: `admission-trust-upgrade-verification.json` in the
protected cutover directory. This closes that upgrade regression, not the broader
historical certificate/key inventory acceptance.

### Existing database audit baseline

Read-only verification of the independent existing-data restore fails at audit
row **53** with `prev_hash mismatch`. The live source has the same broken link:
`scan-job.complete`, **2026-06-14 13:37:16.545671 UTC**. Adjacent rows 48–52 and
54–56 link to their predecessors. This establishes a pre-existing discontinuity;
it does not identify its cause or prove the remaining chain intact. No historical
rows or hashes were rewritten. Preserve this baseline in any transfer and resolve
historical integrity/archival acceptance separately; successful verification of
the new disposable fixture does not certify the existing database's history.

## Chart-managed off-host archive and PITR drills

`backup.offhost` (see docs/deployment-helm.md) renders the off-host
`ObjectStore`, the `archive-offhost-sync` CronJob and a `-recovery`
ObjectStore. Before a point-in-time drill against either store **switch WAL
twice** on the primary (`SELECT pg_switch_wal();` run twice, or wait two
`archive_timeout` periods) so the segment holding the target time is archived
and mirrored; a drill whose target sits in the current, unarchived segment
recovers to the previous checkpoint instead.

## Operator and plugin images

The CloudNativePG operator and the Barman Cloud plugin are installed outside the Helm
release (namespace `cnpg-system`), but their images are release artifacts:
`deploy/cnpg/build-images.sh` rebuilds CNPG 1.30.1 and plugin-barman-cloud 0.15.1 from
their verified tag commits on the repository Go toolchain (go >= 1.27.3, the eMudhra
floor), applies the reviewed `golang.org/x` bumps, and runs the release gate,
`scripts/check-image-go.sh` and cosign signing. The pinned references are in
`deploy/cnpg/images.env`; the operand is the release `postgres:16.15-v<appVersion>` image.

Roll them in this order (take a `Backup` first; archiving must stay green):

```sh
. deploy/cnpg/images.env
# 1. plugin: its Deployment image and the sidecar it injects into instance pods
kubectl -n cnpg-system set image deploy/barman-cloud barman-cloud="$BARMAN_PLUGIN_IMAGE"
kubectl -n cnpg-system set env deploy/barman-cloud SIDECAR_IMAGE="$BARMAN_SIDECAR_IMAGE"
kubectl -n cnpg-system rollout status deploy/barman-cloud
# 2. operator: image and OPERATOR_IMAGE_NAME must be the identical string
kubectl -n cnpg-system set image deploy/cnpg-controller-manager manager="$CNPG_OPERATOR_IMAGE"
kubectl -n cnpg-system set env deploy/cnpg-controller-manager OPERATOR_IMAGE_NAME="$CNPG_OPERATOR_IMAGE"
kubectl -n cnpg-system rollout status deploy/cnpg-controller-manager
# 3. operand (restarts the instance; single-instance clusters see a short outage)
kubectl -n <ns> patch cluster <name> --type merge -p '{"spec":{"imageName":"<registry>/postgres:16.15-v<appVersion>@<digest>"}}'
```

Verify `pg_stat_archiver` (`failed_count` not increasing after a `pg_switch_wal()`), the
Cluster `ContinuousArchiving=True` condition, and a fresh `Backup` reaching `completed`.

## October 23 current-backup recovery and migration qualification

A new chart-rendered `lifecycle-restore-20261023-postgres` cluster restored the
current live archive into its own 24-GiB volume in `constellation-system`. The
source remained `constellation-cnpg-postgres`; no application DSN was switched.
The recovery used the source's pinned PostgreSQL 16.15 image and the existing
`rustfs-archive` object store, with no archive-writer plugin configured on the test
cluster. This is same-host recovery, not a node-loss or off-host drill.

The first bootstrap attempts failed because the namespace's default-deny policy
did not allow the new cluster to reach the Kubernetes API. A policy rendered from
`networkpolicies-cnpg.yaml`, selected only for the new cluster, supplied DNS,
API, operator and object-store access. Recovery then completed. Include this
policy in future isolated rehearsals; database credentials alone are insufficient.

Creation was 17:03:12 UTC; CNPG reported Ready at 17:13:29 UTC: **10 minutes 17
seconds**, including the policy failure/retry. This measures database readiness,
not application login or failover RTO. The restored audit stream's latest timestamp
was 17:11:47 UTC; it is an observed recovered receipt, not a proven RPO guarantee.
`pgcrypto`, `pg_trgm` and `vector` were present. A freshly compiled API migration
runner applied migrations 191 and 192 to the restored copy. Exact counts were
unchanged before and after:

| Family | Rows |
| --- | ---: |
| Raw flows | 1,923,052 |
| Hourly rollups | 174,066 |
| Events | 4,718,506 |
| Audit events | 2,015,126 |
| Findings | 22,185 |
| CVE catalog | 412,772 |
| Scan evidence | 1,310 |
| Organization backup catalog | 0 |

Audit verification reports the same **row-53 `prev_hash` mismatch** before and
after migration. A SHA256 over the complete first 53 rows matched between the
live source and restore. Restoration preserved the pre-existing discontinuity;
no hashes or historical rows were rewritten. DB-07/08 integrity qualification
must continue to report this limitation.

Evidence and private generated credentials are under
`/root/constellation-lifecycle-completion-20261023/`. Do not commit the rendered
Secret manifest. The restored copy remains isolated while subsequent lifecycle
and query-plan checks use it; its resources must be removed when that work ends.
