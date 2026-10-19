# Development registry recovery

These files pin the reviewed development image graphs published on 2026-10-19.
They are development deployment evidence, not a substitute for the gated release
workflow or a claim that the broader parity/security gates pass.

`release-20261019.json` records each original local image and verified registry
manifest/index digest. `application-values-20261019.json` pins the application
roles. `infrastructure-values-20261019.json` pins PostgreSQL and configures the
pull secret. The two strategic merge patches pin the external CNPG and Barman
Deployments, including their operand/sidecar environment variables.

## Publishing a new development build

Create an input JSON with a `registry` prefix and `images` entries containing
`name`, `source`, `expected_digest`, and optionally a chart `role`. Obtain the
expected digest from Docker's OCI `Descriptor.digest`, not its configuration ID.
Authenticate Docker to GHCR using a publishing account, then run:

```sh
python3 scripts/publish-dev-images.py /path/to/plan.json --output /path/to/lock.json
python3 scripts/publish-dev-images.py /path/to/plan.json --output /path/to/lock.json --publish
```

Check the command exit status and `verified: true`. A failed publish preserves an
older lock; its presence alone does not prove the new operation succeeded.
The publisher refuses changed local identities and conflicting remote tags,
then verifies both the remote tag and digest reference. Review changes to the
lock and derive role values from its `helm_values` object.

## Recovery requirements

Keep a valid `constellation-ghcr-pull` Docker registry Secret in both
`constellation-system` and `cnpg-system`. Do not commit credentials. The initial
credential has publishing scope; replace it with a dedicated read:packages
credential when available. Existing application packages are public; infrastructure
packages retain their existing private visibility. Verify a private image pull
with Kubernetes before rolling database workloads.

Before infrastructure rollout, complete a CNPG plugin backup and verify its status.
Complete real scans of the exact controller and sidecar digests before changing
the database: connector connectivity alone does not establish tag discovery or
scan freshness. A stale-scan denial must be resolved through fresh scan evidence.
For coordinated operand changes, temporarily set the Cluster annotation
`cnpg.io/reconcilePodSpec=disabled`, apply the matching Cluster and controller
configuration, verify both controller rollouts, then remove that annotation.
This limits pod-spec changes to one planned database restart. Do not leave the
restart hold set after the rollout. Keep normal reconciliation and admission
validation enabled. Single-instance development databases incur downtime.
The development application release uses external database mode: its CNPG Cluster
is managed separately. Apply `constellation-cnpg-postgres-patch.json` with
`kubectl patch cluster constellation-cnpg-postgres --type=merge --patch-file ...`
in `constellation-system`. For chart-managed CNPG installations, use the reviewed
infrastructure Helm values instead. Apply the two deployment patches using
`kubectl patch --type=strategic --patch-file ...` in `cnpg-system`. Preserve all
other configuration. CNPG requires a PostgreSQL version tag alongside the digest
to validate upgrade compatibility; the published `16.14-dev-...@sha256:...`
reference preserves both. Admission scan freshness is enforced for controller
updates: refresh scans normally rather than bypassing the policy.
Never apply these values to an unrelated release without reviewing its names,
secret references, enabled roles, and database version.

After rollout, check all seven Deployments, the runtime DaemonSet, CNPG cluster,
CNPG/Barman Deployments, migration job, and authenticated UI. Compare the running
container image IDs to the lock; inspect database init and backup sidecar images
as well as primary containers. Run another backup to prove the new sidecar path.
A digest match proves image identity, not vulnerability absence.

Fresh OCI downloads of all twelve images (including every index member) passed
SHA-256 verification on 2026-10-19. Kubernetes also pulled and successfully ran
the private CNPG image with `imagePullPolicy: Always`. The fresh downloads used
separate OCI directories; the Kubernetes test did not erase the node layer cache.

The temporary restart hold is documented in [CNPG labels and annotations](https://cloudnative-pg.io/docs/1.25/labels_annotations/).
It is an operational coordination measure, not a permanent configuration.
Do not disable CNPG validation or Constellation admission enforcement to complete
this rollout. If stale evidence blocks retirement of an old ReplicaSet, record
that defect; scaling down only the retired replica set through the scale API
preserves the existing admission checks on replacement pods.
