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
Apply the infrastructure values through the existing Helm release with its reviewed
values, then apply the two deployment patches using `kubectl patch --type=strategic
--patch-file ...` in `cnpg-system`. Preserve all other deployment configuration.
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
