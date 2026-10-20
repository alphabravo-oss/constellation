# Deploying scheduled compliance reports

The API stores schedules and queues Run now requests. The separate compliance
scheduler executes them. Enable `complianceScheduler.enabled` only after providing
an image, durable shared storage and a signing Secret:

```yaml
complianceScheduler:
  enabled: true
  image:
    repository: ghcr.io/alphabravo-oss/constellation/compliance-scheduler
    digest: sha256:<verified candidate digest>
  storage:
    existingClaim: constellation-compliance-reports
    accessMode: ReadWriteOnce
  signingSecret: constellation-compliance-report-signing
  interval: 30s
```

The existing PVC must be writable by the chart's nonroot UID/GID. The scheduler
creates a private `reports` subdirectory at
`/var/lib/constellation-reports/reports`. The API mounts the same PVC read-only at
the same path and serves authenticated, organization-scoped artifact downloads.
The chart prevents an API environment override from silently changing this path.
The PVC is managed separately and is not deleted when the scheduler is disabled.

With ReadWriteOnce storage, the scheduler is colocated with an API pod and API
rollouts use Recreate. This is a storage locality requirement, not an HA claim.
Use a suitable ReadWriteMany claim for multiple-node access; chart configuration
must match the actual claim's access mode. The worker currently uses one replica.

The scheduler serves `/healthz`, `/readyz` and `/metrics` on its admin listener
(`ADMIN_LISTEN_ADDR=:9090`, container port `admin`); the chart's readiness and
liveness probes use it. It also heartbeats to the control plane through
`CONSTELLATION_API_URL` (the in-cluster API Service unless
`controlPlane.apiURL` is set) with `CONSTELLATION_COMPLIANCE_SCHEDULER_TOKEN`
from the shared runtime-agent token Secret, mounted read-only at
`RUNTIME_AGENT_TOKEN_FILE` like the discoverer and policy applier, so it shows
up in System Health alongside the other components.

The signing Secret must contain `cosign.key` (encrypted Cosign private key) and
`password` (its passphrase). Keep `cosign.pub` with recovery material for independent
verification. Only the scheduler receives this Secret; the API never mounts the
private key. Back up the report volume and signing Secret using the deployment's
recovery process. Database backup alone does not preserve either.

The packaged worker builds Cosign 3 from the same reviewed source patches and
locked dependencies as the scanner. Its runtime contains only the worker and
Cosign. The dependency patch uses the maintained Azure credential helper and
Rekor 1.5.4 with maintained ProtonMail OpenPGP support. It requests a modern bundle with an explicit signing configuration that
has no external services. Signing therefore needs no public transparency log,
certificate authority or timestamp service. It checks the bundle format,
SHA-256 report digest and signature encoding, then retains the detached base64
signature expected by the API. Key bootstrap is bounded to 30 seconds and report
signing to two minutes, including earlier cancellation. Failed configured signing
prevents delivery. The standalone binary's existing checksum fallback when no
signer can be configured remains distinct from a signed report.

The hosted proof runs the real tool with Docker networking disabled. Go's crypto
library independently verifies the resulting signature and rejects modified
report bytes. The normal regression suite also covers delivery failures and
artifact confinement. The image does not include a PDF renderer: PDF requests
retain the existing explicit HTML fallback and recorded media type. JSON, CSV
and HTML rendering do not require a browser binary.

Before enabling a previously absent scheduler, inspect existing enabled schedules
and their delivery destinations. Once enabled, all due schedules are eligible.
A deployment acceptance check can create a schedule with no external destinations,
request Run now, verify its successful history entry, download the artifact and
verify its signature. Delete that validation schedule afterward. Verify the
artifact remains downloadable after restarting the worker to exercise persistent
storage. This does not validate external email/S3/webhook delivery or full HA.
