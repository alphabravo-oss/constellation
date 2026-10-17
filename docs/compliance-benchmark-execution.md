# Durable benchmark execution

Schema 179 adds tracked kube-bench requests, attempts and result receipts. The
cluster Compliance workspace has a Benchmarks tab with a queue form, execution
history and reviewed retries. This is separate from scheduled compliance report
generation and the existing one-shot benchmark CronJobs.

## Execution states

| State | Meaning |
| --- | --- |
| Queued | The request is persisted; a worker has not claimed it. This does not establish worker availability. |
| Running | A worker holds the current attempt lease. |
| Succeeded | A valid report was ingested. Its source controls can still contain failures or manual checks. |
| Failed | Execution, timeout, report validation or an explicit interrupted outcome failed. |
| Interrupted | The running attempt's lease expired. No automatic retry occurs. |

Source control counts describe the submitted report. Stored evidence row counts
can be larger because controls map to multiple frameworks. Neither a completed
report nor a single worker establishes coverage of every node in a cluster.

The first claim binds an organization-wide request to the authenticated worker's
cluster. That binding survives retries. A request allows at most three attempts;
retry requires the exact currently reviewed revision and a failed or interrupted
state. The browser refreshes stale or uncertain retry receipts before permitting
another attempt. It retains an unconfirmed create request's UUID in session
storage, scoped to the user, organization, cluster and benchmark selectors.

Legacy pending/claimed requests remain unchanged and are excluded from the new
history. They are not automatically replayed or presented as completed scans.

## Worker deployment

The worker is disabled by default. Enabling it requires a qualified image that
bundles the Constellation runner, upstream kube-bench executable and its config
tree; an exclusive durable PVC; and the registered cluster's runtime-agent
credential. The chart uses one replica with a Recreate strategy and a file lock
to protect the execution journal. It does not use an ephemeral volume for state.

Relevant Helm values:

```yaml
kubeBenchWorker:
  enabled: true
  image:
    repository: ghcr.io/alphabravo-oss/constellation/kube-bench-runner
    tag: "<qualified-release-tag>"
  clusterId: "<registered-cluster-uuid>"
  state:
    existingClaim: "<exclusive-worker-pvc>"
  interval: "30s"
  nodeSelector: {}
  hostVolumes: []
  hostVolumeMounts: []
```

Select the intended benchmark node and configure the host paths required by that
platform's kube-bench configuration. The pod uses host PID visibility; host
volume mounts must be reviewed for the selected platform. Empty host-volume
defaults are not a qualified host-coverage configuration. The worker's node and
pod UID are attribution supplied by Kubernetes, not independent node credentials.
The server authorizes every request using the runtime-agent token and its exact
cluster binding; a configured cluster ID is also asserted before dispatch.

An optional benchmark identifier pins the actual invocation and evidence
attribution. Empty selects automatic detection and removes a configured pin from
the claimed invocation. Durable docker-bench execution is unsupported: the API
returns 422, and enabling `dockerBenchWorker` fails chart rendering.

## Recovery and receipts

The worker writes private intent before claiming or executing, then persists the
result before upload. Lost claim acknowledgements reuse the same claim key; lost
result acknowledgements resubmit the same attempt and report digest. An identical
terminal result returns its original receipt without refreshing evidence or audit
timestamps. An uncertain executing journal recovered after a restart is reported
as interrupted rather than running the attempt again.

The server gives an initial ten-minute lease. Heartbeats renew it to at most ten
minutes from current server time, capped at fifteen minutes from attempt start.
Expired or replaced attempts cannot be revived. A reviewed retry closes the old
expired attempt and queues the next one atomically with its audit record.

The state directory must be private and persistent. A credential or scope change
while state is pending refuses automatic rebinding. Preserve that journal, review
the server attempt and its lease, and reconcile the pending execution before
changing its scope. Credential files are read at startup; restart a drained worker
after rotation. A rejected stale result is retained as one private
`last-rejected.json` for review, never submitted to a replacement attempt.

Reports are bounded to 16 MiB. Their SHA-256 covers compact JSON bytes with
whitespace removed, without key sorting. Evidence, terminal attempt, request and
completion audit commit in one transaction. Failures record bounded outcome
codes; raw command stderr is not stored or sent as an error response. A missing
database commit acknowledgement remains uncertain and must be reconciled using
the same request or attempt identity.

The main development deployment at Helm79/schema179 includes this lifecycle and
the cluster Benchmarks workspace. Its benchmark worker remains disabled. The
isolated qualification below does not establish host coverage; actual platform
configuration and main-cluster execution require qualification before enabling it.


## Qualified worker boundary

The `610ad3d` development worker image includes upstream kube-bench v0.10.7,
its configuration tree and procps for process-based checks. An isolated real API,
PostgreSQL and worker acceptance run queued and completed two actual source
checks (one PASS, one FAIL), then recreated all three processes with their owned
persistent volumes. The original receipt, evidence timestamps and single
completion audit remained unchanged, without another execution. A separate
controlled lost-acknowledgement fixture proves replay of the same durable result.

These fixtures expose neither host PID visibility nor host files. They qualify
the execution protocol and restart persistence; they do not qualify node coverage,
full platform benchmark configuration, backup recovery of the execution ledger,
airgapped deployment or a fleet rollout. Evidence:
`/tmp/constellation-bench-real-e2e/evidence/summary.json`.
