# Discoverer platform reporting credentials

Platform facts require a runtime-agent token explicitly issued for the reported
cluster through a cluster init bundle. A bootstrap token without that binding can
still authenticate, but receives HTTP 403 for platform reports. Do not remove the
binding check or create synthetic bundle rows to bypass enrollment.

For an existing installation using an unbound shared bootstrap token:

1. As an organization administrator, create an init bundle for the **existing exact
   cluster name**, preserving its distro and region. Check that the returned cluster
   UUID is the intended cluster. Choose a bounded credential lifetime and record the
   expiration for rotation.
2. Store the returned `spec.runtime_agent_token` in a Kubernetes Secret in the
   release namespace, under key `token`. Keep bundle contents and credentials out of
   source control, logs, shell arguments, and Helm values.
3. Set `discoverer.tokenSecret` to that Secret's name and upgrade the release. Both
   environment references and the mounted token file use this dedicated Secret.
   Other components continue using their existing runtime-agent credentials.
4. Verify a fresh `cluster_platform_facts.observed_at` for the intended cluster,
   successful discoverer reconciliation, and absence of platform-report 403 errors.

An empty `discoverer.tokenSecret` preserves the shared runtime-agent Secret. That
shared credential must itself be bundle-bound for platform reporting to work.
The chart does not create the dedicated Secret or renew credentials automatically.
Before expiry, mint a replacement bundle for the same cluster, update the Secret,
roll out the discoverer to refresh all credential sources, verify reporting, and
revoke the old bundle once no consumer needs it. Revoking a bundle also revokes its
scanner credential; only revoke bundles whose consumers have all been migrated.

The development installation's dedicated enrollment expires January 17, 2027.
The release validation artifact records its non-secret bundle ID and exact expiry.

## Platform component evidence

The discoverer identifies platform components from exact recognized image
repositories, independently for each container. Namespace and workload names are
source locations, not product evidence. For example, a k3s `svclb-ingress-nginx-*`
DaemonSet using `rancher/klipper-lb` must not report ingress-nginx at the helper's
version. Unrelated sidecars and init containers likewise do not inherit identity.

Recognized repository aliases are explicit in `platformComponentName`. Unknown
repositories and private mirrors remain in ordinary image inventory/scanning, but
are not guessed into platform package identities. Add a verified repository mapping
when supporting a new mirror. Tags provide reported version evidence; untagged,
`latest`, and digest-only references do not supply a guessed version. Repository
recognition is not image signature verification. Correcting current platform facts
does not delete historical findings or assert that a vulnerability was remediated.

## Complete platform snapshots

Platform reporting reads every page of Nodes, Deployments, and DaemonSets before
sending a report. A failed page, expired continuation, or collection timeout aborts
that report; it does not overwrite the last complete facts or scan evidence with
an empty or partial inventory. Collection has a shared 20-second deadline. The
next reconciliation retries, and the existing observed timestamp remains unchanged
until a complete report succeeds. This is a complete read of each resource list,
not an atomic snapshot across Kubernetes resource types.

## Scan status and inventory changes

Scan jobs record `claimed_inventory_hash` from the owned target in the same SQL
statement that claims the job. A target update cannot rewrite that claimed
identity; a retry records the newly selected inventory. Migration 183 leaves older
jobs unverified instead of copying today's target identity into historical jobs.

The platform response returns this hash on `latest_job`. Its top-level status is
`scanned` only for a completed job matching the current target and package evidence.
A different claimed hash is `outdated`; an absent hash or inconsistent evidence is
`unverified`. Pending jobs have not selected inventory yet and remain `pending`.
The advanced job status still describes that individual job, so it can legitimately
say `completed` while the overall platform status is `outdated`. Historical finding
counts remain historical/open records and are not proof of a current scan.
