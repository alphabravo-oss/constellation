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
