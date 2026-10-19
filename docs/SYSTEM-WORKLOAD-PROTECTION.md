# System workload visibility and enforcement

The findings page and cluster landing page default to application scope, with an
“Include Constellation system workloads” toggle. Shared images and unknown owners
remain visible. This presentation classification never grants enforcement immunity.
Scanning, findings retention, and alerts continue independently of the filter.
The dashboard applies the same selection to finding totals, vulnerability metrics,
and top vulnerable workloads, and preserves it in finding links. Inventory,
hardening, policy coverage, and operational signals retain their full-cluster scope,
which is stated beside the toggle. Executive downloads are labeled as reports for
the entire cluster. Ownership of separately managed dependencies remains open work.

## Shared dependency configuration

`systemProtection.protectedNamespaces` adds trusted dependency namespaces to
admission exclusions, runtime enforcement protection, and network-policy applier
protection together. The installation namespace and kube-system, kube-public,
and kube-node-lease are mandatory in all three rendered configurations. Existing
runtime and network-policy component-specific additions remain additive. Custom
admission selectors are ANDed with the mandatory exclusion. Namespace values are
validated as Kubernetes namespace names; workload labels never feed this setting.
This is namespace-wide protection, including unrelated workloads in those namespaces.

## Network policy write boundary

The network-policy applier protects its own namespace, obtained from the downward
API, plus kube-system, kube-public, and kube-node-lease. Helm's
`networkPolicyApplier.protectedNamespaces` adds dependency namespaces; it cannot
remove the mandatory set. External invocation must supply
`CONSTELLATION_POD_NAMESPACE` explicitly. Missing protection refuses writes.

The Kubernetes client checks the parsed manifest identity and protection immediately
before applying policies, covering lifecycle policies and direct enforcement actions.
Native and Cilium policies targeting protected namespaces return an error before a
Kubernetes write. Calico global policies preserve their namespace selector and add
an AND condition requiring a namespace-name label and excluding the protected set.
The original pod selector and policy rules are retained. Unbalanced selector grouping
and ambiguous escape syntax are rejected before composition. Kubernetes still
validates the selector grammar. The effective Calico namespace selector is narrower
than the stored candidate by this mandatory exclusion.

Policy deletion remains available so existing policies can be lifted. This guard
protects policy targets; it does not exempt every application connection to a system
service from an application policy. Application isolation can still disconnect an
application from system services.

Reference: https://docs.tigera.io/calico/latest/reference/resources/globalnetworkpolicy

## Remaining protection review

Admission excludes the installation and core namespaces plus shared dependencies. Runtime process/file protections and
session endpoint safeguards are implemented. The existing namespace-wide exclusions
also protect unrelated workloads installed in those namespaces. Finer component
identity protection remains open; UI classification labels are not sufficient proof.

Remaining work includes image-wide response coverage, verification of every separately managed dependency assignment, and a complete audit of
all disruptive response paths. Calico selector transformation is tested at the client
write boundary; live Calico/Cilium data-plane enforcement still requires their own
cluster fixtures. The development cluster's native rollout does not prove those CNIs.

## Manual quarantine refusal

The API refuses workload and namespace quarantine requests for the mandatory core
namespaces. When `clusterRegistration.clusterId` is explicitly configured, the chart
passes that UUID's own and shared dependency namespaces to the API through
`CONSTELLATION_QUARANTINE_PROTECTED_NAMESPACES` (a JSON map of cluster UUID to namespace
array). This configuration is trusted installation input, never workload labels.
Organization ownership and workload existence checks run first. Refusals return
HTTP 403 with `code: protected_namespace` and create no quarantine entry. Invalid
protection configuration refuses creation with HTTP 503; lifting remains available.

Without an explicit cluster UUID the chart does not guess which cluster owns the
installation namespace. Other clusters require their own trusted mapping in the API
environment; only mandatory core refusals apply without one. Image-scoped quarantine
can cover both system and application owners and is retained; protected namespaces
are excluded by admission at enforcement time.

The runtime response-rule bridge uses this same configuration before quarantine,
isolation, or process-kill actions. Protected or unattributed workload namespaces
return refusal warnings and queue no quarantine, network-policy, or process-action
rows. The dispatcher logs those warnings and appends a hash-chained
`runtime.response_rule.refused` audit event for each rule with protection refusals.
The audit event targets the cluster and records the rule, source event, workload,
and refusal reasons. Audit lists, selected-record views, CSV exports, and the audit
page expose a refusal-specific summary; arbitrary audit metadata is not exposed.
Failure to persist audit evidence is logged explicitly and never permits the action.
The dispatcher does not report refused actions as successful. Ordinary application responses remain enabled. These guards do not yet
cover image-wide scan response rules. Audit persistence is best-effort under database
failure or request cancellation; a durable retry queue remains open work.

## Inline network inspection

The runtime container inventory adapter checks the same trusted protected namespace
set before marking any target for inline NFQUEUE enforcement. The fleet gate and
pod opt-in must both be enabled, protection configuration must exist, and container
identity and namespace must be known. Protected or unattributed targets retain their
passive inspection settings but cannot opt into inline enforcement through labels.
This covers the container provider; alternate passive providers cannot activate the
inline provider. Host-network namespace exclusion also remains in the tap provider.
Production verification keeps inline blocking disabled; guard and provider tests
exercise the enabled-gate cases without blocking live system traffic.

## Direct enforcement status and removal

Direct network enforcement actions hold their database row lock while applying or
removing the Kubernetes policy and recording the outcome. A removal request waits
for an in-flight apply. Appliers recheck the row state after acquiring the lock;
a stale active snapshot cannot recreate a policy already marked removed. Status
updates also require the expected state. Operations have a 30-second context bound.
Learned-policy reconciliation also locks its lifecycle row and rereads current
mode, approval, manifests, and candidate identity before acting. A polling snapshot
cannot override a newer demotion, rollback, candidate replacement, or pending state.
Its report is written in the same transaction as that locked read. These locks
serialize normal operations; network timeouts can still leave an uncertain remote
result that the next reconciliation must resolve.

Requesting removal clears the old apply outcome. The UI distinguishes pending
application, protected-target refusal, application failure, pending removal, and
removal failure. It reports successful application as an applier report, not proof
of CNI traffic enforcement, and does not promise removal within a fixed interval.

## Controller presence and history

Discovery stores a complete controller snapshot separately from pod presence.
Deployment and StatefulSet replicas set to zero are `scaled_to_zero`, not absent.
DaemonSets remain present regardless of current scheduling count. Controller keys
include namespace, kind and name. A fresh snapshot may establish `absent` only
for supported controller kinds and inventory rows observed no later than that
snapshot. Missing, expired, or unsupported evidence is `unverified`. Older
snapshots cannot replace newer ones; incomplete Kubernetes lists are refused.

Workload lists, their summaries and CSV, dashboard hardening/top workloads, and
cluster workload counts exclude only confirmed-absent rows by default. The
presence filter can reopen those retained rows. Zero-replica workloads remain
visible and are labeled. This changes inventory classification, not finding
lifecycle: absence does not mean vulnerabilities were fixed. Previously stored
findings and workload identities remain available for investigation.

## Image-wide scan responses

Registry scan responses resolve only clusters owned by the scanning organization,
including when image-link inventory is inconsistent. Each quarantine insert checks
cluster ownership again at the database write boundary; nonexistent or foreign
clusters are errors rather than successful no-ops. Duplicate owned entries remain
idempotent. Image-wide entries are retained for shared application owners; protected
namespaces remain excluded from admission validation.

Scan-response audit payloads report `outcome: quarantine_recorded`,
`enforced: not_verified`, and `recorded_clusters`. They do not claim that a deny-list
entry proves a pod was blocked. Webhook coverage, namespace exclusions, and actual
admission decisions determine effective blocking. Automatic scan entries (`origin=auto`, `source_kind=scan`) match canonical repository
names, covering tags and digests of that repository without matching similarly named
repositories or child paths. Historical scan fallback keys containing a tag or digest
match that exact normalized reference. Malformed automatic references do not match.
Manual and older non-scan entries retain their explicit raw-prefix semantics.

Quarantine checks regular, init, and ephemeral containers. Default webhook rules include
`pods/ephemeralcontainers` UPDATE requests. Upgrades using `--reuse-values` must also
update the stored webhook rules to include that subresource; the development release
records this explicit rule update. Existing system namespace exclusions still apply.
Automatic repository quarantine intentionally covers every tag in the repository;
quarantining only the scanned digest while resolving tagged admissions requires further
image-resolution work.
