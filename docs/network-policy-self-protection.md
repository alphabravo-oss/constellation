# Network policy system communication protection

Constellation's network policy applier protects its installation namespace,
Kubernetes system namespaces and administrator-configured additional namespaces.
The installation namespace comes from the downward API. Presentation labels,
finding visibility and request-supplied workload attribution do not grant an
exception. This is a namespace trust boundary; finer component-level protection
inside shared namespaces remains separate work.

Immediately before each Kubernetes write, the applier checks the target and reads
complete paginated pod, node, service and EndpointSlice inventories. It also reads
the built-in Kubernetes API Endpoints object by its exact `default/kubernetes`
identity and resolves protected service hostnames. Any failed/incomplete inventory,
unresolved protected service address or untrusted selected EndpointSlice refuses
the write. Deletes remain available for recovery.

Direct writes into protected namespaces are refused. Calico global policies retain
their original namespace selector, conjoined with protected namespace and host
endpoint exclusions. On the application side:

- Native policies retain their original affected directions and application rules.
  Installation and administrator-added namespace peers are allowed. Core Kubernetes namespaces are protected targets but receive only DNS/API communication exceptions, avoiding blanket access through infrastructure proxies. Additional egress exceptions use exact
  service/backend addresses and declared protocol/destination ports.
- Calico puts those protected allows before the original rules. IPv4 and IPv6 nets
  are emitted separately. Original direction defaults are pinned before rules are
  added, so an egress-only policy does not acquire ingress isolation.
- Cilium preserves empty directions and explicit default-deny settings. Trusted installation
  peers and required service ports are added to affected directions, including deny-only
  directions. Node identities receive only declared service/backend destination
  ports for egress, never unrestricted node egress. Managed pod backends additionally
  use verified Cilium security identities and declared ports, so default CIDR
  matching does not break DNS or shared pod dependencies. Node-origin ingress follows
  the native Kubernetes trust boundary.
- Explicit Cilium CIDR denies are refused when they overlap any protected endpoint.
  IPv4-mapped CIDRs, unbounded denies, other deny-selector forms and `fromRequires`/
  `toRequires` constraints are refused until their interaction with protection can
  be proven. An ordinary external IP block remains supported.

EndpointSlice service-name labels alone do not establish ownership. A slice must
reference the selected Service's current UID in the same namespace. The special
Kubernetes API service uses its exact canonical Endpoints object instead of an
arbitrary service-name label. Completed/failed pod addresses do not retain an
exemption after their IPs can be reused.

Node addresses are protected against whole-IP denies, but they are not blanket
allow destinations. Only a protected service's declared NodePort or concrete
backend port receives an egress exception. This prevents an unrelated application
NodePort from inheriting a system exception. Likewise, when a system dependency
shares an IP with an application, only its declared port receives an exception.

Effective Kubernetes manifests carry
`constellation.alphabravo.io/system-communication: preserved` and the protected
namespace list. Refusals use the existing enforcement status/error reporting path.
A refused write does not remove an older policy object; existing unsafe denies
need an explicit lift through the normal recovery path. The stored requested
manifest remains the user's intent; the live Kubernetes
manifest includes the applier's mandatory protection adjustments.

## Validation and limits

`System communication validation` runs repeated race/shuffle tests with a fresh
database and builds the opt-in live test helper on hosted runners. The disposable
`scripts/test-system-communication.py` proof uses that binary and the actual
Kubernetes write path. It tests protected pod/service traffic, DNS/API transport,
blocked application ingress/egress and NodePorts, a shared IP with a permitted
service port and blocked unrelated port, and recovery after policy deletion.
Every fixture namespace is uniquely owned and removed afterward. Production
runtime response/kill flags are not enabled by this probe.

Native live evidence does not qualify Cilium or Calico dataplanes. Their rule
construction tests are separate from full CNI qualification.

### Cilium profile qualification (2026-10-19)

The hosted `Cilium communication validation` workflow now builds the actual
apply-path helper and creates a disposable kind v0.33.0 / Kubernetes v1.35.8 /
Cilium v1.20.3 cluster. It uses kube-proxy, default CIDR matching, pinned node and
fixture images, positive traffic controls, and owned-namespace cleanup. It does
not install or change Cilium in the live Constellation cluster.

[Run 39247081837](https://github.com/alphabravo-oss/constellation/actions/runs/39247081837)
**failed** at `protected-0-sharedRequiredPort`. All six baseline probes and the
protected pod/service probes succeeded; the required port 18081 on the shared
pod endpoint timed out after policy application. Namespace cleanup completed.
The Kubernetes API accepted the policy and its protection annotation was present;
neither establishes dataplane protection. Later DNS/API and recovery probes were
not reached, so this run makes no claim about their outcome.

Cilium's [documented CIDR semantics](https://docs.cilium.io/en/v1.20/security/policy/layer3/)
exclude managed pod peers in the default profile. Selectorless `toServices` rules
also translate to CIDRs, so changing that field alone is insufficient. This
established that the original CIDR-only
implementation was **not qualified** under default Cilium settings. The workflow's
manual `cidr_mode=pods` input permits a separate explicit-profile experiment;
a passing explicit profile must not be represented as a default-profile fix.

[Run 39247533627](https://github.com/alphabravo-oss/constellation/actions/runs/39247533627)
used the same applier implementation and probes with `policyCIDRMatchMode: [pods]`.
All 29 traffic probes passed, as did DNS, API transport, blocked DNS metrics and
recovery after policy deletion. Both fixture namespaces and the kind cluster
were removed. This qualifies only this single-node IPv4, kube-proxy-enabled
Cilium 1.20.3 profile. It does not qualify kube-proxy replacement, multi-node,
other versions, or the default profile. That experiment did not fix the
default-profile gap; the identity-aware change
below subsequently addresses it.
Machine-readable evidence and artifact hashes are in
`deploy/dev/registry-release/validation-cilium-communication-20261019.json`.


### Identity-aware protection under default Cilium settings (Helm 131)

Helm 131 deploys operator/applier source `bb2d19b4354da97a29419b91401f0f240b8b58e8`.
The [regression run](https://github.com/alphabravo-oss/constellation/actions/runs/39248982471)
passed 482 executions with two opt-in helper skips. Default Cilium runs
[39248503840](https://github.com/alphabravo-oss/constellation/actions/runs/39248503840)
and [39248982479](https://github.com/alphabravo-oss/constellation/actions/runs/39248982479)
each passed 29 traffic checks plus the shared-identity refusal, DNS/API and
DNS-metrics checks. The native live proof also passed its 29 checks and cleanup.
Evidence is in `deploy/dev/registry-release/validation-cilium-identities-20261019.json`.

The applier now reads complete paginated `CiliumEndpoint` and `CiliumIdentity`
inventories when required service addresses belong to managed pods. It verifies
that each backend endpoint belongs to the current Pod UID and contains the
observed IP, then obtains the actual identity's security labels. Kubernetes
presentation labels are not a substitute for Cilium identity data. Host-network
and external addresses retain their existing port-limited treatment.

Required pod access uses `toEndpoints` plus the exact declared protocol/port.
Before writing, every observed Cilium endpoint whose identity matches those
labels (including identities with additional labels) must already be authorized
for that port or belong to a trusted communication namespace. Otherwise the
write is refused explicitly. Empty/missing identities, ownership/address changes,
failed inventory pages and repeated pagination tokens also refuse the write.
The new RBAC permissions are list-only for the two Cilium resource types.

The default-profile proof includes a pod that shares the dependency identity but
is not a declared backend: the attempted exception must be refused and no policy
created. After deleting that pod, the same apply path must preserve the required
shared port, DNS and API transport while blocking ordinary ingress/egress,
unrelated NodePorts and DNS metrics. The live proof checks recovery after deletion.

Cilium endpoint/identity CRD publication must be enabled. Missing, initializing or
unresolvable identities cause refusal and retry, not a wider exception. Cilium
security identities remain a label-based trust boundary: an endpoint introduced
after the snapshot can join an identity. Kubernetes and Cilium reads are not an
atomic transaction; inventory churn, alternate identity backends without these
CRDs and IPv6 need separate qualification. Cross-node and kube-proxy replacement
coverage is scoped below.

### Cross-node and kube-proxy replacement qualification

[Run 39250010832](https://github.com/alphabravo-oss/constellation/actions/runs/39250010832)
uses the same production applier sources as Helm 131 and Cilium 1.20.3 with
default CIDR matching. All three isolated kind profiles passed:

| Profile | Nodes | Traffic checks | Kube-proxy |
| --- | ---: | ---: | --- |
| Single node | 1 | 29 | Present |
| Cross-node | 3 | 33 | Present |
| Cross-node Cilium replacement | 3 | 33 | Absent; Cilium reports replacement enabled |

The cross-node fixture explicitly pins the client and peers to different workers
and verifies their actual placement. It adds NodePort checks through both the
client and backend nodes. Every profile additionally passes the shared-identity
refusal before a write, DNS/API transport and DNS-metrics isolation checks.
Namespace and kind cluster cleanup completed in all profiles. Cilium runtime
status reports IPv4 VXLAN with legacy host routing; this is not a claim about
native routing, cloud CNIs, IPv6, runtime DPI/IPS or large-cluster performance.

Source/build compatibility, node platform details, runtime status, every probe
and artifact hashes are retained in
`deploy/dev/registry-release/validation-cilium-topology-20261019.json`.
The live cluster remains on Helm 131 and native CNI; this test-only expansion
requires no deployment change.

Third-party policies, CNI configuration, external firewall rules and availability failures can still
block communication. Address-based exceptions trust the declared network endpoint;
shared external IP/port hosting is not an application-layer identity boundary.
Inventory is refreshed on policy reconciliation, not in a distributed transaction
with every endpoint/DNS change. If refresh fails, an existing policy remains in
place; this does not establish uninterrupted access to newly introduced endpoints.

Reference semantics: [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/),
[Cilium default-deny](https://docs.cilium.io/en/stable/security/policy/intro/),
[Cilium deny precedence](https://docs.cilium.io/en/stable/security/policy/deny/), and
[Calico rule ordering](https://docs.tigera.io/calico/latest/reference/resources/globalnetworkpolicy).
