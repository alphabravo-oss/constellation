# Disposable Flannel packet acceptance

This opt-in test runs the unchanged qualified native DP under the real Go
Supervisor, ContainerTap/Enforce providers, and RuntimePolicySyncWorker. It never
runs the runtime-agent main or constructs the eBPF agent. The HTTP policy source
is a private, protocol-v2 fixture; no application API/database is contacted.

`bash scripts/test-flannel-policy.sh prepare` only compiles the driver against the
frozen `1cb1045` archive (an independent temporary copy) with the three new test
files overlaid, and compiles the small HTTP fixture. The required existing runtime
image is pinned to image ID `sha256:58a1dfe1ce01f77007243106143edceb3db0071cbcbd2765b2be267679a0ff8e`.
No native/Go production sources or libraries are rebuilt/replaced. The native DP
and all linked-library hashes are captured at execution.

Do not execute the next command until root has reviewed this source and fresh
headroom. A separate instruction authorizes the run; passing the environment
flag alone is not authorization:

```
CONSTELLATION_FLANNEL_POLICY_APPROVED_RUN=1 bash scripts/test-flannel-policy.sh run
```

The run creates a new random `flannel-policy-*` k3s-in-Docker node and
`packet-proof-*` namespace. It never updates/switches the default kubeconfig or
uses the existing convergence cluster. The pinned node image is `rancher/k3s:v1.35.5-k3s1`, ID `sha256:2074403abe1bded11ef3dde09d457e13be8e0b64c218b1c4f8269b4565cfbc65`. Its normal privileged node boundary is isolated in its own mount/PID/network namespaces; it receives only the four newly owned volumes, with no host bind mounts. The API binds an ephemeral loopback port only; fixture pods
have no service-account tokens, Services, host mounts, privileges, or persistence.
The test driver joins only this owned k3s node's PID/network namespaces, with a
private IPC/mount filesystem. It receives only exact pod identity evidence, not
Docker/CRI sockets or kubeconfig. Limited capabilities allow pod setns and NFQUEUE;
no explicit BPF, PERFMON, or SYS_MODULE capability is requested, and no host-network or host-PID mode is used. SYS_ADMIN remains a powerful shared-kernel capability, required here only for namespace setns; this is not a security sandbox for untrusted code. The disposable k3s node still
shares the host kernel; this is disposable-container isolation, not off-host proof.

The driver refuses host namespace identity, foreign subnets, duplicate PID/UID/IP,
changed PID netns/cgroup ownership, or any unexpected native child. It checks real
pod UID, PID, netns, container ID, IP and discovered interface MAC. Only two fixture
servers enter NFQUEUE; the client has no interception. Every request uses a new
source port and nonce. Sequential timestamp buckets and event cursors reject
previous verdict evidence. Native TCP Connection records aggregate source ports
as zero, so the exact source port comes from server observations, not an invented
native field. A denial requires a new matching native MAC/IP/server-port/action/
policy-ID verdict, NFQUEUE packet-counter increase, and absence of the nonce in
actual server logs. A timeout alone never passes.

Phases prove both baseline ports, monitor-mode violations while both remain
reachable, Protect A while B remains monitor, opposite allowed ports under Protect
B, and a fresh A policy change. Nested HTTP-app allow rules carry the source policy
RID; the unmatched port tests the real default action. The final phase kills only
the supervisor's exact owned DP child via pidfd, while a long restart backoff keeps
it stopped. Queue listeners must disappear, retained queue-bypass rules must still
count packets, and both servers must become reachable. Supervisor cancellation
then runs normal teardown. The cleanup trap removes the verified owned driver,
new cluster, its exact nonce-labeled network and four named k3s volumes, and only its own fixture/base tags. No k3d tools container or Docker-socket mount is used. Fixture image import streams directly into the exact owned node with pipefail; no image volume or anonymous node volumes are accepted. Partial creation is cleaned even when no server node exists. Evidence remains private under
`/tmp/constellation-flannel-policy-*`.

The run requires at least48GiB free initially and stops at40GiB. No cluster/driver
execution is part of ordinary Go tests. Off-host paths, real node failure, ICMP
packets, application detector accuracy, BPF attachment and main-cluster rollout are
outside this TCP packet proof. Native in-memory acceptance separately covers ICMP
policy isolation. Do not describe either as those broader guarantees.
