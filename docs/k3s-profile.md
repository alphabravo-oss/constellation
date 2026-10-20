# k3s host profile

Constellation's reference single-node and small-cluster target is upstream k3s
(Technology Selection Guide ch.04). Two host-level settings are not Helm's job
and ship as files under `deploy/k3s/`:

| File | Install to | Purpose |
|---|---|---|
| `deploy/k3s/config.yaml` | `/etc/rancher/k3s/config.yaml` | kubelet eviction / image-GC thresholds, PSA admission config reference |
| `deploy/k3s/psa-admission.yaml` | `/etc/rancher/k3s/psa-admission.yaml` | PodSecurity defaults and the runtime-agent exemption |

Apply with `systemctl restart k3s` (the API server restarts; workloads keep running).

## Kubelet eviction and image GC

On k3s the containerd image store, the kubelet `imagefs` and every
`local-path` PersistentVolume share the root filesystem. With the kubelet
defaults (image GC at 85 %, hard eviction at 10 % free) one scanner
vulnerability-DB refresh or a backup burst can push the node into
`DiskPressure` and evict the admission webhook. `config.yaml` sets explicit
thresholds:

```yaml
kubelet-arg:
  - "eviction-hard=memory.available<500Mi,nodefs.available<10%,nodefs.inodesFree<5%,imagefs.available<15%"
  - "eviction-soft=memory.available<1Gi,nodefs.available<15%,imagefs.available<20%"
  - "eviction-soft-grace-period=memory.available=2m,nodefs.available=5m,imagefs.available=5m"
  - "eviction-minimum-reclaim=nodefs.available=2Gi,imagefs.available=5Gi"
  - "image-gc-high-threshold=80"
  - "image-gc-low-threshold=65"
```

`image-minimum-gc-age` is no longer a kubelet flag; the thresholds above are
the supported knobs. The chart's `metrics.prometheusRule.includeClusterRules`
alerts (`NodeImageFsAbove80Percent`, `NodeDiskPressure`, `PodEvicted`) fire
before the kubelet acts.

## Pod Security Admission

Every chart pod is `restricted`-clean except the runtime agent, which needs
`hostNetwork`, `hostPID` and host mounts by design (ADR 0003/0005). PSA
evaluates the *requesting* user, and DaemonSet pods are created by
`kube-system:daemon-set-controller`, so the agent is exempted through that
controller plus its own ServiceAccount (direct creates). The cluster default
stays `privileged` with `baseline` audit/warn; raise individual namespaces with
`pod-security.kubernetes.io/enforce=restricted` labels. For RKE2 the same
`AdmissionConfiguration` goes in `/etc/rancher/rke2/rke2-pss.yaml` and
`profile: cis` already references it.

## Admission webhook exemptions

The webhook's built-in rules block `hostNetwork` / `hostPID` / privileged pods.
System namespaces legitimately use them (CNI, node-exporter, ingress
controllers), so `admission.exemptNamespaces` (default: kube-system,
kube-public, kube-node-lease, cnpg-system, cert-manager, ingress-nginx,
monitoring) and any namespace labelled
`constellation.alphabravo.io/admission=ignore` skip the built-ins. DB-backed
policies still apply unless scoped otherwise.
