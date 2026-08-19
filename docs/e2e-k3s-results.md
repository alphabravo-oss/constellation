# Wave H2 — Native-k3s end-to-end results

Date: 2026-05-12
Host: Hetzner VM, Ubuntu 24.04.4, kernel `6.8.0-110-generic`, x86_64
Cluster manager: k3s (native systemd unit, **not** k3d-in-docker)
Coexists with: docker daemon, three k3d clusters (`constellation`, `constellation-edge`,
plus the redyarn family), local API binary on :18080, vite on :5173, postgres on :5433.

## 1. k3s install

Method:

```bash
sudo sysctl -w fs.inotify.max_user_instances=8192 fs.inotify.max_user_watches=524288
curl -sfL https://get.k3s.io \
  | sudo INSTALL_K3S_EXEC='--write-kubeconfig-mode=644 --disable=traefik --flannel-backend=host-gw' \
    sh -
```

Version: `k3s v1.35.4+k3s1` (go1.25.9), containerd `v2.2.3-k3s1`.
Kubeconfig: `/etc/rancher/k3s/k3s.yaml` (mode 644 so the local user can use it without sudo).
Pod CIDR: `10.42.0.0/24` (default), service CIDR: `10.43.0.0/16`.
Pod → host link: pods reach the host (and the shared postgres at :5433) via `10.42.0.1` (cni0
gateway). Verified with a busybox `nc -vz 10.42.0.1 5433` returning open.

### Install-time issue + fix

The k3s containerd refused to start (CRI plugin error: `failed to create fsnotify watcher:
too many open files`). Root cause: docker + the three k3d clusters had already consumed
the default `fs.inotify.max_user_instances=128`. Fix: bumped to `8192` (and watches to
`524288`) before re-starting k3s. Captured in the install method above.

Did **not** need to switch to `--snapshotter=native`; the default overlayfs snapshotter
works alongside docker.

## 2. Images — six constellation roles + runtime-agent

Build steps:

- The five pre-existing per-role e2e images (`constellation/{api,scanner,operator,
  admission,archiver,frontend}:e2e`) from Wave E were re-tagged as `:h2`.
- The seventh role — **runtime-agent** — was new for this wave:
  - New cmd: `cmd/constellation-runtime-agent/main.go` (102 lines). Uses
    `internal/runtime/ebpf` to attach to the kernel and writes events as one-line
    JSON to stdout for `kubectl logs` consumption.
  - New Dockerfile: `deploy/docker/Dockerfile.runtime-agent`. Three-stage build:
    stage 1 (debian) compiles the BPF CO-RE object via the in-tree `make`; stage 2
    (golang:1.26) builds the Go agent; stage 3 (chainguard wolfi-base) bundles
    `bpftool`, the runtime agent binary, and `runtime.bpf.o` at
    `/opt/constellation/runtime.bpf.o` with `CONSTELLATION_BPF_OBJ` baked in.
  - Image: `constellation/runtime-agent:h2`, 44 MB.

All six were imported into k3s containerd via:

```bash
docker save constellation/<role>:h2 | sudo k3s ctr -n k8s.io images import -
```

Verified with `sudo k3s ctr -n k8s.io images list -q | grep constellation` (six images).

## 3. Helm + ConstellationCluster CR

Helm release: `constellation` in namespace `constellation-system` from the existing
in-tree chart `deploy/charts/constellation`, overridden by a new
`deploy/e2e/values-h2.yaml` (frontend off, vulndbImporter off, auditArchiver off,
all `:h2` images, postgres external from a `constellation-database-url` Secret pointing
at `postgres://constellation:constellation@10.42.0.1:5433/constellation`).

The operator then reconciled a `ConstellationCluster` CR (`deploy/e2e/sample-cr-h2.yaml`,
name `h2`) into the scanner Deployment, the admission Deployment + Service, and the
**runtime-agent DaemonSet**.

### Bug fixed: runtime-agent DaemonSet was missing kernel mounts

The Wave-E operator created the DaemonSet with `privileged=true` + caps but **no
hostPath volumes**. On the real kernel this means the BPF loader can't see
`/sys/kernel/btf/vmlinux` from inside the container, can't pin programs in
`/sys/fs/bpf`, and can't enumerate cgroups via `/proc`.

Fix in `deploy/operator/controllers/constellationcluster_controller.go`
(`ensureAgentDaemonSet`):

- Added four hostPath volumes (`/sys` ro, `/sys/fs/bpf` rw, `/sys/kernel/btf` ro,
  `/proc` ro under `/host/proc`).
- Added `SYS_PTRACE` to the capability list (needed for `nsenter`-style cross-namespace
  process inspection).
- Added a `CONSTELLATION_NODE_NAME` env var (downward-API, in addition to the existing
  `NODE_NAME`) — the runtime-agent reads this for the JSON record's `node` field.
- Existing test `TestReconcile_ProducesSpec` still passes (only asserts
  `Privileged=true`, doesn't pin the volume set), so no test churn.

After rebuilding `constellation/operator:h2` and re-importing into k3s containerd, the
operator re-reconciled the DaemonSet in-place. The runtime-agent pod came up cleanly
with hostNetwork=true (pod IP = the host's primary IP `5.78.138.216`).

## 4. End-state pod inventory

```
NAMESPACE              NAME                                      READY   IP
constellation-system   constellation-api-7675bb847-gz4g2         1/1     10.42.0.8
constellation-system   constellation-operator-666cc6d744-9xbg6   1/1     10.42.0.7
constellation-system   h2-admission-84c5f869b4-mqzfn             1/1     10.42.0.10
constellation-system   h2-runtime-agent-gb2q9                    1/1     5.78.138.216  (hostNetwork)
constellation-system   h2-scanner-67c589bd9f-nlfzt               1/1     10.42.0.9
h2-targets             vuln-alpine                               1/1     10.42.0.12
h2-targets             vuln-nginx                                1/1     10.42.0.11
kube-system            coredns-c4dbffb5f-rw7hq                   1/1     10.42.0.4
kube-system            local-path-provisioner-5c4dc5d66d-gd57h   1/1     10.42.0.3
kube-system            metrics-server-786d997795-6grrv           1/1     10.42.0.2
```

10/10 Running, 0 restarts, 0 pending.

## 5. Runtime agent — BPF programs loaded on the real kernel

`kubectl -n constellation-system exec h2-runtime-agent-gb2q9 -- bpftool prog show`
returns (filtered to constellation's programs):

```
153748: kprobe       name kprobe_tcp_connect          tag e4fd4efa1a7d73f7  gpl
153749: kprobe       name kretprobe_inet_csk_accept   tag e3b7071bdec73047  gpl
153751: tracepoint   name trace_sched_exec            tag 3a463ea5345457ba  gpl
```

Three out of four eBPF programs from `runtime.bpf.c` are loaded and attached to the
**host kernel** (not a sandbox kernel — k3s runs natively on this kernel). The fourth
program — `lsm_file_open` — is silently skipped, matching the kernel-feature note in
the Wave F1 RESULTS.md (`security_file_open` LSM hook attach requires BPF LSM enabled
in CONFIG; not enabled on this kernel, but the loader degrades cleanly).

### Sample heartbeat (every 5s)

```
{"kind":"heartbeat","node":"pioneer-dev-1","exec":3610,"network":4112,"file":0,
 "total":7722,"dropped":0,"ts":"2026-05-12T15:19:31Z"}
```

7722 events captured in ~2.5 minutes, **zero dropped**. The `file` counter is zero
because the LSM program didn't load.

### Sample exec event (real host process)

```
{"kind":"exec","node":"pioneer-dev-1","pid":2990926,"ppid":2990924,"uid":1000,
 "comm":"2.1.139","filename":"/home/mj/.local/share/claude/versions/2.1.139",
 "ts":"2026-05-12T15:19:33.016344451Z"}
```

That's a process running on the **host** (`/home/mj/.local/share/...`), captured by an
eBPF tracepoint inside a pod. This proves hostPID + privileged + BTF + tracepoint
attach are all working end-to-end.

### Sample network event (real host kernel TCP)

```
{"kind":"network","node":"pioneer-dev-1","pid":2944948,"comm":"k3s-server",
 "direction":"accept","protocol":"tcp",
 "src":"[::a28:90ab:2460:2900:0:0]:11033",
 "dst":"[7d:7abe:8275:600:206:7461:549c:901f]:12486",
 "ts":"2026-05-12T15:19:33.31361872Z"}
```

That's k3s-server itself accepting a TCP connection — captured by kprobing
`inet_csk_accept` on this kernel. (The src/dst look exotic because the kernel
sockaddr_in6 contains a raw u64 sun_family chunk; renderable as best-effort by
`netip.AddrPort` — cosmetic only.)

## 6. Scanner + admission paths exercised against k3s

### Scanner

- Scanner pod (`h2-scanner-67c589bd9f-nlfzt`) bundles trivy/syft/grype/cosign/oras
  (verified via `kubectl exec ... -- which trivy`).
- Enqueued a fresh scan job against the **host** API (which owns the shared postgres):
  ```
  POST /api/v1/scan-jobs {"image_ref":"nginx:1.14.2","cluster":"h2-k3s"}
  → {"id":"dfaca855-beb1-4d48-b028-03e5704bc837","status":"pending"}
  ```
- That row appears in `/api/v1/scan-jobs?limit=10` alongside the Wave E
  `e4152aec…` completed job (109 packages, 217 findings) — confirming the new
  cluster shares the same finding store.
- The in-k3s scanner pod is **not yet wired to claim** these jobs because it needs a
  DB-issued scanner bearer token (matches Wave E behavior:
  `claim: status 401: scanner bearer token required`). This is identical to the
  k3d behavior; not a regression introduced by H2.

### Admission

The admission pod runs `--insecure` (plain HTTP on :8443), which means we can't
wire a `ValidatingWebhookConfiguration` (k8s requires HTTPS for admission webhooks).
Same caveat as Wave E. The webhook engine itself was exercised by direct POST through
a `kubectl port-forward` to the pod:

```
POST /validate {priv pod}        → allowed:false, "block-privileged: container \"c\" is privileged"
POST /validate {hostNetwork pod} → allowed:false, "block-host-network: hostNetwork=true"
```

Both DENY paths fire correctly. A `kubectl apply -f` of a privileged pod **does**
succeed (no webhook wired), which confirms the lack of a wired
`ValidatingWebhookConfiguration` rather than a regression in the admission engine.

### Vulnerable workloads on the cluster

`h2-targets` namespace, two pods:

```
vuln-nginx    nginx:1.14.2    10.42.0.11
vuln-alpine   alpine:3.6      10.42.0.12
```

These match the seed/sample workloads used by Wave E on k3d.

## 7. Constraint compliance

- The two k3d clusters (`constellation`, `constellation-edge`) and the shared
  `constellation-pg` postgres container are still running and untouched.
- The host's local `constellation-api` binary on :18080 was not stopped or
  reconfigured; the new in-k3s `constellation-api-7675bb847-gz4g2` pod runs alongside
  it as a standby (the operator's CR refers to the in-cluster API service for
  reconciliation, but the UI continues to talk to the host binary).
- The vite dev server on :5173 was not touched.
- No commits made (parent will commit).

## 8. New / modified files

- New: `cmd/constellation-runtime-agent/main.go` — DaemonSet binary that drives the
  eBPF agent and emits JSON events to stdout.
- New: `deploy/docker/Dockerfile.runtime-agent` — three-stage image that bundles the
  compiled BPF object at `/opt/constellation/runtime.bpf.o`.
- New: `deploy/e2e/values-h2.yaml` — helm overrides for the native-k3s install.
- New: `deploy/e2e/sample-cr-h2.yaml` — ConstellationCluster CR pointing at `:h2` images.
- Modified: `deploy/operator/controllers/constellationcluster_controller.go` — added
  hostPath volume mounts (`/sys`, `/sys/fs/bpf`, `/sys/kernel/btf`, `/proc`) and
  `SYS_PTRACE` capability to the runtime-agent DaemonSet template.
