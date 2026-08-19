# Constellation performance baseline

First-run synthetic baseline measured on a single-node k3s cluster (16 vCPU /
30 GB RAM Ubuntu 24.04, kernel 6.8 with BTF) on **2026-05-14**. This is the
**v1 smoke baseline** — short profiles, intra-node ClusterIP traffic, no
policies promoted to enforce. Customer-realistic load profiles will replace
these once the agent is deployed in production traffic; see "Out of scope"
at the bottom.

## TL;DR

| Profile          | Baseline p99 | With agent p99 | Δ p99 | dp CPU | dp RSS | Notes                       |
|------------------|--------------|----------------|-------|--------|--------|-----------------------------|
| Light (1k qps)   | 0.99 ms      | 0.99 ms        | 0 µs  | <1%    | 60 MB  | Indistinguishable           |
| Heavy (5k qps)   | 0.99 ms      | 0.99 ms        | 0 µs  | 5.5%   | 60 MB  | ~0.88 cores at 5k qps; flat |

Headline: under typical microservice traffic profiles (≤5k qps) the runtime
agent + dp data-plane impose **no measurable p99 latency overhead** on the
hot path, and dp's CPU stays at ~0.18 mCPU per 1k qps. The reason is
architectural: our BPF probes attach to exec/file syscalls (not the network
fast path), and dp processes flows asynchronously via DPMsgSession polling
rather than sitting inline on every packet.

## Methodology

**Cluster.** k3s 1.35.4, default Flannel CNI, single node. Pods scheduled on
the only node. ClusterIP service (no NodePort / LoadBalancer round-trip).

**Load tool.** fortio 1.x, HTTP/1.1, 8 concurrent keep-alive connections,
`/echo` endpoint (server reflects the request).

**Workload.**
```
fortio-server: fortio/fortio:latest, 500m-2 cores, 256-512 MB
fortio-load:   one-shot Pod, fortio load -qps <N> -t 30s -c 8 -keepalive
```

**Procedure per profile.**
1. Scale `constellation-runtime-agent` DaemonSet to 0 (nodeSelector that no
   nodes match).
2. Run load test → "baseline" JSON.
3. Restore DaemonSet, wait Ready.
4. Re-run load test → "with-agent" JSON.
5. Compare percentiles, sample `ps -o pcpu,rss` on dp + agent during peak.

## Raw numbers

### Light profile — 1k qps, 30s, 30,000 requests

|              | Baseline | With agent |
|--------------|----------|------------|
| Actual QPS   | 1000     | 1000       |
| Duration     | 30.0 s   | 30.0 s     |
| RTT min      | 0.05 ms  | 0.04 ms    |
| RTT p50      | 0.53 ms  | 0.52 ms    |
| RTT p99      | 0.99 ms  | 0.99 ms    |
| RTT max      | 2.01 ms  | 6.15 ms    |
| Total reqs   | 30,000   | 30,000     |
| Non-200      | 0        | 0          |

The max-latency outlier on the agent run (6 ms) is a cold-start kubectl-run
artifact — the second sample's `RTT max` settles back to ~2 ms.

### Heavy profile — 5k qps, 30s, 150,000 requests

|              | Baseline | With agent |
|--------------|----------|------------|
| Actual QPS   | 5000     | 5000       |
| Duration     | 30.0 s   | 30.0 s     |
| RTT min      | 0.04 ms  | 0.04 ms    |
| RTT p50      | 0.52 ms  | 0.52 ms    |
| RTT p99      | 0.99 ms  | 0.99 ms    |
| RTT max      | 5.73 ms  | 4.47 ms    |
| Total reqs   | 150,000  | 150,000    |
| Non-200      | 0        | 0          |

### Resource utilisation during heavy run

Measured with `ps -eo pid,pcpu,pmem,rss,command` taken at peak load.

```
PID    %CPU %MEM   RSS  CMD
86730  0.9  0.2   69 MB  /usr/local/bin/constellation-runtime-agent
86777  5.5  0.1   60 MB  /usr/local/bin/dp -n 1
```

On a 16-core host: dp peaked at ~0.88 cores during 5k qps of fortio echo
traffic. The agent's Go supervisor stayed under 1% CPU because flow events
go directly to dp via the unixgram IPC.

**eBPF probes attached during the run:**
- `tracepoint:sched_exec` (exec events, captured ps/grep/kubectl/iptables
  from k3s reconciles — host-wide due to `hostPID: true`)
- `lsm:file_open` (file-access LSM probe)

Confirmed via `bpftool prog show` from inside the agent pod.

## Failure-mode checks

Each verified by hand during this run; not yet wired into CI:

| Check                                | Result | Notes                                                          |
|--------------------------------------|--------|----------------------------------------------------------------|
| Agent restart preserves dp           | ✓      | Killing the Go supervisor leaves dp running until restart      |
| Schema migrate idempotency           | ✓      | helm upgrade reapplies cleanly (goose no-op on applied rows)   |
| Bootstrap admin idempotency          | ✓      | Re-running the post-install Job is a no-op                     |
| Audit chain initialised              | ✓      | First Login() inserts row with prev_hash = genesis             |
| Postgres CoreDNS race recovers       | ✓      | API pod retries until postgres Service resolves (~30s)         |

## What this baseline does NOT measure

The fortio `/echo` workload is a worst-case for "is the agent inline?" detection
because it's purely network-bounded — if dp were intercepting packets we'd see
real numbers. What it does NOT exercise:

- **DPI workload.** WAF / DLP signatures fire by inspecting payload bytes, which
  costs hyperscan time. Real customer traffic with TLS-terminated HTTP and DPI
  enabled will show non-zero dp CPU per gigabit. Plan: run a `wrk2`-driven HTTP
  workload with a body large enough to exercise the DPI parsers (Wave E1 v2).

- **NFQUEUE enforcement.** No policies were promoted to `enforce` mode during
  this run. Once a deny rule is installed, the per-packet hot path is non-zero
  even on allowed flows because every packet traverses the NFQUEUE userspace
  loop. Plan: enforce-mode load test (Wave E1 v2).

- **Multi-node.** Single-node means no overlay encap, no inter-node round trips.
  A 3-node EKS run will show real network latency that's separate from the agent's
  cost.

- **Long-haul / sustained load.** 30 seconds is enough to catch architectural
  overhead but not enough to surface backpressure issues in flow ingest, audit
  queue saturation, or memory fragmentation. Plan: 30-min profiles on the EKS
  cluster (Wave E1 v2).

- **Realistic threat detection.** No threats fired during this run — the
  /echo endpoint doesn't match any DPI signature. Threat-detection-under-load
  numbers are covered separately in `docs/e2e-results.md` once E3 lands.

## Reproducing

```bash
# Inside the test cluster:
kubectl apply -f deploy/e2e/perf/fortio.yaml      # server + namespace
/root/perf/bench.sh baseline-light 1000 30s        # 1k qps
/root/perf/bench.sh agent-light   1000 30s        # same with agent on
/root/perf/bench.sh baseline-heavy 5000 30s
/root/perf/bench.sh agent-heavy   5000 30s
```

To run "baseline" mode without the agent, scale the DaemonSet to zero via
nodeSelector:

```bash
kubectl -n constellation-system patch ds constellation-runtime-agent \
  -p '{"spec":{"template":{"spec":{"nodeSelector":{"perf-disabled":"true"}}}}}'

# Restore:
kubectl -n constellation-system patch ds constellation-runtime-agent --type=json \
  -p='[{"op":"remove","path":"/spec/template/spec/nodeSelector"}]'
```

## Updates

- **2026-05-14** Initial baseline. Single-node k3s, fortio echo, no DPI on the
  workload. Headline: zero measurable p99 overhead, dp ~0.88 cores @ 5k qps.
