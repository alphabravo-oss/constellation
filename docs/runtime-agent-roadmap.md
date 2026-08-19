# Runtime-Agent Roadmap

This document picks up where the eleven shipped waves left off. It covers
the **inline enforcement step** (turning dp from an IDS into an IPS), the
fidelity / coverage items that single-session execution didn't fit, and the
broader work that makes the runtime-agent a production-grade replacement for
NeuVector + StackRox + a CNI-level firewall.

Track via task IDs (A1, A2, B1, …). Each task lists acceptance criteria,
files touched, dependencies, and an effort estimate. Tasks within a wave
can run in parallel unless `dependsOn` is set.

---

## Status going in

What's already in the tree (referenced in tasks below):

```
third_party/neuvector/            — vendored C dp (~30k LOC) + base.h + defs.h
internal/runtime/dp/              — Go IPC supervisor, tap reconciler, RPCs
internal/runtime/ebpf/            — exec + file BPF probes
cmd/constellation-runtime-agent/  — DaemonSet entrypoint, dp event router,
                                    flow + threat ingest clients, /healthz,
                                    /readyz, /metrics
internal/handler/                 — /api/v1/network-flows:bulk,
                                    /api/v1/runtime-threats[:bulk|/{id}]
db/migrations/                    — 040_network_flows_dp_metrics.sql,
                                    041_runtime_threats.sql
deploy/charts/constellation/      — runtime-agent DaemonSet + PDB + probes
frontend/src/pages/NetworkMapPage.tsx — dp-aware edges, ThreatsCard,
                                        ThreatDrilldownDialog
```

What dp emits today: `DPMsgConnect` (aggregated per-bucket metrics) and
`DPMsgThreatLog` (signature hits with captured packet bytes). The agent
decodes these and POSTs to the API. Network observation is end-to-end.

What dp **does not** do today: drop packets. dp's policy table is unset; in
TAP mode dp can't drop anyway; the agent has no policy-push channel.

---

## Decisions baked into this plan

These came from the planning Q&A. Subsequent tasks treat them as fixed.

1. **Scope = full backlog.** Inline enforcement + fidelity items + new work
   I haven't proposed yet. Tasks E1–E5 below cover the latter.
2. **CNI target matrix mirrors NeuVector's**: k3s/Flannel default,
   Calico + Cilium + EKS/GKE/AKS supported with documented caveats. We
   target k8s ≥ 1.24 (LSM bpf hook is required for the existing eBPF
   file probe; NFQUEUE works on every kernel ≥ 3.8).
3. **Enforcement default = monitor-only per namespace.** When Wave A
   ships, every policy starts in `monitor` mode: dp computes the verdict
   and records it on the flow row, but the kernel still ACCEPTs the packet.
   Operators promote a namespace to `enforce` via the UI. Lowest possible
   blast radius.

---

## Wave structure at a glance

| Wave | Theme | Effort | Risk |
|---|---|---|---|
| **A** | Enforcement foundation: policy push → dp, NFQUEUE plumbing per CNI | 2–3 weeks | High (CNI matrix) |
| **B** | Enforcement UX: policy authoring, simulation, auto-gen | 2 weeks | Medium |
| **C** | Fidelity + coverage: byte split, host-net attribution, PCAP, DLP | 2 weeks | Low |
| **D** | Platform breadth: Cilium-native, multi-cluster, FIPS, custom sigs | 3 weeks | Medium |
| **E** | Operations + scale: load tests, audit, quarantine, sync workflow | 1–2 weeks | Low |

Total realistic engineering time: **~10–12 calendar weeks** (assumes
one engineer, with parallelism on independent tasks). Compressing further
risks the CNI compatibility matrix biting in production.

---

## Wave A — Enforcement foundation

Goal: dp drops packets per a policy the control plane pushed. Default
behavior is monitor-only; operator can toggle to enforce per namespace.

### A1. Agent → dp policy push channel

**Scope.** Implement `ctrl_cfg_policy` and `ctrl_cfg_dlp_rule` RPCs in
`internal/runtime/dp/client.go`. Mirror NeuVector's
`neuvector/agent/dp/ctrl.go` JSON shapes. Each RPC takes a policy version
+ a list of rules; dp's policy table swap is atomic per version (existing
behavior in `third_party/neuvector/dp/ctrl.c`).

Rule shape mirrors `share/clus_apis.go` `CLUSDerivedPolicyRule`: workload
EPMAC, peer wildcards or specific MAC/IP, ports, L4 proto, L7 app id,
action (allow/learn/violate/deny).

**Acceptance.**
- New types in `dp/client.go`: `PolicyRule`, `ConfigPolicy`, `ConfigDLPRule`.
- `Supervisor.PushPolicy(version, rules)` public method.
- Round-trip test: build a 3-rule policy, push, dp's debug log shows
  `cfg_policy: replaced N rules`.
- Pure-Go encode; no CGO.

**Files.** `internal/runtime/dp/client.go`, `internal/runtime/dp/supervisor.go`,
`internal/runtime/dp/client_test.go`.

**Depends on.** None (extends existing RPC scaffold).

**Effort.** 3 days.

---

### A2. Policy schema + storage

**Scope.** New tables:

```sql
-- Migration 042
CREATE TABLE runtime_policies (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL,
    cluster_id   UUID NOT NULL,
    workload     TEXT NOT NULL,           -- "<ns>/<deployment>" or "<ns>/*"
    namespace    TEXT NOT NULL,
    name         TEXT NOT NULL,           -- operator-friendly label
    mode         TEXT NOT NULL DEFAULT 'monitor', -- monitor|enforce|disabled
    rules        JSONB NOT NULL,          -- array of PolicyRule
    version      BIGINT NOT NULL,         -- monotonic per workload
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id, workload, name)
);

CREATE INDEX idx_runtime_policies_cluster_ns
  ON runtime_policies(org_id, cluster_id, namespace, mode);
```

PolicyRule JSONB shape:
```jsonc
{
  "id":        123,        // numeric for dp's hash table
  "direction": "ingress",  // or "egress"
  "peer": {
    "workload": "kube-system/coredns",  // or "*", "external", "cluster/<cidr>"
    "ip_cidrs": ["10.0.0.0/8"],         // optional intersection
    "ports":    [{"proto":"tcp","port":53}, ...]
  },
  "l7":     {"app": "dns"},   // optional
  "action": "allow"           // allow|monitor|deny
}
```

**Acceptance.**
- Migration applies + reverts cleanly.
- Type generation for `RuntimePolicy` (sqlc or hand-rolled).
- One test that round-trips a policy through INSERT + SELECT.

**Files.** `db/migrations/042_runtime_policies.sql`,
`internal/handler/runtime_policies.go` (new file, types only in this task).

**Depends on.** None.

**Effort.** 1 day.

---

### A3. NFQUEUE plumbing for k3s / Flannel / kube-proxy iptables

**Scope.** When a namespace has at least one policy in `enforce` mode,
the agent installs iptables NFQUEUE redirects on every host-side veth
that belongs to a pod in that namespace. Mirror NeuVector's approach in
`neuvector/agent/pipe/port.go` `createIptablesNvRules`.

Per-pod rule shape:
```
iptables -t mangle -I PREROUTING -i <host-veth> -j NFQUEUE \
    --queue-num <qnum> --queue-bypass
iptables -t mangle -I POSTROUTING -o <host-veth> -j NFQUEUE \
    --queue-num <qnum> --queue-bypass
```

`--queue-bypass` is critical: if dp dies, packets bypass NFQUEUE and the
pod stays reachable. dp listens on `<qnum>` via the existing `AddNfqPort`
RPC (already scaffolded in `internal/runtime/dp/client.go`).

Queue number allocation: per-node bitmap, queue `qnum = base + veth_index`
where `base` is an env-configured offset (default 4000) so we don't collide
with other iptables NFQUEUE users.

**Acceptance.**
- New `EnforceProvider` in `internal/runtime/dp/` that the tap reconciler
  uses *instead of* `TapProvider` when the workload's namespace is in
  `enforce` mode.
- iptables rules visible in `iptables -t mangle -L PREROUTING -nv` after
  policy push.
- Pod connectivity unaffected when dp is healthy (verdict=allow on every
  packet).
- Pod connectivity unaffected when dp is killed (verified: `--queue-bypass`
  lets traffic through).

**Files.** `internal/runtime/dp/enforce.go`, `internal/runtime/dp/iptables.go`,
`internal/runtime/dp/enforce_test.go`.

**Depends on.** A1.

**Effort.** 5 days.

**Risk.** This is the high-risk piece. The first deploy onto a real
cluster needs operator hand-holding and `--queue-bypass` belt-and-braces.

---

### A4. Calico + Cilium + EKS compatibility passes

**Scope.** Each non-default CNI gets its own integration audit:

- **Calico (Felix-managed iptables).** Calico's Felix rewrites `mangle`
  every ~5s. Three options, ranked by effort:
    1. (recommended) Insert rules into a *named subchain* Felix doesn't
       touch (`-N NVAGENT-PRE`), then `-I PREROUTING -j NVAGENT-PRE` so
       Felix's rewrite preserves our anchor. Document this in
       `docs/deployment-helm.md`.
    2. Use Calico's `iptables-rules.yaml` mechanism.
    3. Punt: detect Calico, refuse to enable enforce mode, log loudly.

- **Cilium (eBPF-native).** Cilium bypasses iptables entirely in its
  default eBPF mode. Two options:
    1. (recommended) Run dp in **TAP-only mode** on Cilium clusters —
       observation works, enforcement does not. Add a feature flag
       `runtimeAgent.dp.enforceOnCilium = false` that the agent
       enforces. Document the limitation; defer real enforcement to D1.
    2. Wave D1: dedicated Cilium eBPF integration. Out of scope for A.

- **EKS VPC CNI (prefix delegation).** Each pod has its own veth in the
  default netns; iptables works as on stock k8s. Test that
  `iptables-restore` is available in the AL2023 host (it is).

- **GKE / AKS managed.** Standard kube-proxy iptables; expected to work
  out of the box. Validate.

**Acceptance.**
- `docs/runtime-enforcement-cni-matrix.md` (or a section in
  `deployment-helm.md`) lists each CNI's status: enforce / tap-only / unsupported.
- Detector at agent startup: read `/etc/cni/net.d/` and `kube-system`
  DaemonSets to identify the CNI; emit a structured log line + a
  `constellation_runtime_agent_cni_detected{cni=...}` gauge.
- `runtimeAgent.dp.enforceOnCilium` value gate enforces "tap-only on Cilium".

**Files.** `internal/runtime/dp/cnidetect.go`,
`deploy/charts/constellation/values.yaml`, `docs/`.

**Depends on.** A3.

**Effort.** 1 week (1 day each for detect + 4 CNIs).

**Risk.** Calico testing requires a real Calico cluster; spin up a kind
cluster with the calico-vxlan installer.

---

### A5. Enforcement state machine + audit-log integration

**Scope.** Wire policy CRUD through the existing
`pkg/audit` package so every policy create / mode-change / delete lands
an `audit_events` row. Auto-revert: if a policy in `enforce` mode causes
the namespace's policy-error counter to spike, revert to `monitor`.

State machine per policy:
```
created (mode=monitor)
  ↓ operator promotes
monitor → enforce (mode=enforce)
  ↓ runtime error rate > threshold for 60s
enforce → monitor (auto-rollback)
```

`audit_events` rows: `action="runtime.policy.create"`,
`"runtime.policy.promote"`, `"runtime.policy.demote"`,
`"runtime.policy.auto_rollback"`, `target_type="workload"`,
`target_id=workload`, `metadata={mode_from, mode_to, rule_count, reason}`.

**Acceptance.**
- Toggling mode via API writes an audit row.
- An induced policy-error storm (simulated by pushing a bad rule) flips
  the policy back to monitor within 60s and writes the auto_rollback row.
- The auto-rollback threshold is configurable per cluster.

**Files.** `internal/handler/runtime_policies.go`,
`pkg/audit/runtime.go` (new sub-package).

**Depends on.** A2.

**Effort.** 3 days.

---

## Wave B — Enforcement UX

Goal: an operator who's never read this doc can author a policy, watch
it run in monitor mode, see what it would block, then flip to enforce.

### B1. Policy authoring UI

**Scope.** New page `frontend/src/pages/RuntimePoliciesPage.tsx`. Two
tabs:

1. **Authored** — list of policies. Each row shows mode (with badge),
   workload, rule count, last edit, "promote" / "demote" / "edit" /
   "delete" actions.
2. **Editor** — split pane: rule list on left, JSON preview on right.
   Rule form has dropdowns for direction, peer kind (workload | CIDR |
   external | any), ports (multi-add), L7 app (dropdown of dp app ids),
   action (allow / monitor / deny).

API client: `policies.list()`, `policies.get(id)`, `policies.create(body)`,
`policies.update(id, body)`, `policies.promote(id)`, `policies.demote(id)`,
`policies.delete(id)`.

**Acceptance.**
- Type-check clean.
- All four CRUD verbs hit the API and refresh the table.
- Mode badge uses the existing severity color tokens (monitor=info,
  enforce=success, disabled=muted).

**Files.** `frontend/src/pages/RuntimePoliciesPage.tsx`,
`frontend/src/api/client.ts` (add `runtimePolicies` block),
`internal/handler/runtime_policies.go` (CRUD endpoints, REST routes).

**Depends on.** A2, A5.

**Effort.** 4 days.

---

### B2. Enforcement state toggle per namespace

**Scope.** Surface mode toggles on the existing
`NetworkPolicyLifecyclePanel` (the bottom-left collapsible on the
Network Map). Promoting a workload to `enforce` confirms with a modal
that shows: "this will start dropping packets for X. Last 1h of
matched flows: N allowed, M would-be-blocked. Continue?"

The "would-be-blocked" count comes from the existing `verdict='alert'`
column on `network_flows` rows, populated by dp's policy engine even
in monitor mode (dp computes the verdict; the agent doesn't drop;
the row still records what would have happened).

**Acceptance.**
- Promote / demote buttons land HTTP 200 + audit row.
- Modal shows correct allow / would-block counts.
- Auto-rollback shows a toast notification.

**Files.** `frontend/src/pages/NetworkMapPage.tsx`,
`frontend/src/components/PolicyPromoteDialog.tsx` (new).

**Depends on.** A5, B1.

**Effort.** 2 days.

---

### B3. "What would this policy drop" simulation

**Scope.** Backend endpoint `POST /api/v1/runtime-policies/{id}/simulate`
runs the candidate policy against the last `hours` of `network_flows`
and returns a count of allow / monitor / deny matches plus a sample of
each. Implementation: server-side rule evaluator that mirrors dp's
match semantics (5-tuple + L7 app + direction). Doesn't need bit-perfect
parity with dp; "close enough to spot bad rules" is the bar.

**Acceptance.**
- A rule that matches every flow returns 100% deny.
- A rule that matches nothing returns 0 of each.
- Sample size capped at 50 rows per bucket.

**Files.** `internal/handler/runtime_policies_simulate.go`,
`pkg/policy/eval` (already exists, may need extension).

**Depends on.** B1.

**Effort.** 3 days.

---

### B4. Threat-aware NetworkPolicy auto-gen

**Scope.** Already exists in skeleton form (`internal/handler/network_policies.go`
has lifecycle / discover / monitor / protect modes). Extend to:

1. Auto-generate a `runtime_policies` row from observed dp flows in the
   last 24h for any deployment that's been in `discover` mode for that
   long.
2. Filter out flows that tripped a threat signature (don't generate
   "allow SQL injection paths" rules — alert on them instead).
3. Translate the generated rules into both a `runtime_policies` row
   (dp enforcement) AND a k8s `NetworkPolicy` YAML (kube-proxy
   enforcement). Two-layer defense.

**Acceptance.**
- Discover-mode workload with `connection` events but no threats →
  generated rules allow exactly those edges.
- Workload with threats → generated rules don't include the threat
  flows; threat verdicts stay alert/deny.
- Generated NetworkPolicy YAML downloadable from the UI.

**Files.** `internal/handler/network_policies.go`,
`pkg/netpolicy/generator.go` (new), `frontend/src/pages/NetworkPoliciesPage.tsx`.

**Depends on.** A2, A5.

**Effort.** 1 week.

---

## Wave C — Fidelity + coverage

Single-day or two-day items that close known fidelity gaps.

### C1. True client/server bytes split via DPMsgSession polling

**Scope.** Today the agent stores `bytes` (total) and leaves
`client_bytes` / `server_bytes` as `total / 0`. dp's `DPMsgSession`
wire type carries the split. Implementation:

1. Add a periodic request from the agent: every 30s,
   `ctrl_get_session_list` → dp emits a `DP_KIND_SESSION_LIST` reply
   with N `DPMsgSession` entries.
2. New decoder in `internal/runtime/dp/proto.go`: `decodeSessionList`.
3. New event kind `EventSession` with directional byte counts.
4. Correlator in `dpConnToFlowIngest`: when a `Connection` event arrives,
   look up the matching session in the most-recent session-list cache
   and use its wing-split. Fall back to "all in client_bytes" if no
   match (the bucket already aggregated).

**Acceptance.**
- Decoder round-trips a synthetic `DPMsgSession` correctly.
- A flow that's known to be server-heavy (e.g., a download from an
  in-cluster file server) shows `server_bytes > client_bytes`.
- Latency overhead < 50ms per poll on a 500-session host (mostly dp's
  serialization; we just decode).

**Files.** `internal/runtime/dp/proto.go`,
`internal/runtime/dp/proto_test.go`, `internal/runtime/dp/client.go`
(add `GetSessionList()` RPC), `cmd/constellation-runtime-agent/dp_flow.go`.

**Depends on.** None.

**Effort.** 1 day.

---

### C2. Per-MAC pod attribution for host-network pods (best-effort)

**Scope.** Host-network pods share the host's MAC, so a `pod_macs`
table can't disambiguate. Real solution: PID → cgroup → pod
correlation. The agent already has `hostPID: true` + `/proc` mount;
walk `/proc/<pid>/cgroup`, parse the kubepods cgroup path
(`kubepods.slice/kubepods-podXXXX.slice/...`), extract the pod UID,
join against the existing `pod_ips` discoverer output (which has UIDs).

This requires the discoverer to also write the pod UID into `pod_ips`
(it's available on the API server already).

**Acceptance.**
- New migration adds `pod_ips.pod_uid TEXT`.
- Discoverer fills `pod_uid`.
- Agent's flow emitter, on EPMAC = host MAC, falls back to PID→cgroup→
  pod_uid → `<ns>/<deployment>` via the discoverer's table.
- Host-network pod traffic is correctly attributed in the UI.

**Files.** `db/migrations/043_pod_ips_uid.sql`,
`cmd/constellation-discoverer/main.go`,
`cmd/constellation-runtime-agent/host_pid_resolver.go` (new),
`cmd/constellation-runtime-agent/dp_flow.go`.

**Depends on.** None (independent of A/B).

**Effort.** 3 days.

---

### C3. PCAP forensics — full-packet capture into object storage

**Scope.** Today dp captures up to ~2 KB per threat (`DPLOG_MAX_PKT_LEN`).
For deeper forensics, expose dp's existing pcap subsystem (`SnifferCmd`
gRPC in `share/enforcer_service.proto`) via the agent:

1. New endpoint: `POST /api/v1/runtime-pcap/start { workload, duration_s }`
2. Agent receives the request, calls dp's `start_pcap` ctrl, captures
   pcap rolling buffer for N seconds (capped at 60).
3. Agent uploads the .pcap file to the existing artifact store
   (`pkg/backup` / S3 / GCS bucket configured in Helm).
4. UI: `Threat Drilldown` gets a "Capture next 30s" button that
   triggers the flow.

**Acceptance.**
- 30s pcap of HTTP traffic decodes cleanly in Wireshark.
- Cap of 100 MB per pcap; agent rejects oversize.
- pcap URL appears on the threat row.

**Files.** `internal/handler/runtime_pcap.go`,
`internal/runtime/dp/client.go` (add `StartPcap` / `StopPcap` RPCs),
`cmd/constellation-runtime-agent/pcap_uploader.go` (new),
`frontend/src/pages/NetworkMapPage.tsx`.

**Depends on.** None.

**Effort.** 4 days.

---

### C4. DLP rules exposure

**Scope.** dp already has a Data Loss Prevention engine
(`third_party/neuvector/dp/dpi/sig/dpi_sigopt_pcre.c`) that matches
payload regexes for things like credit-card numbers, AWS keys, SSNs.
NeuVector exposes a DLP rule API; we don't.

Add a thin API to push user-authored DLP regex rules via the existing
`ctrl_cfg_dlp_rule` RPC (already scaffolded in A1).

**Acceptance.**
- Operator can add a DLP rule via UI: name, pattern, severity.
- A payload matching the pattern produces a `runtime_threats` row with
  `dlp_name_hash` set (already exists in the schema!).
- DLP threats render in the ThreatsCard with a "DLP" badge.

**Files.** `internal/handler/runtime_dlp.go`,
`frontend/src/pages/RuntimeDLPPage.tsx` (new).

**Depends on.** A1.

**Effort.** 3 days.

---

## Wave D — Platform breadth

Goal: shrink the "doesn't work on platform X" footnotes.

### D1. Cilium-native eBPF enforcement

**Scope.** On Cilium clusters, NFQUEUE is bypassed. Two integration
options:

1. **Cilium policy hooks (preferred).** Cilium has a CIDR policy
   model. We export our `runtime_policies` rules as Cilium
   `CiliumNetworkPolicy` CRDs. Cilium's own eBPF enforcement applies
   them. dp stays in TAP mode for observation.
2. **Native TC ingress.** Install our own TC ingress eBPF program
   per veth that calls dp via a perf event. Complex, fights Cilium.

Recommendation: option 1, document the L7 limitations (we lose dp's
DPI verdict; Cilium's L7 is HTTP-only).

**Acceptance.**
- Cilium cluster runs with `runtimeAgent.dp.enforceOnCilium=true`.
- Promoting a policy emits a `CiliumNetworkPolicy` instead of NFQUEUE
  rules.
- Detector picks "cilium-policy-export" mode automatically.

**Files.** `pkg/netpolicy/cilium_export.go` (new),
`internal/runtime/dp/enforce.go`.

**Depends on.** A4.

**Effort.** 1 week.

**Risk.** Cilium's CiliumNetworkPolicy CRD evolves; we test against
a specific version.

---

### D2. Multi-cluster fan-in

**Scope.** Today the agent assumes a single control plane. For
federation: one constellation API consuming agents from many clusters.
This is mostly already there — the API resolves `cluster_id` from the
runtime-agent token's org + cluster registration. Tasks:

1. Audit all `network_flows`, `runtime_threats`, `events` queries for
   `cluster_id` filtering — confirm zero cross-cluster leakage.
2. Add a cluster picker to the Network Map (we have one for some
   pages, not all).
3. Per-cluster row visibility in the policy editor.
4. Cluster-scoped audit logs.

**Acceptance.**
- E2E test: two clusters, two agents, two policies, no cross-talk.

**Files.** Many handlers, several frontend pages, an e2e suite.

**Depends on.** Wave B (policy UI).

**Effort.** 1 week.

---

### D3. FIPS-compliant build

**Scope.** `docs/fips.md` exists for the Go side. Extend:

1. dp's hyperscan (`vectorscan-dev`) uses non-FIPS crypto. Replace with
   FIPS-validated regex library (Intel hyperscan-fips? PCRE2-FIPS?), or
   document that DPI is non-FIPS-validated and the rest of the stack is.
2. Use FIPS-mode openssl in the runtime image.
3. Go: `GOEXPERIMENT=boringcrypto` build flag (already in
   constellation's main path).

**Acceptance.**
- `make image-runtime-agent FIPS=true` builds with the FIPS toggles.
- `go version -m /usr/local/bin/constellation-runtime-agent` shows
  boringcrypto.
- Documentation explicitly scopes what's FIPS and what isn't.

**Files.** `deploy/docker/Dockerfile.runtime-agent`,
`docs/fips.md`.

**Depends on.** None.

**Effort.** 4 days (mostly research + doc).

---

### D4. Custom DPI signatures

**Scope.** dp's hyperscan signature engine takes pattern databases.
NeuVector ships a default set (in `third_party/neuvector/dp/dpi/sig/`);
let users add their own via the API.

1. New table `dp_custom_signatures` (org_id, name, pattern_pcre,
   severity, threat_id_offset).
2. Agent fetches the org's signatures on startup, compiles via
   `bpf_get_pattern_db` (already exists in dp), pushes to dp via
   `ctrl_cfg_dlp_rule`.
3. UI for authoring patterns. PCRE syntax with a "test" pane.

**Acceptance.**
- User-authored pattern that matches "TESTSTR" appears in
  `runtime_threats` when traffic contains "TESTSTR".

**Files.** `db/migrations/044_dp_custom_signatures.sql`,
`internal/handler/runtime_signatures.go`,
`frontend/src/pages/RuntimeSignaturesPage.tsx`.

**Depends on.** A1.

**Effort.** 5 days.

---

## Wave E — Operations + scale

### E1. Performance baseline + load testing

**Scope.** k6 / vegeta scripts that drive synthetic traffic through a
test cluster while the agent runs. Measure:
- dp CPU at 100, 500, 1000, 5000 connections/sec
- agent memory at 50, 500 active pod taps
- ingest API throughput

Publish a baseline doc (`docs/scale-hardening.md` already exists —
extend with runtime-agent numbers).

**Effort.** 4 days.

---

### E2. Compliance audit-log mappings

**Scope.** Every enforcement action lands in `audit_events`. Add
compliance-framework annotations: PCI-DSS req 1.2.1 (network
segmentation), SOC2 CC6.6 (logical access), HIPAA 164.312(a)(1)
(access control).

Operators query: "show me every enforce action in the last 30 days
that maps to PCI 1.2.1."

**Effort.** 3 days.

---

### E3. Threat scenario e2e suite expansion

**Scope.** `deploy/e2e/threat-scenarios/` has 9 scenarios today. Add:
- SQL injection → dp threat → policy auto-gen
- DNS tunneling → dp threat → DLP rule
- TLS heartbleed (synthetic) → dp threat → PCAP capture
- Cross-namespace lateral movement → enforce policy → kernel drop

**Effort.** 4 days.

---

### E4. Runtime quarantine via signal + admission webhook

**Scope.** A pod that's tripped a critical threat can be "quarantined":
1. dp's enforce mode immediately drops all traffic to/from the pod.
2. A constellation admission webhook blocks any restart attempt
   (`MutatingAdmissionWebhook` rejects pods with the
   `constellation.io/quarantined=true` annotation, which we set
   via the API).
3. Operator manually un-quarantines via UI after investigation.

**Acceptance.**
- Quarantine button on the Threat Drilldown.
- Pod loses network within 1s of click.
- Pod cannot restart even after deletion.
- Un-quarantine restores within 1 reconcile cycle.

**Files.** `cmd/constellation-admission/`, `internal/handler/quarantine.go`,
`frontend/src/pages/NetworkMapPage.tsx`.

**Effort.** 5 days.

---

### E5. NeuVector sync workflow tooling

**Scope.** `third_party/neuvector/README.md` documents how to sync from
upstream. Make it a Makefile target with checks:

```
make neuvector-sync          # rebases third_party/neuvector to a new upstream rev
make neuvector-sync-check    # CI check: are we drifted from a tagged upstream?
```

Includes:
- Validates LICENSE / NOTICE update
- Re-runs the docker dp-build stage
- Runs `go test ./internal/runtime/dp/...` to confirm wire-format compat

**Effort.** 1 day.

---

## Cross-cutting concerns

These don't live in any single wave but get tracked alongside the work.

- **Backwards compat.** New schema columns nullable. Old agents keep
  working through Wave A; they just don't emit policy verdicts. Old
  UI keeps working through Wave B; the new pages are additive.
- **Rollout order.** Within a multi-cluster environment, roll Wave A
  out one cluster at a time. Monitor metrics for 24h before moving on.
- **Kill switch.** Helm value `runtimeAgent.dp.enforce.killSwitch=true`
  forces every policy in the cluster back to monitor mode. Implement
  in A5.
- **Telemetry.** Every wave adds Prometheus metrics under the existing
  `constellation_runtime_agent_*` namespace. The /metrics endpoint
  (already shipped) is the single scrape target.
- **Documentation.** Each wave updates the relevant `docs/*.md`. No
  separate docs created — extend `deployment-helm.md`, `fips.md`,
  `scale-hardening.md`, `integrations.md` in place.

---

## Task index (sortable)

| ID | Title | Wave | Effort | Depends on |
|---|---|---|---|---|
| A1 | Agent → dp policy push channel | A | 3d | — |
| A2 | Policy schema + storage | A | 1d | — |
| A3 | NFQUEUE plumbing (k3s/Flannel) | A | 5d | A1 |
| A4 | Calico + Cilium + EKS compat | A | 5d | A3 |
| A5 | State machine + audit-log | A | 3d | A2 |
| B1 | Policy authoring UI | B | 4d | A2, A5 |
| B2 | Per-namespace enforce toggle | B | 2d | A5, B1 |
| B3 | "What would this drop" simulation | B | 3d | B1 |
| B4 | Threat-aware policy auto-gen | B | 5d | A2, A5 |
| C1 | DPMsgSession byte split | C | 1d | — |
| C2 | Host-network pod attribution | C | 3d | — |
| C3 | PCAP forensics | C | 4d | — |
| C4 | DLP rules exposure | C | 3d | A1 |
| D1 | Cilium-native eBPF enforcement | D | 5d | A4 |
| D2 | Multi-cluster fan-in | D | 5d | B |
| D3 | FIPS-compliant build | D | 4d | — |
| D4 | Custom DPI signatures | D | 5d | A1 |
| E1 | Perf baseline + load test | E | 4d | — |
| E2 | Compliance audit mappings | E | 3d | A5 |
| E3 | Threat scenario e2e expansion | E | 4d | A, B |
| E4 | Quarantine via webhook | E | 5d | A3 |
| E5 | NeuVector sync workflow | E | 1d | — |

**Total**: ~80 engineer-days. With one engineer dedicated and reasonable
parallelism, ~10–12 calendar weeks. With two engineers, ~6–7 weeks
(B and C parallelize after A1+A2 land).

---

## Recommended execution order

1. **A1, A2 in parallel** (independent, both small)
2. **A3** (kernel-side, highest-risk, get it on real hardware first)
3. **A5** (state machine — needed before any UI work)
4. **C1** (small fidelity win, ship while A4 is in CNI testing)
5. **A4** (CNI matrix — needs a real Calico cluster to test against)
6. **B1, B2 in parallel** (UI and toggle — independent)
7. **B3, B4 in parallel** (advanced UX — both depend on B1)
8. **C2, C3, C4 in parallel** (independent fidelity items)
9. **D1, D3, D4 in parallel** (independent platform items)
10. **D2** (multi-cluster — needs all prior schema settled)
11. **E1–E5** (operations — running through, can start early on E1+E5)

First merge-able milestone: end of step 3 (A1+A2+A3+A5). At that point
operators can author policies, push them to dp, see verdicts in monitor
mode. The marquee feature exists; everything after is polish + breadth.

---

## What this plan deliberately does NOT include

- **Replacing the kube-proxy iptables data plane.** We add NFQUEUE
  redirects; we don't take over `kube-proxy`'s job.
- **Network performance tuning beyond defaults.** dp's TAP-mode
  inspection adds ~5% CPU per Gbps. NFQUEUE adds 10–30%. We document
  this; we don't optimize.
- **Replacing existing constellation policy types.** `pkg/policy/`
  is for the compliance / image scanning policy engine. Wave A's
  `runtime_policies` is a new, separate domain. Don't merge them.
- **Building a new gRPC layer.** dp's IPC is unixgram + JSON; we
  match that. No protobuf in the dp path.
- **Hot-reload of dp's hyperscan database.** Pattern set is loaded
  at startup. Updates require dp restart (which our supervisor
  handles gracefully).

---

## Open questions to revisit at each wave boundary

- Do we need a `enforce` mode that's stricter than dp's policy verdicts
  (i.e., default-deny if no rule matches, vs default-allow)? Default
  pick: default-allow (NeuVector matches this); revisit at A2.
- Should the policy-authoring UI accept raw dp JSON for power users?
  Default pick: no — the rule form is the only interface; rule JSON
  is read-only in the preview pane.
- Does the auto-rollback in A5 page on-call? Default pick: it writes
  an audit row; pager integration is E2's job.

---

*Last updated: 2026-05-13. Next review at end of Wave A.*
