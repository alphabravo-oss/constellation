# E3 — End-to-end threat scenario validation (testnode 2026-05-14)

Live validation of the deployed constellation stack on the single-node k3s
testnode. This complements the existing scenario library under
`deploy/e2e/threat-scenarios/` (which targets a Wave H3 docker-compose
environment). Three of the highest-value threat detections were exercised
end-to-end against the live cluster; one real bug was found and fixed
during the run.

## Cluster under test

| | |
|---|---|
| Distribution | k3s 1.35.4, default Flannel CNI |
| Hardware | 16 vCPU / 30 GB / Ubuntu 24.04 / kernel 6.8 with BTF |
| Helm release | `constellation` namespace `constellation-system` |
| Bootstrap admin | `admin@constellation.local` / 24-char random (in `constellation-admin-credentials` Secret) |

## Test 1 — Suspicious exec via eBPF (PASS)

**Setup.** Deployed an alpine pod with sleep 1d in `perf-bench` namespace.
Exec'd in to run a reconnaissance pattern: `id`, `whoami`, `hostname`,
`cat /etc/passwd`, `ls -la /`, `find / -name *.conf`.

**Expectation.** The runtime-agent's BPF tracepoint
(`tracepoint:sched_exec`) captures every exec on the host, including those
inside containers (because the agent's pod runs with `hostPID: true`).

**Result.**
```
  exec: comm=cat        pid=90785 ppid=90775 file=/bin/cat
  exec: comm=head       pid=90786 ppid=90775 file=/usr/bin/head
  exec: comm=find       pid=90787 ppid=90775 file=/usr/bin/find
  exec: comm=sh         pid=90939 ppid=90902 file=/bin/sh
  exec: comm=id         pid=90963 ppid=90959 file=/usr/bin/id
  exec: comm=cat        pid=90996 ppid=90980 file=/usr/bin/cat
  ... 42 attack-pattern exec events captured --
```

**42 attack-pattern execs captured** by the BPF probe, including the
`id`, `cat`, and `find` invocations from inside the container. PIDs are
host-namespace because the probe attaches to the host kernel.

## Test 2 — Admission deny (PASS — after fixing a bug)

**Setup.** Three pod manifests submitted to the cluster:
- `priv-pod`: `securityContext.privileged: true`
- `hn-pod`: `hostNetwork: true`
- `ok-pod`: compliant (`readOnlyRootFilesystem: true`)

**Expectation.** First two denied by the `block-privileged` /
`block-host-network` enforce-mode rules. Third admitted with monitor-mode
warnings.

**Result on first try (FAIL).** All three pods were admitted. Investigation
showed:

```
$ kubectl logs deploy/constellation-admission --tail=20
http: TLS handshake error from 10.42.0.1:55398: remote error: tls: bad certificate
http: TLS handshake error from 10.42.0.1:57410: remote error: tls: bad certificate
... (many more)
```

The webhook's TLS handshake failed for every admission request. Root cause:

```
$ kubectl get vwc constellation-admission -o jsonpath='{.webhooks[0].clientConfig.caBundle}'
(empty)
```

The `ValidatingWebhookConfiguration` had an empty `caBundle`. The chart's
pre-install `tls-bootstrap-job` creates the TLS Secret AND tries to patch
the VWC, but at pre-install time the VWC doesn't exist yet — the script
falls into its else branch and logs "VWC not present yet". Nothing ever
patches the VWC after the chart applies it.

Combined with `failurePolicy: Ignore` (the safe default), this means
**every pod was being admitted regardless of policy** — silent failure
of the entire admission engine.

**Fix.** Added `templates/tls-bootstrap-job.yaml` companion Job
`constellation-tls-bootstrap-patch` running as a `post-install,post-upgrade`
hook (weight -10, before migrate). It re-runs the existing `patch.sh`
which by that time finds the VWC and populates `caBundle` from the Secret
the pre-install Job created.

**Result after fix.** Live patch applied to the running cluster. Re-tested:

```
$ kubectl apply -f priv-pod.yaml
Error from server: error when creating "STDIN": admission webhook "pods.constellation.alphabravo.io"
  denied the request: denied by constellation policy "block-privileged":
  container "c" is privileged

$ kubectl apply -f hn-pod.yaml
Error from server: error when creating "STDIN": admission webhook "pods.constellation.alphabravo.io"
  denied the request: denied by constellation policy "block-host-network":
  hostNetwork=true

$ kubectl apply -f ok-pod.yaml
Warning: policy "require-image-signature" (monitor): missing constellation image-signed annotation
pod/ok-pod created
```

All three behave as designed: 2 denied, 1 admitted with monitor warning.

## Test 3 — Audit chain integrity (PASS)

**Setup.** Logged in via `/api/v1/auth/login` with the bootstrap admin,
then called `/api/v1/audit/verify`.

**Expectation.** Chain status: `verified`. Genesis hash matches a fresh
chain's expected value.

**Result.**
```json
{
  "events": 2,
  "genesis_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "last_hash": "cc63b597d312c3e3e7dd0478638f9ac880ba4ca93f3824500230fab82038b7dd",
  "status": "verified"
}
```

`VerifyChain` walked the entire chain (the two login events from this
session) and reported intact.

## Real bugs found and resolved

| # | Bug | Severity | Status |
|---|-----|----------|--------|
| A | VWC `caBundle` never populated → admission webhook silently bypassed | **HIGH** — admission engine non-functional out of the box | Fixed in chart (post-install patch Job); fixed live on testnode |
| B | Admission denials never recorded in `audit_events` table | Medium — compliance evidence gap (E2 mappings exist but no rows produced) | Filed as follow-up — needs DATABASE_URL wiring + token-based ingest path on the admission Deployment |
| C | The 10 existing scenarios under `deploy/e2e/threat-scenarios/` target a Wave H3 docker-compose env, not k8s | Low — they pass on the original env; just don't run as-is on k8s | Will rewrite as part of the proper E3 implementation when we move to a real e2e CI |

## What's NOT in this run

- **WAF / DLP detections.** Would need to deploy a vulnerable workload
  (DVWA, juice-shop) and exercise it. The dp data-plane is alive and the
  signature library compiles, but I haven't proved an end-to-end SQLi or
  PII detection on this cluster.
- **Quarantine via admission.** E4 quarantine entries exist as a backend
  feature but the admission webhook would need to be configured with the
  DSN to consume them. Worth a follow-up validation.
- **Network policy enforcement under load.** Requires promoting a policy
  to enforce mode and verifying NFQUEUE drops the denied flow. Possible
  next iteration.
- **Sustained false-positive baseline.** The plan called for 1 hour of
  fortio traffic with zero spurious alerts. Done implicitly during the
  perf baseline (no `runtime_threats` rows during the 60 seconds of
  combined fortio runs), but not formally measured over a long horizon.

## Provenance

All numbers and outputs are from runs on `temp-constellation-test1`
(178.105.113.213), kernel 6.8, k3s 1.35.4, on 2026-05-14 between
01:36 and 02:05 UTC.
