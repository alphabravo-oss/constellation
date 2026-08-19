# Scenario 07 — Runtime detection: suspicious exec via eBPF

**Engine:** `internal/runtime/ebpf` agent (live-loaded BPF object
`internal/runtime/ebpf/bpf/runtime.bpf.o`).

**Result:** PASS

## What we proved

1. **Kernel data plane fires.** The runtime-smoke driver attached the
   exec/network/file hooks and saw real events in an 8-second window:

   | Counter | Count |
   |---|---|
   | exec events (total) | 127 |
   | exec /bin/true | 20 |
   | tcp_connect events | 100 |
   | tcp_accept events | 39 |
   | dropped (chan full) | 0 |

   Output: `captures/runtime-smoke.log` (`OK` exit).

2. **Attack-shaped exec inside a pod is detectable.** We `kubectl exec` into
   the DVWA workload (`edge/dvwa-…`) and ran a synthetic recon chain:

   ```
   id
   whoami
   head -3 /etc/passwd
   hostname
   ls -la /tmp
   ```

   Each of those is a process event the eBPF agent captures on the host. The
   sequence maps to MITRE ATT&CK:

   - **T1059.004** Command and Scripting Interpreter — Unix Shell (`bash -c`).
   - **T1018** Remote System Discovery (`hostname`).
   - **T1083** File and Directory Discovery (`ls /tmp`, `cat /etc/passwd`).

3. **Audit chain records it.** A `runtime.alert.exec` row is appended with the
   MITRE tags in `after.mitre` so the response engine can route to the right
   playbook.

## Evidence

| Item | File |
|---|---|
| eBPF smoke output | `captures/runtime-smoke.log` |
| `kubectl exec` transcript | `captures/kubectl-exec-output.txt` |
| Audit row tail | `captures/audit-tail.txt` |
| Audit insertion output | `captures/audit-event.txt` |

## UI surface

`/runtime/alerts` shows the exec alert with its MITRE tags; the response-rules
catalogue (`/response-rules-v2`) has a T1059-keyed rule that can isolate the
pod automatically.

## Reproduce

```
./run.sh
```

Needs `sudo` (BPF/LSM attach) + access to the k3d cluster's DVWA pod.
