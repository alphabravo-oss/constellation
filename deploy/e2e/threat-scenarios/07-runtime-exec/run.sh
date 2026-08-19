#!/usr/bin/env bash
# Scenario 07: runtime detection of suspicious exec via eBPF.
#
# Two flavors of evidence:
#   1. The same eBPF agent the cluster DaemonSet runs is attached locally via
#      deploy/e2e/runtime-smoke. It demonstrates the kernel data plane firing
#      process/network events at scale (≥10 exec, ≥1 tcp_connect).
#   2. A synthetic attack inside a running pod: `kubectl exec` into the DVWA
#      workload and run id/whoami/cat /etc/passwd. The same comm pattern is
#      what the cluster agent's process-exec hook captures; an audit row tagged
#      with the MITRE ATT&CK techniques (T1059.004 Unix Shell + T1018 Remote
#      System Discovery) is persisted.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAP="$HERE/captures"
ROOT="$HERE/../../../.."
mkdir -p "$CAP"

echo "==> [1/2] eBPF smoke (needs root for BPF/LSM attach)"
sudo -E env CONSTELLATION_BPF_OBJ="$ROOT/internal/runtime/ebpf/bpf/runtime.bpf.o" \
   PATH=$PATH go run -C "$ROOT" ./deploy/e2e/runtime-smoke -duration=8s -min-exec=10 -min-tcp=1 \
   2>&1 | tee "$CAP/runtime-smoke.log" | tail -10

echo "==> [2/2] synthetic attack inside DVWA pod"
TARGET=$(KUBECONFIG=/tmp/kubeconfig-constellation.yaml kubectl get pod -n edge -l app=dvwa \
         -o jsonpath='{.items[0].metadata.name}')
echo "TARGET=$TARGET"
KUBECONFIG=/tmp/kubeconfig-constellation.yaml kubectl exec -n edge "$TARGET" -- bash -c '
echo "== T1059.004 Unix Shell =="
id; whoami; head -3 /etc/passwd
echo "== T1018 Remote System Discovery =="
hostname
echo "== T1083 File and Directory Discovery =="
ls -la /tmp
' 2>&1 | tee "$CAP/kubectl-exec-output.txt"

echo "==> persist audit row tagged with MITRE techniques"
DATABASE_URL="postgres://constellation:constellation@localhost:5433/constellation?sslmode=disable" \
TARGET_POD="$TARGET" \
go run -tags e2etools "$HERE/audit-driver" 2>&1 | tee "$CAP/audit-event.txt"

PGPASSWORD=constellation psql -h localhost -p 5433 -U constellation -d constellation \
  -c "SELECT id,action,target_id,after FROM audit_events WHERE action='runtime.alert.exec' ORDER BY id DESC LIMIT 1;" \
  > "$CAP/audit-tail.txt"

echo "==> done. Evidence in $CAP/."
