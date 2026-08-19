#!/bin/bash
# Run one fortio load test. $1=label, $2=qps, $3=duration
set -e
LABEL="$1"
QPS="$2"
DUR="$3"
OUT="/root/perf/${LABEL}.json"
echo "=== ${LABEL}: ${QPS} qps for ${DUR} ==="
kubectl -n perf-bench run "fortio-load-${LABEL}" --rm -i --restart=Never \
  --image=fortio/fortio:latest --image-pull-policy=IfNotPresent \
  --command -- /usr/bin/fortio load \
    -qps "${QPS}" -t "${DUR}" -c 8 -keepalive \
    -json - \
    http://fortio-server.perf-bench.svc.cluster.local:8080/echo 2>/dev/null \
  > "${OUT}.raw"
# kubectl run --rm appends `pod "x" deleted` after the JSON; keep only
# the lines up to the closing brace of the outermost JSON object.
awk '/^}$/{print; exit} {print}' "${OUT}.raw" > "${OUT}"
python3 - <<PY
import json
d = json.load(open('${OUT}'))
print(f'  Target QPS : {d["RequestedQPS"]}')
print(f'  Actual QPS : {d["ActualQPS"]:.0f}')
print(f'  Duration   : {d["ActualDuration"] / 1e9:.1f}s')
print(f'  RTT min    : {d["DurationHistogram"]["Min"]*1000:.2f} ms')
def p(n):
    for x in d["DurationHistogram"]["Percentiles"]:
        if x["Percentile"]==n: return x["Value"]*1000
    return 0.0
print(f'  RTT p50    : {p(50):.2f} ms')
print(f'  RTT p95    : {p(95):.2f} ms')
print(f'  RTT p99    : {p(99):.2f} ms')
print(f'  RTT max    : {d["DurationHistogram"]["Max"]*1000:.2f} ms')
print(f'  Total reqs : {d["DurationHistogram"]["Count"]}')
errs = d.get("RetCodes",{})
non200 = {k:v for k,v in errs.items() if k != "200"}
print(f'  RetCodes   : {errs}')
if non200:
    print(f'  *** non-200 ***: {non200}')
PY
