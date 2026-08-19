#!/usr/bin/env bash
# Scenario 01: image vulnerability scan, end-to-end.
#
# Drives `constellationctl image-check nginx:1.14.2` (a known-vulnerable image)
# through the Syft + Trivy + Grype aggregator, persists SARIF + JSON, then proves
# the API side: dashboard tick, findings exist, and an audit row is appended when
# a scan job is enqueued.
#
# Requires: /tmp/constellationctl, syft/trivy/grype on PATH, API on :18080, JWT
# cached at /tmp/h3-token (see INDEX.md for the login one-liner).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAP="$HERE/captures"
mkdir -p "$CAP"

TOKEN="${TOKEN:-$(cat /tmp/h3-token)}"
API="${API:-http://localhost:18080}"
IMAGE="${IMAGE:-nginx:1.14.2}"

echo "==> [1/5] constellationctl image-check $IMAGE"
/tmp/constellationctl image-check "$IMAGE" \
    --sarif "$CAP/nginx-1.14.2.sarif" \
    --json  "$CAP/nginx-1.14.2.json" \
    | tee "$CAP/image-check-summary.txt"

echo "==> [2/5] count SARIF findings"
python3 - <<PY > "$CAP/sarif-count.txt"
import json
d=json.load(open("$CAP/nginx-1.14.2.sarif"))
runs=d.get("runs",[])
print("runs:", len(runs))
n=0
for r in runs:
    n += len(r.get("results", []))
print("total_results:", n)
PY
cat "$CAP/sarif-count.txt"

echo "==> [3/5] /api/v1/findings (kind=vulnerability)"
curl -s -H "Authorization: Bearer $TOKEN" \
  "$API/api/v1/findings?kind=vulnerability&limit=5" \
  | python3 -m json.tool > "$CAP/findings-api.json"

echo "==> [4/5] /api/v1/dashboard/summary"
curl -s -H "Authorization: Bearer $TOKEN" \
  "$API/api/v1/dashboard/summary" \
  | python3 -m json.tool > "$CAP/dashboard-summary.json"

echo "==> [5/5] enqueue scan job (writes scan-job.enqueue audit event)"
RESP=$(curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"image_ref\":\"$IMAGE\"}" "$API/api/v1/scan-jobs")
echo "$RESP" | tee "$CAP/scan-job-enqueue.json"
curl -s -H "Authorization: Bearer $TOKEN" "$API/api/v1/audit/events?limit=5" \
  | python3 -m json.tool > "$CAP/audit-events.json"

echo "==> done. Evidence in $CAP/."
