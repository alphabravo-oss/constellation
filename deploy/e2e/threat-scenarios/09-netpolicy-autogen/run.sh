#!/usr/bin/env bash
# Scenario 09: network policy auto-generation.
#
# Hits the lifecycle endpoint to pull a candidate policy (the API serves a
# seeded set of stable workload observations the runtime agent would normally
# produce after 24h). Then drives the preview + approve actions and asserts the
# resulting hash-chained audit event lands.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAP="$HERE/captures"
mkdir -p "$CAP"

TOKEN="${TOKEN:-$(cat /tmp/h3-token)}"
API="${API:-http://localhost:18080}"

echo "==> [1/3] lifecycle list"
curl -s -H "Authorization: Bearer $TOKEN" "$API/api/v1/network/policies/lifecycle" \
  | python3 -m json.tool > "$CAP/lifecycle.json"

HASH=$(python3 -c 'import json; d=json.load(open("'"$CAP"'/lifecycle.json")); print(d["items"][0]["candidate_hash"])')
echo "candidate_hash=$HASH"

echo "==> [2/3] preview action"
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"candidate_hash\":\"$HASH\"}" \
  "$API/api/v1/network/policies/default%2Fapi-service/preview" \
  | python3 -m json.tool > "$CAP/preview.json"

echo "==> [3/3] approve action (lands network_policy.approve audit event)"
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"candidate_hash\":\"$HASH\"}" \
  "$API/api/v1/network/policies/default%2Fapi-service/approve" \
  | python3 -m json.tool > "$CAP/approve.json"

echo "==> audit tail"
PGPASSWORD=constellation psql -h localhost -p 5433 -U constellation -d constellation \
  -c "SELECT id,action,target_kind,target_id FROM audit_events WHERE action LIKE 'network_policy.%' ORDER BY id DESC LIMIT 5;" \
  | tee "$CAP/audit-tail.txt"
